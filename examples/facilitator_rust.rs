//! Lightweight facilitator demo that leans on `rust-sdk-4mica` to sign a payment envelope.
//!
//! Usage:
//! - Show supported kinds:
//!   `cargo run --example facilitator_rust -- supported http://localhost:8080/`
//! - Build an X-PAYMENT header and POST /verify:
//!   `PAYER_KEY=0x... USER_ADDRESS=0x... RESOURCE_URL=http://localhost:9000/protected cargo run --example facilitator_rust -- verify http://localhost:8080/`
//!   (if RESOURCE_URL is unset, fall back to TAB_ID/AMOUNT/RECIPIENT_ADDRESS/ASSET_ADDRESS env vars)
//! - End-to-end demo (discover → sign → /verify → resource retry → /settle):
//!   `cargo run --example facilitator_rust -- demo http://localhost:8080/`
//!
//! Environment (all but FACILITATOR_URL required for `verify`):
//! - FACILITATOR_URL: defaults to http://localhost:8080/
//! - X402_CORE_API_URL: optional override for SDK RPC URL (defaults to https://api.4mica.xyz/)
//! - RESOURCE_URL: paid API endpoint that returns a 402 and tabEndpoint
//! - PAYER_KEY: 0x-prefixed wallet private key
//! - USER_ADDRESS: address matching the private key
//! - (Manual fallback) RECIPIENT_ADDRESS, TAB_ID, AMOUNT, ASSET_ADDRESS when RESOURCE_URL is unset
//! - X402_SCHEME/X402_NETWORK: optional overrides for the envelope (defaults: 4mica-credit / polygon-amoy)

use std::env;
use std::io::ErrorKind;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use dotenvy::from_filename;
use reqwest::{Client as HttpClient, Method, StatusCode, Url};
use rust_sdk_4mica::{Client, ConfigBuilder, PaymentGuaranteeRequestClaims, SigningScheme, U256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct PaymentRequirements {
    scheme: String,
    network: String,
    max_amount_required: String,
    resource: Option<String>,
    description: Option<String>,
    mime_type: Option<String>,
    output_schema: Option<Value>,
    pay_to: String,
    max_timeout_seconds: Option<u64>,
    asset: String,
    extra: Value,
}

#[derive(Deserialize)]
struct SupportedKind {
    scheme: String,
    network: String,
}

struct PaymentSession {
    header: String,
    verify_body: Value,
    requirements: PaymentRequirements,
    claims: PaymentGuaranteeRequestClaims,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    load_env_files();

    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "supported".into());
    let facilitator = args.next().unwrap_or_else(|| {
        env::var("FACILITATOR_URL").unwrap_or_else(|_| "http://localhost:8080/".into())
    });

    match command.as_str() {
        "supported" => show_supported(&facilitator).await?,
        "verify" => run_verify(&facilitator).await?,
        "demo" => run_demo(&facilitator).await?,
        other => anyhow::bail!("unknown command {other}; use `supported`, `verify`, or `demo`"),
    }

    Ok(())
}

async fn run_verify(facilitator: &str) -> anyhow::Result<()> {
    let payer_key = env_var("PAYER_KEY")?;
    let user_address = env_var("USER_ADDRESS")?;

    let payment = PaymentSession::build(facilitator, &payer_key, &user_address).await?;
    println!("X-PAYMENT header:\n{}\n", payment.header);

    let url = format!("{facilitator}/verify");
    let client = HttpClient::new();
    let resp = client
        .post(&url)
        .json(&payment.verify_body)
        .send()
        .await?
        .error_for_status()?;
    let body: Value = resp.json().await?;
    println!("Verify response:\n{}", serde_json::to_string_pretty(&body)?);

    println!(
        "Signed claims:\n{}",
        serde_json::to_string_pretty(&json!(payment.claims))?
    );

    Ok(())
}

async fn run_demo(facilitator: &str) -> anyhow::Result<()> {
    let payer_key = env_var("PAYER_KEY")?;
    let user_address = env_var("USER_ADDRESS")?;
    let resource_url = env_var("RESOURCE_URL")
        .context("RESOURCE_URL is required for demo flow (paid resource endpoint)")?;
    let resource_method = env_var_opt("RESOURCE_METHOD").unwrap_or_else(|| "GET".into());

    let payment = PaymentSession::build(facilitator, &payer_key, &user_address).await?;
    println!(
        "Resolved paymentRequirements:\n{}\n",
        serde_json::to_string_pretty(&json!(payment.requirements))?
    );

    let client = HttpClient::new();
    // Pre-verify
    let url = format!("{facilitator}/verify");
    let verify_resp = client
        .post(&url)
        .json(&payment.verify_body)
        .send()
        .await?
        .error_for_status()?;
    let verify_body_json: Value = verify_resp.json().await?;
    println!(
        "Facilitator /verify response:\n{}\n",
        serde_json::to_string_pretty(&verify_body_json)?
    );

    // Retry resource with header
    println!("Retrying resource with X-PAYMENT header");
    let retry = client
        .request(parse_method(&resource_method)?, &resource_url)
        .header("X-PAYMENT", &payment.header)
        .send()
        .await
        .context("failed to retry resource with X-PAYMENT")?;
    let status = retry.status();
    let resource_text = retry.text().await.unwrap_or_default();
    println!("Resource retry status: {status}");
    if !resource_text.is_empty() {
        println!("Resource body:\n{resource_text}\n");
    }

    // Settle
    let settle_url = format!("{facilitator}/settle");
    let settle_resp = client
        .post(&settle_url)
        .json(&payment.verify_body)
        .send()
        .await?
        .error_for_status()?;
    let settle_body: Value = settle_resp.json().await?;
    println!(
        "Facilitator /settle response:\n{}\n",
        serde_json::to_string_pretty(&settle_body)?
    );

    println!(
        "Signed claims:\n{}",
        serde_json::to_string_pretty(&json!(payment.claims))?
    );
    println!(
        "Demo complete for scheme={}, network={}",
        payment.requirements.scheme, payment.requirements.network
    );

    Ok(())
}

impl PaymentSession {
    async fn build(
        facilitator: &str,
        payer_key: &str,
        user_address: &str,
    ) -> anyhow::Result<Self> {
        let requirements = load_requirements(facilitator, user_address).await?;
        let claims = claims_from_requirements(&requirements, user_address)?;
        let signature = sign_claims(&claims, payer_key).await?;

        let envelope = json!({
            "x402Version": 1,
            "scheme": requirements.scheme,
            "network": requirements.network,
            "payload": {
                "claims": claims,
                "signature": signature.signature,
                "signingScheme": "eip712"
            }
        });
        let header = BASE64_STANDARD.encode(serde_json::to_vec(&envelope)?);
        let verify_body = json!({
            "x402Version": 1,
            "paymentHeader": header,
            "paymentRequirements": requirements,
        });

        Ok(Self {
            header,
            verify_body,
            requirements,
            claims,
        })
    }
}

async fn show_supported(facilitator: &str) -> anyhow::Result<()> {
    let client = HttpClient::new();
    let url = format!("{facilitator}/supported");
    let resp = client.get(&url).send().await?.error_for_status()?;
    let body: Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

async fn load_requirements(
    facilitator: &str,
    user_address: &str,
) -> anyhow::Result<PaymentRequirements> {
    let requirements = if let Some(resource_url) = env_var_opt("RESOURCE_URL") {
        let method = env_var_opt("RESOURCE_METHOD").unwrap_or_else(|| "GET".into());
        println!("Fetching paymentRequirements from resource at {resource_url}");
        fetch_requirements_from_resource(&resource_url, &method, user_address).await?
    } else {
        manual_requirements_from_env(user_address)?
    };

    align_with_supported(facilitator, requirements).await
}

fn manual_requirements_from_env(
    user_address: &str,
) -> anyhow::Result<PaymentRequirements> {
    let scheme = env::var("X402_SCHEME").unwrap_or_else(|_| "4mica-credit".into());
    let network = env::var("X402_NETWORK").unwrap_or_else(|_| "polygon-amoy".into());
    let pay_to = env_var("RECIPIENT_ADDRESS")?;
    let asset = env_var("ASSET_ADDRESS")?;
    let tab_id_raw = env_var("TAB_ID")?;
    let amount_raw = env_var("AMOUNT")?;
    let amount = parse_u256(&amount_raw)?;
    let resource = env_var_opt("PAYMENT_RESOURCE");
    let description = env_var_opt("PAYMENT_DESCRIPTION");
    let mime_type = env_var_opt("PAYMENT_MIME_TYPE");
    let max_timeout_seconds = env_var_opt("MAX_TIMEOUT_SECONDS")
        .and_then(|v| v.parse().ok())
        .or(Some(300));

    Ok(PaymentRequirements {
        scheme,
        network,
        max_amount_required: format!("{:#x}", amount),
        resource,
        description,
        mime_type,
        output_schema: None,
        pay_to,
        max_timeout_seconds,
        asset,
        extra: json!({
            "tabId": tab_id_raw,
            "userAddress": user_address,
        }),
    })
}

async fn fetch_requirements_from_resource(
    resource_url: &str,
    method: &str,
    user_address: &str,
) -> anyhow::Result<PaymentRequirements> {
    let client = HttpClient::new();
    let method = parse_method(method)?;
    let response = client
        .request(method, resource_url)
        .send()
        .await
        .context("failed to contact resource server")?;

    ensure!(
        response.status() == StatusCode::PAYMENT_REQUIRED,
        "expected 402 Payment Required from resource, got {}",
        response.status()
    );

    let base_url: Url = response.url().clone();
    let payload: Value = response
        .json()
        .await
        .context("failed to decode resource response")?;

    if let Some(reqs) = payload.get("paymentRequirements") {
        return serde_json::from_value(reqs.clone())
            .context("resource returned paymentRequirements but they were invalid");
    }

    if let Some(endpoint) = payload
        .get("tabEndpoint")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        let tab_url = base_url
            .join(endpoint)
            .context("failed to resolve tabEndpoint URL")?;
        let tab_resp = client
            .post(tab_url)
            .json(&json!({ "userAddress": user_address }))
            .send()
            .await
            .context("failed to request tab from resource")?
            .error_for_status()
            .context("tab endpoint returned an error")?;
        let tab_payload: Value = tab_resp
            .json()
            .await
            .context("failed to decode tab endpoint response")?;
        if let Some(reqs) = tab_payload.get("paymentRequirements") {
            return serde_json::from_value(reqs.clone())
                .context("tab endpoint returned paymentRequirements but they were invalid");
        }
        bail!("tab endpoint response missing paymentRequirements");
    }

    bail!("resource response did not include paymentRequirements or tabEndpoint");
}

async fn fetch_supported_kinds(facilitator: &str) -> anyhow::Result<Vec<SupportedKind>> {
    let client = HttpClient::new();
    let url = format!("{facilitator}/supported");
    let resp = client
        .get(&url)
        .send()
        .await
        .context("failed to call facilitator /supported")?
        .error_for_status()
        .context("facilitator /supported returned an error")?;
    let kinds: Vec<SupportedKind> = resp
        .json()
        .await
        .context("failed to decode /supported response")?;
    Ok(kinds)
}

async fn align_with_supported(
    facilitator: &str,
    mut req: PaymentRequirements,
) -> anyhow::Result<PaymentRequirements> {
    let supported = fetch_supported_kinds(facilitator).await.unwrap_or_default();
    if supported.is_empty() {
        return Ok(req);
    }

    let scheme_lower = req.scheme.to_lowercase();
    if let Some(kind) = supported
        .iter()
        .find(|k| k.scheme.to_lowercase() == scheme_lower)
    {
        req.scheme = kind.scheme.clone();
        req.network = kind.network.clone();
        return Ok(req);
    }

    if let Some(kind) = supported
        .iter()
        .find(|k| k.scheme.to_lowercase().contains("4mica"))
    {
        req.scheme = kind.scheme.clone();
        req.network = kind.network.clone();
        return Ok(req);
    }

    if let Some(first) = supported.first() {
        req.scheme = first.scheme.clone();
        req.network = first.network.clone();
    }

    Ok(req)
}

fn claims_from_requirements(
    requirements: &PaymentRequirements,
    user_address: &str,
) -> anyhow::Result<PaymentGuaranteeRequestClaims> {
    let tab_id = extract_u256(&requirements.extra, &["tabId", "tab_id"], "tabId")?;
    let amount = parse_u256(&requirements.max_amount_required)?;
    validate_user_matches(requirements, user_address)?;

    Ok(PaymentGuaranteeRequestClaims::new(
        user_address.to_string(),
        requirements.pay_to.clone(),
        tab_id,
        amount,
        now_ts(),
        Some(requirements.asset.clone()),
    ))
}

async fn sign_claims(
    claims: &PaymentGuaranteeRequestClaims,
    payer_key: &str,
) -> anyhow::Result<rust_sdk_4mica::PaymentSignature> {
    let core_api =
        env::var("X402_CORE_API_URL").unwrap_or_else(|_| "https://api.4mica.xyz/".into());
    let cfg = ConfigBuilder::default()
        .rpc_url(core_api)
        .wallet_private_key(payer_key.to_string())
        .build()
        .context("invalid SDK config")?;
    let client = Client::new(cfg)
        .await
        .context("failed to init SDK client")?;

    client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await
        .context("failed to sign claims")
}

fn parse_u256(value: &str) -> anyhow::Result<U256> {
    let trimmed = value.trim();
    if let Some(rest) = trimmed.strip_prefix("0x") {
        U256::from_str_radix(rest, 16).map_err(Into::into)
    } else {
        U256::from_str_radix(trimmed, 10).map_err(Into::into)
    }
}

fn parse_method(method: &str) -> anyhow::Result<Method> {
    method
        .parse::<Method>()
        .or_else(|_| method.to_uppercase().parse::<Method>())
        .context("invalid HTTP method")
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn env_var(key: &str) -> anyhow::Result<String> {
    env::var(key).with_context(|| format!("missing env {key}"))
}

fn env_var_opt(key: &str) -> Option<String> {
    env::var(key).ok()
}

fn load_env_files() {
    for path in ["examples/.env", ".env"] {
        if let Err(err) = from_filename(path) {
            if !matches!(&err, dotenvy::Error::Io(io_err) if io_err.kind() == ErrorKind::NotFound) {
                eprintln!("warning: failed to load {path}: {err}");
            }
        }
    }
}

fn value_to_string(value: &Value, field: &str) -> anyhow::Result<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(num) => num
            .as_u64()
            .map(|n| n.to_string())
            .ok_or_else(|| anyhow!("{field} must be a string or integer")),
        other => bail!("{field} must be a string or integer, got {other:?}"),
    }
}

fn extract_u256(extra: &Value, keys: &[&str], field: &str) -> anyhow::Result<U256> {
    let extra_obj = extra
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("paymentRequirements.extra must be an object"))?;
    for key in keys {
        if let Some(value) = extra_obj.get(*key) {
            let raw = value_to_string(value, field)?;
            return parse_u256(&raw);
        }
    }
    bail!("paymentRequirements.extra missing {field}")
}

fn validate_user_matches(
    requirements: &PaymentRequirements,
    expected_user: &str,
) -> anyhow::Result<()> {
    let extra_obj = requirements
        .extra
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("paymentRequirements.extra must be an object"))?;
    let candidates = ["userAddress", "user_address"];
    for key in candidates {
        if let Some(value) = extra_obj.get(key) {
            let raw = value_to_string(value, key)?;
            if raw.eq_ignore_ascii_case(expected_user) {
                return Ok(());
            }
            bail!(
                "paymentRequirements.extra.{key} ({raw}) does not match USER_ADDRESS ({expected_user})"
            );
        }
    }
    bail!("paymentRequirements.extra missing userAddress");
}
