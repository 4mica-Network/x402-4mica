//! Minimal facilitator client using the local `rust-sdk-4mica` to sign payment envelopes.
//!
//! Usage:
//! - Show supported kinds:
//!   `cargo run --example facilitator_rust -- supported http://localhost:8080/`
//! - Build an X-PAYMENT header and POST /verify:
//!   `PAYER_KEY=0x... USER_ADDRESS=0x... RECIPIENT_ADDRESS=0x... TAB_ID=1 AMOUNT=10 ASSET_ADDRESS=0xeeee... cargo run --example facilitator_rust -- verify http://localhost:8080/`
//!
//! Environment (all but FACILITATOR_URL required for `verify`):
//! - FACILITATOR_URL: defaults to http://localhost:8080/
//! - X402_CORE_API_URL: optional override for SDK RPC URL (defaults to https://api.4mica.xyz/)
//! - PAYER_KEY: 0x-prefixed wallet private key
//! - USER_ADDRESS: address matching the private key
//! - RECIPIENT_ADDRESS: payTo from paymentRequirements
//! - TAB_ID: decimal or hex tab id
//! - AMOUNT: decimal or hex amount (wei)
//! - ASSET_ADDRESS: ERC20 (or 0xeeee... for native)
//! - X402_SCHEME/X402_NETWORK: optional overrides for the envelope (defaults: 4mica-credit / polygon-amoy)

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use reqwest::Client as HttpClient;
use rust_sdk_4mica::{
    Client, ConfigBuilder, PaymentGuaranteeRequestClaims, PaymentSignature, SigningScheme, U256,
};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PaymentPayload {
    claims: PaymentGuaranteeRequestClaims,
    signature: String,
    signing_scheme: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PaymentEnvelope {
    x402_version: u8,
    scheme: String,
    network: String,
    payload: PaymentPayload,
}

#[derive(Serialize)]
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest {
    x402_version: u8,
    payment_header: String,
    payment_requirements: PaymentRequirements,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "supported".into());
    let facilitator = args.next().unwrap_or_else(|| {
        env::var("FACILITATOR_URL").unwrap_or_else(|_| "http://localhost:8080/".into())
    });

    match command.as_str() {
        "supported" => show_supported(&facilitator).await?,
        "verify" => run_verify(&facilitator).await?,
        other => anyhow::bail!("unknown command {other}; use `supported` or `verify`"),
    }

    Ok(())
}

async fn show_supported(facilitator: &str) -> anyhow::Result<()> {
    let client = HttpClient::new();
    let url = format!("{facilitator}/supported");
    let resp = client.get(&url).send().await?.error_for_status()?;
    let body: Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

async fn run_verify(facilitator: &str) -> anyhow::Result<()> {
    let scheme = env::var("X402_SCHEME").unwrap_or_else(|_| "4mica-credit".into());
    let network = env::var("X402_NETWORK").unwrap_or_else(|_| "polygon-amoy".into());

    let payer_key = env_var("PAYER_KEY")?;
    let user_address = env_var("USER_ADDRESS")?;
    let recipient_address = env_var("RECIPIENT_ADDRESS")?;
    let tab_id = parse_u256(&env_var("TAB_ID")?)?;
    let amount = parse_u256(&env_var("AMOUNT")?)?;
    let asset = env_var("ASSET_ADDRESS")?;

    let core_api =
        env::var("X402_CORE_API_URL").unwrap_or_else(|_| "https://api.4mica.xyz/".into());
    let cfg = ConfigBuilder::default()
        .rpc_url(core_api)
        .wallet_private_key(payer_key)
        .build()
        .context("invalid SDK config")?;
    let client = Client::new(cfg)
        .await
        .context("failed to init SDK client")?;

    let claims = PaymentGuaranteeRequestClaims {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        amount,
        asset_address: asset.clone(),
        timestamp: now_ts(),
    };

    let signature: PaymentSignature = client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await
        .context("failed to sign claims")?;

    let envelope = PaymentEnvelope {
        x402_version: 1,
        scheme: scheme.clone(),
        network: network.clone(),
        payload: PaymentPayload {
            claims: claims.clone(),
            signature: signature.signature.clone(),
            signing_scheme: "eip712".into(),
        },
    };

    let raw = serde_json::to_vec(&envelope)?;
    let payment_header = BASE64_STANDARD.encode(raw);
    println!("X-PAYMENT header:\n{}\n", payment_header);

    let requirements = PaymentRequirements {
        scheme,
        network,
        max_amount_required: format!("{:#x}", amount),
        resource: None,
        description: None,
        mime_type: None,
        output_schema: None,
        pay_to: recipient_address,
        max_timeout_seconds: Some(300),
        asset,
        extra: json!({
            "tabId": format!("{:#x}", tab_id),
            "userAddress": user_address,
        }),
    };

    let verify_body = VerifyRequest {
        x402_version: 1,
        payment_header,
        payment_requirements: requirements,
    };

    let client = HttpClient::new();
    let url = format!("{facilitator}/verify");
    let resp = client
        .post(&url)
        .json(&verify_body)
        .send()
        .await?
        .error_for_status()?;
    let body: Value = resp.json().await?;
    println!("Verify response:\n{}", serde_json::to_string_pretty(&body)?);

    Ok(())
}

fn parse_u256(value: &str) -> anyhow::Result<U256> {
    let trimmed = value.trim();
    if let Some(rest) = trimmed.strip_prefix("0x") {
        U256::from_str_radix(rest, 16).map_err(Into::into)
    } else {
        U256::from_str_radix(trimmed, 10).map_err(Into::into)
    }
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
