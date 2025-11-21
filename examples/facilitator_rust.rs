use std::env;
use std::io::ErrorKind;

use anyhow::{Context, Result};
use dotenvy::from_filename;
use rust_sdk_4mica::{Client, ConfigBuilder, PaymentRequest, U256, X402Flow};
use serde_json::to_string_pretty;

fn load_env_files() {
    for path in ["examples/.env", ".env"] {
        if let Err(err) = from_filename(path)
            && !matches!(&err, dotenvy::Error::Io(io_err) if io_err.kind() == ErrorKind::NotFound)
        {
            eprintln!("warning: failed to load {path}: {err}");
        };
    }
}

fn env_var(key: &str) -> Result<String> {
    env::var(key).with_context(|| format!("missing env {key}"))
}

fn parse_u256(raw: &str) -> Result<U256> {
    let trimmed = raw.trim();
    let value = if let Some(rest) = trimmed.strip_prefix("0x") {
        U256::from_str_radix(rest, 16)
    } else {
        U256::from_str_radix(trimmed, 10)
    };
    value.with_context(|| format!("invalid number: {raw}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    load_env_files();

    let payer_key = env_var("PAYER_KEY")?;
    let user_address = env_var("USER_ADDRESS")?;
    let resource_url = env_var("RESOURCE_URL")?;
    let method = env::var("RESOURCE_METHOD").unwrap_or_else(|_| "GET".into());
    let facilitator_url =
        env::var("FACILITATOR_URL").unwrap_or_else(|_| "http://localhost:8080/".into());
    let asset_address = env_var("ASSET_ADDRESS")?;

    println!("--- x402 / 4mica flow ---");
    println!("1) Discover 402 + accepted requirements from the resource");
    println!("2) Request tab (if required) and sign claims locally");
    println!("3) Retry the resource with X-PAYMENT using the header below (server will handle verify/settle)\n");

    let config = ConfigBuilder::default()
        .wallet_private_key(payer_key)
        .build()
        .context("invalid SDK config")?;
    let core = Client::new(config)
        .await
        .context("failed to init 4mica core client")?;

    // If you need to prime collateral on-chain, uncomment the block below:
    // let one_unit = U256::from(1_000_000u64);
    // println!("Approving allowance for the 4mica contract...");
    // let approve_receipt = core
    //     .user
    //     .approve_erc20(asset_address.clone(), one_unit)
    //     .await
    //     .context("failed to approve asset")?;
    // println!(
    //     "Approval tx hash: 0x{}",
    //     hex::encode(approve_receipt.transaction_hash)
    // );
    //
    // println!("Depositing collateral...");
    // let deposit_receipt = core
    //     .user
    //     .deposit(one_unit, Some(asset_address.clone()))
    //     .await
    //     .context("failed to deposit asset")?;
    // println!(
    //     "Deposit tx hash: 0x{}",
    //     hex::encode(deposit_receipt.transaction_hash)
    // );

    let flow =
        X402Flow::with_base_url(core, &facilitator_url).context("invalid facilitator url")?;
    let request = PaymentRequest::new(resource_url, user_address).with_method_str(&method)?;

    // Prepare the payment requirements and signature. The resource server will call
    // /verify and /settle; the client only needs to attach the X-PAYMENT header.
    let prepared = flow
        .prepare_payment(request)
        .await
        .context("failed to prepare payment")?;

    let payment_asset = &prepared.requirements.asset;
    println!("Payment asset address: {payment_asset}");
    println!(
        "Payment tabId: {}",
        prepared.requirements.extra["tabId"]
    );

    // Sanity checks against the desired USDC flow.
    if !payment_asset.eq_ignore_ascii_case(&asset_address) {
        eprintln!(
            "warning: paymentRequirements.asset ({payment_asset}) does not match ASSET_ADDRESS ({asset_address})"
        );
    }

    let required_amount_raw = &prepared.requirements.max_amount_required;
    if let Ok(required_amount) = parse_u256(required_amount_raw) {
        // Expect 0.0001 units (100 base units) if your resource advertises that price.
        let expected = U256::from(100u64);
        if required_amount != expected {
            eprintln!(
                "warning: paymentRequirements.maxAmountRequired is {} (expected 100 base units)",
                required_amount
            );
        }
    } else {
        eprintln!(
            "warning: could not parse maxAmountRequired={} for sanity check",
            required_amount_raw
        );
    }
    println!("X-PAYMENT header:\n{}\n", prepared.header());
    println!(
        "Facilitator /verify body (server will call):\n{}",
        to_string_pretty(prepared.verify_body())?
    );

    Ok(())
}
