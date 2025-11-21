use std::env;
use std::io::ErrorKind;

use anyhow::{Context, Result};
use dotenvy::from_filename;
use rust_sdk_4mica::{Client, ConfigBuilder, FacilitatorFlow, PaymentRequest};
use serde_json::to_string_pretty;

fn load_env_files() {
    for path in ["examples/.env", ".env"] {
        if let Err(err) = from_filename(path) {
            if !matches!(&err, dotenvy::Error::Io(io_err) if io_err.kind() == ErrorKind::NotFound) {
                eprintln!("warning: failed to load {path}: {err}");
            }
        }
    }
}

fn env_var(key: &str) -> Result<String> {
    env::var(key).with_context(|| format!("missing env {key}"))
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

    let config = ConfigBuilder::default()
        .wallet_private_key(payer_key)
        .build()
        .context("invalid SDK config")?;
    let core = Client::new(config)
        .await
        .context("failed to init 4mica core client")?;
    let flow = FacilitatorFlow::with_facilitator_url(core, facilitator_url)
        .context("invalid facilitator url")?;
    let request = PaymentRequest::new(resource_url, user_address).with_method_str(&method)?;

    let payment = flow
        .prepare_payment(request)
        .await
        .context("failed to prepare payment")?;

    println!("X-PAYMENT header:\n{}\n", payment.header());
    println!(
        "Facilitator /verify body:\n{}",
        to_string_pretty(payment.verify_body())?
    );

    Ok(())
}
