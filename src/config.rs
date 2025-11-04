use std::net::SocketAddr;

use anyhow::{Context, Result};
use reqwest::Url;
use serde::Deserialize;

const DEFAULT_API_URL: &str = "https://api.4mica.xyz/";
const ENV_API_URL: &str = "FOUR_MICA_RPC_URL";
const ENV_SCHEME: &str = "X402_SCHEME";
const ENV_NETWORK: &str = "X402_NETWORK";
const ENV_HOST: &str = "HOST";
const ENV_PORT: &str = "PORT";
const ENV_GUARANTEE_DOMAIN: &str = "FOUR_MICA_GUARANTEE_DOMAIN";

#[derive(Clone)]
pub struct ServiceConfig {
    pub bind_addr: SocketAddr,
    pub scheme: String,
    pub network: String,
}

impl ServiceConfig {
    pub fn from_env() -> Result<Self> {
        let host = std::env::var(ENV_HOST).unwrap_or_else(|_| "0.0.0.0".into());
        let port = std::env::var(ENV_PORT)
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(8080);
        let scheme = std::env::var(ENV_SCHEME).unwrap_or_else(|_| "4mica-guarantee".into());
        let network = std::env::var(ENV_NETWORK).unwrap_or_else(|_| "4mica-mainnet".into());
        let addr = format!("{host}:{port}")
            .parse()
            .with_context(|| format!("invalid HOST/PORT combination: {host}:{port}"))?;

        Ok(Self {
            bind_addr: addr,
            scheme,
            network,
        })
    }
}

#[derive(Clone)]
pub struct PublicParameters {
    pub api_base_url: Url,
    pub operator_public_key: [u8; 48],
    pub guarantee_domain: Option<[u8; 32]>,
}

#[derive(Debug, Deserialize)]
struct CorePublicParameters {
    public_key: Vec<u8>,
}

pub async fn load_public_params() -> Result<PublicParameters> {
    let api_url = std::env::var(ENV_API_URL).unwrap_or_else(|_| DEFAULT_API_URL.into());
    let api_base = normalize_url(&api_url)?;
    let params = fetch_public_params(&api_base).await?;
    let operator_public_key = params.public_key.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("operator public key must be 48 bytes, got {}", bytes.len())
    })?;

    let guarantee_domain = std::env::var(ENV_GUARANTEE_DOMAIN)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| parse_hex_array::<32>(&value))
        .transpose()?;

    Ok(PublicParameters {
        api_base_url: api_base,
        operator_public_key,
        guarantee_domain,
    })
}

fn normalize_url(input: &str) -> Result<Url> {
    let mut url = Url::parse(input).or_else(|_| Url::parse(&format!("{input}/")))?;
    if url.path().is_empty() {
        url.set_path("/");
    }
    Ok(url)
}

async fn fetch_public_params(base: &Url) -> Result<CorePublicParameters> {
    let mut url = base.clone();
    url.set_path("core/public-params");

    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;
    let response = response.error_for_status()?;
    Ok(response.json::<CorePublicParameters>().await?)
}

fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let decoded = hex::decode(trimmed)?;
    if decoded.len() != N {
        return Err(anyhow::anyhow!("expected {N} bytes, got {}", decoded.len()));
    }
    let mut bytes = [0u8; N];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}
