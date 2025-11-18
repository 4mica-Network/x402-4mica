use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use reqwest::Url;
use serde::Deserialize;

const DEFAULT_API_URL: &str = "https://api.4mica.xyz/";
const ENV_API_URLS: [&str; 2] = ["FOUR_MICA_RPC_URL", "4MICA_RPC_URL"];
const ENV_SCHEME: &str = "X402_SCHEME";
const ENV_NETWORK: &str = "X402_NETWORK";
const ENV_NETWORKS: &str = "X402_NETWORKS";
const ENV_HOST: &str = "HOST";
const ENV_PORT: &str = "PORT";
const ENV_GUARANTEE_DOMAIN_VARIANTS: [&str; 2] =
    ["FOUR_MICA_GUARANTEE_DOMAIN", "4MICA_GUARANTEE_DOMAIN"];
const DEFAULT_NETWORK_ID: &str = "sepolia-mainnet";

#[derive(Clone)]
pub struct ServiceConfig {
    pub bind_addr: SocketAddr,
    pub scheme: String,
    pub networks: Vec<NetworkConfig>,
}

#[derive(Clone)]
pub struct NetworkConfig {
    pub id: String,
    pub api_base_url: Url,
}

impl ServiceConfig {
    pub fn from_env() -> Result<Self> {
        let host = std::env::var(ENV_HOST).unwrap_or_else(|_| "0.0.0.0".into());
        let port = std::env::var(ENV_PORT)
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(8080);
        let scheme = std::env::var(ENV_SCHEME).unwrap_or_else(|_| "4mica-credit".into());
        let networks = load_networks_from_env()?;
        let addr = format!("{host}:{port}")
            .parse()
            .with_context(|| format!("invalid HOST/PORT combination: {host}:{port}"))?;

        Ok(Self {
            bind_addr: addr,
            scheme,
            networks,
        })
    }
}

#[derive(Clone)]
pub struct PublicParameters {
    pub operator_public_key: [u8; 48],
    pub guarantee_domain: Option<[u8; 32]>,
}

#[derive(Debug, Deserialize)]
struct CorePublicParameters {
    public_key: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkEnvConfig {
    network: String,
    api_url: String,
}

pub async fn load_public_params(api_base: &Url) -> Result<PublicParameters> {
    let params = fetch_public_params(api_base).await?;
    let operator_public_key = params.public_key.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("operator public key must be 48 bytes, got {}", bytes.len())
    })?;

    let guarantee_domain = first_env_value(&ENV_GUARANTEE_DOMAIN_VARIANTS)
        .map(|value| parse_hex_array::<32>(&value))
        .transpose()?;

    Ok(PublicParameters {
        operator_public_key,
        guarantee_domain,
    })
}

fn load_networks_from_env() -> Result<Vec<NetworkConfig>> {
    if let Ok(raw) = std::env::var(ENV_NETWORKS) {
        return parse_network_list(&raw);
    }

    let network = std::env::var(ENV_NETWORK).unwrap_or_else(|_| DEFAULT_NETWORK_ID.into());
    let api_url = first_env_value(&ENV_API_URLS).unwrap_or_else(|| DEFAULT_API_URL.into());
    let api_base_url = normalize_url(&api_url)?;

    Ok(vec![NetworkConfig {
        id: network,
        api_base_url,
    }])
}

fn parse_network_list(raw: &str) -> Result<Vec<NetworkConfig>> {
    let entries: Vec<NetworkEnvConfig> = serde_json::from_str(raw).with_context(|| {
        format!(
            "{ENV_NETWORKS} must be JSON like \
        '[{{\"network\":\"sepolia-mainnet\",\"apiUrl\":\"https://api.4mica.xyz/\"}}]'"
        )
    })?;
    if entries.is_empty() {
        bail!("{ENV_NETWORKS} must include at least one network entry");
    }

    let mut configs = Vec::with_capacity(entries.len());
    for entry in entries {
        let network = entry.network.trim();
        if network.is_empty() {
            bail!("{ENV_NETWORKS} entries require a non-empty `network` field");
        }
        let url = normalize_url(entry.api_url.trim())
            .with_context(|| format!("failed to parse apiUrl for network {}", entry.network))?;
        configs.push(NetworkConfig {
            id: network.to_owned(),
            api_base_url: url,
        });
    }

    Ok(configs)
}

fn first_env_value(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
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
