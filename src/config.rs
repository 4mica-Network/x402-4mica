use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use reqwest::Url;
use serde::Deserialize;

const DEFAULT_CORE_API_URL: &str = "https://api.4mica.xyz/";
const ENV_SCHEME: &str = "X402_SCHEME";
const ENV_NETWORK: &str = "X402_NETWORK";
const ENV_NETWORKS: &str = "X402_NETWORKS";
const ENV_CORE_API_URL: &str = "X402_CORE_API_URL";
const ENV_HOST: &str = "HOST";
const ENV_PORT: &str = "PORT";
const ENV_ASSET_ADDRESS: &str = "ASSET_ADDRESS";
const ENV_GUARANTEE_DOMAIN_VARIANTS: [&str; 3] = [
    "X402_GUARANTEE_DOMAIN",
    "FOUR_MICA_GUARANTEE_DOMAIN",
    "4MICA_GUARANTEE_DOMAIN",
];
const DEFAULT_NETWORK_ID: &str = "eip155:11155111";

#[derive(Clone)]
pub struct ServiceConfig {
    pub bind_addr: SocketAddr,
    pub scheme: String,
    pub networks: Vec<NetworkConfig>,
    pub asset_address: Option<String>,
}

#[derive(Clone)]
pub struct NetworkConfig {
    pub id: String,
    pub core_api_base_url: Url,
}

impl ServiceConfig {
    pub fn from_env() -> Result<Self> {
        let bind_addr = bind_addr_from_env()?;
        let scheme = std::env::var(ENV_SCHEME).unwrap_or_else(|_| "4mica-credit".into());
        let networks = load_networks_from_env()?;
        let asset_address = optional_asset_address_from_env();
        Ok(Self {
            bind_addr,
            scheme,
            networks,
            asset_address,
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
    core_api_url: String,
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
    let network = normalize_network_id(&network);
    let api_url = std::env::var(ENV_CORE_API_URL).unwrap_or_else(|_| DEFAULT_CORE_API_URL.into());
    let api_base_url = normalize_url(&api_url)?;

    Ok(vec![NetworkConfig {
        id: network,
        core_api_base_url: api_base_url,
    }])
}

fn parse_network_list(raw: &str) -> Result<Vec<NetworkConfig>> {
    let entries: Vec<NetworkEnvConfig> = serde_json::from_str(raw).with_context(|| {
        format!(
            "{ENV_NETWORKS} must be JSON like \
        '[{{\"network\":\"eip155:11155111\",\"coreApiUrl\":\"https://api.4mica.xyz/\"}}]'"
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
        let network = normalize_network_id(network);
        let url = normalize_url(entry.core_api_url.trim())
            .with_context(|| format!("failed to parse coreApiUrl for network {}", entry.network))?;
        configs.push(NetworkConfig {
            id: network.to_owned(),
            core_api_base_url: url,
        });
    }

    Ok(configs)
}

fn bind_addr_from_env() -> Result<SocketAddr> {
    let host = std::env::var(ENV_HOST).unwrap_or_else(|_| "0.0.0.0".into());
    let port = std::env::var(ENV_PORT)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);
    let addr = format!("{host}:{port}")
        .parse()
        .with_context(|| format!("invalid HOST/PORT combination: {host}:{port}"))?;
    Ok(addr)
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

pub fn normalize_network_id(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    match trimmed.to_ascii_lowercase().as_str() {
        "polygon-amoy" => "eip155:80002".to_string(),
        "sepolia-mainnet" | "sepolia" => "eip155:11155111".to_string(),
        "base" => "eip155:8453".to_string(),
        "base-sepolia" => "eip155:84532".to_string(),
        _ => trimmed.to_string(),
    }
}

fn optional_asset_address_from_env() -> Option<String> {
    std::env::var(ENV_ASSET_ADDRESS)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    fn clear_network_env() {
        unsafe {
            env::remove_var(ENV_NETWORKS);
            env::remove_var(ENV_NETWORK);
            env::remove_var(ENV_CORE_API_URL);
            env::remove_var(ENV_GUARANTEE_DOMAIN_VARIANTS[0]);
            env::remove_var(ENV_GUARANTEE_DOMAIN_VARIANTS[1]);
            env::remove_var(ENV_GUARANTEE_DOMAIN_VARIANTS[2]);
        }
    }

    #[test]
    #[serial]
    fn parses_networks_from_json_env() {
        clear_network_env();
        unsafe {
            env::set_var(
                ENV_NETWORKS,
                r#"[{"network":"alpha","coreApiUrl":"http://localhost:1234"}]"#,
            );
        }

        let networks = load_networks_from_env().expect("networks parsed");
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].id, "alpha");
        assert_eq!(
            networks[0].core_api_base_url.as_str(),
            "http://localhost:1234/"
        );

        clear_network_env();
    }

    #[test]
    #[serial]
    fn falls_back_to_single_network_env() {
        clear_network_env();
        unsafe {
            env::set_var(ENV_NETWORK, "beta");
            env::set_var(ENV_CORE_API_URL, "http://example.com");
        }

        let networks = load_networks_from_env().expect("networks parsed");
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].id, "beta");
        assert_eq!(
            networks[0].core_api_base_url.as_str(),
            "http://example.com/"
        );

        clear_network_env();
    }

    #[test]
    fn parse_hex_array_rejects_wrong_length() {
        let err = parse_hex_array::<4>("0x01").unwrap_err();
        assert!(
            err.to_string().contains("expected 4 bytes"),
            "unexpected error: {err}"
        );
    }
}
