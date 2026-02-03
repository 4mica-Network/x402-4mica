use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use reqwest::Url;
use serde::Deserialize;

const DEFAULT_CORE_API_URL: &str = "https://api.4mica.xyz/";
const ENV_SCHEME: &str = "X402_SCHEME";
const ENV_NETWORK: &str = "X402_NETWORK";
const ENV_NETWORKS: &str = "X402_NETWORKS";
const ENV_CORE_API_URL: &str = "X402_CORE_API_URL";
const ENV_AUTH_WALLET_PRIVATE_KEY: &str = "X402_AUTH_WALLET_PRIVATE_KEY";
const ENV_AUTH_URL: &str = "X402_AUTH_URL";
const ENV_AUTH_REFRESH_MARGIN_SECS: &str = "X402_AUTH_REFRESH_MARGIN_SECS";
const ENV_HOST: &str = "HOST";
const ENV_PORT: &str = "PORT";
const ENV_ASSET_ADDRESS: &str = "ASSET_ADDRESS";
const ENV_GUARANTEE_DOMAIN_VARIANTS: [&str; 3] = [
    "X402_GUARANTEE_DOMAIN",
    "FOUR_MICA_GUARANTEE_DOMAIN",
    "4MICA_GUARANTEE_DOMAIN",
];
const DEFAULT_NETWORK_ID: &str = "eip155:11155111";
const DEFAULT_AUTH_REFRESH_MARGIN_SECS: u64 = 60;

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
    pub auth: Option<NetworkAuthConfig>,
}

#[derive(Clone)]
pub struct NetworkAuthConfig {
    pub wallet_private_key: String,
    pub auth_url: Url,
    pub refresh_margin_secs: u64,
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
    auth_wallet_private_key: Option<String>,
    auth_url: Option<String>,
    auth_refresh_margin_secs: Option<u64>,
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
    let auth_fallback = load_auth_fallback()?;
    if let Ok(raw) = std::env::var(ENV_NETWORKS) {
        return parse_network_list(&raw, &auth_fallback);
    }

    let network = std::env::var(ENV_NETWORK).unwrap_or_else(|_| DEFAULT_NETWORK_ID.into());
    validate_caip2_network(&network).with_context(|| {
        format!("{ENV_NETWORK} must be a CAIP-2 identifier like \"eip155:11155111\"")
    })?;
    let api_url = std::env::var(ENV_CORE_API_URL).unwrap_or_else(|_| DEFAULT_CORE_API_URL.into());
    let api_base_url = normalize_url(&api_url)?;
    let auth = resolve_auth_config(None, None, None, &auth_fallback, &api_base_url, &network)?;

    Ok(vec![NetworkConfig {
        id: network,
        core_api_base_url: api_base_url,
        auth,
    }])
}

fn parse_network_list(raw: &str, auth_fallback: &AuthFallback) -> Result<Vec<NetworkConfig>> {
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
        validate_caip2_network(network).with_context(|| {
            format!("{ENV_NETWORKS} entry network must be CAIP-2 (e.g., \"eip155:11155111\")")
        })?;
        let url = normalize_url(entry.core_api_url.trim())
            .with_context(|| format!("failed to parse coreApiUrl for network {}", entry.network))?;
        let auth = resolve_auth_config(
            entry.auth_wallet_private_key.as_deref(),
            entry.auth_url.as_deref(),
            entry.auth_refresh_margin_secs,
            auth_fallback,
            &url,
            network,
        )?;
        configs.push(NetworkConfig {
            id: network.to_owned(),
            core_api_base_url: url,
            auth,
        });
    }

    Ok(configs)
}

struct AuthFallback {
    wallet_private_key: Option<String>,
    auth_url: Option<String>,
    refresh_margin_secs: Option<u64>,
}

fn load_auth_fallback() -> Result<AuthFallback> {
    let wallet_private_key = std::env::var(ENV_AUTH_WALLET_PRIVATE_KEY)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let auth_url = std::env::var(ENV_AUTH_URL)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let refresh_margin_secs = std::env::var(ENV_AUTH_REFRESH_MARGIN_SECS)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse::<u64>().with_context(|| {
                format!("{ENV_AUTH_REFRESH_MARGIN_SECS} must be a positive integer")
            })
        })
        .transpose()?;

    if wallet_private_key.is_none() && (auth_url.is_some() || refresh_margin_secs.is_some()) {
        bail!(
            "{ENV_AUTH_WALLET_PRIVATE_KEY} must be set when {ENV_AUTH_URL} or {ENV_AUTH_REFRESH_MARGIN_SECS} is provided"
        );
    }

    Ok(AuthFallback {
        wallet_private_key,
        auth_url,
        refresh_margin_secs,
    })
}

fn resolve_auth_config(
    entry_wallet_private_key: Option<&str>,
    entry_auth_url: Option<&str>,
    entry_refresh_margin_secs: Option<u64>,
    fallback: &AuthFallback,
    core_api_base_url: &Url,
    network: &str,
) -> Result<Option<NetworkAuthConfig>> {
    let wallet_private_key = entry_wallet_private_key
        .or(fallback.wallet_private_key.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let auth_url = entry_auth_url
        .or(fallback.auth_url.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let refresh_margin_secs = entry_refresh_margin_secs.or(fallback.refresh_margin_secs);

    if wallet_private_key.is_none()
        && (entry_auth_url.is_some() || entry_refresh_margin_secs.is_some())
    {
        bail!(
            "{ENV_NETWORKS} entry for {network} provides authUrl/authRefreshMarginSecs without authWalletPrivateKey"
        );
    }

    let Some(wallet_private_key) = wallet_private_key else {
        return Ok(None);
    };

    let auth_url = match auth_url {
        Some(value) => normalize_url(value)?,
        None => core_api_base_url.clone(),
    };

    Ok(Some(NetworkAuthConfig {
        wallet_private_key: wallet_private_key.to_string(),
        auth_url,
        refresh_margin_secs: refresh_margin_secs.unwrap_or(DEFAULT_AUTH_REFRESH_MARGIN_SECS),
    }))
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

pub fn validate_caip2_network(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("network must be a non-empty CAIP-2 identifier");
    }

    let mut parts = trimmed.split(':');
    let namespace = parts.next().unwrap_or_default();
    let reference = parts.next().unwrap_or_default();
    if namespace.is_empty() || reference.is_empty() || parts.next().is_some() {
        bail!("network must be in CAIP-2 format (namespace:reference)");
    }
    if !namespace
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
    {
        bail!("network namespace must be lowercase alphanumeric");
    }
    if !reference
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        bail!("network reference must be alphanumeric or one of '-', '_', '.'");
    }

    Ok(())
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
            env::remove_var(ENV_AUTH_WALLET_PRIVATE_KEY);
            env::remove_var(ENV_AUTH_URL);
            env::remove_var(ENV_AUTH_REFRESH_MARGIN_SECS);
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
                r#"[{"network":"eip155:1","coreApiUrl":"http://localhost:1234"}]"#,
            );
        }

        let networks = load_networks_from_env().expect("networks parsed");
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].id, "eip155:1");
        assert_eq!(
            networks[0].core_api_base_url.as_str(),
            "http://localhost:1234/"
        );
        assert!(networks[0].auth.is_none());

        clear_network_env();
    }

    #[test]
    #[serial]
    fn falls_back_to_single_network_env() {
        clear_network_env();
        unsafe {
            env::set_var(ENV_NETWORK, "eip155:11155111");
            env::set_var(ENV_CORE_API_URL, "http://example.com");
        }

        let networks = load_networks_from_env().expect("networks parsed");
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].id, "eip155:11155111");
        assert_eq!(
            networks[0].core_api_base_url.as_str(),
            "http://example.com/"
        );
        assert!(networks[0].auth.is_none());

        clear_network_env();
    }

    #[test]
    fn validate_caip2_network_accepts_examples() {
        for value in [
            "eip155:1",
            "eip155:11155111",
            "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "cosmos:cosmoshub-4",
        ] {
            assert!(
                validate_caip2_network(value).is_ok(),
                "expected {value} to be valid"
            );
        }
    }

    #[test]
    fn validate_caip2_network_rejects_invalid_values() {
        for value in [
            "",
            "sepolia-mainnet",
            "eip155",
            "eip155:",
            ":11155111",
            "eip155:1:2",
            "EIP155:1",
            "eip155:11 155111",
        ] {
            assert!(
                validate_caip2_network(value).is_err(),
                "expected {value} to be invalid"
            );
        }
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
