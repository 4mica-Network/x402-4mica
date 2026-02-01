use std::{collections::HashSet, sync::Arc};

use anyhow::{Context, bail};
use async_trait::async_trait;
use reqwest::{Client, Url};
use serde::Deserialize;
use tracing::{info, warn};
use x402_rs::chain::ChainRegistry;
use x402_rs::config::Config as X402Config;
use x402_rs::facilitator::Facilitator;
use x402_rs::facilitator_local::FacilitatorLocal;
use x402_rs::proto::{self, SupportedPaymentKind};
use x402_rs::scheme::{SchemeBlueprints, SchemeRegistry};

use crate::server::model::{
    PaymentRequirements, SettleRequest, SettleResponse, SupportedKind, VerifyRequest,
    VerifyResponse,
};
use crate::server::state::ValidationError;

const ENV_DEBIT_URL: &str = "X402_DEBIT_URL";
const ENV_DEBIT_URLS: &str = "X402_DEBIT_URLS";
const ENV_CONFIG_PATH: &str = "X402_CONFIG_PATH";

fn convert_supported_kind(kind: SupportedPaymentKind) -> Result<SupportedKind, ValidationError> {
    Ok(SupportedKind {
        scheme: kind.scheme,
        network: kind.network,
        x402_version: Some(kind.x402_version),
        extra: kind.extra,
    })
}

fn convert_supported(
    response: proto::SupportedResponse,
) -> Result<Vec<SupportedKind>, ValidationError> {
    response
        .kinds
        .into_iter()
        .map(convert_supported_kind)
        .collect()
}

fn convert_requirements(req: &PaymentRequirements) -> serde_json::Value {
    use serde_json::{Map, Value as JsonValue};

    let mut map = Map::new();
    map.insert("scheme".into(), JsonValue::String(req.scheme.clone()));
    map.insert("network".into(), JsonValue::String(req.network.clone()));
    map.insert(
        "maxAmountRequired".into(),
        JsonValue::String(req.max_amount_required.clone()),
    );
    if let Some(amount) = &req.amount {
        map.insert("amount".into(), JsonValue::String(amount.clone()));
    }
    map.insert(
        "resource".into(),
        JsonValue::String(req.resource.clone().unwrap_or_default()),
    );
    map.insert(
        "description".into(),
        JsonValue::String(req.description.clone().unwrap_or_default()),
    );
    map.insert(
        "mimeType".into(),
        JsonValue::String(req.mime_type.clone().unwrap_or_default()),
    );
    if let Some(schema) = &req.output_schema {
        map.insert("outputSchema".into(), schema.clone());
    }
    map.insert("payTo".into(), JsonValue::String(req.pay_to.clone()));
    map.insert(
        "maxTimeoutSeconds".into(),
        JsonValue::Number(req.max_timeout_seconds.unwrap_or_default().into()),
    );
    map.insert("asset".into(), JsonValue::String(req.asset.clone()));
    if let Some(extra) = &req.extra {
        map.insert("extra".into(), extra.clone());
    }

    JsonValue::Object(map)
}

fn convert_verify_request(
    request: &VerifyRequest,
) -> Result<proto::VerifyRequest, ValidationError> {
    use serde_json::{Map, Value as JsonValue};

    let x402_version = request.resolved_x402_version()?;
    if x402_version != 1 && x402_version != 2 {
        return Err(ValidationError::UnsupportedVersion(x402_version));
    }

    let payload = request.payment_payload.clone();
    let payment_requirements = convert_requirements(&request.payment_requirements);

    let mut map = Map::new();
    map.insert(
        "x402Version".into(),
        JsonValue::Number(serde_json::Number::from(x402_version as u64)),
    );
    map.insert(
        "paymentPayload".into(),
        serde_json::to_value(payload).map_err(|err| ValidationError::Other(err.into()))?,
    );
    map.insert("paymentRequirements".into(), payment_requirements);

    Ok(proto::VerifyRequest::from(JsonValue::Object(map)))
}

fn convert_settle_request(
    request: &SettleRequest,
) -> Result<proto::SettleRequest, ValidationError> {
    convert_verify_request(&VerifyRequest {
        x402_version: request.x402_version,
        payment_payload: request.payment_payload.clone(),
        payment_requirements: request.payment_requirements.clone(),
    })
}

pub async fn try_from_env() -> anyhow::Result<Option<Arc<dyn ExactService>>> {
    if let Some(remote) = MultiHttpExactService::from_env()? {
        info!(
            count = remote.services.len(),
            "using multiple remote debit facilitators"
        );
        return Ok(Some(Arc::new(remote)));
    }

    if let Some(remote) = HttpExactService::from_env()? {
        info!(url = %remote.base_url, "using remote debit facilitator");
        return Ok(Some(Arc::new(remote)));
    }

    match LocalExactService::try_from_env().await {
        Ok(Some(service)) => Ok(Some(Arc::new(service))),
        Ok(None) => Ok(None),
        Err(err) => {
            warn!(reason = %err, "exact scheme facilitator disabled");
            Ok(None)
        }
    }
}

#[async_trait]
pub(crate) trait ExactService: Send + Sync {
    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, ValidationError>;
    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, ValidationError>;
    async fn supported(&self) -> Result<Vec<SupportedKind>, ValidationError>;
}

struct LocalExactService {
    inner: Arc<FacilitatorLocal<SchemeRegistry>>,
}

impl LocalExactService {
    pub async fn try_from_env() -> anyhow::Result<Option<Self>> {
        let config = load_x402_config()?;
        if config.chains().is_empty() || config.schemes().is_empty() {
            return Ok(None);
        }

        let chain_registry = match ChainRegistry::from_config(config.chains()).await {
            Ok(registry) => registry,
            Err(err) => {
                warn!(reason = %err, "failed to initialize exact facilitator from environment");
                return Ok(None);
            }
        };

        let scheme_registry =
            SchemeRegistry::build(chain_registry, SchemeBlueprints::full(), config.schemes());
        if scheme_registry.values().next().is_none() {
            return Ok(None);
        }

        let facilitator = FacilitatorLocal::new(scheme_registry);
        Ok(Some(Self {
            inner: Arc::new(facilitator),
        }))
    }

    fn convert_verify_response(
        response: proto::VerifyResponse,
    ) -> Result<VerifyResponse, ValidationError> {
        let response = x402_rs::proto::v1::VerifyResponse::try_from(response)
            .map_err(|err| ValidationError::Exact(err.to_string()))?;
        Ok(match response {
            x402_rs::proto::v1::VerifyResponse::Valid { .. } => VerifyResponse {
                is_valid: true,
                invalid_reason: None,
                certificate: None,
            },
            x402_rs::proto::v1::VerifyResponse::Invalid { reason, .. } => VerifyResponse {
                is_valid: false,
                invalid_reason: Some(reason.to_string()),
                certificate: None,
            },
        })
    }

    fn convert_settle_response(
        response: proto::SettleResponse,
    ) -> Result<SettleResponse, ValidationError> {
        let response: x402_rs::proto::v1::SettleResponse = serde_json::from_value(response.0)
            .map_err(|err| ValidationError::Exact(err.to_string()))?;
        let (success, error, tx_hash, network) = match response {
            x402_rs::proto::v1::SettleResponse::Success {
                transaction,
                network,
                ..
            } => (true, None, Some(transaction), network),
            x402_rs::proto::v1::SettleResponse::Error { reason, network } => {
                (false, Some(reason), None, network)
            }
        };
        Ok(SettleResponse::from_exact(success, error, tx_hash, network))
    }
}

#[async_trait]
impl ExactService for LocalExactService {
    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, ValidationError> {
        let converted = convert_verify_request(request)?;
        let result = self
            .inner
            .verify(&converted)
            .await
            .map_err(|err| ValidationError::Exact(err.to_string()))?;
        Self::convert_verify_response(result)
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, ValidationError> {
        let converted = convert_settle_request(request)?;
        let result = self
            .inner
            .settle(&converted)
            .await
            .map_err(|err| ValidationError::Exact(err.to_string()))?;
        Self::convert_settle_response(result)
    }

    async fn supported(&self) -> Result<Vec<SupportedKind>, ValidationError> {
        let response = self
            .inner
            .supported()
            .await
            .map_err(|err| ValidationError::Exact(err.to_string()))?;
        convert_supported(response)
    }
}

struct HttpExactService {
    client: Client,
    base_url: Url,
}

impl HttpExactService {
    fn new(base_url: Url) -> anyhow::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .user_agent(format!("x402-4mica/{}", env!("CARGO_PKG_VERSION")))
                .default_headers({
                    let mut h = reqwest::header::HeaderMap::new();
                    h.insert(reqwest::header::ACCEPT, "application/json".parse().unwrap());
                    h
                })
                .build()
                .context("failed to build reqwest client")?,
            base_url,
        })
    }

    fn from_env() -> anyhow::Result<Option<Self>> {
        let Some((raw, source)) = Self::debit_url_from_env() else {
            return Ok(None);
        };

        Self::from_raw(&raw, source).map(Some)
    }

    fn from_raw(raw: &str, source: &str) -> anyhow::Result<Self> {
        let base_url = Url::parse(raw)
            .or_else(|_| Url::parse(&format!("{raw}/")))
            .with_context(|| format!("failed to parse {source}"))?;
        Self::new(base_url)
    }

    fn debit_url_from_env() -> Option<(String, &'static str)> {
        let sanitize = |value: String| {
            let trimmed = value.trim().to_string();
            (!trimmed.is_empty()).then_some(trimmed)
        };

        let url = std::env::var(ENV_DEBIT_URL).ok().and_then(sanitize)?;
        Some((url, ENV_DEBIT_URL))
    }

    fn url(&self, path: &str) -> Result<Url, ValidationError> {
        self.base_url
            .join(path)
            .map_err(|err| ValidationError::Exact(format!("invalid debit facilitator URL: {err}")))
    }

    async fn post<Req, Resp>(&self, path: &str, payload: &Req) -> Result<Resp, ValidationError>
    where
        Req: serde::Serialize + ?Sized,
        Resp: for<'de> serde::Deserialize<'de>,
    {
        let url = self.url(path)?;
        let response = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(|err| {
                ValidationError::Exact(format!("failed to POST debit facilitator: {err}"))
            })?;
        Self::parse_response(response).await
    }

    async fn parse_response<T: for<'de> serde::Deserialize<'de>>(
        response: reqwest::Response,
    ) -> Result<T, ValidationError> {
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|err| ValidationError::Exact(err.to_string()))?;

        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes);
            return Err(ValidationError::Exact(format!(
                "debit facilitator returned {status}: {body}"
            )));
        }

        serde_json::from_slice(&bytes).map_err(|err| ValidationError::Exact(err.to_string()))
    }

    async fn get<T: for<'de> serde::Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, ValidationError> {
        let url = self.url(path)?;
        let response = self.client.get(url).send().await.map_err(|err| {
            ValidationError::Exact(format!("failed to GET debit facilitator: {err}"))
        })?;
        Self::parse_response(response).await
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DebitUrlConfig {
    network: String,
    #[serde(alias = "url", alias = "baseUrl")]
    debit_url: String,
}

struct NetworkedExactService {
    network: String,
    service: HttpExactService,
}

struct MultiHttpExactService {
    services: Vec<NetworkedExactService>,
}

impl MultiHttpExactService {
    fn from_env() -> anyhow::Result<Option<Self>> {
        let Some(entries) = parse_debit_urls_from_env()? else {
            return Ok(None);
        };
        let mut services = Vec::with_capacity(entries.len());
        for entry in entries {
            let service = HttpExactService::from_raw(&entry.debit_url, ENV_DEBIT_URLS)?;
            services.push(NetworkedExactService {
                network: entry.network,
                service,
            });
        }
        Ok(Some(Self { services }))
    }

    fn select_service(&self, network: &str) -> Option<&HttpExactService> {
        let mut wildcard: Option<&HttpExactService> = None;
        for entry in &self.services {
            if entry.network == network {
                return Some(&entry.service);
            }
            if wildcard.is_none() && matches_network_pattern(network, &entry.network) {
                wildcard = Some(&entry.service);
            }
        }
        wildcard
    }
}

#[async_trait]
impl ExactService for MultiHttpExactService {
    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, ValidationError> {
        let network = crate::config::normalize_network_id(&request.payment_requirements.network);
        let service = self
            .select_service(&network)
            .ok_or_else(|| ValidationError::UnsupportedNetwork(network))?;
        service.verify(request).await
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, ValidationError> {
        let network = crate::config::normalize_network_id(&request.payment_requirements.network);
        let service = self
            .select_service(&network)
            .ok_or_else(|| ValidationError::UnsupportedNetwork(network))?;
        service.settle(request).await
    }

    async fn supported(&self) -> Result<Vec<SupportedKind>, ValidationError> {
        let mut kinds = Vec::new();
        let mut seen: HashSet<(String, String, Option<u8>)> = HashSet::new();
        for entry in &self.services {
            let response = entry.service.supported().await?;
            for kind in response {
                let key = (kind.scheme.clone(), kind.network.clone(), kind.x402_version);
                if seen.insert(key) {
                    kinds.push(kind);
                }
            }
        }
        Ok(kinds)
    }
}

fn parse_debit_urls_from_env() -> anyhow::Result<Option<Vec<DebitUrlConfig>>> {
    let raw = std::env::var(ENV_DEBIT_URLS)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let Some(raw) = raw else {
        return Ok(None);
    };

    let mut entries: Vec<DebitUrlConfig> = serde_json::from_str(&raw).with_context(|| {
        format!(
            "{ENV_DEBIT_URLS} must be JSON like \
        '[{{\"network\":\"eip155:8453\",\"debitUrl\":\"https://x402.example.com\"}}]'"
        )
    })?;
    if entries.is_empty() {
        bail!("{ENV_DEBIT_URLS} must include at least one entry");
    }

    for entry in &mut entries {
        entry.network = crate::config::normalize_network_id(&entry.network);
        if entry.network.trim().is_empty() {
            bail!("{ENV_DEBIT_URLS} entries require a non-empty network");
        }
        entry.debit_url = entry.debit_url.trim().to_string();
        if entry.debit_url.is_empty() {
            bail!("{ENV_DEBIT_URLS} entries require a non-empty debitUrl");
        }
    }

    Ok(Some(entries))
}

fn matches_network_pattern(network: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return network.starts_with(prefix);
    }
    network == pattern
}

#[async_trait]
impl ExactService for HttpExactService {
    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, ValidationError> {
        let converted = convert_verify_request(request)?;
        let response: proto::VerifyResponse = self.post("verify", &converted).await?;
        LocalExactService::convert_verify_response(response)
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, ValidationError> {
        let converted = convert_settle_request(request)?;
        let response: proto::SettleResponse = self.post("settle", &converted).await?;
        LocalExactService::convert_settle_response(response)
    }

    async fn supported(&self) -> Result<Vec<SupportedKind>, ValidationError> {
        let response: proto::SupportedResponse = self.get("supported").await.map_err(|err| {
            ValidationError::Exact(format!(
                "failed to fetch supported from {}: {err}",
                self.base_url
            ))
        })?;
        convert_supported(response)
    }
}

fn load_x402_config() -> anyhow::Result<X402Config> {
    let config_path = std::env::var(ENV_CONFIG_PATH)
        .ok()
        .and_then(|raw| {
            let trimmed = raw.trim().to_string();
            (!trimmed.is_empty()).then_some(std::path::PathBuf::from(trimmed))
        })
        .or_else(|| {
            let default_path = std::path::PathBuf::from("config.json");
            default_path.exists().then_some(default_path)
        });

    match config_path {
        Some(path) => {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read x402 config at {}", path.display()))?;
            let config = serde_json::from_str(&content)
                .with_context(|| format!("failed to parse x402 config at {}", path.display()))?;
            Ok(config)
        }
        None => Ok(X402Config::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    fn set_debit_url(url: &str) {
        unsafe { env::set_var(ENV_DEBIT_URL, url) };
    }

    fn clear_debit_url() {
        unsafe { env::remove_var(ENV_DEBIT_URL) };
    }

    fn set_debit_urls(value: &str) {
        unsafe { env::set_var(ENV_DEBIT_URLS, value) };
    }

    fn clear_debit_urls() {
        unsafe { env::remove_var(ENV_DEBIT_URLS) };
    }

    #[test]
    #[serial]
    fn parses_debit_url_from_env() {
        set_debit_url("http://example.com");
        let service = HttpExactService::from_env()
            .expect("from_env")
            .expect("present");
        let url = service.url("verify").expect("url");
        assert_eq!(url.as_str(), "http://example.com/verify");
        clear_debit_url();
    }

    #[test]
    #[serial]
    fn parses_debit_urls_from_env() {
        set_debit_urls(r#"[{"network":"eip155:8453","debitUrl":"http://example.com"}]"#);
        let service = MultiHttpExactService::from_env()
            .expect("from_env")
            .expect("present");
        assert_eq!(service.services.len(), 1);
        assert_eq!(service.services[0].network, "eip155:8453");
        let url = service.services[0].service.url("verify").expect("url");
        assert_eq!(url.as_str(), "http://example.com/verify");
        clear_debit_urls();
    }
}
