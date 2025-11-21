use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use reqwest::{Client, Url};
use tracing::{info, warn};
use x402_rs::facilitator::Facilitator;
use x402_rs::facilitator_local::FacilitatorLocal;
use x402_rs::provider_cache::{ProviderCache, ProviderMap};
use x402_rs::types::{
    Base64Bytes, PaymentPayload, PaymentRequirements as XPaymentRequirements,
    SettleRequest as XSettleRequest, SettleResponse as XSettleResponse, SupportedPaymentKind,
    SupportedPaymentKindsResponse, VerifyRequest as XVerifyRequest,
    VerifyResponse as XVerifyResponse, X402Version,
};

use crate::server::state::{
    ExactService, PaymentRequirements, SettleRequest, SettleResponse, SupportedKind,
    ValidationError, VerifyRequest, VerifyResponse,
};

const ENV_DEBIT_URL: &str = "X402_DEBIT_URL";

fn convert_supported_kind(kind: SupportedPaymentKind) -> Result<SupportedKind, ValidationError> {
    let extra = kind
        .extra
        .map(|value| {
            serde_json::to_value(value).map_err(|err| ValidationError::Exact(err.to_string()))
        })
        .transpose()?;
    let x402_version = match kind.x402_version {
        X402Version::V1 => 1,
    };

    Ok(SupportedKind {
        scheme: kind.scheme.to_string(),
        network: kind.network,
        x402_version: Some(x402_version),
        extra,
    })
}

fn convert_supported(
    response: SupportedPaymentKindsResponse,
) -> Result<Vec<SupportedKind>, ValidationError> {
    response
        .kinds
        .into_iter()
        .map(convert_supported_kind)
        .collect()
}

pub async fn try_from_env() -> anyhow::Result<Option<Arc<dyn ExactService>>> {
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

struct LocalExactService {
    inner: Arc<FacilitatorLocal<ProviderCache>>,
}

impl LocalExactService {
    pub async fn try_from_env() -> anyhow::Result<Option<Self>> {
        let cache = match ProviderCache::from_env().await {
            Ok(cache) => cache,
            Err(err) => {
                warn!(reason = %err, "failed to initialize exact facilitator from environment");
                return Ok(None);
            }
        };

        if cache.values().next().is_none() {
            return Ok(None);
        }

        let facilitator = FacilitatorLocal::new(cache);
        Ok(Some(Self {
            inner: Arc::new(facilitator),
        }))
    }

    fn convert_requirements(
        req: &PaymentRequirements,
    ) -> Result<XPaymentRequirements, ValidationError> {
        use serde_json::{Map, Value as JsonValue};

        let mut map = Map::new();
        map.insert("scheme".into(), JsonValue::String(req.scheme.clone()));
        map.insert("network".into(), JsonValue::String(req.network.clone()));
        map.insert(
            "maxAmountRequired".into(),
            JsonValue::String(req.max_amount_required.clone()),
        );
        if let Some(resource) = &req.resource {
            map.insert("resource".into(), JsonValue::String(resource.clone()));
        }
        if let Some(description) = &req.description {
            map.insert("description".into(), JsonValue::String(description.clone()));
        }
        if let Some(mime) = &req.mime_type {
            map.insert("mimeType".into(), JsonValue::String(mime.clone()));
        }
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

        serde_json::from_value(JsonValue::Object(map)).map_err(|err| {
            ValidationError::InvalidRequirements(format!(
                "failed to parse paymentRequirements for exact scheme: {err}"
            ))
        })
    }

    fn convert_verify_request(request: &VerifyRequest) -> Result<XVerifyRequest, ValidationError> {
        let version = X402Version::try_from(request.x402_version)
            .map_err(|_| ValidationError::UnsupportedVersion(request.x402_version))?;

        let payload =
            PaymentPayload::try_from(Base64Bytes::from(request.payment_header.as_bytes()))
                .map_err(|err| ValidationError::InvalidHeader(err.to_string()))?;

        let payment_requirements = Self::convert_requirements(&request.payment_requirements)?;

        Ok(XVerifyRequest {
            x402_version: version,
            payment_payload: payload,
            payment_requirements,
        })
    }

    fn convert_settle_request(request: &SettleRequest) -> Result<XSettleRequest, ValidationError> {
        Self::convert_verify_request(&VerifyRequest {
            x402_version: request.x402_version,
            payment_header: request.payment_header.clone(),
            payment_requirements: request.payment_requirements.clone(),
        })
    }

    fn convert_verify_response(response: XVerifyResponse) -> VerifyResponse {
        match response {
            XVerifyResponse::Valid { .. } => VerifyResponse {
                is_valid: true,
                invalid_reason: None,
                certificate: None,
            },
            XVerifyResponse::Invalid { reason, .. } => VerifyResponse {
                is_valid: false,
                invalid_reason: Some(reason.to_string()),
                certificate: None,
            },
        }
    }

    fn convert_settle_response(response: XSettleResponse) -> SettleResponse {
        let tx_hash = response.transaction.map(|hash| format!("{}", hash));
        let error = response.error_reason.map(|reason| reason.to_string());
        SettleResponse::from_exact(
            response.success,
            error,
            tx_hash,
            response.network.to_string(),
        )
    }
}

#[async_trait]
impl ExactService for LocalExactService {
    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, ValidationError> {
        let converted = Self::convert_verify_request(request)?;
        let result = self
            .inner
            .verify(&converted)
            .await
            .map_err(|err| ValidationError::Exact(err.to_string()))?;
        Ok(Self::convert_verify_response(result))
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, ValidationError> {
        let converted = Self::convert_settle_request(request)?;
        let result = self
            .inner
            .settle(&converted)
            .await
            .map_err(|err| ValidationError::Exact(err.to_string()))?;
        Ok(Self::convert_settle_response(result))
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
    fn from_env() -> anyhow::Result<Option<Self>> {
        let Some((raw, source)) = Self::debit_url_from_env() else {
            return Ok(None);
        };

        let base_url = Url::parse(&raw)
            .or_else(|_| Url::parse(&format!("{raw}/")))
            .with_context(|| format!("failed to parse {source}"))?;

        Ok(Some(Self {
            client: Client::new(),
            base_url,
        }))
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

#[async_trait]
impl ExactService for HttpExactService {
    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, ValidationError> {
        self.post("verify", request).await
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, ValidationError> {
        self.post("settle", request).await
    }

    async fn supported(&self) -> Result<Vec<SupportedKind>, ValidationError> {
        let response: SupportedPaymentKindsResponse =
            self.get("supported").await.map_err(|err| {
                ValidationError::Exact(format!(
                    "failed to fetch supported from {}: {err}",
                    self.base_url
                ))
            })?;
        convert_supported(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    #[allow(dead_code)]
    fn sample_verify_request() -> VerifyRequest {
        VerifyRequest {
            x402_version: 1,
            payment_header: "header".into(),
            payment_requirements: PaymentRequirements {
                scheme: "exact".into(),
                network: "base".into(),
                max_amount_required: "1000".into(),
                resource: None,
                description: None,
                mime_type: None,
                output_schema: None,
                pay_to: "0x0000000000000000000000000000000000000008".into(),
                max_timeout_seconds: Some(30),
                asset: "0x0000000000000000000000000000000000000009".into(),
                extra: None,
            },
        }
    }

    #[allow(dead_code)]
    fn sample_settle_request() -> SettleRequest {
        SettleRequest {
            x402_version: 1,
            payment_header: "header".into(),
            payment_requirements: sample_verify_request().payment_requirements,
        }
    }

    fn set_debit_url(url: &str) {
        unsafe { env::set_var(ENV_DEBIT_URL, url) };
    }

    fn clear_debit_url() {
        unsafe { env::remove_var(ENV_DEBIT_URL) };
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
}
