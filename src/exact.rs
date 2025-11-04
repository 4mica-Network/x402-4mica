use std::sync::Arc;

use async_trait::async_trait;
use x402_rs::facilitator::Facilitator;
use x402_rs::facilitator_local::FacilitatorLocal;
use x402_rs::provider_cache::{ProviderCache, ProviderMap};
use x402_rs::types::{
    Base64Bytes, FacilitatorErrorReason, Network, PaymentPayload,
    PaymentRequirements as XPaymentRequirements, Scheme, SettleRequest as XSettleRequest,
    SettleResponse as XSettleResponse, SupportedPaymentKindsResponse,
    VerifyRequest as XVerifyRequest, VerifyResponse as XVerifyResponse, X402Version,
};

use crate::server::state::{
    ExactService, PaymentRequirements, SettleRequest, SettleResponse, ValidationError,
    VerifyRequest, VerifyResponse,
};

pub struct X402ExactService {
    inner: Arc<FacilitatorLocal<ProviderCache>>,
}

impl X402ExactService {
    pub async fn try_from_env() -> anyhow::Result<Option<Self>> {
        let cache = match ProviderCache::from_env().await {
            Ok(cache) => cache,
            Err(err) => return Err(anyhow::Error::from(err)),
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

    fn convert_supported(response: SupportedPaymentKindsResponse) -> Vec<(String, String)> {
        response
            .kinds
            .into_iter()
            .map(|kind| (kind.scheme.to_string(), kind.network.to_string()))
            .collect()
    }
}

#[async_trait]
impl ExactService for X402ExactService {
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

    async fn supported(&self) -> Result<Vec<(String, String)>, ValidationError> {
        let response = self
            .inner
            .supported()
            .await
            .map_err(|err| ValidationError::Exact(err.to_string()))?;
        Ok(Self::convert_supported(response))
    }
}
