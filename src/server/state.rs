use std::{
    collections::HashMap,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::http::StatusCode;
use reqwest::{Client, Url};
use rpc::{
    PaymentGuaranteeClaims, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    PaymentGuaranteeRequestClaimsV1,
};
use rust_sdk_4mica::{Address, U256};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use crate::server::model::{
    CoreCreateTabRequest, CoreCreateTabResponse, CreateTabRequest, CreateTabResponse,
    PaymentRequirements, SettleRequest, SettleResponse, SupportedKind, VerifyRequest,
    VerifyResponse, X402PaymentPayload,
};
use crate::verifier::CertificateValidator;
use crate::{
    exact::ExactService,
    issuer::{GuaranteeIssuer, parse_error_message},
};

const SUPPORTED_VERSIONS: [u8; 2] = [1, 2];

pub(super) type SharedState = Arc<AppState>;

pub(crate) struct AppState {
    four_mica: Vec<FourMicaHandler>,
    tab_services: HashMap<String, Arc<dyn TabService>>,
    default_tab_network: Option<String>,
    exact: Option<Arc<dyn ExactService>>,
}

impl AppState {
    pub fn new(
        four_mica: Vec<FourMicaHandler>,
        tab_services: HashMap<String, Arc<dyn TabService>>,
        default_tab_network: Option<String>,
        exact: Option<Arc<dyn ExactService>>,
    ) -> Self {
        Self {
            four_mica,
            tab_services,
            default_tab_network,
            exact,
        }
    }

    pub fn network(&self) -> &str {
        self.four_mica
            .first()
            .map(|handler| handler.network())
            .unwrap_or("unknown")
    }

    pub fn validate_version(&self, version: u8) -> Result<(), ValidationError> {
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err(ValidationError::UnsupportedVersion(version));
        }
        Ok(())
    }

    fn handler_for(&self, scheme: &str, network: &str) -> Option<&FourMicaHandler> {
        self.four_mica
            .iter()
            .find(|handler| handler.matches(scheme, network))
    }

    pub async fn supported(&self) -> Vec<SupportedKind> {
        let mut kinds = Vec::new();
        for handler in &self.four_mica {
            for version in SUPPORTED_VERSIONS {
                kinds.push(handler.supported_kind(version));
            }
        }
        if let Some(exact) = &self.exact {
            match exact.supported().await {
                Ok(list) => kinds.extend(list),
                Err(err) => tracing::warn!(reason = %err, "failed to fetch exact supported kinds"),
            }
        }
        kinds
    }

    pub async fn verify(
        &self,
        request: &VerifyRequest,
        x402_version: u8,
    ) -> Result<VerifyResponse, ValidationError> {
        let scheme = &request.payment_requirements.scheme;
        let network = &request.payment_requirements.network;

        if let Some(handler) = self.handler_for(scheme, network) {
            return handler.verify(request, x402_version).await;
        }

        if let Some(exact) = &self.exact {
            match exact.supported().await {
                Ok(kinds) => {
                    let matches_scheme = kinds.iter().any(|kind| &kind.scheme == scheme);
                    if kinds
                        .iter()
                        .any(|kind| &kind.scheme == scheme && &kind.network == network)
                    {
                        return exact.verify(request).await;
                    }
                    if matches_scheme {
                        return Err(ValidationError::UnsupportedNetwork(network.clone()));
                    }
                }
                Err(err) => tracing::warn!(reason = %err, "failed to fetch exact supported kinds"),
            }
        }

        if self
            .four_mica
            .iter()
            .any(|handler| &handler.scheme == scheme)
        {
            return Err(ValidationError::UnsupportedNetwork(network.clone()));
        }

        Err(ValidationError::UnsupportedScheme(scheme.clone()))
    }

    pub async fn settle(
        &self,
        request: &SettleRequest,
        x402_version: u8,
    ) -> Result<SettleResponse, ValidationError> {
        let scheme = &request.payment_requirements.scheme;
        let network = &request.payment_requirements.network;

        if let Some(handler) = self.handler_for(scheme, network) {
            return handler.settle(request, x402_version).await;
        }

        if let Some(exact) = &self.exact {
            match exact.supported().await {
                Ok(kinds) => {
                    let matches_scheme = kinds.iter().any(|kind| &kind.scheme == scheme);
                    if kinds
                        .iter()
                        .any(|kind| &kind.scheme == scheme && &kind.network == network)
                    {
                        return exact.settle(request).await;
                    }
                    if matches_scheme {
                        return Err(ValidationError::UnsupportedNetwork(network.clone()));
                    }
                }
                Err(err) => tracing::warn!(reason = %err, "failed to fetch exact supported kinds"),
            }
        }

        if self
            .four_mica
            .iter()
            .any(|handler| &handler.scheme == scheme)
        {
            return Err(ValidationError::UnsupportedNetwork(network.clone()));
        }

        Err(ValidationError::UnsupportedScheme(scheme.clone()))
    }

    pub async fn create_tab(
        &self,
        request: &CreateTabRequest,
    ) -> Result<CreateTabResponse, TabError> {
        if self.tab_services.is_empty() {
            return Err(TabError::Unsupported);
        }
        let requested = request
            .network
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(crate::config::normalize_network_id)
            .or_else(|| self.default_tab_network.clone());
        let Some(network) = requested else {
            return Err(TabError::Unsupported);
        };
        let service = self
            .tab_services
            .get(&network)
            .ok_or_else(|| TabError::UnsupportedNetwork(network.clone()))?;
        service.create_tab(request).await
    }
}

pub(crate) struct FourMicaHandler {
    scheme: String,
    network: String,
    verifier: Arc<dyn CertificateValidator>,
    issuer: Arc<dyn GuaranteeIssuer>,
}

impl FourMicaHandler {
    pub(crate) fn new(
        scheme: String,
        network: String,
        verifier: Arc<dyn CertificateValidator>,
        issuer: Arc<dyn GuaranteeIssuer>,
    ) -> Self {
        Self {
            scheme,
            network,
            verifier,
            issuer,
        }
    }

    pub(crate) fn network(&self) -> &str {
        &self.network
    }

    fn matches(&self, scheme: &str, network: &str) -> bool {
        self.scheme == scheme && self.network == network
    }

    fn supported_kind(&self, version: u8) -> SupportedKind {
        SupportedKind {
            scheme: self.scheme.clone(),
            network: self.network.clone(),
            x402_version: Some(version),
            extra: None,
        }
    }

    async fn verify(
        &self,
        request: &VerifyRequest,
        x402_version: u8,
    ) -> Result<VerifyResponse, ValidationError> {
        let payload = self.decode_payment_payload(
            request.payment_payload.clone(),
            &request.payment_requirements,
        )?;
        self.validate_payment_payload(&payload, &request.payment_requirements, x402_version)?;

        Ok(VerifyResponse {
            is_valid: true,
            invalid_reason: None,
            certificate: None,
        })
    }

    async fn settle(
        &self,
        request: &SettleRequest,
        x402_version: u8,
    ) -> Result<SettleResponse, ValidationError> {
        let payload = self.decode_payment_payload(
            request.payment_payload.clone(),
            &request.payment_requirements,
        )?;
        self.validate_payment_payload(&payload, &request.payment_requirements, x402_version)?;

        let certificate = self
            .issuer
            .issue(payload.claims.clone(), payload.signature, payload.scheme)
            .await
            .map_err(ValidationError::IssueGuarantee)?;

        let claims = self
            .verifier
            .verify_certificate(&certificate)
            .map_err(ValidationError::InvalidCertificate)?;

        match &payload.claims {
            PaymentGuaranteeRequestClaims::V1(claims_request) => {
                self.ensure_certificate_matches_claims_v1(claims_request, &claims)?;
            }
        }

        tracing::info!(
            tab_id = format!("{:#x}", claims.tab_id),
            req_id = format!("{:#x}", claims.req_id),
            amount = format!("{:#x}", claims.amount),
            "4mica guarantee issued during settlement"
        );

        Ok(SettleResponse::four_mica_success(
            &self.network,
            certificate.into(),
        ))
    }

    fn decode_payment_payload(
        &self,
        payload: X402PaymentPayload,
        reqs: &PaymentRequirements,
    ) -> Result<PaymentGuaranteeRequest, ValidationError> {
        match payload {
            X402PaymentPayload::V1(envelope) => {
                if envelope.scheme != self.scheme {
                    return Err(ValidationError::UnsupportedScheme(envelope.scheme));
                }
                if reqs.scheme != self.scheme {
                    return Err(ValidationError::UnsupportedScheme(reqs.scheme.clone()));
                }
                if envelope.network != self.network {
                    return Err(ValidationError::UnsupportedNetwork(envelope.network));
                }
                if reqs.network != self.network {
                    return Err(ValidationError::UnsupportedNetwork(reqs.network.clone()));
                }

                let signature = envelope.payload.signature.trim();
                if signature.is_empty() {
                    return Err(ValidationError::InvalidHeader(
                        "signature cannot be empty".into(),
                    ));
                }

                Ok(envelope.payload.into_request())
            }
            X402PaymentPayload::V2(envelope) => {
                if envelope.accepted.scheme != self.scheme {
                    return Err(ValidationError::UnsupportedScheme(envelope.accepted.scheme));
                }
                if reqs.scheme != self.scheme {
                    return Err(ValidationError::UnsupportedScheme(reqs.scheme.clone()));
                }
                if envelope.accepted.network != self.network {
                    return Err(ValidationError::UnsupportedNetwork(
                        envelope.accepted.network,
                    ));
                }
                if reqs.network != self.network {
                    return Err(ValidationError::UnsupportedNetwork(reqs.network.clone()));
                }
                if envelope.payload.signature.trim().is_empty() {
                    return Err(ValidationError::InvalidHeader(
                        "signature cannot be empty".into(),
                    ));
                }

                Ok(envelope.payload.into_request())
            }
        }
    }

    fn validate_payment_payload(
        &self,
        payload: &PaymentGuaranteeRequest,
        reqs: &PaymentRequirements,
        version: u8,
    ) -> Result<(), ValidationError> {
        match &payload.claims {
            PaymentGuaranteeRequestClaims::V1(claims) => {
                tracing::debug!(
                    tab_id = format!("{:#x}", claims.tab_id),
                    req_id = format!("{:#x}", claims.req_id),
                    amount = format!("{:#x}", claims.amount),
                    "Decoded 4mica claims"
                );
                self.ensure_claims_v1_match_requirements(claims, reqs, version)?;
            }
        }
        Ok(())
    }

    fn ensure_claims_v1_match_requirements(
        &self,
        claims: &PaymentGuaranteeRequestClaimsV1,
        reqs: &PaymentRequirements,
        version: u8,
    ) -> Result<(), ValidationError> {
        let required_pay_to = Address::from_str(&reqs.pay_to)
            .map_err(|_| ValidationError::InvalidRequirements("invalid payTo address".into()))?;
        let claim_recipient = Address::from_str(&claims.recipient_address).map_err(|_| {
            ValidationError::InvalidClaims("invalid recipient address in claims".into())
        })?;

        if claim_recipient != required_pay_to {
            return Err(ValidationError::Mismatch(format!(
                "claim recipient {} does not match payTo {}",
                claim_recipient, required_pay_to
            )));
        }

        let required_asset = Address::from_str(&reqs.asset)
            .map_err(|_| ValidationError::InvalidRequirements("invalid asset address".into()))?;
        let claim_asset = Address::from_str(&claims.asset_address).map_err(|_| {
            ValidationError::InvalidClaims("invalid asset address in claims".into())
        })?;

        if claim_asset != required_asset {
            return Err(ValidationError::Mismatch(format!(
                "claim asset {} does not match requirement {}",
                claim_asset, required_asset
            )));
        }

        let amount_required = required_amount(reqs, version)?;
        if claims.amount.is_zero() {
            return Err(ValidationError::InvalidClaims(
                "claim amount is zero".into(),
            ));
        }
        if claims.amount != amount_required {
            let amount_label = if version == 2 {
                "amount"
            } else {
                "maxAmountRequired"
            };
            return Err(ValidationError::Mismatch(format!(
                "claim amount {} does not match {} {}",
                claims.amount, amount_label, amount_required
            )));
        }

        Ok(())
    }

    fn ensure_certificate_matches_claims_v1(
        &self,
        request: &PaymentGuaranteeRequestClaimsV1,
        issued: &PaymentGuaranteeClaims,
    ) -> Result<(), ValidationError> {
        if issued.tab_id != request.tab_id
            || issued.req_id != request.req_id
            || issued.amount != request.amount
            || issued.recipient_address != request.recipient_address
            || issued.asset_address != request.asset_address
            || issued.user_address != request.user_address
        {
            return Err(ValidationError::Mismatch(
                "certificate values differ from requested claims".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
pub(crate) trait TabService: Send + Sync {
    async fn create_tab(&self, request: &CreateTabRequest) -> Result<CreateTabResponse, TabError>;
}

#[derive(Clone)]
pub(crate) struct CoreTabService {
    client: Client,
    base_url: Url,
    default_asset_address: Option<String>,
}

impl CoreTabService {
    pub fn new(base_url: Url, default_asset_address: Option<String>) -> Self {
        Self {
            client: Client::new(),
            base_url,
            default_asset_address,
        }
    }

    fn url(&self, path: &str) -> Result<Url, TabError> {
        self.base_url
            .join(path)
            .map_err(|err| TabError::Invalid(err.to_string()))
    }

    async fn post<Req, Resp>(&self, path: &str, payload: &Req) -> Result<Resp, TabError>
    where
        Req: Serialize + ?Sized,
        Resp: for<'de> Deserialize<'de>,
    {
        let url = self.url(path)?;
        let response = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .inspect_err(|err| error!(reason = %err, "failed to POST to tab service"))
            .map_err(|err| TabError::Upstream {
                status: StatusCode::BAD_GATEWAY,
                message: err.to_string(),
            })?;

        Self::decode_response(response).await
    }

    async fn decode_response<T>(response: reqwest::Response) -> Result<T, TabError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        let bytes = response.bytes().await.map_err(|err| TabError::Upstream {
            status,
            message: err.to_string(),
        })?;
        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(|err| TabError::Upstream {
                status,
                message: err.to_string(),
            })
        } else {
            let message = parse_error_message(&bytes);
            Err(TabError::Upstream { status, message })
        }
    }
}

#[async_trait]
impl TabService for CoreTabService {
    async fn create_tab(&self, request: &CreateTabRequest) -> Result<CreateTabResponse, TabError> {
        let asset_address = self.resolve_asset_address(request)?;
        let payload = CoreCreateTabRequest {
            user_address: request.user_address.clone(),
            recipient_address: request.recipient_address.clone(),
            erc20_token: Some(asset_address.clone()),
            ttl: request.ttl_seconds,
        };

        let result: CoreCreateTabResponse = self.post("core/payment-tabs", &payload).await?;
        let tab_id = canonical_u256(&result.id);
        let next_req_id = canonical_u256(&result.next_req_id.unwrap_or(U256::ZERO));
        let asset_address = result
            .erc20_token
            .clone()
            .or(result.asset_address.clone())
            .unwrap_or_else(|| asset_address.clone());
        let start_timestamp = current_timestamp();
        let ttl_seconds = request
            .ttl_seconds
            .map(|value| value as i64)
            .unwrap_or_default();

        Ok(CreateTabResponse {
            tab_id,
            user_address: request.user_address.clone(),
            recipient_address: request.recipient_address.clone(),
            asset_address: asset_address.clone(),
            start_timestamp,
            ttl_seconds,
            next_req_id,
        })
    }
}

impl CoreTabService {
    fn resolve_asset_address(&self, request: &CreateTabRequest) -> Result<String, TabError> {
        let value = request
            .erc20_token
            .as_deref()
            .or(self.default_asset_address.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                TabError::Invalid("erc20Token is required (or set ASSET_ADDRESS env)".into())
            })?;
        Ok(value.to_string())
    }
}

fn canonical_u256(value: &U256) -> String {
    format!("{:#x}", value)
}

fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

pub fn resolve_x402_version(
    payment_payload: &X402PaymentPayload,
    request_version: Option<u8>,
) -> Result<u8, ValidationError> {
    let payload_version = payment_payload.x402_version();

    if let Some(request_version) = request_version
        && request_version != payload_version
    {
        return Err(ValidationError::InvalidHeader(format!(
            "x402Version {} does not match paymentPayload x402Version {}",
            request_version, payload_version
        )));
    }

    Ok(payload_version)
}

fn parse_u256_field(value: &str, field: &str) -> Result<U256, String> {
    if value.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    if let Some(rest) = value.strip_prefix("0x") {
        U256::from_str_radix(rest, 16).map_err(|err| format!("invalid hex amount: {err}"))
    } else {
        U256::from_str_radix(value, 10).map_err(|err| format!("invalid decimal amount: {err}"))
    }
}

fn parse_u256(value: &str) -> Result<U256, String> {
    parse_u256_field(value, "maxAmountRequired")
}

fn required_amount(reqs: &PaymentRequirements, version: u8) -> Result<U256, ValidationError> {
    match version {
        1 => parse_u256(&reqs.max_amount_required).map_err(ValidationError::InvalidRequirements),
        2 => {
            let amount = reqs.amount.as_deref().ok_or_else(|| {
                ValidationError::InvalidRequirements("amount is required for x402Version 2".into())
            })?;
            parse_u256_field(amount, "amount").map_err(ValidationError::InvalidRequirements)
        }
        _ => Err(ValidationError::UnsupportedVersion(version)),
    }
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("{0}")]
    InvalidHeader(String),
    #[error("{0}")]
    InvalidRequirements(String),
    #[error("{0}")]
    InvalidClaims(String),
    #[error("{0}")]
    InvalidCertificate(String),
    #[error("{0}")]
    IssueGuarantee(String),
    #[error("{0}")]
    Mismatch(String),
    #[error("unsupported scheme {0}")]
    UnsupportedScheme(String),
    #[error("unsupported network {0}")]
    UnsupportedNetwork(String),
    #[error("unsupported x402Version {0}")]
    UnsupportedVersion(u8),
    #[error("exact flow error: {0}")]
    Exact(String),

    #[error(transparent)]
    Other(anyhow::Error),
}

#[derive(Debug, Error)]
pub enum TabError {
    #[error("4mica tab provisioning is disabled")]
    Unsupported,
    #[error("unsupported network {0}")]
    UnsupportedNetwork(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{message}")]
    Upstream { status: StatusCode, message: String },
}
