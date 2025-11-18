use std::{
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use reqwest::{Client, Url};
use rust_sdk_4mica::{
    Address, BLSCert, PaymentGuaranteeClaims, PaymentGuaranteeRequestClaims, SigningScheme, U256,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::issuer::{GuaranteeIssuer, parse_error_message};
use crate::verifier::CertificateValidator;

const SUPPORTED_VERSION: u8 = 1;
const ETH_SENTINEL_ADDRESS: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

pub(super) type SharedState = Arc<AppState>;

pub(crate) struct AppState {
    four_mica: Vec<FourMicaHandler>,
    tab_service: Option<Arc<dyn TabService>>,
    exact: Option<Arc<dyn ExactService>>,
}

impl AppState {
    pub fn new(
        four_mica: Vec<FourMicaHandler>,
        tab_service: Option<Arc<dyn TabService>>,
        exact: Option<Arc<dyn ExactService>>,
    ) -> Self {
        Self {
            four_mica,
            tab_service,
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
        if version != SUPPORTED_VERSION {
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
            kinds.push(handler.supported_kind());
        }
        if let Some(exact) = &self.exact {
            match exact.supported().await {
                Ok(list) => {
                    for (scheme, network) in list {
                        kinds.push(SupportedKind { scheme, network });
                    }
                }
                Err(err) => tracing::warn!(reason = %err, "failed to fetch exact supported kinds"),
            }
        }
        kinds
    }

    pub async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, ValidationError> {
        if let Some(handler) = self.handler_for(
            &request.payment_requirements.scheme,
            &request.payment_requirements.network,
        ) {
            return handler
                .verify(&request.payment_header, &request.payment_requirements)
                .await;
        }

        if let Some(exact) = &self.exact {
            return exact.verify(request).await;
        }

        Err(ValidationError::UnsupportedScheme(
            request.payment_requirements.scheme.clone(),
        ))
    }

    pub async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, ValidationError> {
        if let Some(handler) = self.handler_for(
            &request.payment_requirements.scheme,
            &request.payment_requirements.network,
        ) {
            return handler
                .settle(&request.payment_header, &request.payment_requirements)
                .await;
        }

        if let Some(exact) = &self.exact {
            return exact.settle(request).await;
        }

        Err(ValidationError::UnsupportedScheme(
            request.payment_requirements.scheme.clone(),
        ))
    }

    pub async fn create_tab(
        &self,
        request: &CreateTabRequest,
    ) -> Result<CreateTabResponse, TabError> {
        match &self.tab_service {
            Some(service) => service.create_tab(request).await,
            None => Err(TabError::Unsupported),
        }
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

    fn supported_kind(&self) -> SupportedKind {
        SupportedKind {
            scheme: self.scheme.clone(),
            network: self.network.clone(),
        }
    }

    async fn verify(
        &self,
        header_b64: &str,
        reqs: &PaymentRequirements,
    ) -> Result<VerifyResponse, ValidationError> {
        self.prepare_and_validate(header_b64, reqs)?;

        Ok(VerifyResponse {
            is_valid: true,
            invalid_reason: None,
            certificate: None,
        })
    }

    async fn settle(
        &self,
        header_b64: &str,
        reqs: &PaymentRequirements,
    ) -> Result<SettleResponse, ValidationError> {
        let prepared = self.prepare_and_validate(header_b64, reqs)?;

        let certificate = self
            .issuer
            .issue(&prepared.claims, &prepared.signature, prepared.scheme)
            .await
            .map_err(ValidationError::IssueGuarantee)?;

        let claims = self
            .verifier
            .verify_certificate(&certificate)
            .map_err(ValidationError::InvalidCertificate)?;

        self.ensure_certificate_matches_claims(&prepared.claims, &claims)?;

        tracing::info!(
            tab_id = format!("{:#x}", claims.tab_id),
            req_id = format!("{:#x}", claims.req_id),
            amount = format!("{:#x}", claims.amount),
            "4Mica guarantee issued during settlement"
        );

        Ok(SettleResponse::four_mica_success(
            &self.network,
            certificate.into(),
        ))
    }

    fn prepare_claim(
        &self,
        header_b64: &str,
        reqs: &PaymentRequirements,
    ) -> Result<PreparedClaim, ValidationError> {
        let envelope = decode_payment_header(header_b64).map_err(ValidationError::InvalidHeader)?;

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
        if envelope.x402_version != SUPPORTED_VERSION {
            return Err(ValidationError::UnsupportedVersion(envelope.x402_version));
        }

        let scheme = parse_signing_scheme(envelope.payload.signing_scheme.as_deref())?;
        let signature = envelope.payload.signature.trim();
        if signature.is_empty() {
            return Err(ValidationError::InvalidHeader(
                "signature cannot be empty".into(),
            ));
        }

        Ok(PreparedClaim {
            claims: envelope.payload.claims,
            signature: signature.to_string(),
            scheme,
        })
    }

    fn prepare_and_validate(
        &self,
        header_b64: &str,
        reqs: &PaymentRequirements,
    ) -> Result<PreparedClaim, ValidationError> {
        let prepared = self.prepare_claim(header_b64, reqs)?;
        self.ensure_claims_match_requirements(&prepared.claims, reqs)?;
        Ok(prepared)
    }

    fn ensure_claims_match_requirements(
        &self,
        claims: &PaymentGuaranteeRequestClaims,
        reqs: &PaymentRequirements,
    ) -> Result<(), ValidationError> {
        let extra = parse_extra(&reqs.extra)?;

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

        let expected_user = parse_address(&extra.user_address).map_err(|_| {
            ValidationError::InvalidRequirements("invalid userAddress in requirements.extra".into())
        })?;
        let claim_user = parse_address(&claims.user_address)
            .map_err(|_| ValidationError::InvalidClaims("invalid user_address in claims".into()))?;
        if claim_user != expected_user {
            return Err(ValidationError::Mismatch(format!(
                "claim user {} does not match expected user {}",
                claim_user, expected_user
            )));
        }

        let expected_tab = parse_u256_str(&extra.tab_id).map_err(|_| {
            ValidationError::InvalidRequirements("invalid tabId in requirements.extra".into())
        })?;
        if claims.tab_id != expected_tab {
            return Err(ValidationError::Mismatch(format!(
                "claim tab_id {} does not match expected tab_id {}",
                claims.tab_id, expected_tab
            )));
        }

        let amount_required =
            parse_u256(&reqs.max_amount_required).map_err(ValidationError::InvalidRequirements)?;
        if claims.amount.is_zero() {
            return Err(ValidationError::InvalidClaims(
                "claim amount is zero".into(),
            ));
        }
        if claims.amount != amount_required {
            return Err(ValidationError::Mismatch(format!(
                "claim amount {} does not match maxAmountRequired {}",
                claims.amount, amount_required
            )));
        }

        Ok(())
    }

    fn ensure_certificate_matches_claims(
        &self,
        request: &PaymentGuaranteeRequestClaims,
        issued: &PaymentGuaranteeClaims,
    ) -> Result<(), ValidationError> {
        if issued.tab_id != request.tab_id
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
}

impl CoreTabService {
    pub fn new(base_url: Url) -> Self {
        Self {
            client: Client::new(),
            base_url,
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
        let payload = CoreCreateTabRequest {
            user_address: request.user_address.clone(),
            recipient_address: request.recipient_address.clone(),
            erc20_token: request.erc20_token.clone(),
            ttl: request.ttl_seconds,
        };

        let result: CoreCreateTabResponse = self.post("core/payment-tabs", &payload).await?;
        let tab_id = canonical_u256(&result.id);
        let asset_address = request
            .erc20_token
            .clone()
            .unwrap_or_else(|| ETH_SENTINEL_ADDRESS.to_string());
        let start_timestamp = current_timestamp();
        let ttl_seconds = request
            .ttl_seconds
            .map(|value| value as i64)
            .unwrap_or_default();

        Ok(CreateTabResponse {
            tab_id,
            user_address: request.user_address.clone(),
            recipient_address: request.recipient_address.clone(),
            asset_address,
            start_timestamp,
            ttl_seconds,
        })
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

#[async_trait]
pub(crate) trait ExactService: Send + Sync {
    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, ValidationError>;
    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, ValidationError>;
    async fn supported(&self) -> Result<Vec<(String, String)>, ValidationError>;
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedKind {
    scheme: String,
    network: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedResponse {
    kinds: Vec<SupportedKind>,
}

impl SupportedResponse {
    pub fn new(kinds: Vec<SupportedKind>) -> Self {
        Self { kinds }
    }
}

#[derive(Serialize)]
pub struct HealthResponse<'a> {
    pub status: &'a str,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub max_amount_required: String,
    pub resource: Option<String>,
    pub description: Option<String>,
    pub mime_type: Option<String>,
    pub output_schema: Option<Value>,
    pub pay_to: String,
    pub max_timeout_seconds: Option<u64>,
    pub asset: String,
    pub extra: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateTabRequest {
    #[serde(alias = "userAddress")]
    pub user_address: String,
    #[serde(alias = "recipientAddress")]
    pub recipient_address: String,
    #[serde(alias = "erc20Token")]
    #[serde(default)]
    pub erc20_token: Option<String>,
    #[serde(alias = "ttlSeconds")]
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTabResponse {
    pub tab_id: String,
    pub user_address: String,
    pub recipient_address: String,
    pub asset_address: String,
    pub start_timestamp: i64,
    pub ttl_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifyRequest {
    #[serde(rename = "x402Version")]
    pub x402_version: u8,
    #[serde(rename = "paymentHeader")]
    pub payment_header: String,
    #[serde(rename = "paymentRequirements")]
    pub payment_requirements: PaymentRequirements,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettleRequest {
    #[serde(rename = "x402Version")]
    pub x402_version: u8,
    #[serde(rename = "paymentHeader")]
    pub payment_header: String,
    #[serde(rename = "paymentRequirements")]
    pub payment_requirements: PaymentRequirements,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub is_valid: bool,
    pub invalid_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertificateResponse>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CertificateResponse {
    pub claims: String,
    pub signature: String,
}

impl From<BLSCert> for CertificateResponse {
    fn from(cert: BLSCert) -> Self {
        Self {
            claims: cert.claims,
            signature: cert.signature,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleResponse {
    pub success: bool,
    pub error: Option<String>,
    pub tx_hash: Option<String>,
    pub network_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertificateResponse>,
}

impl SettleResponse {
    pub fn invalid(reason: String, network: &str) -> Self {
        Self {
            success: false,
            error: Some(reason),
            tx_hash: None,
            network_id: Some(network.to_string()),
            certificate: None,
        }
    }

    pub fn from_exact(
        success: bool,
        error: Option<String>,
        tx_hash: Option<String>,
        network: String,
    ) -> Self {
        Self {
            success,
            error,
            tx_hash,
            network_id: Some(network),
            certificate: None,
        }
    }

    pub fn four_mica_success(network: &str, certificate: CertificateResponse) -> Self {
        Self {
            success: true,
            error: None,
            tx_hash: None,
            network_id: Some(network.to_string()),
            certificate: Some(certificate),
        }
    }
}

#[derive(Debug, Deserialize)]
struct PaymentEnvelope {
    #[serde(rename = "x402Version")]
    x402_version: u8,
    scheme: String,
    network: String,
    payload: FourMicaPaymentPayload,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FourMicaPaymentPayload {
    claims: PaymentGuaranteeRequestClaims,
    signature: String,
    #[serde(default)]
    signing_scheme: Option<String>,
}

struct PreparedClaim {
    claims: PaymentGuaranteeRequestClaims,
    signature: String,
    scheme: SigningScheme,
}

fn decode_payment_header(header_b64: &str) -> Result<PaymentEnvelope, String> {
    let trimmed = header_b64.trim();
    let decoded = BASE64_STANDARD
        .decode(trimmed)
        .map_err(|err| format!("failed to base64 decode payment header: {err}"))?;
    serde_json::from_slice(&decoded)
        .map_err(|err| format!("failed to decode payment header JSON: {err}"))
}

fn parse_signing_scheme(value: Option<&str>) -> Result<SigningScheme, ValidationError> {
    match value.unwrap_or("eip712").to_ascii_lowercase().as_str() {
        "eip712" => Ok(SigningScheme::Eip712),
        "eip191" => Ok(SigningScheme::Eip191),
        other => Err(ValidationError::InvalidHeader(format!(
            "unsupported signingScheme {other}",
        ))),
    }
}

fn parse_u256(value: &str) -> Result<U256, String> {
    if value.is_empty() {
        return Err("maxAmountRequired cannot be empty".into());
    }
    if let Some(rest) = value.strip_prefix("0x") {
        U256::from_str_radix(rest, 16).map_err(|err| format!("invalid hex amount: {err}"))
    } else {
        U256::from_str_radix(value, 10).map_err(|err| format!("invalid decimal amount: {err}"))
    }
}

fn parse_u256_str(value: &str) -> Result<U256, String> {
    parse_u256(value)
}

fn parse_address(value: &str) -> Result<Address, String> {
    Address::from_str(value).map_err(|err| err.to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequirementsExtra {
    #[serde(rename = "tabId")]
    tab_id: String,
    #[serde(rename = "userAddress")]
    user_address: String,
}

fn parse_extra(extra: &Option<Value>) -> Result<RequirementsExtra, ValidationError> {
    match extra {
        Some(value) => serde_json::from_value::<RequirementsExtra>(value.clone()).map_err(|err| {
            ValidationError::InvalidRequirements(format!("invalid requirements.extra: {err}"))
        }),
        None => Err(ValidationError::InvalidRequirements(
            "paymentRequirements.extra must include tabId and userAddress".into(),
        )),
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
}

#[derive(Debug, Error)]
pub enum TabError {
    #[error("4Mica tab provisioning is disabled")]
    Unsupported,
    #[error("{0}")]
    Invalid(String),
    #[error("{message}")]
    Upstream { status: StatusCode, message: String },
}

#[derive(Debug, Serialize)]
struct CoreCreateTabRequest {
    user_address: String,
    recipient_address: String,
    erc20_token: Option<String>,
    ttl: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct CoreCreateTabResponse {
    id: U256,
}
