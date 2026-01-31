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
use rust_sdk_4mica::{Address, BLSCert, U256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tracing::error;

use crate::issuer::{GuaranteeIssuer, parse_error_message};
use crate::verifier::CertificateValidator;

const SUPPORTED_VERSIONS: [u8; 2] = [1, 2];

pub(super) type SharedState = Arc<AppState>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X402PaymentPayloadV1 {
    x402_version: u64,
    scheme: String,
    network: String,
    payload: PaymentGuaranteeRequestCompat,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X402PaymentPayloadV2 {
    x402_version: u8,
    accepted: PaymentRequirements,
    payload: PaymentGuaranteeRequestCompat,
}

#[derive(Debug, Deserialize)]
struct PaymentGuaranteeRequestCompat {
    claims: PaymentGuaranteeRequestClaimsCompat,
    signature: String,
    scheme: rpc::SigningScheme,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", tag = "version")]
enum PaymentGuaranteeRequestClaimsCompat {
    V1(PaymentGuaranteeRequestClaimsV1Compat),
}

#[derive(Debug, Deserialize)]
struct PaymentGuaranteeRequestClaimsV1Compat {
    user_address: String,
    recipient_address: String,
    tab_id: U256,
    #[serde(alias = "reqId")]
    req_id: U256,
    amount: U256,
    asset_address: String,
    timestamp: u64,
}

impl PaymentGuaranteeRequestCompat {
    fn into_request(self) -> PaymentGuaranteeRequest {
        let claims = match self.claims {
            PaymentGuaranteeRequestClaimsCompat::V1(claims) => {
                PaymentGuaranteeRequestClaims::V1(PaymentGuaranteeRequestClaimsV1 {
                    user_address: claims.user_address,
                    recipient_address: claims.recipient_address,
                    tab_id: claims.tab_id,
                    req_id: claims.req_id,
                    amount: claims.amount,
                    asset_address: claims.asset_address,
                    timestamp: claims.timestamp,
                })
            }
        };
        PaymentGuaranteeRequest::new(claims, self.signature, self.scheme)
    }
}

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
        let payload = self.extract_payload(request, x402_version)?;
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
        let payload = self.extract_payload_for_settle(request, x402_version)?;
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

    fn extract_payload(
        &self,
        request: &VerifyRequest,
        x402_version: u8,
    ) -> Result<PaymentGuaranteeRequest, ValidationError> {
        self.extract_payload_parts(
            x402_version,
            &request.payment_payload,
            &request.payment_requirements,
        )
    }

    fn extract_payload_for_settle(
        &self,
        request: &SettleRequest,
        x402_version: u8,
    ) -> Result<PaymentGuaranteeRequest, ValidationError> {
        self.extract_payload_parts(
            x402_version,
            &request.payment_payload,
            &request.payment_requirements,
        )
    }

    fn extract_payload_parts(
        &self,
        x402_version: u8,
        payment_payload: &Value,
        reqs: &PaymentRequirements,
    ) -> Result<PaymentGuaranteeRequest, ValidationError> {
        self.decode_payment_payload(payment_payload, reqs, x402_version)
    }

    fn decode_payment_payload(
        &self,
        payload: &Value,
        reqs: &PaymentRequirements,
        version: u8,
    ) -> Result<PaymentGuaranteeRequest, ValidationError> {
        match version {
            1 => {
                let envelope: X402PaymentPayloadV1 = serde_json::from_value(payload.clone())
                    .map_err(|err| {
                        ValidationError::InvalidHeader(format!(
                            "failed to deserialize v1 payment payload: {err}"
                        ))
                    })?;

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
                if envelope.x402_version as u8 != version {
                    return Err(ValidationError::InvalidHeader(format!(
                        "payment payload x402Version {} does not match request x402Version {}",
                        envelope.x402_version, version
                    )));
                }

                let signature = envelope.payload.signature.trim();
                if signature.is_empty() {
                    return Err(ValidationError::InvalidHeader(
                        "signature cannot be empty".into(),
                    ));
                }

                Ok(envelope.payload.into_request())
            }
            2 => {
                let envelope: X402PaymentPayloadV2 = serde_json::from_value(payload.clone())
                    .map_err(|err| {
                        ValidationError::InvalidHeader(format!(
                            "failed to deserialize v2 payment payload: {err}"
                        ))
                    })?;

                if envelope.x402_version != version {
                    return Err(ValidationError::InvalidHeader(format!(
                        "payment payload x402Version {} does not match request x402Version {}",
                        envelope.x402_version, version
                    )));
                }
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
            _ => Err(ValidationError::UnsupportedVersion(version)),
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

#[async_trait]
pub(crate) trait ExactService: Send + Sync {
    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, ValidationError>;
    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, ValidationError>;
    async fn supported(&self) -> Result<Vec<SupportedKind>, ValidationError>;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedKind {
    pub scheme: String,
    pub network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x402_version: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedResponse {
    pub kinds: Vec<SupportedKind>,
    pub extensions: Vec<String>,
    pub signers: HashMap<String, Vec<String>>,
}

impl SupportedResponse {
    pub fn new(kinds: Vec<SupportedKind>) -> Self {
        Self {
            kinds,
            extensions: Vec::new(),
            signers: HashMap::new(),
        }
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
    #[serde(default)]
    pub max_amount_required: String,
    #[serde(default)]
    pub amount: Option<String>,
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
    #[serde(alias = "erc20Token", alias = "assetAddress")]
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
    pub next_req_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifyRequest {
    #[serde(rename = "x402Version")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x402_version: Option<u8>,
    #[serde(rename = "paymentPayload")]
    pub payment_payload: Value,
    #[serde(rename = "paymentRequirements")]
    pub payment_requirements: PaymentRequirements,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettleRequest {
    #[serde(rename = "x402Version")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x402_version: Option<u8>,
    #[serde(rename = "paymentPayload")]
    pub payment_payload: Value,
    #[serde(rename = "paymentRequirements")]
    pub payment_requirements: PaymentRequirements,
}

impl VerifyRequest {
    pub(crate) fn resolved_x402_version(&self) -> Result<u8, ValidationError> {
        resolve_x402_version(self.x402_version, &self.payment_payload)
    }
}

impl SettleRequest {
    pub(crate) fn resolved_x402_version(&self) -> Result<u8, ValidationError> {
        resolve_x402_version(self.x402_version, &self.payment_payload)
    }
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

fn extract_payload_x402_version(payload: &Value) -> Option<u8> {
    match payload.get("x402Version")? {
        Value::Number(value) => value.as_u64().and_then(|raw| u8::try_from(raw).ok()),
        Value::String(value) => value.parse::<u8>().ok(),
        _ => None,
    }
}

fn resolve_x402_version(
    request_version: Option<u8>,
    payment_payload: &Value,
) -> Result<u8, ValidationError> {
    let payload_version = extract_payload_x402_version(payment_payload);
    match (request_version, payload_version) {
        (Some(request_version), Some(payload_version)) if request_version != payload_version => {
            Err(ValidationError::InvalidHeader(format!(
                "x402Version {} does not match paymentPayload x402Version {}",
                request_version, payload_version
            )))
        }
        (Some(request_version), _) => Ok(request_version),
        (None, Some(payload_version)) => Ok(payload_version),
        (None, None) => Err(ValidationError::InvalidHeader(
            "x402Version missing from request and paymentPayload".into(),
        )),
    }
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
}

#[derive(Debug, Error)]
pub enum TabError {
    #[error("4mica tab provisioning is disabled")]
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
    #[serde(default)]
    #[serde(alias = "asset_address", alias = "assetAddress")]
    asset_address: Option<String>,
    #[serde(default)]
    erc20_token: Option<String>,
    #[serde(default)]
    #[serde(alias = "nextReqId", alias = "reqId")]
    next_req_id: Option<U256>,
}
