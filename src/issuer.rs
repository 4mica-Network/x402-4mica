use async_trait::async_trait;
use reqwest::Url;
use rpc::{PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims, SigningScheme};
use rust_sdk_4mica::BLSCert;
use tracing::debug;

#[async_trait]
pub trait GuaranteeIssuer: Send + Sync {
    async fn issue(
        &self,
        claims: PaymentGuaranteeRequestClaims,
        signature: String,
        scheme: SigningScheme,
    ) -> Result<BLSCert, String>;
}

pub struct LiveGuaranteeIssuer {
    client: reqwest::Client,
    base_url: Url,
}

impl LiveGuaranteeIssuer {
    pub fn try_new(base_url: Url) -> anyhow::Result<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
            base_url,
        })
    }
}

#[async_trait]
impl GuaranteeIssuer for LiveGuaranteeIssuer {
    async fn issue(
        &self,
        claims: PaymentGuaranteeRequestClaims,
        signature: String,
        scheme: SigningScheme,
    ) -> Result<BLSCert, String> {
        let body = PaymentGuaranteeRequest::new(claims, signature, scheme);

        let mut url = self.base_url.clone();
        url.set_path("core/guarantees");

        let payload = serde_json::to_string(&body).unwrap_or_else(|_| "<serialize_failed>".into());
        debug!(url = %url, payload = %payload, "Sending core guarantee request");

        let response = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|err| err.to_string())?;

        let status = response.status();
        let bytes = response.bytes().await.map_err(|err| err.to_string())?;
        debug!(
            status = %status,
            body = %String::from_utf8_lossy(&bytes),
            "Core guarantee response"
        );

        if !status.is_success() {
            let message = parse_error_message(&bytes);
            return Err(format!(
                "core guarantee request failed ({status}): {message}"
            ));
        }

        serde_json::from_slice::<BLSCert>(&bytes)
            .map_err(|err| format!("failed to decode guarantee response: {err}"))
    }
}

pub(crate) fn parse_error_message(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "unknown error".to_string();
    }

    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
        if let Some(msg) = value.get("error").and_then(|v| v.as_str()) {
            return msg.to_string();
        }
        if let Some(msg) = value.get("message").and_then(|v| v.as_str()) {
            return msg.to_string();
        }
    }

    match std::str::from_utf8(bytes) {
        Ok(text) if !text.trim().is_empty() => text.trim().to_string(),
        _ => "unknown error".to_string(),
    }
}
