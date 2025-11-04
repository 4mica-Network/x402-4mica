use async_trait::async_trait;
use reqwest::Url;
use rust_sdk_4mica::{BLSCert, PaymentGuaranteeRequestClaims, SigningScheme};
use serde_json::{Value, json};

#[async_trait]
pub trait GuaranteeIssuer: Send + Sync {
    async fn issue(
        &self,
        claims: &PaymentGuaranteeRequestClaims,
        signature: &str,
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

    fn build_request_body(
        &self,
        claims: &PaymentGuaranteeRequestClaims,
        signature: &str,
        scheme: SigningScheme,
    ) -> Result<Value, String> {
        if signature.trim().is_empty() {
            return Err("signature cannot be empty".into());
        }

        let mut claims_value = serde_json::to_value(claims).map_err(|err| err.to_string())?;
        match &mut claims_value {
            Value::Object(map) => {
                map.insert("version".into(), Value::String("v1".into()));
            }
            _ => return Err("claims payload must serialize to an object".into()),
        }

        let scheme_str = match scheme {
            SigningScheme::Eip712 => "eip712",
            SigningScheme::Eip191 => "eip191",
        };

        Ok(json!({
            "claims": claims_value,
            "signature": signature,
            "scheme": scheme_str,
        }))
    }
}

#[async_trait]
impl GuaranteeIssuer for LiveGuaranteeIssuer {
    async fn issue(
        &self,
        claims: &PaymentGuaranteeRequestClaims,
        signature: &str,
        scheme: SigningScheme,
    ) -> Result<BLSCert, String> {
        let body = self.build_request_body(claims, signature, scheme)?;

        let mut url = self.base_url.clone();
        url.set_path("core/guarantees");

        let response = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|err| err.to_string())?;

        let response = response.error_for_status().map_err(|err| err.to_string())?;
        response
            .json::<BLSCert>()
            .await
            .map_err(|err| err.to_string())
    }
}
