use std::sync::Arc;

use http::StatusCode;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use x402_axum::facilitator_client::{FacilitatorClient, FacilitatorClientError};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenTabRequest {
    pub user_address: String,
    pub recipient_address: String,
    pub network: Option<String>,
    pub erc20_token: Option<String>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenTabResponse {
    pub tab_id: String,
    pub user_address: String,
    pub recipient_address: String,
    pub asset_address: String,
    pub start_timestamp: i64,
    pub ttl_seconds: i64,
    pub next_req_id: Option<String>,
}

pub struct TabFacilitatorClient {
    base: Arc<FacilitatorClient>,
    client: Client,
}

impl TabFacilitatorClient {
    pub fn new(base: Arc<FacilitatorClient>) -> Self {
        Self {
            base,
            client: Client::new(),
        }
    }

    /// Sends a `POST /tabs` request to the facilitator.
    pub async fn open_tab(
        &self,
        request: &OpenTabRequest,
    ) -> Result<OpenTabResponse, FacilitatorClientError> {
        let tabs_url =
            self.base
                .base_url()
                .join("./tabs")
                .map_err(|e| FacilitatorClientError::UrlParse {
                    context: "Failed to construct ./tabs URL",
                    source: e,
                })?;

        let mut req = self.client.post(tabs_url).json(request);
        for (key, value) in self.base.headers().iter() {
            req = req.header(key, value);
        }
        if let Some(timeout) = *self.base.timeout() {
            req = req.timeout(timeout);
        }

        let http_response = req.send().await.map_err(|e| FacilitatorClientError::Http {
            context: "POST /tabs",
            source: e,
        })?;

        if http_response.status() == StatusCode::OK {
            http_response.json::<OpenTabResponse>().await.map_err(|e| {
                FacilitatorClientError::JsonDeserialization {
                    context: "POST /tabs",
                    source: e,
                }
            })
        } else {
            let status = http_response.status();
            let body = http_response.text().await.map_err(|e| {
                FacilitatorClientError::ResponseBodyRead {
                    context: "POST /tabs",
                    source: e,
                }
            })?;
            Err(FacilitatorClientError::HttpStatus {
                context: "POST /tabs",
                status,
                body,
            })
        }
    }
}
