use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::Json;
use axum::body::to_bytes;
use axum_core::extract::Request;
use axum_core::response::{IntoResponse, Response};
use http::StatusCode;
use log::error;
use sdk_4mica::x402::TabRequestParams;
use tower::Service;
use tower::util::BoxCloneSyncService;
use x402_axum::{X402Middleware, facilitator_client::FacilitatorClient};

use crate::server::config::{self, TabConfig};
use crate::server::facilitator::{OpenTabRequest, TabFacilitatorClient};
use crate::server::model::TabRequestRequirements;

pub trait BuildTabMiddleware {
    fn tab_middleware(&self) -> anyhow::Result<FourMicaTabMiddleware>;
}

#[derive(Clone)]
pub struct FourMicaTabMiddleware {
    facilitator: Arc<TabFacilitatorClient>,
    tab_config: TabConfig,
}

impl BuildTabMiddleware for X402Middleware<Arc<FacilitatorClient>> {
    fn tab_middleware(&self) -> anyhow::Result<FourMicaTabMiddleware> {
        let tab_config = TabConfig::from_env()
            .map_err(|err| anyhow::anyhow!("Failed to load tab config from environment: {err}"))?;
        Ok(FourMicaTabMiddleware {
            tab_config,
            facilitator: Arc::new(TabFacilitatorClient::new(self.facilitator().clone())),
        })
    }
}

impl<S> tower::Layer<S> for FourMicaTabMiddleware
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
{
    type Service = FourMicaTabService;

    fn layer(&self, inner: S) -> Self::Service {
        FourMicaTabService {
            facilitator: self.facilitator.clone(),
            tab_config: self.tab_config.clone(),
            inner: BoxCloneSyncService::new(inner),
        }
    }
}

#[derive(Clone)]
pub struct FourMicaTabService {
    facilitator: Arc<TabFacilitatorClient>,
    tab_config: TabConfig,
    inner: BoxCloneSyncService<Request, Response, Infallible>,
}

impl Service<Request> for FourMicaTabService {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    /// Delegates readiness polling to the wrapped inner service.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let facilitator = self.facilitator.clone();
        let tab_config = self.tab_config.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let tab_endpoint_path = config::extract_path(&tab_config.advertised_endpoint);
            if req.uri().path() != tab_endpoint_path {
                return inner.call(req).await;
            }

            let (_parts, body) = req.into_parts();
            let body_bytes = match to_bytes(body, usize::MAX).await {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(
                        (StatusCode::BAD_REQUEST, "Failed to read request body").into_response()
                    );
                }
            };

            let params = match serde_json::from_slice::<TabRequestParams<TabRequestRequirements>>(
                &body_bytes,
            ) {
                Ok(params) => params,
                Err(err) => {
                    return Ok((StatusCode::BAD_REQUEST, format!("Invalid request: {err}"))
                        .into_response());
                }
            };

            let open_tab_request = OpenTabRequest {
                user_address: params.user_address.clone(),
                recipient_address: params.payment_requirements.pay_to.clone(),
                network: Some(params.payment_requirements.network.clone()),
                erc20_token: Some(params.payment_requirements.asset.clone()),
                ttl_seconds: tab_config.ttl_seconds,
            };

            let tab_response = match facilitator.open_tab(&open_tab_request).await {
                Ok(response) => response,
                Err(err) => {
                    error!("Failed to open tab: {err}");
                    return Ok((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to open tab: {err}"),
                    )
                        .into_response());
                }
            };
            return Ok((StatusCode::OK, Json(tab_response)).into_response());
        })
    }
}
