mod config;
mod exact;
mod issuer;
mod request_ids;
mod server;
mod telemetry;
mod verifier;

use std::sync::Arc;

use anyhow::Context;

use crate::config::{ServiceConfig, load_public_params};
use crate::exact::X402ExactService;
use crate::issuer::{GuaranteeIssuer, LiveGuaranteeIssuer};
use crate::request_ids::{LiveRequestIdTracker, RequestIdTracker};
use crate::server::state::{AppState, ExactService, FourMicaHandler};
use crate::verifier::{CertificateValidator, CertificateVerifier};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if dotenvy::from_filename(".env").is_err() {
        dotenvy::dotenv().ok();
    }
    telemetry::init();

    let service_cfg =
        ServiceConfig::from_env().context("failed to load facilitator configuration")?;
    let public_params = load_public_params()
        .await
        .context("failed to load 4Mica public parameters")?;

    let verifier = Arc::new(CertificateVerifier::new(
        public_params.operator_public_key,
        public_params.guarantee_domain,
    ));
    let issuer = Arc::new(
        LiveGuaranteeIssuer::try_new(public_params.api_base_url.clone())
            .context("failed to initialize 4Mica guarantee issuer")?,
    );
    let request_ids = Arc::new(LiveRequestIdTracker::new(
        public_params.api_base_url.clone(),
    ));

    let four_mica_handler = FourMicaHandler::new(
        service_cfg.scheme.clone(),
        service_cfg.network.clone(),
        verifier.clone() as Arc<dyn CertificateValidator>,
        issuer.clone() as Arc<dyn GuaranteeIssuer>,
        request_ids.clone() as Arc<dyn RequestIdTracker>,
    );

    let exact_service: Option<Arc<dyn ExactService>> = match X402ExactService::try_from_env().await
    {
        Ok(Some(service)) => Some(Arc::new(service) as Arc<dyn ExactService>),
        Ok(None) => None,
        Err(err) => {
            tracing::warn!(reason = %err, "exact scheme facilitator disabled");
            None
        }
    };

    let state = AppState::new(Some(four_mica_handler), exact_service);

    server::run(service_cfg, state).await
}
