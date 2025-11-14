mod config;
mod exact;
mod issuer;
mod server;
mod telemetry;
mod verifier;

use std::sync::Arc;

use anyhow::Context;

use crate::config::{ServiceConfig, load_public_params};
use crate::exact::X402ExactService;
use crate::issuer::{GuaranteeIssuer, LiveGuaranteeIssuer};
use crate::server::state::{AppState, CoreTabService, ExactService, FourMicaHandler, TabService};
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

    let api_base_url = public_params.api_base_url.clone();
    let verifier = Arc::new(CertificateVerifier::new(
        public_params.operator_public_key,
        public_params.guarantee_domain,
    ));
    let issuer = Arc::new(
        LiveGuaranteeIssuer::try_new(api_base_url.clone())
            .context("failed to initialize 4Mica guarantee issuer")?,
    );
    let tab_service: Option<Arc<dyn TabService>> =
        Some(Arc::new(CoreTabService::new(api_base_url.clone())) as Arc<dyn TabService>);
    let four_mica_handler = FourMicaHandler::new(
        service_cfg.scheme.clone(),
        service_cfg.network.clone(),
        verifier.clone() as Arc<dyn CertificateValidator>,
        issuer.clone() as Arc<dyn GuaranteeIssuer>,
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

    let state = AppState::new(Some(four_mica_handler), tab_service, exact_service);

    server::run(service_cfg, state).await
}
