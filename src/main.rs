mod auth;
mod config;
mod exact;
mod issuer;
mod server;
mod telemetry;
mod verifier;

use std::sync::Arc;

use anyhow::Context;

use crate::auth::AuthSession;
use crate::config::{ServiceConfig, load_public_params};
use crate::exact::ExactService;
use crate::exact::try_from_env as build_exact_service;
use crate::issuer::{GuaranteeIssuer, LiveGuaranteeIssuer};
use crate::server::state::{
    AppState, CoreTabService, FourMicaHandler, NetworkTabService, TabService,
};
use crate::verifier::{CertificateValidator, CertificateVerifier};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if dotenvy::from_filename(".env").is_err() {
        dotenvy::dotenv().ok();
    }
    telemetry::init();

    let service_cfg =
        ServiceConfig::from_env().context("failed to load facilitator configuration")?;
    let mut four_mica_handlers = Vec::new();
    let mut tab_services = Vec::new();
    let mut default_tab_network = None;
    for (idx, network) in service_cfg.networks.iter().enumerate() {
        let auth_session = match &network.auth {
            Some(auth_cfg) => Some(Arc::new(
                AuthSession::try_new(
                    auth_cfg.auth_url.clone(),
                    &auth_cfg.wallet_private_key,
                    auth_cfg.refresh_margin_secs,
                )
                .with_context(|| {
                    format!(
                        "failed to initialize auth session for network {}",
                        network.id
                    )
                })?,
            )),
            None => None,
        };
        if idx == 0 {
            default_tab_network = Some(network.id.clone());
        }

        let public_params = load_public_params(&network.core_api_base_url)
            .await
            .with_context(|| {
                format!(
                    "failed to load 4mica public parameters for network {}",
                    network.id
                )
            })?;

        let verifier = Arc::new(CertificateVerifier::new(
            public_params.operator_public_key,
            public_params.guarantee_domain,
        )) as Arc<dyn CertificateValidator>;
        let issuer = Arc::new(
            LiveGuaranteeIssuer::try_new(network.core_api_base_url.clone(), auth_session.clone())
                .with_context(|| {
                format!(
                    "failed to initialize 4mica guarantee issuer for network {}",
                    network.id
                )
            })?,
        ) as Arc<dyn GuaranteeIssuer>;

        four_mica_handlers.push(FourMicaHandler::new(
            service_cfg.scheme.clone(),
            network.id.clone(),
            verifier,
            issuer,
        ));

        let tab_service = Arc::new(CoreTabService::new(
            network.core_api_base_url.clone(),
            service_cfg.asset_address.clone(),
            auth_session.clone(),
        )) as Arc<dyn TabService>;
        tab_services.push(NetworkTabService {
            network: network.id.clone(),
            service: tab_service,
        });
    }

    let exact_service: Option<Arc<dyn ExactService>> = build_exact_service().await?;

    let state = AppState::new(
        four_mica_handlers,
        tab_services,
        default_tab_network,
        exact_service,
    );

    server::run(service_cfg, state).await
}
