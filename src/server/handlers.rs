use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use super::state::{
    HealthResponse, SettleRequest, SettleResponse, SharedState, SupportedResponse, VerifyRequest,
    VerifyResponse,
};

pub(super) fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/supported", get(supported_handler))
        .route("/verify", post(verify_handler))
        .route("/settle", post(settle_handler))
        .route("/health", get(health_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn supported_handler(State(state): State<SharedState>) -> impl IntoResponse {
    let kinds = state.supported().await;
    Json(SupportedResponse::new(kinds))
}

async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse { status: "ok" })
}

async fn verify_handler(
    State(state): State<SharedState>,
    Json(request): Json<VerifyRequest>,
) -> impl IntoResponse {
    if let Err(err) = state.validate_version(request.x402_version) {
        warn!(reason = %err, "verify request rejected");
        return Json(VerifyResponse {
            is_valid: false,
            invalid_reason: Some(err.to_string()),
            certificate: None,
        });
    }

    match state.verify(&request).await {
        Ok(response) => Json(response),
        Err(err) => {
            warn!(reason = %err, "payment validation failed");
            Json(VerifyResponse {
                is_valid: false,
                invalid_reason: Some(err.to_string()),
                certificate: None,
            })
        }
    }
}

async fn settle_handler(
    State(state): State<SharedState>,
    Json(request): Json<SettleRequest>,
) -> impl IntoResponse {
    if let Err(err) = state.validate_version(request.x402_version) {
        warn!(reason = %err, "settle request rejected");
        return Json(SettleResponse::invalid(err.to_string(), state.network()));
    }

    match state.settle(&request).await {
        Ok(response) => {
            if response.tx_hash.is_some() {
                info!(
                    tx_hash = response.tx_hash.as_deref().unwrap(),
                    "settlement forwarded to on-chain handler"
                );
            } else {
                info!("settlement acknowledged (deferred)");
            }
            Json(response)
        }
        Err(err) => {
            warn!(reason = %err, "settlement validation failed");
            Json(SettleResponse::invalid(err.to_string(), state.network()))
        }
    }
}
