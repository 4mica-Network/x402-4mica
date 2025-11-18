use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Serialize;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use super::state::{
    CreateTabRequest, HealthResponse, SettleRequest, SettleResponse, SharedState,
    SupportedResponse, TabError, VerifyRequest, VerifyResponse,
};

pub(super) fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/supported", get(supported_handler))
        .route("/verify", post(verify_handler))
        .route("/settle", post(settle_handler))
        .route("/tabs", post(create_tab_handler))
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
            if let Some(tx_hash) = response.tx_hash.as_deref() {
                info!(tx_hash, "settlement forwarded to on-chain handler");
            } else if response.certificate.is_some() {
                info!("settlement completed with 4Mica guarantee");
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

async fn create_tab_handler(
    State(state): State<SharedState>,
    Json(request): Json<CreateTabRequest>,
) -> impl IntoResponse {
    match state.create_tab(&request).await {
        Ok(response) => Json(response).into_response(),
        Err(err) => {
            let status = match &err {
                TabError::Unsupported => StatusCode::NOT_IMPLEMENTED,
                TabError::Invalid(_) => StatusCode::BAD_REQUEST,
                TabError::Upstream { status, .. } => *status,
            };
            let body = ErrorResponse {
                error: err.to_string(),
            };
            (status, Json(body)).into_response()
        }
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}
