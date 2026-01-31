use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rust_sdk_4mica::{Address, BLSCert, PaymentGuaranteeClaims, U256};
use serde::Serialize;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::issuer::GuaranteeIssuer;
use crate::verifier::CertificateValidator;

use super::{
    handlers::build_router,
    state::{
        AppState, CreateTabRequest, CreateTabResponse, ExactService, FourMicaHandler,
        PaymentRequirements, SettleRequest, SettleResponse, SharedState, SupportedKind, TabError,
        TabService, ValidationError, VerifyRequest, VerifyResponse,
    },
};

#[tokio::test]
async fn verify_endpoint_accepts_valid_payload() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = VerifyRequest {
        x402_version: 1,
        payment_header: Some(encoded_header()),
        payment_payload: None,
        payment_requirements: sample_requirements(),
    };

    let response = router
        .oneshot(post_json("/verify", &request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(payload.is_valid);
    assert!(payload.certificate.is_none());
    assert_eq!(verifier.verify_calls(), 0);
    assert_eq!(issuer.issue_calls(), 0);
}

#[tokio::test]
async fn verify_accepts_duplicate_payloads() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = VerifyRequest {
        x402_version: 1,
        payment_header: Some(encoded_header()),
        payment_payload: None,
        payment_requirements: sample_requirements(),
    };

    // First verification performs only preflight validation.
    let response = router
        .clone()
        .oneshot(post_json("/verify", &request_body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(payload.is_valid);
    assert!(payload.certificate.is_none());

    // Second verification with the same payload succeeds without calling downstream services.
    let response = router
        .oneshot(post_json("/verify", &request_body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(payload.is_valid);
    assert!(payload.certificate.is_none());
    assert_eq!(issuer.issue_calls(), 0);
}

#[tokio::test]
async fn verify_endpoint_accepts_v2_payload() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = VerifyRequest {
        x402_version: 2,
        payment_header: None,
        payment_payload: Some(payment_payload_v2("10")),
        payment_requirements: sample_requirements_v2("10"),
    };

    let response = router
        .oneshot(post_json("/verify", &request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(payload.is_valid);
    assert!(payload.certificate.is_none());
    assert_eq!(verifier.verify_calls(), 0);
    assert_eq!(issuer.issue_calls(), 0);
}

#[tokio::test]
async fn settle_endpoint_returns_certificate() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = SettleRequest {
        x402_version: 1,
        payment_header: Some(encoded_header()),
        payment_payload: None,
        payment_requirements: sample_requirements(),
    };

    let response = router
        .oneshot(post_json("/settle", &request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: SettleResponse = serde_json::from_slice(&body).unwrap();
    assert!(payload.success);
    assert!(payload.certificate.is_some());
    assert!(payload.tx_hash.is_none());
    assert_eq!(payload.network_id.as_deref(), Some("sepolia-mainnet"));
    assert_eq!(verifier.verify_calls(), 1);
    assert_eq!(issuer.issue_calls(), 1);
}

#[tokio::test]
async fn settle_endpoint_accepts_v2_payload() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = SettleRequest {
        x402_version: 2,
        payment_header: None,
        payment_payload: Some(payment_payload_v2("10")),
        payment_requirements: sample_requirements_v2("10"),
    };

    let response = router
        .oneshot(post_json("/settle", &request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: SettleResponse = serde_json::from_slice(&body).unwrap();
    assert!(payload.success);
    assert!(payload.certificate.is_some());
    assert!(payload.tx_hash.is_none());
    assert_eq!(payload.network_id.as_deref(), Some("sepolia-mainnet"));
    assert_eq!(verifier.verify_calls(), 1);
    assert_eq!(issuer.issue_calls(), 1);
}

#[tokio::test]
async fn supported_endpoint_returns_configured_kind() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier, issuer);
    let router = build_router(state);

    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/supported")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    let kinds = payload["kinds"].as_array().expect("kinds array");
    assert!(
        kinds
            .iter()
            .any(|k| k["scheme"] == "4mica-credit" && k["network"] == "sepolia-mainnet")
    );
}

#[tokio::test]
async fn supported_includes_exact_when_available() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let handler = FourMicaHandler::new(
        "4mica-credit".into(),
        "sepolia-mainnet".into(),
        verifier as Arc<dyn CertificateValidator>,
        issuer as Arc<dyn GuaranteeIssuer>,
    );
    let exact = Arc::new(MockExact::new());
    let state = AppState::new(
        vec![handler],
        None,
        Some(exact.clone() as Arc<dyn ExactService>),
    );
    let router = build_router(Arc::new(state));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/supported")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    let kinds = payload["kinds"].as_array().expect("kinds array");
    assert_eq!(kinds.len(), 3);
    assert!(kinds.iter().any(|k| k["scheme"] == "4mica-credit"));
    assert!(kinds.iter().any(|k| k["scheme"] == "exact"));
}

#[tokio::test]
async fn supported_includes_v2_kind() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier, issuer);
    let router = build_router(state);

    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/supported")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    let kinds = payload["kinds"].as_array().expect("kinds array");
    assert!(kinds.iter().any(|k| {
        k["scheme"] == "4mica-credit" && k["network"] == "sepolia-mainnet" && k["x402Version"] == 2
    }));
}

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier, issuer);
    let router = build_router(state);

    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["status"], "ok");
}

#[tokio::test]
async fn tabs_endpoint_returns_response_from_service() {
    let tab_response = CreateTabResponse {
        tab_id: "0x1".into(),
        user_address: "0xabc".into(),
        recipient_address: "0xdef".into(),
        asset_address: "0xeee".into(),
        start_timestamp: 123,
        ttl_seconds: 60,
        next_req_id: "0x0".into(),
    };
    let service = Arc::new(MockTabService::success(tab_response.clone()));
    let state = Arc::new(AppState::new(
        Vec::new(),
        Some(service as Arc<dyn TabService>),
        None,
    ));
    let router = build_router(state);

    let request = CreateTabRequest {
        user_address: "0xabc".into(),
        recipient_address: "0xdef".into(),
        erc20_token: Some("0xeee".into()),
        ttl_seconds: Some(60),
    };

    let response = router.oneshot(post_json("/tabs", &request)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: CreateTabResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload.tab_id, "0x1");
    assert_eq!(payload.start_timestamp, 123);
    assert_eq!(payload.next_req_id, "0x0");
}

#[tokio::test]
async fn tabs_endpoint_returns_not_implemented_when_disabled() {
    let state = Arc::new(AppState::new(Vec::new(), None, None));
    let router = build_router(state);

    let request = CreateTabRequest {
        user_address: "0xabc".into(),
        recipient_address: "0xdef".into(),
        erc20_token: Some("0xeee".into()),
        ttl_seconds: None,
    };

    let response = router.oneshot(post_json("/tabs", &request)).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        payload["error"]
            .as_str()
            .unwrap()
            .contains("tab provisioning")
    );
}

#[tokio::test]
async fn tabs_endpoint_propagates_upstream_errors() {
    let service = Arc::new(MockTabService::failing(TabError::Upstream {
        status: StatusCode::BAD_REQUEST,
        message: "user not registered".into(),
    }));
    let state = Arc::new(AppState::new(
        Vec::new(),
        Some(service as Arc<dyn TabService>),
        None,
    ));
    let router = build_router(state);

    let request = CreateTabRequest {
        user_address: "0xabc".into(),
        recipient_address: "0xdef".into(),
        erc20_token: Some("0xeee".into()),
        ttl_seconds: Some(60),
    };

    let response = router.oneshot(post_json("/tabs", &request)).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        payload["error"]
            .as_str()
            .unwrap()
            .contains("user not registered")
    );
}

#[tokio::test]
async fn verify_rejects_invalid_version() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = VerifyRequest {
        x402_version: 99,
        payment_header: Some(encoded_header()),
        payment_payload: None,
        payment_requirements: sample_requirements(),
    };

    let response = router
        .oneshot(post_json("/verify", &request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(!payload.is_valid);
    let reason = payload.invalid_reason.expect("reason");
    assert!(reason.contains("unsupported x402Version"));
    assert_eq!(verifier.verify_calls(), 0);
    assert_eq!(issuer.issue_calls(), 0);
}

#[tokio::test]
async fn verify_rejects_mismatched_amount() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let mut requirements = sample_requirements();
    requirements.max_amount_required = "11".into();

    let request_body = VerifyRequest {
        x402_version: 1,
        payment_header: Some(encoded_header()),
        payment_payload: None,
        payment_requirements: requirements,
    };

    let response = router
        .oneshot(post_json("/verify", &request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(!payload.is_valid);
    let reason = payload.invalid_reason.expect("reason");
    assert!(reason.contains("claim amount"));
    assert_eq!(verifier.verify_calls(), 0);
    assert_eq!(issuer.issue_calls(), 0);
}

#[tokio::test]
async fn verify_rejects_v2_mismatched_amount() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = VerifyRequest {
        x402_version: 2,
        payment_header: None,
        payment_payload: Some(payment_payload_v2("10")),
        payment_requirements: sample_requirements_v2("11"),
    };

    let response = router
        .oneshot(post_json("/verify", &request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(!payload.is_valid);
    let reason = payload.invalid_reason.expect("reason");
    assert!(reason.contains("claim amount"));
    assert_eq!(verifier.verify_calls(), 0);
    assert_eq!(issuer.issue_calls(), 0);
}

#[tokio::test]
async fn settle_propagates_issue_errors() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::failing());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = SettleRequest {
        x402_version: 1,
        payment_header: Some(encoded_header()),
        payment_payload: None,
        payment_requirements: sample_requirements(),
    };

    let response = router
        .oneshot(post_json("/settle", &request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["success"], false);
    assert!(payload["error"].as_str().unwrap().contains("issue failure"));
    assert_eq!(verifier.verify_calls(), 0);
    assert_eq!(issuer.issue_calls(), 1);
}

#[tokio::test]
async fn settle_propagates_certificate_errors() {
    let verifier = Arc::new(MockVerifier::failing());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = SettleRequest {
        x402_version: 1,
        payment_header: Some(encoded_header()),
        payment_payload: None,
        payment_requirements: sample_requirements(),
    };

    let response = router
        .oneshot(post_json("/settle", &request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["success"], false);
    assert_eq!(payload["error"].as_str(), Some("verify failure"));
    assert_eq!(verifier.verify_calls(), 1);
    assert_eq!(issuer.issue_calls(), 1);
}

#[tokio::test]
async fn settle_rejects_invalid_version() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = SettleRequest {
        x402_version: 99,
        payment_header: Some(encoded_header()),
        payment_payload: None,
        payment_requirements: sample_requirements(),
    };

    let response = router
        .oneshot(post_json("/settle", &request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["success"], false);
    assert!(
        payload["error"]
            .as_str()
            .unwrap()
            .contains("unsupported x402Version")
    );
    assert!(payload["certificate"].is_null());
    assert_eq!(verifier.verify_calls(), 0);
    assert_eq!(issuer.issue_calls(), 0);
}

fn test_state(verifier: Arc<MockVerifier>, issuer: Arc<MockIssuer>) -> SharedState {
    let handler = FourMicaHandler::new(
        "4mica-credit".into(),
        "sepolia-mainnet".into(),
        verifier.clone() as Arc<dyn CertificateValidator>,
        issuer.clone() as Arc<dyn GuaranteeIssuer>,
    );
    Arc::new(AppState::new(vec![handler], None, None))
}

fn exact_state(exact: Arc<MockExact>) -> SharedState {
    let exact_service: Arc<dyn ExactService> = exact;
    Arc::new(AppState::new(Vec::new(), None, Some(exact_service)))
}

fn sample_requirements() -> PaymentRequirements {
    PaymentRequirements {
        scheme: "4mica-credit".into(),
        network: "sepolia-mainnet".into(),
        max_amount_required: "10".into(),
        amount: None,
        resource: None,
        description: None,
        mime_type: None,
        output_schema: None,
        pay_to: format!("{:#x}", recipient_address()),
        max_timeout_seconds: None,
        asset: format!("{:#x}", asset_address()),
        extra: Some(json!({
            "tabId": "0x1",
            "userAddress": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        })),
    }
}

fn sample_requirements_v2(amount: &str) -> PaymentRequirements {
    PaymentRequirements {
        scheme: "4mica-credit".into(),
        network: "sepolia-mainnet".into(),
        max_amount_required: "".into(),
        amount: Some(amount.into()),
        resource: None,
        description: None,
        mime_type: None,
        output_schema: None,
        pay_to: format!("{:#x}", recipient_address()),
        max_timeout_seconds: None,
        asset: format!("{:#x}", asset_address()),
        extra: Some(json!({
            "tabId": "0x1",
            "userAddress": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        })),
    }
}

fn encoded_header() -> String {
    let recipient = format!("{:#x}", recipient_address());
    let asset = format!("{:#x}", asset_address());
    BASE64_STANDARD.encode(
        json!({
            "x402Version": 1,
            "scheme": "4mica-credit",
            "network": "sepolia-mainnet",
            "payload": {
                    "claims": {
                        "version": "v1",
                        "user_address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "recipient_address": recipient,
                        "tab_id": "0x1",
                        "req_id": "0x0",
                        "amount": "10",
                        "asset_address": asset,
                        "timestamp": 1
                    },
                "signature": "0x1111",
                "scheme": "eip712"
            }
        })
        .to_string(),
    )
}

fn payment_payload_v2(amount: &str) -> Value {
    let recipient = format!("{:#x}", recipient_address());
    let asset = format!("{:#x}", asset_address());
    json!({
        "x402Version": 2,
        "accepted": {
            "scheme": "4mica-credit",
            "network": "sepolia-mainnet",
            "amount": amount,
            "payTo": recipient,
            "asset": asset
        },
        "payload": {
            "claims": {
                "version": "v1",
                "user_address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "recipient_address": recipient,
                "tab_id": "0x1",
                "req_id": "0x0",
                "amount": amount,
                "asset_address": asset,
                "timestamp": 1
            },
            "signature": "0x1111",
            "scheme": "eip712"
        }
    })
}

fn post_json<T: Serialize>(uri: &str, payload: &T) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(payload).unwrap()))
        .unwrap()
}

fn recipient_address() -> Address {
    Address::from_slice(&[0x11; 20])
}

fn asset_address() -> Address {
    Address::from_slice(&[0x22; 20])
}

fn sample_claims() -> PaymentGuaranteeClaims {
    PaymentGuaranteeClaims {
        domain: [0u8; 32],
        user_address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        recipient_address: format!("{:#x}", recipient_address()),
        tab_id: U256::from(1),
        req_id: U256::ZERO,
        amount: U256::from(10),
        total_amount: U256::from(10),
        asset_address: format!("{:#x}", asset_address()),
        timestamp: 1,
        version: 1,
    }
}

struct MockExact {
    verify_calls: AtomicUsize,
    settle_calls: AtomicUsize,
}

impl MockExact {
    fn new() -> Self {
        Self {
            verify_calls: AtomicUsize::new(0),
            settle_calls: AtomicUsize::new(0),
        }
    }

    fn verify_calls(&self) -> usize {
        self.verify_calls.load(Ordering::SeqCst)
    }

    fn settle_calls(&self) -> usize {
        self.settle_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ExactService for MockExact {
    async fn verify(&self, _: &VerifyRequest) -> Result<VerifyResponse, ValidationError> {
        self.verify_calls.fetch_add(1, Ordering::SeqCst);
        Ok(VerifyResponse {
            is_valid: true,
            invalid_reason: None,
            certificate: None,
        })
    }

    async fn settle(&self, _: &SettleRequest) -> Result<SettleResponse, ValidationError> {
        self.settle_calls.fetch_add(1, Ordering::SeqCst);
        Ok(SettleResponse::from_exact(
            true,
            None,
            Some("0xdeadbeef".into()),
            "base".into(),
        ))
    }

    async fn supported(&self) -> Result<Vec<SupportedKind>, ValidationError> {
        Ok(vec![SupportedKind {
            scheme: "exact".into(),
            network: "base".into(),
            x402_version: Some(1),
            extra: None,
        }])
    }
}

struct MockTabService {
    result: Result<CreateTabResponse, TabError>,
    calls: AtomicUsize,
}

impl MockTabService {
    fn success(response: CreateTabResponse) -> Self {
        Self {
            result: Ok(response),
            calls: AtomicUsize::new(0),
        }
    }

    #[allow(dead_code)]
    fn failing(error: TabError) -> Self {
        Self {
            result: Err(error),
            calls: AtomicUsize::new(0),
        }
    }

    #[allow(dead_code)]
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl TabService for MockTabService {
    async fn create_tab(&self, _: &CreateTabRequest) -> Result<CreateTabResponse, TabError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.result {
            Ok(response) => Ok(response.clone()),
            Err(err) => Err(clone_tab_error(err)),
        }
    }
}

fn clone_tab_error(err: &TabError) -> TabError {
    match err {
        TabError::Unsupported => TabError::Unsupported,
        TabError::Invalid(message) => TabError::Invalid(message.clone()),
        TabError::Upstream { status, message } => TabError::Upstream {
            status: *status,
            message: message.clone(),
        },
    }
}

#[tokio::test]
async fn verify_routes_to_exact_service() {
    let exact = Arc::new(MockExact::new());
    let state = exact_state(exact.clone());
    let router = build_router(state);

    let request_body = VerifyRequest {
        x402_version: 1,
        payment_header: Some(BASE64_STANDARD.encode("dummy")),
        payment_payload: None,
        payment_requirements: PaymentRequirements {
            scheme: "exact".into(),
            network: "base".into(),
            max_amount_required: "1000".into(),
            amount: None,
            resource: None,
            description: None,
            mime_type: None,
            output_schema: None,
            pay_to: "0x8288d9C5d18FFB9f78C1B9Ce3F96F8C75d2a29f8".into(),
            max_timeout_seconds: Some(30),
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
            extra: None,
        },
    };

    let response = router
        .oneshot(post_json("/verify", &request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(payload.is_valid);
    assert!(payload.certificate.is_none());
    assert_eq!(exact.verify_calls(), 1);
}

#[tokio::test]
async fn settle_routes_to_exact_service() {
    let exact = Arc::new(MockExact::new());
    let state = exact_state(exact.clone());
    let router = build_router(state);

    let request_body = SettleRequest {
        x402_version: 1,
        payment_header: Some(BASE64_STANDARD.encode("dummy")),
        payment_payload: None,
        payment_requirements: PaymentRequirements {
            scheme: "exact".into(),
            network: "base".into(),
            max_amount_required: "1000".into(),
            amount: None,
            resource: None,
            description: None,
            mime_type: None,
            output_schema: None,
            pay_to: "0x8288d9C5d18FFB9f78C1B9Ce3F96F8C75d2a29f8".into(),
            max_timeout_seconds: Some(30),
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
            extra: None,
        },
    };

    let response = router
        .oneshot(post_json("/settle", &request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["success"], true);
    assert_eq!(payload["txHash"], "0xdeadbeef");
    assert!(payload["certificate"].is_null());
    assert_eq!(exact.settle_calls(), 1);
}

struct MockVerifier {
    claims: PaymentGuaranteeClaims,
    fail: bool,
    verify_calls: AtomicUsize,
}

impl MockVerifier {
    fn success() -> Self {
        Self {
            claims: sample_claims(),
            fail: false,
            verify_calls: AtomicUsize::new(0),
        }
    }

    fn failing() -> Self {
        Self {
            claims: sample_claims(),
            fail: true,
            verify_calls: AtomicUsize::new(0),
        }
    }

    fn verify_calls(&self) -> usize {
        self.verify_calls.load(Ordering::SeqCst)
    }
}

impl CertificateValidator for MockVerifier {
    fn verify_certificate(&self, _cert: &BLSCert) -> Result<PaymentGuaranteeClaims, String> {
        self.verify_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err("verify failure".into())
        } else {
            Ok(self.claims.clone())
        }
    }
}

struct MockIssuer {
    certificate: BLSCert,
    fail: bool,
    issue_calls: AtomicUsize,
}

impl MockIssuer {
    fn success() -> Self {
        Self {
            certificate: BLSCert {
                claims: "00".into(),
                signature: "11".into(),
            },
            fail: false,
            issue_calls: AtomicUsize::new(0),
        }
    }

    fn failing() -> Self {
        Self {
            certificate: BLSCert {
                claims: "00".into(),
                signature: "11".into(),
            },
            fail: true,
            issue_calls: AtomicUsize::new(0),
        }
    }

    fn issue_calls(&self) -> usize {
        self.issue_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl GuaranteeIssuer for MockIssuer {
    async fn issue(
        &self,
        _claims: rpc::PaymentGuaranteeRequestClaims,
        _signature: String,
        _scheme: rust_sdk_4mica::SigningScheme,
    ) -> Result<BLSCert, String> {
        self.issue_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err("issue failure".into())
        } else {
            Ok(self.certificate.clone())
        }
    }
}
