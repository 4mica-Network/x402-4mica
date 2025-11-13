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
        AppState, ExactService, FourMicaHandler, PaymentRequirements, SettleRequest,
        SettleResponse, SharedState, ValidationError, VerifyRequest, VerifyResponse,
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
        payment_header: encoded_header(),
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
        payment_header: encoded_header(),
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
async fn settle_endpoint_returns_certificate() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = SettleRequest {
        x402_version: 1,
        payment_header: encoded_header(),
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
    assert_eq!(payload.network_id.as_deref(), Some("4mica-mainnet"));
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
    assert_eq!(payload["kinds"][0]["scheme"], "4mica-guarantee");
    assert_eq!(payload["kinds"][0]["network"], "4mica-mainnet");
}

#[tokio::test]
async fn supported_includes_exact_when_available() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let handler = FourMicaHandler::new(
        "4mica-guarantee".into(),
        "4mica-mainnet".into(),
        verifier as Arc<dyn CertificateValidator>,
        issuer as Arc<dyn GuaranteeIssuer>,
    );
    let exact = Arc::new(MockExact::new());
    let state = AppState::new(Some(handler), Some(exact.clone() as Arc<dyn ExactService>));
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
    assert_eq!(kinds.len(), 2);
    assert!(kinds.iter().any(|k| k["scheme"] == "4mica-guarantee"));
    assert!(kinds.iter().any(|k| k["scheme"] == "exact"));
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
async fn verify_rejects_invalid_version() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::success());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = VerifyRequest {
        x402_version: 99,
        payment_header: encoded_header(),
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
async fn settle_propagates_issue_errors() {
    let verifier = Arc::new(MockVerifier::success());
    let issuer = Arc::new(MockIssuer::failing());
    let state = test_state(verifier.clone(), issuer.clone());
    let router = build_router(state);

    let request_body = SettleRequest {
        x402_version: 1,
        payment_header: encoded_header(),
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
        payment_header: encoded_header(),
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
        payment_header: encoded_header(),
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
        "4mica-guarantee".into(),
        "4mica-mainnet".into(),
        verifier.clone() as Arc<dyn CertificateValidator>,
        issuer.clone() as Arc<dyn GuaranteeIssuer>,
    );
    Arc::new(AppState::new(Some(handler), None))
}

fn exact_state(exact: Arc<MockExact>) -> SharedState {
    Arc::new(AppState::new(None, Some(exact)))
}

fn sample_requirements() -> PaymentRequirements {
    PaymentRequirements {
        scheme: "4mica-guarantee".into(),
        network: "4mica-mainnet".into(),
        max_amount_required: "1000".into(),
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
            "scheme": "4mica-guarantee",
            "network": "4mica-mainnet",
            "payload": {
                    "claims": {
                        "user_address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "recipient_address": recipient,
                        "tab_id": "0x1",
                        "amount": "10",
                        "asset_address": asset,
                        "timestamp": 1
                    },
                "signature": "0x1111",
                "signingScheme": "eip712"
            }
        })
        .to_string(),
    )
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

    async fn supported(&self) -> Result<Vec<(String, String)>, ValidationError> {
        Ok(vec![("exact".into(), "base".into())])
    }
}

#[tokio::test]
async fn verify_routes_to_exact_service() {
    let exact = Arc::new(MockExact::new());
    let state = exact_state(exact.clone());
    let router = build_router(state);

    let request_body = VerifyRequest {
        x402_version: 1,
        payment_header: BASE64_STANDARD.encode("dummy"),
        payment_requirements: PaymentRequirements {
            scheme: "exact".into(),
            network: "base".into(),
            max_amount_required: "1000".into(),
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
        payment_header: BASE64_STANDARD.encode("dummy"),
        payment_requirements: PaymentRequirements {
            scheme: "exact".into(),
            network: "base".into(),
            max_amount_required: "1000".into(),
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
        _claims: &rust_sdk_4mica::PaymentGuaranteeRequestClaims,
        _signature: &str,
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
