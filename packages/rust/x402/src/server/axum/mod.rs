use alloy_primitives::ruint::aliases::U256;
use axum_core::{body::Body, response::Response};
use http::{HeaderValue, StatusCode};
use log::warn;
use rpc::PaymentGuaranteeRequest;
use serde_json::json;
use x402_axum::{
    PaygateProtocol,
    paygate::{PaygateError, VerificationError},
};
use x402_chain_eip155::chain::{ChecksummedAddress, Eip155TokenDeployment};
use x402_types::{
    chain::{ChainId, DeployedTokenAmount},
    proto::{
        self,
        v1::X402Version1,
        v2::{ResourceInfo, X402Version2},
    },
    util::Base64Bytes,
};

use crate::{
    networks::FOUR_MICA_SCHEME,
    server::{FourMicaPriceTag, config, model::EnrichedPaymentRequirementsExtra},
};

mod tab;

pub use tab::*;

pub struct V1Eip155FourMica;

impl V1Eip155FourMica {
    pub fn price_tag<A: Into<ChecksummedAddress>>(
        pay_to: A,
        asset: DeployedTokenAmount<U256, Eip155TokenDeployment>,
    ) -> FourMicaPriceTag<1> {
        FourMicaPriceTag::<1> {
            pay_to: pay_to.into().to_string(),
            asset,
        }
    }
}

pub struct V2Eip155FourMica;
impl V2Eip155FourMica {
    pub fn price_tag<A: Into<ChecksummedAddress>>(
        pay_to: A,
        asset: DeployedTokenAmount<U256, Eip155TokenDeployment>,
    ) -> FourMicaPriceTag<2> {
        FourMicaPriceTag::<2> {
            pay_to: pay_to.into().to_string(),
            asset,
        }
    }
}

impl PaygateProtocol for FourMicaPriceTag<1> {
    type PaymentPayload = sdk_4mica::x402::X402PaymentEnvelope;

    const PAYMENT_HEADER_NAME: &'static str = "X-PAYMENT";

    fn make_verify_request(
        payload: Self::PaymentPayload,
        accepts: &[Self],
        resource: &ResourceInfo,
    ) -> Result<proto::VerifyRequest, VerificationError> {
        let payment_requirements = price_tag_to_v1_requirements(accepts, resource);
        let selected = payment_requirements
            .iter()
            .find(|requirement| {
                requirement.scheme == payload.scheme && requirement.network == payload.network
            })
            .ok_or(VerificationError::NoPaymentMatching)?;

        let verify_request = proto::v1::VerifyRequest {
            x402_version: X402Version1,
            payment_payload: payload,
            payment_requirements: selected.clone(),
        };
        verify_request
            .try_into()
            .map_err(|e| VerificationError::VerificationFailed(format!("{e}")))
    }

    fn error_into_response(
        err: PaygateError,
        accepts: &[Self],
        resource: &ResourceInfo,
    ) -> Response {
        match err {
            PaygateError::Verification(err) => {
                let payment_required_response = proto::v1::PaymentRequired {
                    error: Some(err.to_string()),
                    accepts: price_tag_to_v1_requirements(accepts, resource),
                    x402_version: X402Version1,
                };
                let payment_required_response_bytes =
                    serde_json::to_vec(&payment_required_response).expect("serialization failed");
                let body = Body::from(payment_required_response_bytes);
                Response::builder()
                    .status(StatusCode::PAYMENT_REQUIRED)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .expect("Fail to construct response")
            }
            PaygateError::Settlement(err) => build_settlement_error_response(err),
        }
    }

    fn validate_verify_response(
        verify_response: proto::VerifyResponse,
    ) -> Result<(), VerificationError> {
        let verify_response: super::model::VerifyResponse =
            serde_json::from_value(verify_response.0)
                .map_err(|e| VerificationError::VerificationFailed(format!("{e}")))?;

        if !verify_response.is_valid {
            return Err(VerificationError::VerificationFailed(
                verify_response
                    .invalid_reason
                    .unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        Ok(())
    }

    fn enrich_with_capabilities(&mut self, _capabilities: &proto::SupportedResponse) {}
}

fn price_tag_to_v1_requirements(
    accepts: &[FourMicaPriceTag<1>],
    resource: &ResourceInfo,
) -> Vec<proto::v1::PaymentRequirements> {
    let tab_endpoint = match config::tab_endpoint_from_env_with_resource(&resource.url) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            warn!("Failed to resolve tab endpoint from env: {err}");
            return Vec::new();
        }
    };

    accepts
        .iter()
        .filter_map(|accept| {
            let chain_id: ChainId = accept.asset.token.chain_reference.into();

            let extra = EnrichedPaymentRequirementsExtra::new(
                tab_endpoint.as_str(),
                None,
                accept.asset.token.eip712.clone(),
            );
            let extra = serde_json::to_value(&extra)
                .inspect_err(|err| {
                    warn!(
                        "Failed to serialize enriched payment requirements extra: {:?}",
                        err
                    );
                })
                .ok()?;

            Some(proto::v1::PaymentRequirements {
                scheme: FOUR_MICA_SCHEME.to_string(),
                network: chain_id.to_string(),
                max_amount_required: accept.asset.amount.to_string(),
                resource: resource.url.clone(),
                description: resource.description.clone(),
                mime_type: resource.mime_type.clone(),
                output_schema: None,
                pay_to: accept.pay_to.clone(),
                max_timeout_seconds: 300,
                asset: accept.asset.token.address.to_string(),
                extra: Some(extra),
            })
        })
        .collect()
}

impl PaygateProtocol for FourMicaPriceTag<2> {
    type PaymentPayload =
        proto::v2::PaymentPayload<proto::v2::PaymentRequirements, PaymentGuaranteeRequest>;

    const PAYMENT_HEADER_NAME: &'static str = "Payment-Signature";

    fn make_verify_request(
        payload: Self::PaymentPayload,
        _accepts: &[Self],
        _resource: &ResourceInfo,
    ) -> Result<proto::VerifyRequest, VerificationError> {
        let accepted = payload.accepted.clone();
        let verify_request = proto::v2::VerifyRequest {
            x402_version: X402Version2,
            payment_payload: payload.clone(),
            payment_requirements: accepted,
        };

        let json = serde_json::to_value(&verify_request)
            .map_err(|e| VerificationError::VerificationFailed(format!("{e}")))?;

        Ok(proto::VerifyRequest::from(json))
    }

    fn error_into_response(
        err: PaygateError,
        accepts: &[Self],
        resource: &ResourceInfo,
    ) -> Response {
        match err {
            PaygateError::Verification(err) => {
                let payment_required_response = proto::v2::PaymentRequired {
                    error: Some(err.to_string()),
                    accepts: price_tag_to_v2_requirements(accepts, resource),
                    x402_version: X402Version2,
                    resource: resource.clone(),
                };

                // V2 sends payment required in the "Payment-Required" header (base64 encoded)
                let payment_required_bytes =
                    serde_json::to_vec(&payment_required_response).expect("serialization failed");
                let payment_required_header = Base64Bytes::encode(&payment_required_bytes);
                let header_value = HeaderValue::from_bytes(payment_required_header.as_ref())
                    .expect("Failed to create header value");

                Response::builder()
                    .status(StatusCode::PAYMENT_REQUIRED)
                    .header("Payment-Required", header_value)
                    .body(Body::empty())
                    .expect("Fail to construct response")
            }
            PaygateError::Settlement(err) => build_settlement_error_response(err),
        }
    }

    fn validate_verify_response(
        verify_response: proto::VerifyResponse,
    ) -> Result<(), VerificationError> {
        <FourMicaPriceTag<1> as PaygateProtocol>::validate_verify_response(verify_response)
    }

    fn enrich_with_capabilities(&mut self, _capabilities: &proto::SupportedResponse) {}
}

fn price_tag_to_v2_requirements(
    accepts: &[FourMicaPriceTag<2>],
    resource: &ResourceInfo,
) -> Vec<proto::v2::PaymentRequirements> {
    let tab_endpoint = match config::tab_endpoint_from_env_with_resource(&resource.url) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            warn!("Failed to resolve tab endpoint from env: {err}");
            return Vec::new();
        }
    };

    accepts
        .iter()
        .filter_map(|accept| {
            let chain_id: ChainId = accept.asset.token.chain_reference.into();

            let extra = EnrichedPaymentRequirementsExtra::new(
                tab_endpoint.as_str(),
                None,
                accept.asset.token.eip712.clone(),
            );
            let extra = serde_json::to_value(&extra)
                .inspect_err(|err| {
                    warn!(
                        "Failed to serialize enriched payment requirements extra: {:?}",
                        err
                    );
                })
                .ok()?;

            Some(proto::v2::PaymentRequirements {
                scheme: FOUR_MICA_SCHEME.to_string(),
                network: chain_id,
                amount: accept.asset.amount.to_string(),
                pay_to: accept.pay_to.clone(),
                max_timeout_seconds: 300,
                asset: accept.asset.token.address.to_string(),
                extra: Some(extra),
            })
        })
        .collect()
}

fn build_settlement_error_response(err: String) -> Response {
    let body = Body::from(
        json!({
            "error": "Settlement failed",
            "details": err
        })
        .to_string(),
    );
    Response::builder()
        .status(StatusCode::PAYMENT_REQUIRED)
        .header("Content-Type", "application/json")
        .body(body)
        .expect("Fail to construct response")
}
