use sdk_4mica::x402::{
    PaymentRequirements as FourMicaPaymentRequirementsV1,
    PaymentRequirementsV2 as FourMicaPaymentRequirementsV2, X402PaymentRequirements,
};
use serde::Deserialize;
use x402_types::proto::v1::PaymentRequirements as PaymentRequirementsV1;
use x402_types::proto::v2::PaymentRequirements as PaymentRequirementsV2;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirementsExtra {
    #[allow(dead_code)]
    pub tab_endpoint: String,
    pub rpc_url: Option<String>,
}

pub enum VPaymentRequirements {
    V1(FourMicaPaymentRequirementsV1),
    V2(FourMicaPaymentRequirementsV2),
}

impl From<PaymentRequirementsV1> for VPaymentRequirements {
    fn from(reqs: PaymentRequirementsV1) -> Self {
        VPaymentRequirements::V1(FourMicaPaymentRequirementsV1 {
            scheme: reqs.scheme,
            network: reqs.network,
            max_amount_required: reqs.max_amount_required,
            resource: Some(reqs.resource),
            description: Some(reqs.description),
            mime_type: Some(reqs.mime_type),
            output_schema: reqs.output_schema,
            pay_to: reqs.pay_to,
            max_timeout_seconds: Some(reqs.max_timeout_seconds),
            asset: reqs.asset,
            extra: reqs.extra,
        })
    }
}

impl From<PaymentRequirementsV2> for VPaymentRequirements {
    fn from(reqs: PaymentRequirementsV2) -> Self {
        VPaymentRequirements::V2(FourMicaPaymentRequirementsV2 {
            scheme: reqs.scheme,
            network: reqs.network.to_string(),
            asset: reqs.asset,
            amount: reqs.amount,
            pay_to: reqs.pay_to,
            max_timeout_seconds: Some(reqs.max_timeout_seconds),
            extra: reqs.extra,
        })
    }
}

impl X402PaymentRequirements for VPaymentRequirements {
    fn amount(&self) -> &str {
        match self {
            VPaymentRequirements::V1(reqs) => &reqs.max_amount_required,
            VPaymentRequirements::V2(reqs) => &reqs.amount,
        }
    }

    fn asset(&self) -> &str {
        match self {
            VPaymentRequirements::V1(reqs) => &reqs.asset,
            VPaymentRequirements::V2(reqs) => &reqs.asset,
        }
    }

    fn pay_to(&self) -> &str {
        match self {
            VPaymentRequirements::V1(reqs) => &reqs.pay_to,
            VPaymentRequirements::V2(reqs) => &reqs.pay_to,
        }
    }

    fn extra(&self) -> Option<&serde_json::Value> {
        match self {
            VPaymentRequirements::V1(reqs) => reqs.extra.as_ref(),
            VPaymentRequirements::V2(reqs) => reqs.extra.as_ref(),
        }
    }
}
