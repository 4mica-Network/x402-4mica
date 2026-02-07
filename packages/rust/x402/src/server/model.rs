use serde::{Deserialize, Serialize};
use x402_chain_eip155::chain::TokenDeploymentEip712;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EnrichedPaymentRequirementsExtra {
    pub tab_endpoint: String,
    pub rpc_url: Option<String>,
    /// The token name as specified in the EIP-712 domain.
    pub name: Option<String>,
    /// The token version as specified in the EIP-712 domain.
    pub version: Option<String>,
}

impl EnrichedPaymentRequirementsExtra {
    pub fn new(
        tab_endpoint: &str,
        rpc_url: Option<String>,
        token_deployment: Option<TokenDeploymentEip712>,
    ) -> Self {
        Self {
            tab_endpoint: tab_endpoint.to_string(),
            rpc_url,
            name: token_deployment.as_ref().map(|t| t.name.clone()),
            version: token_deployment.map(|t| t.version),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TabRequestRequirements {
    pub network: String,
    pub asset: String,
    pub pay_to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifyResponse {
    pub is_valid: bool,
    pub invalid_reason: Option<String>,
}
