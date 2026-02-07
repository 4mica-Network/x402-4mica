use alloy_primitives::ruint::aliases::U256;
use x402_chain_eip155::chain::Eip155TokenDeployment;
use x402_types::chain::DeployedTokenAmount;

pub mod axum;
mod config;
pub mod facilitator;
mod model;

#[derive(Debug, Clone)]
pub struct FourMicaPriceTag<const VERSION: u8> {
    pub pay_to: String,
    pub asset: DeployedTokenAmount<U256, Eip155TokenDeployment>,
}
