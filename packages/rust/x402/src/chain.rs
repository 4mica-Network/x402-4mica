use x402_types::scheme::X402SchemeId;

pub const FOUR_MICA_SCHEME: &str = "4mica-credit";
pub const EIP155_NAMESPACE: &str = "eip155";
pub const ETHEREUM_SEPOLIA_CHAIN_REFERENCE: &str = "11155111";
pub const POLYGON_AMOY_CHAIN_REFERENCE: &str = "80002";

pub struct Eip155FourMica;

impl X402SchemeId for Eip155FourMica {
    fn namespace(&self) -> &str {
        EIP155_NAMESPACE
    }

    fn scheme(&self) -> &str {
        FOUR_MICA_SCHEME
    }
}
