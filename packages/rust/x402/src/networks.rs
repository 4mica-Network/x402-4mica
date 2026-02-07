use std::str::FromStr;

use x402_chain_eip155::chain::{
    EIP155_NAMESPACE, Eip155ChainReference, Eip155TokenDeployment, TokenDeploymentEip712,
};
use x402_types::{
    chain::ChainId,
    networks::{NetworkInfo, USDC},
};

pub const FOUR_MICA_SCHEME: &str = "4mica-credit";
pub const ETHEREUM_SEPOLIA_CHAIN_REFERENCE: &str = "11155111";
pub const POLYGON_AMOY_CHAIN_REFERENCE: &str = "80002";

#[derive(Debug, Clone)]
pub(crate) struct NetworkRpcUrl {
    pub network: NetworkInfo,
    pub rpc_url: &'static str,
    pub aliases: &'static [&'static str],
}

impl Into<ChainId> for NetworkRpcUrl {
    fn into(self) -> ChainId {
        ChainId::new(self.network.namespace, self.network.reference)
    }
}

const SUPPORTED_NETWORKS: &[NetworkRpcUrl] = &[
    NetworkRpcUrl {
        network: NetworkInfo {
            name: "ethereum-sepolia",
            namespace: EIP155_NAMESPACE,
            reference: ETHEREUM_SEPOLIA_CHAIN_REFERENCE,
        },
        rpc_url: "https://ethereum.sepolia.api.4mica.xyz",
        aliases: &["sepolia"],
    },
    NetworkRpcUrl {
        network: NetworkInfo {
            name: "polygon-amoy",
            namespace: EIP155_NAMESPACE,
            reference: POLYGON_AMOY_CHAIN_REFERENCE,
        },
        rpc_url: "https://api.4mica.xyz",
        aliases: &["amoy"],
    },
];

impl FromStr for NetworkRpcUrl {
    type Err = anyhow::Error;

    fn from_str(network: &str) -> Result<Self, Self::Err> {
        let network_info = SUPPORTED_NETWORKS
            .iter()
            .find(|n| {
                let chain_id: ChainId = (**n).clone().into();
                n.network.name == network
                    || chain_id.to_string() == network
                    || n.aliases.contains(&network)
            })
            .map(Clone::clone);
        network_info.ok_or(anyhow::anyhow!("Unsupported network: {:?}", network))
    }
}

impl TryFrom<&ChainId> for NetworkRpcUrl {
    type Error = anyhow::Error;

    fn try_from(chain: &ChainId) -> Result<Self, Self::Error> {
        let network_info = SUPPORTED_NETWORKS
            .iter()
            .find(|n| {
                n.network.namespace == chain.namespace() && n.network.reference == chain.reference()
            })
            .map(Clone::clone);
        network_info.ok_or(anyhow::anyhow!("Unsupported chain: {}", chain))
    }
}

pub trait SupportedNetworkEip155<A> {
    /// Returns the instance for Ethereum Sepolia testnet (eip155:11155111)
    fn ethereum_sepolia() -> A;

    /// Returns the instance for Polygon Amoy testnet (eip155:80002)
    fn polygon_amoy() -> A;
}

impl SupportedNetworkEip155<Eip155TokenDeployment> for USDC {
    fn ethereum_sepolia() -> Eip155TokenDeployment {
        Eip155TokenDeployment {
            chain_reference: Eip155ChainReference::new(11155111),
            address: alloy_primitives::address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"),
            decimals: 6,
            eip712: Some(TokenDeploymentEip712 {
                name: "USDC".into(),
                version: "2".into(),
            }),
        }
    }

    fn polygon_amoy() -> Eip155TokenDeployment {
        Eip155TokenDeployment {
            chain_reference: Eip155ChainReference::new(80002),
            address: alloy_primitives::address!("0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582"),
            decimals: 6,
            eip712: Some(TokenDeploymentEip712 {
                name: "USDC".into(),
                version: "2".into(),
            }),
        }
    }
}
