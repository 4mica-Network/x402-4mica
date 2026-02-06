use std::{collections::HashMap, str::FromStr, sync::Arc};

use alloy_primitives::ruint::aliases::U256;
use alloy_signer::Signer;
use async_trait::async_trait;
use parking_lot::Mutex;
use sdk_4mica::{
    Client, ConfigBuilder, X402Flow,
    x402::{X402PaymentRequiredV2, X402PaymentRequirements, X402ResourceInfo},
};
use x402_types::{
    chain::ChainId,
    networks::NetworkInfo,
    proto::{PaymentRequired, v2::ResourceInfo},
    scheme::{
        X402SchemeId,
        client::{PaymentCandidate, PaymentCandidateSigner, X402Error, X402SchemeClient},
    },
};

use crate::model::VPaymentRequirements;
use crate::{
    chain::{
        EIP155_NAMESPACE, ETHEREUM_SEPOLIA_CHAIN_REFERENCE, Eip155FourMica, FOUR_MICA_SCHEME,
        POLYGON_AMOY_CHAIN_REFERENCE,
    },
    model::PaymentRequirementsExtra,
};

#[derive(Debug, Clone)]
struct NetworkRpcUrl {
    network: NetworkInfo,
    rpc_url: &'static str,
    aliases: &'static [&'static str],
}

impl Into<ChainId> for NetworkRpcUrl {
    fn into(self) -> ChainId {
        ChainId::new(self.network.namespace, self.network.reference)
    }
}

const NETWORK_RPC_URLS: &[NetworkRpcUrl] = &[
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
        let network_info = NETWORK_RPC_URLS
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
        let network_info = NETWORK_RPC_URLS
            .iter()
            .find(|n| {
                n.network.namespace == chain.namespace() && n.network.reference == chain.reference()
            })
            .map(Clone::clone);
        network_info.ok_or(anyhow::anyhow!("Unsupported chain: {}", chain))
    }
}

struct Inner<S> {
    signer: S,
    clients: Mutex<HashMap<String, Arc<X402Flow<Client<S>>>>>,
}

#[derive(Clone)]
pub struct Eip155FourMicaClient<S> {
    inner: Arc<Inner<S>>,
}

impl<S> Eip155FourMicaClient<S> {
    /// Creates a new EIP-155 fourmica client with the given signer.
    pub fn new(signer: S) -> Self {
        Self {
            inner: Arc::new(Inner {
                signer,
                clients: Mutex::default(),
            }),
        }
    }
}

impl<S> X402SchemeId for Eip155FourMicaClient<S> {
    fn namespace(&self) -> &str {
        Eip155FourMica.namespace()
    }

    fn scheme(&self) -> &str {
        Eip155FourMica.scheme()
    }
}

impl<S> X402SchemeClient for Eip155FourMicaClient<S>
where
    S: Signer + Send + Sync + Clone + 'static,
{
    fn accept(&self, payment_required: &PaymentRequired) -> Vec<PaymentCandidate> {
        match payment_required {
            PaymentRequired::V1(payment_required) => payment_required
                .accepts
                .iter()
                .filter_map(|pr| {
                    if pr.scheme != FOUR_MICA_SCHEME {
                        return None;
                    }

                    let network = NetworkRpcUrl::from_str(pr.network.as_str()).ok()?;
                    let amount = U256::from_str(&pr.max_amount_required).ok()?;
                    let requirements: VPaymentRequirements = pr.clone().into();

                    Some(PaymentCandidate {
                        chain_id: network.clone().into(),
                        asset: pr.asset.to_string(),
                        amount,
                        scheme: FOUR_MICA_SCHEME.to_string(),
                        x402_version: 1,
                        pay_to: pr.pay_to.to_string(),
                        signer: Box::new(FourMicaSigner::new(
                            self.clone(),
                            network,
                            requirements,
                            None,
                        )),
                    })
                })
                .collect(),
            PaymentRequired::V2(payment_required) => payment_required
                .accepts
                .iter()
                .filter_map(|pr| {
                    if pr.scheme != FOUR_MICA_SCHEME {
                        return None;
                    }

                    let network = NetworkRpcUrl::try_from(&pr.network).ok()?;
                    let amount = U256::from_str(&pr.amount).ok()?;
                    let requirements: VPaymentRequirements = pr.clone().into();

                    Some(PaymentCandidate {
                        chain_id: pr.network.clone(),
                        asset: pr.asset.to_string(),
                        amount,
                        scheme: FOUR_MICA_SCHEME.to_string(),
                        x402_version: 1,
                        pay_to: pr.pay_to.to_string(),
                        signer: Box::new(FourMicaSigner::new(
                            self.clone(),
                            network,
                            requirements,
                            Some(payment_required.resource.clone()),
                        )),
                    })
                })
                .collect(),
        }
    }
}

impl<S> Eip155FourMicaClient<S>
where
    S: Signer + Send + Sync + Clone,
{
    async fn get_client_for_rpc_url(
        &self,
        rpc_url: &str,
    ) -> anyhow::Result<Arc<X402Flow<Client<S>>>> {
        if let Some(client) = self.inner.clients.lock().get(rpc_url) {
            return Ok(client.clone());
        }

        let config = ConfigBuilder::default()
            .signer(self.inner.signer.clone())
            .rpc_url(rpc_url.to_string())
            .build()?;
        let client = Client::new(config).await?;
        let flow = Arc::new(X402Flow::new(client)?);

        self.inner
            .clients
            .lock()
            .insert(rpc_url.to_string(), flow.clone());

        Ok(flow)
    }
}

struct FourMicaSigner<S> {
    client: Eip155FourMicaClient<S>,
    network: NetworkRpcUrl,
    requirements: VPaymentRequirements,
    resource: Option<ResourceInfo>,
}

impl<S> FourMicaSigner<S> {
    pub fn new(
        client: Eip155FourMicaClient<S>,
        network: NetworkRpcUrl,
        requirements: VPaymentRequirements,
        resource: Option<ResourceInfo>,
    ) -> Self {
        Self {
            client,
            network,
            requirements,
            resource,
        }
    }
}

#[async_trait]
impl<S> PaymentCandidateSigner for FourMicaSigner<S>
where
    S: Signer + Send + Sync + Clone,
{
    async fn sign_payment(&self) -> Result<String, X402Error> {
        let Some(extra) = self.requirements.extra() else {
            return Err(X402Error::SigningError(
                "No requirements.extra found".to_string(),
            ));
        };
        let extra: PaymentRequirementsExtra = serde_json::from_value(extra.clone())?;
        let rpc_url = extra.rpc_url.unwrap_or(self.network.rpc_url.to_string());
        let client = self
            .client
            .get_client_for_rpc_url(&rpc_url)
            .await
            .map_err(|e| X402Error::SigningError(e.to_string()))?;

        let signed = match self.requirements {
            VPaymentRequirements::V1(ref requirements) => client
                .sign_payment(
                    requirements.clone(),
                    self.client.inner.signer.address().to_string(),
                )
                .await
                .map_err(|e| X402Error::SigningError(e.to_string()))?,
            VPaymentRequirements::V2(ref requirements) => {
                let resource = self.resource.clone().ok_or(X402Error::SigningError(
                    "resource info not provided".to_string(),
                ))?;
                let payment_required = X402PaymentRequiredV2 {
                    x402_version: 2,
                    error: None,
                    resource: X402ResourceInfo {
                        url: resource.url,
                        description: resource.description,
                        mime_type: resource.mime_type,
                    },
                    accepts: vec![requirements.clone()],
                    extensions: None,
                };
                client
                    .sign_payment_v2(
                        payment_required,
                        requirements.clone(),
                        self.client.inner.signer.address().to_string(),
                    )
                    .await
                    .map_err(|e| X402Error::SigningError(e.to_string()))?
            }
        };

        Ok(signed.header)
    }
}
