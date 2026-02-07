# Rust SDK (sdk-4mica)

## Install
```toml
[dependencies]
sdk-4mica = "0.5.0"
```

## Configuration
- `wallet_private_key` is required.
- `rpc_url` defaults to `https://api.4mica.xyz/`.
- Optional: `ethereum_http_rpc_url`, `contract_address` (fetched from core if omitted).

Environment variables:
- `4MICA_WALLET_PRIVATE_KEY`, `4MICA_RPC_URL`, `4MICA_ETHEREUM_HTTP_RPC_URL`,
  `4MICA_CONTRACT_ADDRESS`.

## Basic Client
```rust
use sdk_4mica::{Client, ConfigBuilder};

let client = Client::new(
    ConfigBuilder::default()
        .wallet_private_key(std::env::var("WALLET_PRIVATE_KEY")?)
        .build()?,
).await?;
```

## X402 Flow (Client/Payer)
Version 1:
```rust
use sdk_4mica::{Client, ConfigBuilder, X402Flow};
use sdk_4mica::x402::PaymentRequirements;

let payer = Client::new(
    ConfigBuilder::default()
        .wallet_private_key(std::env::var("PAYER_KEY")?)
        .build()?,
).await?;

let flow = X402Flow::new(payer)?;
let signed = flow.sign_payment(requirements, user_address).await?;
let header = signed.header; // send as X-PAYMENT
```

Version 2:
```rust
use sdk_4mica::{Client, ConfigBuilder, X402Flow};
use sdk_4mica::x402::X402PaymentRequiredV2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

let payer = Client::new(
    ConfigBuilder::default()
        .wallet_private_key(std::env::var("PAYER_KEY")?)
        .build()?,
).await?;

let flow = X402Flow::new(payer)?;
let decoded = BASE64.decode(payment_required_header)?;
let required: X402PaymentRequiredV2 = serde_json::from_slice(&decoded)?;
let accepted = required.accepts[0].clone();
let signed = flow.sign_payment_v2(required, accepted, user_address).await?;
let header = signed.header; // send as PAYMENT-SIGNATURE
```

## Key Client Methods
- `client.user`: `deposit`, `approve_erc20`, `sign_payment`, `pay_tab`, withdrawals.
- `client.recipient`: `create_tab`, `issue_payment_guarantee`, `verify_payment_guarantee`, `remunerate`.

Notes:
- Scheme must include `4mica` or X402Flow will reject.
- `RecipientClient::remunerate` requires BLS decoding dependencies.
