# x402-4mica

Rust integration for [x402 Payment Protocol](https://x402.org) with [4mica credit flow](https://4mica.xyz).

This library provides both client and server implementations for integrating 4mica payments into your Rust applications using the x402 protocol. It builds on top of [x402-reqwest](https://crates.io/crates/x402-reqwest) and [x402-axum](https://crates.io/crates/x402-axum).

## Features

- **Client Support**: Automatic payment handling with reqwest
- **Server Support**: Axum middleware for protecting routes with payments
- **Multi-chain**: Support for Ethereum Sepolia and Polygon Amoy testnets
- **4mica Credit Scheme**: Seamless integration with 4mica payment tabs
- **V1 and V2 Protocol**: Full support for x402 protocol versions

## Installation

Add to your `Cargo.toml`:

```toml
# Client only (default)
x402-4mica = "0.1"

# With server support
x402-4mica = { version = "0.1", features = ["server"] }
```

### Feature Flags

- **`server`**: Enables server-side functionality including Axum middleware for protecting routes. When disabled, only the client module is available, reducing dependencies.

The `client` module is always available. Server-specific dependencies (`axum`, `axum-core`, `tower`, `x402-axum`, `envconfig`) are only included when the `server` feature is enabled.

## Quick Start

### Server Example

Protect your Axum routes with payment requirements (requires `server` feature):

```rust,no_run
use alloy_primitives::{address, Address};
use axum::{routing::get, Router};
use x402_4mica::{
    server::axum::{BuildTabMiddleware, V1Eip155FourMica},
    SupportedNetworkEip155,
};
use x402_axum::X402Middleware;
use x402_types::networks::USDC;

#[tokio::main]
async fn main() {
    let x402 = X402Middleware::new("https://x402.4mica.xyz");
    let tab_middleware = x402.tab_middleware().unwrap();

    let app = Router::new()
        .route(
            "/api/premium",
            get(handler).layer(
                x402.with_price_tag(V1Eip155FourMica::price_tag(
                    address!("0xBAc675C310721717Cd4A37F6cbeA1F081b1C2a07"),
                    USDC::ethereum_sepolia().parse("0.01").unwrap(),
                ))
            ),
        )
        .layer(tab_middleware);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handler() -> &'static str {
    "Premium content!"
}
```

### Client Example

Make requests that automatically handle payments:

```rust,no_run
use alloy_signer_local::PrivateKeySigner;
use reqwest::Client;
use x402_4mica::client::Eip155FourMicaClient;
use x402_reqwest::{ReqwestWithPayments, ReqwestWithPaymentsBuild, X402Client};

#[tokio::main]
async fn main() {
    let signer: PrivateKeySigner = "0x...".parse().unwrap();

    let x402_client = X402Client::new()
        .register(Eip155FourMicaClient::new(signer));

    let http_client = Client::new()
        .with_payments(x402_client)
        .build();

    let response = http_client
        .get("http://localhost:3000/api/premium")
        .send()
        .await
        .unwrap();

    println!("Response: {}", response.text().await.unwrap());
}
```

## Configuration

### Payment Tab Endpoint

The 4mica payment tab endpoint is where clients open payment tabs. Configure it using environment variables:

```bash
# Endpoint path (default: /4mica/tab)
export 4MICA_TAB_ENDPOINT="/payment/tab"

# Tab time-to-live in seconds (optional, defines how long a tab stays open)
export 4MICA_TAB_TTL_SECONDS=3600
```

The `4MICA_TAB_ENDPOINT` can be:
- **Absolute URL**: `https://api.example.com/payment/tab` - Fully qualified endpoint
- **Relative path**: `/4mica/tab` - Resolved relative to the protected resource's base URL

The middleware automatically registers this endpoint and handles tab creation requests.

### Protocol Versions

Use `V1Eip155FourMica` or `V2Eip155FourMica` to specify the x402 protocol version:

```rust
// V1 Protocol (uses X-PAYMENT header in request body)
use x402_4mica::server::axum::V1Eip155FourMica;

// V2 Protocol (uses Payment-Signature header)
use x402_4mica::server::axum::V2Eip155FourMica;
```

Both versions work with the same client implementation.

### Supported Networks

Currently supported networks:
- **Ethereum Sepolia** (`eip155:11155111`)
- **Polygon Amoy** (`eip155:80002`)

Use the `SupportedNetworkEip155` trait to access network-specific token deployments:

```rust
use x402_4mica::SupportedNetworkEip155;
use x402_types::networks::USDC;

// Ethereum Sepolia USDC
let sepolia_usdc = USDC::ethereum_sepolia();

// Polygon Amoy USDC
let amoy_usdc = USDC::polygon_amoy();
```

## Running Examples

The `examples/` directory contains complete working examples for both server and client.

### Prerequisites

1. Navigate to the crate directory:

```bash
cd packages/rust/x402
```

Create a `.env` file with the following variables:

```bash
# Required for both server and client
PRIVATE_KEY=0xYourPrivateKeyHere
PAY_TO_ADDRESS=0xYourPaymentAddress

# Optional server configuration
PORT=3000
4MICA_TAB_ENDPOINT=/4mica/tab
4MICA_TAB_TTL_SECONDS=3600

# Optional client configuration
API_URL=http://localhost:3000
```

2. Ensure your account has testnet tokens on Ethereum Sepolia

### Run the Server

```bash
cargo run --example server --features server
```

The server will start on `http://localhost:3000` with:
- `/` - Server info
- `/api/premium-data` - Protected endpoint (requires $0.01 payment)
- `/4mica/tab` - Payment tab endpoint (handled by middleware)

### Run the Client

In another terminal:

```bash
cargo run --example client
```

The client will:
1. Make a request to the protected endpoint
2. Receive a `402 Payment Required` response
3. Automatically open a payment tab with the 4mica facilitator
4. Sign the payment guarantee
5. Retry the request with the payment header
6. Display the protected content

Example output:
```
Initializing x402 client...
Target endpoint: http://localhost:3000/api/premium-data
Using account: 0xYourAddress
Making request to protected endpoint...
Request successful!
Response: {
  "message": "Success! You've accessed the premium data.",
  ...
}
```

## How It Works

### Payment Flow

1. **Client → Server**: Initial request to protected endpoint
2. **Server → Client**: 402 Payment Required with payment requirements
3. **Client → Tab Endpoint**: Open payment tab
4. **Client**: Sign payment guarantee using 4mica SDK
5. **Client → Server**: Retry request with payment header
6. **Server → Facilitator**: Verify payment
7. **Server → Client**: Return protected content

### 4mica Credit Scheme

The library uses the `4mica-credit` scheme which:
- Opens payment tabs through the 4mica facilitator
- Uses EIP-712 signatures for payment guarantees
- Settles payments asynchronously after content delivery
- Supports both V1 and V2 x402 protocol versions

## Related Crates

- [x402-reqwest](https://crates.io/crates/x402-reqwest): Reqwest middleware for x402
- [x402-axum](https://crates.io/crates/x402-axum): Axum middleware for x402
- [x402-types](https://crates.io/crates/x402-types): Core x402 types and protocol
- [x402-chain-eip155](https://crates.io/crates/x402-chain-eip155): EVM chain support

## License

CC-BY-NC-4.0
