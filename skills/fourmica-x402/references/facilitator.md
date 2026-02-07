# Facilitator (x402-4mica)

## Purpose
- Open or reuse tabs for recipients.
- Verify payment payloads against payment requirements.
- Settle guarantees and return BLS certificates.
- Optionally proxy x402 debit flows when configured.

## Default Hosted URL
- https://x402.4mica.xyz/

## Core Endpoints
- `GET /supported` returns supported `{ scheme, network }` pairs.
- `GET /health` returns `{ "status": "ok" }`.
- `POST /tabs` opens or reuses a tab.
- `POST /verify` validates `{ paymentPayload, paymentRequirements }`.
- `POST /settle` validates and issues the BLS certificate.

## Request and Response Shapes

### `POST /tabs`
Request:
```json
{
  "userAddress": "0x...",
  "recipientAddress": "0x...",
  "network": "eip155:80002",
  "erc20Token": "0x...",
  "ttlSeconds": 300
}
```

Response:
```json
{
  "tabId": "0x...",
  "userAddress": "0x...",
  "recipientAddress": "0x...",
  "assetAddress": "0x...",
  "startTimestamp": 1716500000,
  "ttlSeconds": 300,
  "nextReqId": "0x..."
}
```

### `POST /verify`
Request:
```json
{
  "x402Version": 1,
  "paymentPayload": { "...": "..." },
  "paymentRequirements": { "...": "..." }
}
```

Response:
```json
{
  "isValid": true,
  "invalidReason": null,
  "certificate": null
}
```

### `POST /settle`
Request is the same shape as `/verify`.

Response (4Mica credit flow):
```json
{
  "success": true,
  "networkId": "eip155:80002",
  "certificate": { "claims": "...", "signature": "..." }
}
```

## PaymentRequirements Rules
- `scheme` must include `4mica` (example: `4mica-credit`).
- `network` must match a supported CAIP-2 network (example: `eip155:80002`).
- `payTo`, `asset`, and `amount` or `maxAmountRequired` must match the signed claims exactly.
- `extra.tabEndpoint` must be present and reachable for X402Flow tab refresh.

## Configuration (Env Vars)
- `HOST`, `PORT`, `X402_SCHEME`.
- `X402_NETWORKS` for multi-network configuration (JSON list of `{ network, coreApiUrl }`).
- `X402_NETWORK` and `X402_CORE_API_URL` for legacy single-network configuration.
- `ASSET_ADDRESS` default asset when callers omit `erc20Token` on `/tabs`.
- `X402_GUARANTEE_DOMAIN` to pin expected domain separator.
- `X402_DEBIT_URL` to proxy debit flows to x402-rs.
- `SIGNER_TYPE`, `EVM_PRIVATE_KEY`, and RPC URLs to enable standard x402 settlement.

## Code Touch Points (x402-4mica repo)
- `src/main.rs` bootstraps the server.
- `src/config.rs` loads env configuration.
- `src/server/handlers.rs` defines `/supported`, `/tabs`, `/verify`, `/settle`.
- `src/server/state.rs` contains verification and settlement logic.
