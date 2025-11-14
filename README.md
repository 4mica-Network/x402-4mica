# x402-4Mica Facilitator

An Axum-based facilitator that speaks the x402 protocol while orchestrating 4Mica credit
guarantees. The service is **stateless**: it never stores recipient wallets or pushes on-chain
transactions. It accepts signed guarantee claims from clients, checks them against the resource
server’s `paymentRequirements`, and, on settlement, asks the 4Mica core service to mint and verify a
BLS certificate before returning it to the recipient.

## How the facilitator moves data

- **Startup** – the process loads configuration from the environment, then calls
  `FOUR_MICA_RPC_URL/core/public-params` (or the `4MICA_RPC_URL` alias) to fetch the operator’s BLS
  public key, domain separator, and API base URL. Those values are kept in memory and reused for all
  later requests.
- **Tab provisioning (`POST /tabs`)** – recipients can ask the facilitator to open a payment tab on
  their behalf. The facilitator relays the request to `core/payment-tabs`, converts the 4Mica
  response into a plain JSON payload, and hands the tab metadata back to the resource server.
- **Verification (`POST /verify`)** – recipients send the base64 `X-PAYMENT` header plus the
  `paymentRequirements` they issued to the client. The facilitator decodes the header, validates the
  claims against the requirements, and mirrors the upstream x402 error semantics. No 4Mica network
  call is made in this path.
- **Settlement (`POST /settle`)** – recipients replay the same payload once they are ready to accept
  credit. The facilitator re-runs validation, submits the signed guarantee to
  `core/guarantees`, receives the BLS certificate, verifies it against the cached operator public
  key (and optional domain), and returns the certificate to the caller.

If EVM settlement variables are present the facilitator also instantiates the upstream `exact`
facilitator from `x402-rs`, exposing those `(scheme, network)` pairs on `/supported`.

## End-to-end credit flow

The sequence below highlights each HTTP request, who sends it, and how data travels through
x402-4Mica and the 4Mica core service.

1. **Recipient opens or refreshes a tab**
   - Recipient → Facilitator: `POST /tabs` with `{ userAddress, recipientAddress, erc20Token?, ttlSeconds? }`.
   - Facilitator → 4Mica core: `POST core/payment-tabs` using the supplied body.
   - 4Mica core → Facilitator: tab metadata (`id`).
   - Facilitator → Recipient: `{ tabId, userAddress, recipientAddress, assetAddress, startTimestamp, ttlSeconds }`.
     The `tabId` becomes part of every `paymentRequirements.extra.tabId`.
2. **Client discovers the paywall**
   - Client → Recipient resource: request missing credit evidence.
   - Recipient → Client: `402 Payment Required` that embeds the latest
     `paymentRequirements`. For the 4Mica scheme the `.extra` field **must** include:
     - `tabId` – decimal or hex string returned by `/tabs`.
     - `userAddress` – checksum wallet required to sign the claim.
     The body also defines `scheme`, `network`, `payTo`, `asset`, and `maxAmountRequired`.
3. **Client signs a guarantee**
   - Client builds the JSON payload that matches the resource requirements, signs it with their
     private key (EIP‑712 by default; EIP‑191 is also accepted), and wraps the result in a base64
     `X-PAYMENT` header.
4. **Client retries the protected call**
   - Client → Recipient resource: same HTTP request plus `X-PAYMENT: <base64 envelope>`.
5. **Recipient verifies the header**
   - Recipient → Facilitator: `POST /verify` with
     `{ x402Version, paymentHeader, paymentRequirements }`.
   - Facilitator: decodes `paymentHeader`, ensures `scheme`/`network` match `/supported`, confirms
     the claims reference the advertised tab, user, asset, `payTo`, and that `amount` does not exceed
     `maxAmountRequired`.
   - Facilitator → Recipient: `{ isValid, invalidReason?, certificate: null }`. No request touches
     4Mica core here; this is purely structural validation so recipients can pre-flight calls.
6. **Recipient settles the tab**
   - Recipient → Facilitator: `POST /settle` with the same payload.
   - Facilitator: revalidates the header, then
     - sends `POST core/guarantees` with `{ claims, signature, scheme }` where `claims` contains the
       tab id, user, recipient, asset, amount, and timestamp (plus a version field injected by the
       facilitator),
     - receives a BLS signature over those claims,
     - verifies the certificate by reusing the public parameters fetched at startup, rejecting the
       settlement if the signature or expected domain fail to match.
   - Facilitator → Recipient: `{ success, networkId, certificate, error: null, txHash: null }`.
     `certificate.claims` and `certificate.signature` are byte strings that recipients can persist or
     pass to downstream infrastructure as proof of credit issuance. If the request belonged to a
     delegated `exact` scheme the facilitator instead forwards the settlement to x402-rs and returns
     that response (which may contain a `txHash` instead of a certificate).

## Responsibilities

**Client (payer)**
- Collect the latest `paymentRequirements` from the resource server.
- Produce a guarantee payload whose fields exactly match what the recipient advertised (tab id,
  addresses, asset, and amount).
- Sign the payload with the key that matches `paymentRequirements.extra.userAddress` and send the
  resulting `X-PAYMENT` header when retrying the protected request.

**Recipient / resource server**
- Keep track of the tab returned from `POST /tabs` (and refresh it when TTLs lapse).
- Embed `tabId`, `userAddress`, the desired `payTo`, and the tightest `maxAmountRequired` in the
  `paymentRequirements` they return in `402` responses.
- Call `/verify` whenever an `X-PAYMENT` header appears to ensure the signature, scheme, and tab data
  all line up before trusting the client’s retry.
- Call `/settle` once the resource work is ready to complete; persist the returned certificate as
  proof that 4Mica extended credit for the specified amount.

## HTTP API

- `GET /supported` – returns all `(scheme, network)` tuples the facilitator can service (4Mica and,
  if configured, any additional `exact` flows).
- `GET /health` – liveness probe that returns `{ "status": "ok" }`.
- `POST /tabs`
  - Request: `{ "userAddress", "recipientAddress", "erc20Token"?, "ttlSeconds"? }`.
    Use `erc20Token = null` (or omit it) for ETH tabs; otherwise pass the token contract address.
  - Response: `{ "tabId", "userAddress", "recipientAddress", "assetAddress", "startTimestamp", "ttlSeconds" }`.
    `tabId` is always emitted as a canonical hex string.
- `POST /verify`
  - Request: `{ "x402Version": 1, "paymentHeader": "<base64 X-PAYMENT>", "paymentRequirements": { ... } }`.
  - Response: `{ "isValid": true|false, "invalidReason"?, "certificate": null }`.
- `POST /settle`
  - Request: same shape as `/verify`.
  - Response: for 4Mica, `{ "success": true, "networkId": "<network>", "certificate": { "claims", "signature" } }`.
    When delegating to the `exact` facilitator the structure mirrors upstream x402 responses and may
    include `txHash`.

## X-PAYMENT header schema

`X-PAYMENT` must be a base64-encoded JSON envelope:

```json
{
  "x402Version": 1,
  "scheme": "4mica-guarantee",
  "network": "4mica-mainnet",
  "payload": {
    "claims": {
      "user_address": "<0x-prefixed checksum string>",
      "recipient_address": "<0x-prefixed checksum string>",
      "tab_id": "<decimal or 0x value>",
      "amount": "<decimal or 0x value>",
      "asset_address": "<0x-prefixed checksum string>",
      "timestamp": 1716500000
    },
    "signature": "<0x-prefixed wallet signature>",
    "signingScheme": "eip712"
  }
}
```

The facilitator enforces that:

- `scheme` / `network` match both `/supported` and the resource server’s requirements.
- `payTo` equals the `recipient_address` present inside the claim.
- `asset` and `maxAmountRequired` bound the signed `amount`.
- `paymentRequirements.extra.tabId` and `.userAddress` match the claim’s `tab_id` and `user_address`.
- If `FOUR_MICA_GUARANTEE_DOMAIN` is set, the certificate domain returned by core matches it exactly.

## Configuration

Environment variables (defaults shown):

```bash
export HOST=0.0.0.0
export PORT=8080
export X402_SCHEME=4mica-guarantee
export X402_NETWORK=4mica-mainnet

# 4Mica public API – used to fetch operator parameters
export FOUR_MICA_RPC_URL=https://api.4mica.xyz/
# (alias supported for consistency with rust-sdk-4mica: 4MICA_RPC_URL)

# Optional: pin the expected domain separator (32-byte hex, 0x-prefixed)
export FOUR_MICA_GUARANTEE_DOMAIN=0x...
# (alias supported: 4MICA_GUARANTEE_DOMAIN)

# Optional: enable standard x402 settlement for EVM networks
export SIGNER_TYPE=private-key
export EVM_PRIVATE_KEY=0x...
export RPC_URL_BASE=https://mainnet.base.org
export RPC_URL_BASE_SEPOLIA=https://sepolia.base.org
```

On startup the facilitator loads the public parameters described above and, if the optional x402
variables are present, initialises the upstream `exact` ERC-3009 facilitator as well. Any schemes
that fail to initialise are omitted from `/supported`.

## Running

```bash
cargo run
```

The bound address is logged on start-up. Use `GET /supported` to read the `(scheme, network)` pair
that resource servers should use inside their `402 Payment Required` responses.

## Python client example

`examples/x402_facilitator_client.py` walks through the client responsibilities:

- `discover` — call a paywalled resource, capture the `paymentRequirements`, and show what needs to
  be signed.
- `verify` / `settle` — send the base64 `paymentHeader` and requirements to the facilitator once the
  client has signed the claims with their private key.
- `auto` — end-to-end helper that signs the guarantee locally, replays the resource request with the
  generated `X-PAYMENT` header, and optionally submits `/verify`/`/settle` for diagnostics.
- `supported`, `health` — quick facilitator diagnostics.

You can pair the client with `examples/mock_paid_api.py`, a FastAPI server that simulates a
paywalled endpoint. Start it with `python examples/mock_paid_api.py` (set `PORT` to override the
default `9000`). The mock resource will call the facilitator’s `/verify` endpoint (defaulting to
`http://localhost:8080`; override with `FACILITATOR_URL`) whenever it receives an `X-PAYMENT`
header. With both services running you can execute
`python examples/x402_facilitator_client.py discover --resource-url http://localhost:9000/protected`
to see the mock `paymentRequirements` payload.

Run `python examples/x402_facilitator_client.py --help` inside a virtualenv with
`pip install -r examples/requirements.txt` for full usage details.

## Testing

```bash
cargo test
```

Integration-style tests use a mock verifier to exercise `/verify`, `/settle`, `/tabs`, and the
discovery endpoints without contacting 4Mica.

Point your x402 resource server at this facilitator to outsource 4Mica guarantee verification while
keeping custody, settlement, and tab management under your own infrastructure.
