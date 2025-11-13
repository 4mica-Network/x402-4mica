# x402-4Mica Facilitator

An Axum-based facilitator that speaks the x402 protocol while orchestrating 4Mica credit
guarantees.  The service is **stateless**: it never holds a recipient wallet or submits on-chain
transactions. Instead, it accepts signed guarantee claims from clients, checks that they satisfy the
resource server’s declared `paymentRequirements`, and on settlement requests asks the 4Mica core
service to mint and verify a BLS certificate before returning it to the recipient.

`/verify` performs the same structural checks as the upstream x402 facilitator so callers can
pre-flight requests, while `/settle` drives the 4Mica guarantee flow and returns the verified
certificate alongside the settlement status.

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

On startup the facilitator calls `FOUR_MICA_RPC_URL/core/public-params`
(or `4MICA_RPC_URL/core/public-params`) to obtain the operator’s BLS
public key, EIP‑712 metadata, and contract address. If the optional x402 environment variables are set,
the service also initialises the default `exact` ERC-3009 facilitator from `x402-rs`; otherwise those
networks are simply omitted from `/supported`.

## Running

```bash
cargo run
```

The bound address is logged on start-up. Use `GET /supported` to read the advertised
`(scheme, network)` pair that resource servers should use in their `402 Payment Required` responses.

## Python Client Example

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

Integration-style tests use a mock verifier to exercise `/verify`, `/settle`, and the discovery
endpoints without contacting 4Mica.

## Payment Flow (User / Resource / Facilitator / 4Mica)

1. **User** calls the resource server, including their wallet address in the request headers/body so
   the server can key lookups off the caller identity.
2. **Recipient** checks 4Mica for an open tab with that user (creating one if none exists) and
   records the tab metadata needed to accept credit.
3. **Recipient** responds with `402 Payment Required`, embedding the tab ID, required asset, amount,
   and guarantee parameters in the `paymentRequirements` body. The facilitator expects the
   `paymentRequirements.extra` object to include:
   - `tabId`: hex or decimal string identifying the open tab.
   - `startTimestamp`: optional UNIX epoch (seconds) used when the tab was opened. Including it lets
     recipients enforce that the client is referencing the correct tab metadata.
   - `userAddress`: checksum user address that must sign the claim.
   4Mica core now assigns per-request identifiers internally, so resource servers no longer need to
   track or send `reqId` values.
4. **User** signs an EIP‑712 guarantee claim using the tab details and retries the HTTP call with
   `X-PAYMENT`, a base64 JSON envelope containing the claim and signature.
5. **Recipient** posts the header and requirements to the facilitator’s `/verify`. When the scheme is
   `4mica-guarantee`, the facilitator performs the same structural validation as the upstream x402
   facilitator—ensuring the payment header decodes correctly and matches the declared requirements.
   For other schemes (e.g. `exact`), the request is forwarded to the upstream `x402-rs`
   implementation for its native verification.
6. **Recipient** calls `/settle` to drive the actual settlement. For 4Mica requests the facilitator
   submits the claim to 4Mica core, verifies the returned certificate against the operator parameters,
   and includes the certificate in the settlement response together with the success status. Other
   schemes still delegate settlement to the upstream x402 facilitator, which may return an on-chain
   transaction hash.

## X-PAYMENT Header Schema

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

During settlement the facilitator issues and verifies a certificate, enforcing that:

- `scheme` / `network` match both `/supported` and the resource server’s requirements.
- `payTo` equals the recipient address inside the claims/certificate.
- `asset` and `maxAmountRequired` bound the signed amount.
- If `FOUR_MICA_GUARANTEE_DOMAIN` is set, the certificate domain must match.

## HTTP Surface

- `GET /supported` – supported `(scheme, network)` tuples for both the 4Mica credit flow and any
  x402 `exact` flows initialised from environment configuration.
- `POST /verify` – `{ "x402Version", "paymentHeader", "paymentRequirements" }` → `{ "isValid", "invalidReason", "certificate" }`
  where 4Mica requests report only the validation status (no certificate is produced) and other
  schemes mirror the upstream x402 facilitator’s response.
- `POST /settle` – same payload; revalidates the request and, for 4Mica, submits it to the core
  service. The response is `{ "success", "networkId", "error", "txHash", "certificate" }` with
  `certificate` populated only for 4Mica guarantees and `txHash` populated only for upstream x402
  settlements that touch the chain.
- `GET /health` – `{ "status": "ok" }`.

Point your x402 resource server at this facilitator to outsource 4Mica guarantee verification while
keeping custody, settlement, and tab management under your own recipient infrastructure.
