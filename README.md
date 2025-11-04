# x402-4Mica Facilitator

An Axum-based facilitator that speaks the x402 protocol while orchestrating 4Mica credit
guarantees.  The service is **stateless**: it never holds a recipient wallet or submits on-chain
transactions. Instead, it accepts signed guarantee claims from clients, asks the 4Mica core service
to mint a BLS certificate, verifies the certificate, and makes sure the result matches the resource
server’s declared `paymentRequirements`.

`/settle` is kept for protocol compatibility, but it simply replays verification and acknowledges the
request—actual remuneration is a responsibility of the recipient’s infrastructure.

## Configuration

Environment variables (defaults shown):

```bash
export HOST=0.0.0.0
export PORT=8080
export X402_SCHEME=4mica-guarantee
export X402_NETWORK=4mica-mainnet

# 4Mica public API – used to fetch operator parameters
export FOUR_MICA_RPC_URL=https://api.4mica.xyz/

# Optional: pin the expected domain separator (32-byte hex, 0x-prefixed)
export FOUR_MICA_GUARANTEE_DOMAIN=0x...

# Optional: enable standard x402 settlement for EVM networks
export SIGNER_TYPE=private-key
export EVM_PRIVATE_KEY=0x...
export RPC_URL_BASE=https://mainnet.base.org
export RPC_URL_BASE_SEPOLIA=https://sepolia.base.org
```

On startup the facilitator calls `FOUR_MICA_RPC_URL/core/public-params` to obtain the operator’s BLS
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

An HTTP client script is available under `examples/x402_facilitator_client.py`. It can fetch
supported schemes, run health checks, and submit `/verify` or `/settle` requests once you provide
the `paymentRequirements` JSON alongside either a pre-encoded payment header or the raw guarantee
claims plus signature. Run `python examples/x402_facilitator_client.py --help` for usage details.

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
   - `reqId`: per-request identifier unique within the tab.
   - `userAddress`: checksum user address that must sign the claim.
4. **User** signs an EIP‑712 guarantee claim using the tab details and retries the HTTP call with
   `X-PAYMENT`, a base64 JSON envelope containing the claim and signature.
5. **Recipient** posts the header and requirements to the facilitator’s `/verify`. When the scheme is
   `4mica-guarantee`, the facilitator validates the payload, requests a BLS guarantee from 4Mica core,
   and verifies the returned certificate against operator parameters and the original claim. For other
   schemes (e.g. `exact`), the facilitator forwards the request to the upstream `x402-rs`
   implementation and follows the standard ERC-3009 verification flow.
6. **Facilitator** returns `certificate` in the `/verify` response for 4Mica requests, or a standard
   x402 verification response for other schemes. `/settle` remains a no-op acknowledgement in the
   4Mica case; when the scheme is handled by x402, `/settle` executes the on-chain transfer through the
   upstream facilitator.

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
      "req_id": "<decimal or 0x value>",
      "amount": "<decimal or 0x value>",
      "asset_address": "<0x-prefixed checksum string>",
      "timestamp": 1716500000
    },
    "signature": "<0x-prefixed wallet signature>",
    "signingScheme": "eip712"
  }
}
```

On decode the facilitator issues and verifies a certificate, enforcing that:

- `scheme` / `network` match both `/supported` and the resource server’s requirements.
- `payTo` equals the recipient address inside the claims/certificate.
- `asset` and `maxAmountRequired` bound the signed amount.
- If `FOUR_MICA_GUARANTEE_DOMAIN` is set, the certificate domain must match.

## HTTP Surface

- `GET /supported` – supported `(scheme, network)` tuples for both the 4Mica credit flow and any
  x402 `exact` flows initialised from environment configuration.
- `POST /verify` – `{ "x402Version", "paymentHeader", "paymentRequirements" }` → `{ "isValid", "invalidReason", "certificate" }`
  where `certificate` is present only for `scheme: "4mica-guarantee"` and contains the
  hex-encoded `claims`/`signature` returned by 4Mica after the facilitator has submitted the
  user-signed claim. For other schemes (for example `exact`) the field is omitted and the response
  mirrors the upstream x402 facilitator’s result.
- `POST /settle` – same payload; re-runs verification and returns `{ "success", "networkId", "error" }`
  with `success: true` indicating the payment was acknowledged (no on-chain action is taken).
- `GET /health` – `{ "status": "ok" }`.

Point your x402 resource server at this facilitator to outsource 4Mica guarantee verification while
keeping custody, settlement, and tab management under your own recipient infrastructure.
