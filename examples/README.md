# x402-4mica Examples

Quick-start references for the facilitator examples shipped with this repository.

## Rust facilitator client (`facilitator_rust.rs`)

This example shows how to use `rust-sdk-4mica`'s `FacilitatorFlow` to run the full x402 lifecycle against a paid resource: follow the 402, request a tab, sign the guarantee, and settle through the facilitator with a single call.

Environment variables (loaded from `examples/.env` and then `.env`):

```
PAYER_KEY=0x...           # payer's private key used to sign the guarantee
USER_ADDRESS=0x...        # payer's address to place in the guarantee claims
RESOURCE_URL=http://localhost:9000/protected
RESOURCE_METHOD=GET       # optional, defaults to GET
FACILITATOR_URL=http://localhost:8080/  # optional, defaults to localhost
```

Run it from the repo root:

```
cargo run --example facilitator_rust
```

What it prints:
- `X-PAYMENT` header you can attach to the protected request: `X-PAYMENT: <header>`
- JSON body ready to send to `${FACILITATOR_URL}/verify` (already POSTed to `/settle` for you)
- Settlement response from `${FACILITATOR_URL}/settle`

Recommended flow:
1) Start the facilitator (`cargo run`) pointed at your 4mica core API.
2) (Optional) Start the mock paid API below on port 9000.
3) Run the Rust example to generate the header, `/verify` body, and trigger settlement for the target resource.

## Mock paid API (`mock_paid_api.py`)

A minimal FastAPI server that returns `402 Payment Required`, issues payment requirements via `/tab`, and calls the facilitator to verify X-PAYMENT headers.

Setup:
```
cd examples
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Configure via environment or `examples/.env` (required: `RECIPIENT_ADDRESS`; optional: `FACILITATOR_URL`, `ASSET_ADDRESS`, `X402_SCHEME`, `X402_NETWORK`, `MAX_AMOUNT_WEI`, `TAB_TTL_SECONDS`, `ERC20_TOKEN`).

Run the server:
```
uvicorn examples.mock_paid_api:app --reload --port 9000 --factory
```

Flow to exercise end-to-end:
- GET `/protected` without X-PAYMENT to receive a 402 with `tabEndpoint` `/tab`.
- POST `/tab` with `{ "userAddress": "<wallet>" }` to mint `paymentRequirements` for that wallet.
- Use the Rust example above to build the X-PAYMENT header for those requirements.
- Retry GET `/protected` with `X-PAYMENT: <header>`; the server calls the facilitator `/verify` under the hood and returns the paid content.
