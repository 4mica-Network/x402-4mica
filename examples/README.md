# x402-4mica Examples

Quick-start references that follow the standard x402 flow (as in `~/x402`): the client only talks to the resource server, while the server calls the facilitator for `/tabs`, `/verify`, and `/settle`. Users never interact with the facilitator or 4mica Core directly.

## Server-driven mock paid API (`mock_paid_api.py`)

A minimal FastAPI server that returns `402 Payment Required`, issues payment requirements via `/tab`, and calls the facilitator to verify **and settle** X-PAYMENT headers on behalf of the user.

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
- GET `/protected` without X-PAYMENT to receive a 402 with `paymentRequirementsTemplate` and `tabEndpoint` `/tab`.
- POST `/tab` with `{ "userAddress": "<wallet>" }`; the server calls the facilitator `/tabs` and returns concrete `paymentRequirements` for that wallet.
- Sign the requirements with your wallet to produce `X-PAYMENT` (no facilitator calls from the client).
- Retry GET `/protected` with `X-PAYMENT: <header>`; the server calls the facilitator `/verify` **and** `/settle` and returns the paid content plus the facilitator responses.

## Rust helper (`facilitator_rust.rs`)

An optional diagnostics tool for operators to prepare headers with `rust-sdk-4mica` (not part of the user-facing x402 flow). It discovers requirements, requests tabs, signs, and prints the X-PAYMENT header plus the `/verify` body that the server will POST.

Environment variables (loaded from `examples/.env` and then `.env`):
```
PAYER_KEY=0x...           # payer's private key used to sign the guarantee
USER_ADDRESS=0x...        # payer's address to place in the guarantee claims
RESOURCE_URL=http://localhost:9000/protected
RESOURCE_METHOD=GET       # optional, defaults to GET
FACILITATOR_URL=http://localhost:8080/  # optional, defaults to localhost
ASSET_ADDRESS=0x...       # asset used for tab funding and guarantees
```

Run from the repo root for debugging:
```
cargo run --example facilitator_rust
```
