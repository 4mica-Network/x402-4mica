# 4mica-x402

Python integration for the x402 Payment Protocol with 4mica credit flow support.

## Install

```bash
pip install 4mica-x402
```

Optional extras:
- `fastapi` (FastAPI middleware)
- `flask` (Flask middleware)
- `httpx` (async HTTP client wrapper)
- `requests` (sync HTTP client wrapper)
- `all` (everything)

## Quick Start (Server)

```python
from fastapi import FastAPI
from fourmica_x402.http import fastapi_payment_middleware_from_config

app = FastAPI()

routes = {
    "GET /premium": {
        "accepts": {
            "scheme": "4mica-credit",
            "price": "$0.01",
            "network": "eip155:11155111",
            "payTo": "0xRecipient",
        }
    }
}

middleware = fastapi_payment_middleware_from_config(
    routes,
    tab_endpoint="https://api.example.com/payment/tab",
)

@app.middleware("http")
async def x402_mw(request, call_next):
    return await middleware(request, call_next)
```

## Quick Start (Client)

```python
from x402 import x402ClientSync
from x402.http.clients import x402_requests
from fourmica_x402.client_scheme import FourMicaEvmScheme

client = x402ClientSync()
client.register("eip155:11155111", FourMicaEvmScheme("0xYourPrivateKey"))

session = x402_requests(client)
resp = session.get("https://api.example.com/premium")
print(resp.status_code, resp.text)
```

## V2 Validation Policy Notes

For x402 V2 requests, include validation policy metadata in `paymentRequirements.extra`:

- `validationRegistryAddress`
- `validatorAddress`
- `validatorAgentId`
- `minValidationScore`
- optional `requiredValidationTag`

`validationChainId` is optional. When omitted, the underlying 4mica SDK derives
`validation_chain_id` from the CAIP-2 `network` value (for example, `eip155:1`).
If provided, it must match that network chain id.

## Development

```bash
python -m build
python -m pytest
```

Install dev tools:

```bash
pip install -e .[dev]
```
