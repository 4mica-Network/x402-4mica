# Python SDK Example (fourmica_sdk)

The x402-4mica facilitator repo includes a Python example that uses `sdk-4mica`.

## Install
```bash
pip install sdk-4mica
```

## Example
```python
import asyncio
from fourmica_sdk import Client, ConfigBuilder, PaymentRequirements, X402Flow

payer_key = "0x..."
user_address = "0x..."

async def main():
    cfg = ConfigBuilder().wallet_private_key(payer_key).rpc_url("https://api.4mica.xyz/").build()
    client = await Client.new(cfg)
    flow = X402Flow.from_client(client)

    req_raw = fetch_requirements_somehow()[0]
    requirements = PaymentRequirements.from_raw(req_raw)

    payment = await flow.sign_payment(requirements, user_address)
    headers = {"X-PAYMENT": payment.header}

    await client.aclose()

asyncio.run(main())
```
