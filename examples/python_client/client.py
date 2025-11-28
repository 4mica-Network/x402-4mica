"""Prepare and attach X-PAYMENT headers using the official Python SDK."""

import asyncio
import base64
import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fourmica_sdk import Client, ConfigBuilder, PaymentRequirements, X402Flow

# Load .env files
base = Path(__file__).resolve()
for path in [base.parents[1] / ".env", base.parents[2] / ".env"]:
    if path.exists():
        load_dotenv(path)

payer_key = os.getenv("PAYER_KEY")
user_address = os.getenv("USER_ADDRESS")
resource_url = os.getenv("RESOURCE_URL")

if not payer_key or not user_address or not resource_url:
    raise SystemExit("PAYER_KEY, USER_ADDRESS, and RESOURCE_URL must be set")


async def main() -> None:
    print("--- x402 / 4mica flow (Python SDK) ---")
    cfg = ConfigBuilder().wallet_private_key(payer_key).build()
    client = await Client.new(cfg)
    flow = X402Flow.from_client(client)

    async with httpx.AsyncClient() as http:
        resp = await http.get(resource_url)
    if resp.status_code != 402:
        raise SystemExit(f"expected HTTP 402 from the resource, got {resp.status_code}")
    body = resp.json()
    accepts = body.get("accepts") or []
    if not accepts:
        raise SystemExit("resource did not return any payment requirements in 'accepts'")
    requirements = PaymentRequirements.from_raw(accepts[0])

    payment = await flow.sign_payment(requirements, user_address)
    decoded = json.loads(base64.b64decode(payment.header).decode())

    print(f"\nX-PAYMENT header:\n{payment.header}\n")
    print("Decoded header:")
    print(json.dumps(decoded, indent=2))

    async with httpx.AsyncClient() as http:
        resource_resp = await http.get(resource_url, headers={"X-PAYMENT": payment.header})
    print("\nResponse from resource server:\n")
    try:
        print(json.dumps(resource_resp.json(), indent=2))
    except ValueError:
        print(resource_resp.text)

    await flow.http.aclose()
    await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
