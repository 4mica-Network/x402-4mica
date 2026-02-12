# Building a Paid AI API with x402 Micropayments Using 4mica SDK

Learn how to monetize your API with cryptocurrency micropayments using the HTTP 402 Payment Required protocol.

## Introduction

Imagine building an API where every request automatically handles payment, no subscription management, no
invoicing, no payment processors taking 3% cuts. Just pure pay-per-use with instant settlement.

This is what the x402 protocol enables, and in this tutorial, we'll build a fully functional AI-powered NFT generator
that accepts cryptocurrency micropayments using the 4mica SDK.

By the end of this tutorial, you'll have:

- A FastAPI server that generates DALL-E minion NFTs for $0.005 USDC each
- An AI agent (using LangGraph + OpenAI) that autonomously pays for and collects NFTs
- A working understanding of the x402 payment flow

Time to complete: 30 minutes
Prerequisites: Python 3.9+, basic understanding of async Python, an Ethereum wallet

## What is 4mica?

4mica is a decentralized payment network built on blockchain infrastructure that enables instant, trustless financial
exchanges. At its core is the concept of credit tabs, configurable lines of credit between users and service providers.
Think of it like opening a bar tab: you deposit collateral upfront, consume services, and settle later. But unlike a bar
tab, everything is cryptographically secured and verifiable on-chain.

The sdk-4mica Python library provides:

- Tab Management: Create and manage per-user credit ledgers
- Guarantee Signing: Sign payment guarantees for a specific request
- Facilitator Integration: Verify and settle guarantees without writing cryptography
- X402Flow: Build X-PAYMENT headers for x402-protected endpoints

## How x402 Works (Credit Flow)

1. Client calls a protected endpoint without payment.
2. Server responds with `402 Payment Required` and `paymentRequirements`.
3. Client calls the server `POST /tab` endpoint to open or reuse a tab.
4. Client uses `X402Flow` to sign the guarantee and constructs the `X-PAYMENT` header.
5. Client retries the request with `X-PAYMENT`.
6. Server calls the facilitator `/verify` endpoint to validate the payment payload.
7. Server performs the protected work.
8. Server calls the facilitator `/settle` endpoint to obtain the BLS certificate.
9. Server returns the resource data (and optionally the settlement).

The beauty of this flow is that payments happen within the HTTP request lifecycle, no webhooks, no polling, no
eventual consistency headaches.

## Project Setup

### 1. Install Dependencies

```bash
pip install 'sdk-4mica[bls]' fastapi uvicorn httpx langchain-openai langgraph openai python-dotenv eth-account
```

The `[bls]` extra installs `py-ecc` for BLS signature support, which enables advanced cryptographic features.

### 2. Configure Environment

Create a `.env` file:

```bash
# Server wallet (recipient)
RECIPIENT_KEY=0x...your_private_key...
RECIPIENT_ADDRESS=0x...your_address... # required for this example

# Agent wallet (payer)
PAYER_KEY=0x...your_private_key...

# OpenAI for AI agent and DALL-E image generation
OPENAI_API_KEY=sk-...

# Network configuration
USDC_ADDRESS=0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582
X402_NETWORK=eip155:80002
SERVER_URL=http://localhost:8402
FACILITATOR_URL=https://x402.4mica.xyz
```

Note: We're using Polygon Amoy testnet. Get test USDC from the Polygon Faucet.

## Building the Server (Recipient)

The server generates AI-powered minion NFTs using DALL-E and accepts payments via x402. It uses the hosted
facilitator to open tabs, verify guarantees, and settle payments.

### Initialize the Server Configuration

```python
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
import base64
import httpx
import json
import os

DEFAULT_FACILITATOR_URL = "https://x402.4mica.xyz"
DEFAULT_NETWORK = "eip155:80002"
FACILITATOR_URL = os.getenv("FACILITATOR_URL", DEFAULT_FACILITATOR_URL)

def requirements_template():
    return {
        "scheme": "4mica-credit",
        "network": os.getenv("X402_NETWORK", DEFAULT_NETWORK),
        "maxAmountRequired": "5000",  # 0.005 USDC with 6 decimals
        "payTo": os.environ["RECIPIENT_ADDRESS"],
        "asset": os.getenv("USDC_ADDRESS"),
        "description": "x402 Minion NFT Generator (DALL-E)",
        "resource": "minion-nft",
        "extra": {
            "tabEndpoint": f\"{os.getenv('SERVER_URL', 'http://localhost:8402')}/tab\",
        },
    }
```

### Create the Tab Endpoint

When a client wants to pay, they first need a tab, a credit ledger that tracks their payments.
Your `/tab` endpoint calls the facilitator `POST /tabs` and returns the enriched requirements.

```python
app = FastAPI()
requirements_state = {}


@app.post("/tab")
async def open_tab(payload: dict):
    user_address = payload["userAddress"]
    base_requirements = payload.get("paymentRequirements") or requirements_template()

    async with httpx.AsyncClient() as http:
        response = await http.post(
            f\"{FACILITATOR_URL}/tabs\",
            json={
                "userAddress": user_address,
                "recipientAddress": base_requirements["payTo"],
                "network": base_requirements["network"],
                "erc20Token": base_requirements["asset"],
                "ttlSeconds": 3600,
            },
        )
        response.raise_for_status()
        tab = response.json()

    base_requirements["extra"].update(
        {
            "tabId": tab.get("tabId"),
            "userAddress": tab.get("userAddress"),
            "nextReqId": tab.get("nextReqId"),
            "startTimestamp": tab.get("startTimestamp"),
        }
    )
    requirements_state[user_address] = base_requirements
    return {"tabId": tab.get("tabId"), "userAddress": tab.get("userAddress"), "nextReqId": tab.get("nextReqId"), "paymentRequirements": base_requirements}
```

### Implement the Paid Endpoint

The magic happens in the `/image` endpoint. It returns `402 Payment Required` if no payment is provided.
When a payment is present, the server verifies and settles with the facilitator.

```python
def decode_x_payment(header: str) -> dict:
    decoded = base64.b64decode(header).decode("utf-8")
    envelope = json.loads(decoded)
    return envelope["payload"]


@app.get("/image")
async def get_image(x_payment: str | None = Header(default=None, alias="X-PAYMENT")):
    if not x_payment:
        return JSONResponse(
            status_code=402,
            content={"error": "Payment Required", "paymentRequirements": requirements_template()},
        )

    payment_payload = decode_x_payment(x_payment)  # base64 -> dict with claims/signature
    user_address = payment_payload["claims"]["user_address"]
    requirements = requirements_state.get(user_address)
    if not requirements:
        return JSONResponse(status_code=402, content={"error": "Call /tab first"})

    async with httpx.AsyncClient() as http:
        verify = await http.post(
            f\"{FACILITATOR_URL}/verify\",
            json={"x402Version": 1, "paymentPayload": payment_payload, "paymentRequirements": requirements},
        )
        if verify.json().get("isValid") is not True:
            return JSONResponse(status_code=402, content={"error": verify.json().get("invalidReason")})

        # Generate the NFT with DALL-E (or a placeholder if OpenAI is not configured)
        img_base64, traits = await generator.generate()

        settle = await http.post(
            f\"{FACILITATOR_URL}/settle\",
            json={"x402Version": 1, "paymentPayload": payment_payload, "paymentRequirements": requirements},
        )
        if settle.json().get("success") is not True:
            return JSONResponse(status_code=402, content={"error": settle.json().get("error")})

    return {"image": img_base64, "traits": traits, "settlement": settle.json()}
```

The facilitator at `https://x402.4mica.xyz` handles cryptographic verification and settlement, you don't
need to implement the complex signature verification yourself.

## Building the AI Agent (Payer)

Now for the fun part, an AI agent that autonomously pays for and collects NFTs.

### Set Up the X402Flow

The SDK provides `X402Flow` to handle the payment signing:

```python
from fourmica_sdk import Client, ConfigBuilder, X402Flow, PaymentRequirementsV1
from eth_account import Account
import os

PAYER_KEY = os.environ["PAYER_KEY"]

async def get_payer_client():
    cfg = ConfigBuilder().wallet_private_key(PAYER_KEY).build()
    client = await Client.new(cfg)
    flow = X402Flow.from_client(client)
    return client, flow
```

### Create the NFT Collection Tool

Using LangChain's `@tool` decorator, we create a function the AI agent can call:

```python
@tool
async def get_minion_nft() -> str:
    client, flow = await get_payer_client()
    payer_address = Account.from_key(PAYER_KEY).address
    try:
        async with httpx.AsyncClient() as http:
            # Step 1: Request image, get 402
            resp = await http.get(f\"{SERVER_URL}/image\")
            if resp.status_code != 402:
                return json.dumps({\"error\": \"Unexpected response\"})

            # Step 2: Parse payment requirements
            requirements_raw = resp.json()[\"paymentRequirements\"]
            requirements = PaymentRequirementsV1.from_raw(requirements_raw)

            # Step 3: Sign payment with X402Flow
            payment = await flow.sign_payment(requirements, payer_address)

            # Step 4: Retry with payment header
            image_resp = await http.get(
                f\"{SERVER_URL}/image\",
                headers={\"X-PAYMENT\": payment.header},
            )
            return json.dumps(image_resp.json())
    finally:
        await client.aclose()
```

The `X402Flow.sign_payment()` method handles all the cryptographic complexity, creating the payment
guarantee, signing it with your wallet, and encoding it as a base64 header.

### Build the LangGraph Agent

Wire everything together with LangGraph:

```python
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_openai import ChatOpenAI

def build_agent():
    llm = ChatOpenAI(model="gpt-4o", temperature=0)
    tools = [get_minion_nft]
    llm_with_tools = llm.bind_tools(tools)

    async def agent_node(state):
        response = await llm_with_tools.ainvoke(state["messages"])
        return {"messages": [response]}

    workflow = StateGraph(AgentState)
    workflow.add_node("agent", agent_node)
    workflow.add_node("tools", ToolNode(tools))
    workflow.set_entry_point("agent")
    workflow.add_conditional_edges("agent", should_continue)
    workflow.add_edge("tools", "agent")
    return workflow.compile()
```

## Running the Complete System

### Terminal 1: Start the Server

```bash
python server.py
```

```
==================================================
 x402 Minion NFT Generator (DALL-E)
==================================================
 Network   | eip155:80002
 Price     | 0.005 USDC
 Generator | OpenAI (gpt-image-1)
 Port      | 8402
==================================================
```

### Terminal 2: Run the Agent

```bash
python agent.py
```

```
==================================================
 x402 Minion NFT Collector Agent
==================================================
 Server  | http://localhost:8402
 Network | Polygon Amoy
 Model   | gpt-4o
==================================================
```

You: get me a minion

```
==================================================
 MINION #42069 [RARE]
==================================================

Image returned as base64 in the JSON response

Traits:
 Body: yellow | Eyes: red | Goggles: gold
 Hair: mohawk | Accessory: crown
 Cyclops: No | Overalls: denim
==================================================
```

## Key Takeaways

- x402 enables pay-per-request APIs without traditional payment infrastructure
- 4mica SDK abstracts away the complexity of blockchain payments with a clean async Python API
- Credit tabs allow efficient batching of micropayments
- The facilitator handles verification and settlement, so you don't need to implement cryptography
- AI agents can autonomously pay for services using the X402Flow helper

## Resources

- sdk-4mica on PyPI
- 4mica Documentation
- 4mica x402 Examples
- Polygon Amoy Faucet
