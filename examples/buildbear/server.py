#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import random
from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal, ROUND_DOWN
from typing import Any, Dict, Optional, Tuple

import httpx
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional dependency
    load_dotenv = None

try:
    from eth_account import Account
except Exception:  # pragma: no cover - optional dependency
    Account = None

JsonDict = Dict[str, Any]


DEFAULT_FACILITATOR_URL = "https://x402.4mica.xyz"
DEFAULT_SCHEME = "4mica-credit"
DEFAULT_NETWORK = "eip155:80002"  # Polygon Amoy
DEFAULT_USDC_ADDRESS = "0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582"
DEFAULT_PRICE_USDC = "0.005"
DEFAULT_USDC_DECIMALS = 6
DEFAULT_SERVER_URL = "http://localhost:8402"
DEFAULT_DESCRIPTION = "x402 Minion NFT Generator (DALL-E)"
DEFAULT_RESOURCE = "minion-nft"
DEFAULT_TAB_TTL_SECONDS = 3600

PLACEHOLDER_PNG_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMA"
    "ASsJTYQAAAAASUVORK5CYII="
)

logger = logging.getLogger("buildbear.server")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


@dataclass
class ServerConfig:
    facilitator_url: str
    scheme: str
    network: str
    usdc_address: str
    price_usdc_base_units: str
    server_url: str
    recipient_address: str
    description: str
    resource: str
    tab_ttl_seconds: int


class MinionGenerator:
    def __init__(self) -> None:
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("OPENAI_IMAGE_MODEL", "gpt-image-1")

    async def generate(self) -> Tuple[str, Dict[str, str]]:
        traits = self._random_traits()
        prompt = (
            "Pixel art minion NFT, pastel background, "
            f"body {traits['body']}, eyes {traits['eyes']}, "
            f"goggles {traits['goggles']}, hair {traits['hair']}, "
            f"accessory {traits['accessory']}."
        )
        if not self.api_key:
            return PLACEHOLDER_PNG_BASE64, traits

        try:
            return await asyncio.to_thread(self._generate_openai, prompt, traits)
        except Exception as exc:  # pragma: no cover - network/external dependency
            logger.warning("OpenAI generation failed, using placeholder image: %s", exc)
            return PLACEHOLDER_PNG_BASE64, traits

    def _generate_openai(self, prompt: str, traits: Dict[str, str]) -> Tuple[str, Dict[str, str]]:
        try:
            from openai import OpenAI
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("openai package is not installed") from exc

        client = OpenAI(api_key=self.api_key)
        response = client.images.generate(
            model=self.model,
            prompt=prompt,
            size="1024x1024",
            response_format="b64_json",
        )
        data = response.data[0]
        b64_image = getattr(data, "b64_json", None)
        if not b64_image:
            raise RuntimeError("OpenAI response missing base64 image data")
        return b64_image, traits

    @staticmethod
    def _random_traits() -> Dict[str, str]:
        return {
            "body": random.choice(["yellow", "pastel yellow", "banana" ]),
            "eyes": random.choice(["brown", "red", "green", "blue"]),
            "goggles": random.choice(["silver", "gold", "bronze"]),
            "hair": random.choice(["mohawk", "short", "spiky", "none"]),
            "accessory": random.choice(["crown", "banana", "bow tie", "none"]),
        }


def _load_env() -> None:
    if load_dotenv is None:
        return
    load_dotenv()


def _decimal_to_base_units(value: str, decimals: int) -> str:
    quant = Decimal(10) ** decimals
    amount = (Decimal(value) * quant).to_integral_value(rounding=ROUND_DOWN)
    return str(int(amount))


def _resolve_recipient_address() -> str:
    recipient_address = os.getenv("RECIPIENT_ADDRESS")
    if recipient_address:
        return recipient_address

    recipient_key = os.getenv("RECIPIENT_KEY")
    if recipient_key and Account is not None:
        return Account.from_key(recipient_key).address
    if recipient_key and Account is None:
        raise RuntimeError("RECIPIENT_KEY is set but eth-account is not installed")

    raise RuntimeError("Set RECIPIENT_ADDRESS or RECIPIENT_KEY in the environment")


def _load_config() -> ServerConfig:
    _load_env()
    price_override = os.getenv("PRICE_USDC_BASE_UNITS")
    if price_override:
        price_usdc_base_units = price_override
    else:
        price_usdc = os.getenv("PRICE_USDC", DEFAULT_PRICE_USDC)
        decimals = int(os.getenv("USDC_DECIMALS", str(DEFAULT_USDC_DECIMALS)))
        price_usdc_base_units = _decimal_to_base_units(price_usdc, decimals)

    return ServerConfig(
        facilitator_url=os.getenv("FACILITATOR_URL", DEFAULT_FACILITATOR_URL),
        scheme=os.getenv("X402_SCHEME", DEFAULT_SCHEME),
        network=os.getenv("X402_NETWORK", DEFAULT_NETWORK),
        usdc_address=os.getenv("USDC_ADDRESS", DEFAULT_USDC_ADDRESS),
        price_usdc_base_units=price_usdc_base_units,
        server_url=os.getenv("SERVER_URL", DEFAULT_SERVER_URL).rstrip("/"),
        recipient_address=_resolve_recipient_address(),
        description=os.getenv("PAYMENT_DESCRIPTION", DEFAULT_DESCRIPTION),
        resource=os.getenv("PAYMENT_RESOURCE", DEFAULT_RESOURCE),
        tab_ttl_seconds=int(os.getenv("TAB_TTL_SECONDS", str(DEFAULT_TAB_TTL_SECONDS))),
    )


def _requirements_template(cfg: ServerConfig) -> JsonDict:
    return {
        "scheme": cfg.scheme,
        "network": cfg.network,
        "maxAmountRequired": cfg.price_usdc_base_units,
        "payTo": cfg.recipient_address,
        "asset": cfg.usdc_address,
        "description": cfg.description,
        "resource": cfg.resource,
        "extra": {"tabEndpoint": f"{cfg.server_url}/tab"},
    }


def _decode_x_payment(header: str) -> JsonDict:
    decoded = base64.b64decode(header).decode("utf-8")
    envelope = json.loads(decoded)
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("Missing payment payload")
    return payload


def _extract_user_address(payment_payload: JsonDict) -> Optional[str]:
    claims = payment_payload.get("claims")
    if not isinstance(claims, dict):
        return None
    user = claims.get("user_address")
    if isinstance(user, str):
        return user
    return None


async def _request_tab(
    client: httpx.AsyncClient,
    cfg: ServerConfig,
    user_address: str,
    requirements: JsonDict,
) -> JsonDict:
    url = f"{cfg.facilitator_url.rstrip('/')}/tabs"
    payload = {
        "userAddress": user_address,
        "recipientAddress": requirements.get("payTo"),
        "network": requirements.get("network"),
        "erc20Token": requirements.get("asset"),
        "ttlSeconds": cfg.tab_ttl_seconds,
    }
    response = await client.post(url, json=payload, timeout=15)
    response.raise_for_status()
    data = response.json()

    merged = deepcopy(requirements)
    extra = merged.get("extra") or {}
    extra.update(
        {
            "tabId": data.get("tabId"),
            "userAddress": data.get("userAddress"),
            "nextReqId": data.get("nextReqId"),
            "startTimestamp": data.get("startTimestamp"),
            "tabEndpoint": extra.get("tabEndpoint"),
        }
    )
    merged["extra"] = extra
    return {
        "tabId": data.get("tabId"),
        "userAddress": data.get("userAddress"),
        "nextReqId": data.get("nextReqId"),
        "paymentRequirements": merged,
    }


async def _verify_with_facilitator(
    client: httpx.AsyncClient,
    cfg: ServerConfig,
    payment_payload: JsonDict,
    requirements: JsonDict,
) -> Tuple[bool, Optional[JsonDict], Optional[str]]:
    url = f"{cfg.facilitator_url.rstrip('/')}/verify"
    payload = {
        "x402Version": 1,
        "paymentPayload": payment_payload,
        "paymentRequirements": requirements,
    }
    response = await client.post(url, json=payload, timeout=15)
    data = response.json()
    if response.is_success and data.get("isValid") is True:
        return True, data, None
    reason = data.get("invalidReason") or data.get("error") or "Facilitator rejected payment"
    return False, data, reason


async def _settle_with_facilitator(
    client: httpx.AsyncClient,
    cfg: ServerConfig,
    payment_payload: JsonDict,
    requirements: JsonDict,
) -> Tuple[bool, Optional[JsonDict], Optional[str]]:
    url = f"{cfg.facilitator_url.rstrip('/')}/settle"
    payload = {
        "x402Version": 1,
        "paymentPayload": payment_payload,
        "paymentRequirements": requirements,
    }
    response = await client.post(url, json=payload, timeout=15)
    data = response.json()
    if response.is_success and data.get("success") is True:
        return True, data, None
    reason = data.get("error") or "Facilitator rejected settlement"
    return False, data, reason


def create_app() -> FastAPI:
    cfg = _load_config()
    template_requirements = _requirements_template(cfg)
    generator = MinionGenerator()
    requirements_state: Dict[str, JsonDict] = {}

    app = FastAPI(title="x402 Minion NFT Generator")

    @app.get("/")
    async def index() -> JsonDict:
        return {
            "message": "x402 Minion NFT Generator",
            "network": cfg.network,
            "price_base_units": cfg.price_usdc_base_units,
            "resource": cfg.resource,
        }

    @app.post("/tab")
    async def open_tab(payload: JsonDict) -> JSONResponse:
        user_address = payload.get("userAddress") or payload.get("user_address")
        if not isinstance(user_address, str):
            return JSONResponse({"error": "userAddress is required"}, status_code=400)

        reqs = payload.get("paymentRequirements")
        if isinstance(reqs, dict):
            requirements = deepcopy(reqs)
            requirements.setdefault("extra", {})
            requirements["extra"].setdefault("tabEndpoint", f"{cfg.server_url}/tab")
        else:
            requirements = deepcopy(template_requirements)

        async with httpx.AsyncClient() as http:
            try:
                tab_response = await _request_tab(http, cfg, user_address, requirements)
            except httpx.HTTPError as exc:
                return JSONResponse(
                    {"error": f"failed to contact facilitator: {exc}"},
                    status_code=502,
                )

        requirements_state[user_address] = tab_response["paymentRequirements"]
        return JSONResponse(tab_response)

    @app.get("/image")
    async def get_image(x_payment: Optional[str] = Header(default=None, alias="X-PAYMENT")) -> JSONResponse:
        if not x_payment:
            return JSONResponse(
                {
                    "error": "Payment Required",
                    "paymentRequirements": template_requirements,
                },
                status_code=402,
            )

        try:
            payment_payload = _decode_x_payment(x_payment)
        except Exception as exc:
            return JSONResponse({"error": f"invalid X-PAYMENT header: {exc}"}, status_code=400)

        user_address = _extract_user_address(payment_payload)
        if not user_address:
            return JSONResponse(
                {
                    "error": "Unable to extract user address from payment payload",
                    "paymentRequirements": template_requirements,
                },
                status_code=402,
            )

        requirements = requirements_state.get(user_address)
        if not requirements:
            return JSONResponse(
                {
                    "error": "Unknown payment requirements; call /tab first",
                    "paymentRequirements": template_requirements,
                },
                status_code=402,
            )

        async with httpx.AsyncClient() as http:
            ok, verify_response, verify_error = await _verify_with_facilitator(
                http, cfg, payment_payload, requirements
            )
            if not ok:
                return JSONResponse({"error": verify_error}, status_code=402)

            img_base64, traits = await generator.generate()

            settled, settle_response, settle_error = await _settle_with_facilitator(
                http, cfg, payment_payload, requirements
            )
            if not settled:
                return JSONResponse({"error": settle_error}, status_code=402)

        return JSONResponse(
            {
                "image": img_base64,
                "traits": traits,
                "settlement": settle_response,
            }
        )

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="0.0.0.0", port=8402, reload=True)
