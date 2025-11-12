#!/usr/bin/env python3
"""
Mock paid API that uses the x402 payment protocol to protect a resource.

The mock server acts as the resource server from the protocol diagram:
  • When a client calls the paid endpoint without a payment, respond with 402
    and embed `paymentRequirements` describing what has to be signed.
  • If a client supplies an X-PAYMENT header the server asks the facilitator to
    verify it and, on success, returns the protected resource payload. A static
    fallback signature is still accepted for quick smoke tests.

Run with:

    uvicorn mock_paid_api:app --reload --port 9000 --factory

The `factory` option lets uvicorn call `create_app()` so we can update the
requirements easily when extending the example.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple, Union

import requests
from fastapi import FastAPI, Header, status
from fastapi.responses import JSONResponse

JsonDict = Dict[str, Any]


ENV_PATH = Path(__file__).with_name(".env")
DEFAULT_SCHEME = "4mica-guarantee"
DEFAULT_NETWORK = "4mica-mainnet"
DEFAULT_MAX_AMOUNT = "0x2386f26fc10000"  # 0.01 ETH
DEFAULT_ASSET = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
DEFAULT_DESCRIPTION = "Demo paid API – 4Mica tab verification required"
DEFAULT_RESOURCE = "mock-paid-endpoint"
DEFAULT_CORE_URL = "http://localhost:3000"
DEFAULT_FACILITATOR_URL = "http://localhost:8080"

_ENV_FILE_CACHE: Optional[Dict[str, str]] = None
_REQUIREMENTS_CACHE: Optional[JsonDict] = None
_TAB_STATE: Dict[str, Any] = {"tab_id": None, "start_timestamp": None}


def _load_env_file() -> Dict[str, str]:
    global _ENV_FILE_CACHE
    if _ENV_FILE_CACHE is not None:
        return _ENV_FILE_CACHE

    data: Dict[str, str] = {}
    if ENV_PATH.exists():
        with ENV_PATH.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                data[key.strip()] = value.strip()

    _ENV_FILE_CACHE = data
    return data


def _config_value(
    keys: Union[str, Sequence[str]],
    *,
    required: bool = True,
    default: Optional[str] = None,
) -> Optional[str]:
    """Read configuration from environment variables or the local .env file."""
    key_list: Tuple[str, ...]
    if isinstance(keys, str):
        key_list = (keys,)
    else:
        key_list = tuple(keys)

    env_file = _load_env_file()
    for key in key_list:
        value = os.environ.get(key)
        if value is None:
            value = env_file.get(key)
        if value is not None and value.strip():
            return value.strip()

    if not required:
        return default

    joined = "/".join(key_list)
    raise RuntimeError(
        f"Missing configuration for {joined}. Provide it via environment or {ENV_PATH}."
    )



def _normalize_address(value: str, *, field: str) -> str:
    addr = value.strip()
    if not addr.lower().startswith("0x"):
        raise RuntimeError(f"{field} must be a 0x-prefixed hexadecimal address.")
    if len(addr) != 42:
        raise RuntimeError(f"{field} must be a 42-character 0x-prefixed Ethereum address.")
    return addr


def _as_hex_u256(value: Any) -> str:
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, str):
        trimmed = value.strip()
        if not trimmed:
            raise RuntimeError("U256 value cannot be empty.")
        if trimmed.lower().startswith("0x"):
            digits = trimmed[2:].lstrip("0") or "0"
            return "0x" + digits.lower()
        return f"0x{int(trimmed, 10):x}"
    raise RuntimeError(f"Unsupported U256 representation: {value!r}")


def _parse_optional_int(name: str, value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value, 10)
    except ValueError as err:
        raise RuntimeError(f"{name} must be an integer value.") from err


def _ensure_payment_tab(
    user_address: str,
    recipient_address: str,
    ttl_seconds: Optional[int],
    erc20_token: Optional[str],
) -> str:
    base_url = _config_value(
        ("FOUR_MICA_RPC_URL", "4MICA_RPC_URL"),
        required=False,
        default=DEFAULT_CORE_URL,
    )
    existing = _TAB_STATE.get("tab_id")
    if existing is None:
        url = f"{base_url.rstrip('/')}/core/payment-tabs"
        payload = {
            "user_address": user_address,
            "recipient_address": recipient_address,
            "erc20_token": erc20_token,
            "ttl": ttl_seconds,
        }

        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
        except requests.RequestException as err:
            raise RuntimeError(f"Failed to create payment tab via {url}: {err}") from err

        data = response.json()
        tab_id = data.get("id")
        if tab_id is None:
            raise RuntimeError("4Mica response missing tab id.")
        tab_id_hex = _as_hex_u256(tab_id)
        _TAB_STATE["tab_id"] = tab_id_hex
    else:
        tab_id_hex = existing

    if _TAB_STATE.get("start_timestamp") is None:
        _TAB_STATE["start_timestamp"] = int(time.time())

    return tab_id_hex


def _build_payment_requirements() -> JsonDict:
    # Ensure required values exist (even if unused in this module yet).
    _config_value("USER_PRIVATE_KEY")

    user_address = _normalize_address(
        _config_value("USER_ADDRESS"),
        field="USER_ADDRESS",
    )
    recipient_address = _normalize_address(
        _config_value("RECIPIENT_ADDRESS"),
        field="RECIPIENT_ADDRESS",
    )
    asset_address = _normalize_address(
        _config_value("ASSET_ADDRESS", required=False, default=DEFAULT_ASSET),
        field="ASSET_ADDRESS",
    )

    max_amount_required = _as_hex_u256(
        _config_value("MAX_AMOUNT_WEI", required=False, default=DEFAULT_MAX_AMOUNT)
    )
    description = _config_value("PAYMENT_DESCRIPTION", required=False, default=DEFAULT_DESCRIPTION)
    resource_name = _config_value("PAYMENT_RESOURCE", required=False, default=DEFAULT_RESOURCE)
    scheme = _config_value("X402_SCHEME", required=False, default=DEFAULT_SCHEME)
    network = _config_value("X402_NETWORK", required=False, default=DEFAULT_NETWORK)

    ttl_seconds = _parse_optional_int(
        "TAB_TTL_SECONDS",
        _config_value("TAB_TTL_SECONDS", required=False),
    )

    erc20_token = _config_value("ERC20_TOKEN", required=False)
    if erc20_token:
        erc20_token = _normalize_address(erc20_token, field="ERC20_TOKEN")

    tab_id = _ensure_payment_tab(user_address, recipient_address, ttl_seconds, erc20_token)
    start_ts = _TAB_STATE.get("start_timestamp")
    if start_ts is None:
        start_ts = int(time.time())
        _TAB_STATE["start_timestamp"] = start_ts

    requirements: JsonDict = {
        "scheme": scheme,
        "network": network,
        "maxAmountRequired": max_amount_required,
        "payTo": recipient_address,
        "asset": asset_address,
        "description": description,
        "resource": resource_name,
        "extra": {
            "tabId": tab_id,
            "userAddress": user_address,
            "startTimestamp": str(start_ts),
        },
    }

    return requirements


def encode_demo_header(requirements: JsonDict) -> str:
    payload = {
        "x402Version": 1,
        "scheme": requirements["scheme"],
        "network": requirements["network"],
        "payload": {
            "claims": {
                "user_address": requirements["extra"]["userAddress"],
                "recipient_address": requirements["payTo"],
                "tab_id": requirements["extra"]["tabId"],
                "amount": requirements["maxAmountRequired"],
                "asset_address": requirements["asset"],
                "timestamp": 1,
            },
            "signature": "0xdeadbeef",
            "signingScheme": "eip712",
        },
    }
    encoded = json.dumps(payload, separators=(",", ":"))
    return base64.b64encode(encoded.encode("utf-8")).decode("utf-8")


def payment_requirements(*, refresh: bool = False) -> JsonDict:
    raw = os.environ.get("MOCK_REQUIREMENTS_JSON")
    if raw:
        return json.loads(raw)

    global _REQUIREMENTS_CACHE
    if refresh or _REQUIREMENTS_CACHE is None:
        _REQUIREMENTS_CACHE = _build_payment_requirements()
    # return a copy so callers can mutate safely
    return json.loads(json.dumps(_REQUIREMENTS_CACHE))


def expected_header(requirements: JsonDict) -> str:
    override = os.environ.get("MOCK_EXPECTED_HEADER")
    if override:
        return override
    return encode_demo_header(requirements)


def verify_with_facilitator(
    facilitator_url: str, header: str, requirements: JsonDict
) -> Tuple[bool, Optional[JsonDict], Optional[str]]:
    payload = {
        "x402Version": 1,
        "paymentHeader": header,
        "paymentRequirements": json.loads(json.dumps(requirements)),
    }
    endpoint = f"{facilitator_url.rstrip('/')}/verify"
    try:
        response = requests.post(endpoint, json=payload, timeout=10)
        response.raise_for_status()
    except requests.RequestException as err:
        return False, None, f"failed to contact facilitator at {endpoint}: {err}"

    data = response.json()
    if data.get("isValid") is True:
        return True, data, None

    reason = data.get("invalidReason") or "facilitator rejected payment"
    return False, data, reason


def create_app() -> FastAPI:
    app = FastAPI(title="Mock Paid API")

    requirements_state: Dict[str, Optional[JsonDict]] = {"current": None}
    expected_state: Dict[str, Optional[str]] = {"value": None}
    facilitator_url = _config_value(
        "FACILITATOR_URL",
        required=False,
        default=DEFAULT_FACILITATOR_URL,
    )

    def refresh_requirements() -> JsonDict:
        reqs = payment_requirements(refresh=True)
        requirements_state["current"] = reqs
        expected_state["value"] = expected_header(reqs)
        return reqs

    def current_requirements() -> JsonDict:
        if requirements_state["current"] is None:
            return refresh_requirements()
        return requirements_state["current"]

    @app.get("/")
    async def index() -> JsonDict:
        return {
            "message": "Mock paid API",
            "protected": "/protected",
            "hint": "Call /protected without X-PAYMENT to receive paymentRequirements.",
        }

    @app.get("/protected")
    async def protected_resource(
        x_payment: Optional[str] = Header(default=None, alias="X-PAYMENT")
    ) -> JSONResponse:
        if x_payment is None:
            reqs = refresh_requirements()
            response_body = {
                "error": "payment required",
                "paymentRequirements": reqs,
            }
            return JSONResponse(response_body, status_code=status.HTTP_402_PAYMENT_REQUIRED)

        requirements = current_requirements()
        expected = expected_state["value"]
        if expected is None:
            expected = expected_header(requirements)
            expected_state["value"] = expected

        success, verify_response, failure_reason = verify_with_facilitator(
            facilitator_url, x_payment, requirements
        )
        if success:
            body: JsonDict = {"message": "paid content"}
            tab_id = requirements.get("extra", {}).get("tabId")
            if tab_id is not None:
                body["tab"] = tab_id
            if verify_response is not None:
                body["verify"] = verify_response
            requirements_state["current"] = None
            expected_state["value"] = None
            return JSONResponse(body)

        if x_payment == expected:
            body: JsonDict = {"message": "paid content"}
            tab_id = requirements.get("extra", {}).get("tabId")
            if tab_id is not None:
                body["tab"] = tab_id
            requirements_state["current"] = None
            expected_state["value"] = None
            return JSONResponse(body)

        response_body = {
            "error": "payment required",
            "paymentRequirements": requirements,
        }
        if failure_reason:
            response_body["hint"] = failure_reason
        else:
            response_body["hint"] = "header does not match the demo signature"
        if verify_response is not None:
            response_body["facilitatorResponse"] = verify_response
        requirements_state["current"] = None
        expected_state["value"] = None
        return JSONResponse(response_body, status_code=status.HTTP_402_PAYMENT_REQUIRED)

    return app


def app() -> FastAPI:
    return create_app()


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "9000"))
    uvicorn.run(create_app(), host="0.0.0.0", port=port)
