#!/usr/bin/env python3
"""
Mock paid API that uses the x402 payment protocol to protect a resource.

The mock server acts as the resource server from the protocol diagram:
  • When a client calls the paid endpoint without a payment, respond with 402,
    advertise the supported scheme/network, and point the client at `/tab`
    so they can request a tab with their wallet address.
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
import binascii
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
DEFAULT_FACILITATOR_URL = "http://localhost:8080"

_ENV_FILE_CACHE: Optional[Dict[str, str]] = None
_TAB_STATE: Dict[str, Dict[str, Any]] = {}


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
) -> Dict[str, Any]:
    existing = _TAB_STATE.get(user_address)
    now = int(time.time())
    if existing is not None:
        stored_ttl = existing.get("ttl_seconds")
        start_ts = existing.get("start_timestamp", now)
        if stored_ttl and stored_ttl > 0 and (start_ts + stored_ttl) <= now:
            existing = None
        else:
            return dict(existing)

    facilitator_url = _config_value(
        "FACILITATOR_URL",
        required=False,
        default=DEFAULT_FACILITATOR_URL,
    )
    url = f"{facilitator_url.rstrip('/')}/tabs"
    payload = {
        "user_address": user_address,
        "recipient_address": recipient_address,
        "erc20_token": erc20_token,
        "ttl_seconds": ttl_seconds,
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
    except requests.HTTPError as err:
        message = _extract_error_from_response(err.response)
        raise RuntimeError(
            f"Facilitator rejected payment tab ({err.response.status_code}): {message}"
        ) from err
    except requests.RequestException as err:
        raise RuntimeError(f"Failed to request payment tab via facilitator at {url}: {err}") from err

    data = response.json()
    tab_id = data.get("tabId")
    if tab_id is None:
        raise RuntimeError("Facilitator response missing tabId.")

    def _parse_int(value: Any, *, field: str, default: int) -> int:
        if value is None:
            return default
        try:
            return int(value)
        except (TypeError, ValueError) as err:
            raise RuntimeError(f"Facilitator response included invalid {field}") from err

    start_timestamp = _parse_int(
        data.get("startTimestamp"),
        field="startTimestamp",
        default=now,
    )
    ttl_value = _parse_int(
        data.get("ttlSeconds"),
        field="ttlSeconds",
        default=ttl_seconds or 0,
    )

    tab_state = {
        "tab_id": str(tab_id),
        "asset_address": data.get("assetAddress"),
        "start_timestamp": start_timestamp,
        "ttl_seconds": ttl_value,
    }
    _TAB_STATE[user_address] = tab_state
    return dict(tab_state)


def _extract_error_from_response(response: Optional[requests.Response]) -> str:
    if response is None:
        return "unknown error"
    try:
        payload = response.json()
    except ValueError:
        text = response.text.strip()
        return text or "unknown error"
    if isinstance(payload, dict) and "error" in payload:
        return str(payload["error"])
    return response.text.strip() or "unknown error"


def _build_payment_requirements(user_address: str) -> JsonDict:
    recipient_address = _normalize_address(
        _config_value("RECIPIENT_ADDRESS"),
        field="RECIPIENT_ADDRESS",
    )
    configured_asset = _normalize_address(
        _config_value("ASSET_ADDRESS", required=False, default=DEFAULT_ASSET),
        field="ASSET_ADDRESS",
    )
    tab_asset = _TAB_STATE.get("asset_address")
    if tab_asset:
        asset_address = _normalize_address(tab_asset, field="assetAddress")
    else:
        asset_address = configured_asset

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

    tab_data = _ensure_payment_tab(user_address, recipient_address, ttl_seconds, erc20_token)
    tab_id = tab_data["tab_id"]
    start_ts = tab_data.get("start_timestamp", int(time.time()))
    tab_asset = tab_data.get("asset_address")
    if tab_asset:
        asset_address = _normalize_address(tab_asset, field="assetAddress")
    else:
        asset_address = configured_asset

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


def _requirements_template() -> JsonDict:
    recipient_address = _normalize_address(
        _config_value("RECIPIENT_ADDRESS"),
        field="RECIPIENT_ADDRESS",
    )
    configured_asset = _normalize_address(
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

    template: JsonDict = {
        "scheme": scheme,
        "network": network,
        "maxAmountRequired": max_amount_required,
        "payTo": recipient_address,
        "asset": configured_asset,
        "description": description,
        "resource": resource_name,
        "extra": None,
    }
    return template


def _load_custom_requirements() -> Optional[JsonDict]:
    raw = os.environ.get("MOCK_REQUIREMENTS_JSON")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError as err:
        raise RuntimeError("MOCK_REQUIREMENTS_JSON must contain valid JSON") from err


def _maybe_normalize_address(value: Any, *, field: str) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        return _normalize_address(value, field=field)
    except RuntimeError:
        return None


def _user_address_from_header(header: str) -> Optional[str]:
    trimmed = header.strip()
    if not trimmed:
        return None
    try:
        decoded = base64.b64decode(trimmed)
        payload = json.loads(decoded)
    except (ValueError, binascii.Error):
        return None

    claims_payload = payload.get("payload")
    if not isinstance(claims_payload, dict):
        return None
    claims = claims_payload.get("claims")
    if not isinstance(claims, dict):
        return None
    return _maybe_normalize_address(claims.get("user_address"), field="claims.user_address")


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

    requirements_state: Dict[str, JsonDict] = {}
    expected_state: Dict[str, Optional[str]] = {}
    facilitator_url = _config_value(
        "FACILITATOR_URL",
        required=False,
        default=DEFAULT_FACILITATOR_URL,
    )
    template_requirements = _requirements_template()
    tab_endpoint = "/tab"

    def _clone_requirements(requirements: JsonDict) -> JsonDict:
        return json.loads(json.dumps(requirements))

    def _record_requirements(user_address: str, requirements: JsonDict) -> None:
        requirements_state[user_address] = _clone_requirements(requirements)
        expected_state[user_address] = expected_header(requirements)

    def _active_requirements(user_address: str) -> Optional[JsonDict]:
        entry = requirements_state.get(user_address)
        if entry is None:
            return None
        return _clone_requirements(entry)

    def _clear_user_state(user_address: str) -> None:
        requirements_state.pop(user_address, None)
        expected_state.pop(user_address, None)

    @app.get("/")
    async def index() -> JsonDict:
        return {
            "message": "Mock paid API",
            "protected": "/protected",
            "hint": "Call /protected without X-PAYMENT to discover the required scheme.",
        }

    @app.post("/tab")
    async def issue_tab(payload: JsonDict) -> JSONResponse:
        user_address_raw = payload.get("userAddress") or payload.get("user_address")
        if not isinstance(user_address_raw, str):
            body = {"error": "userAddress is required"}
            return JSONResponse(body, status_code=status.HTTP_400_BAD_REQUEST)
        try:
            user_address = _normalize_address(user_address_raw, field="userAddress")
        except RuntimeError as err:
            return JSONResponse({"error": str(err)}, status_code=status.HTTP_400_BAD_REQUEST)

        override = _load_custom_requirements()
        if override is not None:
            requirements = _clone_requirements(override)
        else:
            requirements = _build_payment_requirements(user_address)
        _record_requirements(user_address, requirements)

        extra = requirements.get("extra") or {}
        response_body: JsonDict = {
            "tabId": extra.get("tabId"),
            "paymentRequirements": requirements,
        }
        if extra.get("startTimestamp"):
            response_body["startTimestamp"] = extra["startTimestamp"]
        response_body["userAddress"] = user_address
        return JSONResponse(response_body)

    @app.get("/protected")
    async def protected_resource(
        x_payment: Optional[str] = Header(default=None, alias="X-PAYMENT")
    ) -> JSONResponse:
        if x_payment is None:
            response_body = {
                "error": "payment required",
                "paymentRequirementsTemplate": template_requirements,
                "tabEndpoint": tab_endpoint,
                "hint": "Send POST /tab with { userAddress } to mint payment requirements for your wallet.",
            }
            return JSONResponse(response_body, status_code=status.HTTP_402_PAYMENT_REQUIRED)

        user_address = _user_address_from_header(x_payment)
        if user_address is None:
            response_body = {
                "error": "invalid payment header",
                "hint": "Unable to extract user address; request a tab and retry.",
                "tabEndpoint": tab_endpoint,
            }
            return JSONResponse(response_body, status_code=status.HTTP_402_PAYMENT_REQUIRED)

        requirements = _active_requirements(user_address)
        if requirements is None:
            response_body = {
                "error": "tab required",
                "hint": "Call POST /tab with your wallet to receive paymentRequirements.",
                "tabEndpoint": tab_endpoint,
            }
            return JSONResponse(response_body, status_code=status.HTTP_402_PAYMENT_REQUIRED)

        expected = expected_state.get(user_address)
        if expected is None:
            expected = expected_header(requirements)
            expected_state[user_address] = expected

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
            _clear_user_state(user_address)
            return JSONResponse(body)

        if x_payment == expected:
            body: JsonDict = {"message": "paid content"}
            tab_id = requirements.get("extra", {}).get("tabId")
            if tab_id is not None:
                body["tab"] = tab_id
            _clear_user_state(user_address)
            return JSONResponse(body)

        response_body = {
            "error": "payment required",
            "paymentRequirements": requirements,
            "tabEndpoint": tab_endpoint,
        }
        if failure_reason:
            response_body["hint"] = failure_reason
        else:
            response_body["hint"] = "header does not match the demo signature"
        if verify_response is not None:
            response_body["facilitatorResponse"] = verify_response
        return JSONResponse(response_body, status_code=status.HTTP_402_PAYMENT_REQUIRED)

    return app


def app() -> FastAPI:
    return create_app()


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "9000"))
    uvicorn.run(create_app(), host="0.0.0.0", port=port)
