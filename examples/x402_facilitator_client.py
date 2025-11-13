#!/usr/bin/env python3
"""
x402-4Mica client walkthrough.

Entities involved in a payment:
  - Client (this script): calls a protected resource, constructs the guarantee request,
    signs it with the user's private key, and submits the payment evidence to the facilitator.
  - Resource Server: exposes the paid API. When the user has not paid yet it answers 402 and
    returns the `paymentRequirements` that describe what must be signed.
  - Facilitator (x402-4Mica): verifies the signed header and asks 4Mica core for a BLS guarantee.

This script focuses on the client view:
  1. Call the paid API and extract the payment requirements.
  2. Build or load the X-PAYMENT header (base64 JSON envelope).
  3. Submit `/verify` or `/settle` to the facilitator and pretty-print the response.

Signing is intentionally pluggable: supply either an already signed payment header or provide the
claims JSON and signature (which you can obtain from your wallet tooling or the 4Mica Rust SDK).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple, Union


def _bootstrap_local_site_packages() -> None:
    """Allow running the script without manually activating the bundled virtualenv."""
    if os.environ.get("VIRTUAL_ENV"):
        return
    if os.environ.get("X402_SKIP_VENV_BOOTSTRAP"):
        return

    venv_root = Path(__file__).resolve().parents[1] / "venv"
    if not venv_root.exists():
        return

    candidates = [
        venv_root / "lib",
        venv_root / "Lib",  # Windows virtualenv layout
    ]
    for base in candidates:
        if not base.exists():
            continue
        for entry in base.iterdir():
            if not entry.is_dir():
                continue
            if not entry.name.lower().startswith("python"):
                continue
            site_packages = entry / "site-packages"
            if site_packages.exists():
                site_path = str(site_packages)
                if site_path not in sys.path:
                    sys.path.insert(0, site_path)


_bootstrap_local_site_packages()

import requests

JsonDict = Dict[str, Any]

ENV_DEFAULT_PATH = Path(__file__).with_name(".env")


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def load_env_map(path: Path) -> Dict[str, str]:
    data: Dict[str, str] = {}
    if not path.exists():
        return data

    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()
    return data


def resolve_config_value(
    keys: Union[str, Sequence[str]],
    env_map: Dict[str, str],
    *,
    required: bool = True,
    default: Optional[str] = None,
) -> Optional[str]:
    if isinstance(keys, str):
        key_list = (keys,)
    else:
        key_list = tuple(keys)

    for key in key_list:
        value = os.environ.get(key)
        if value is None:
            value = env_map.get(key)

        if value is not None and value.strip():
            return value.strip()

    if required:
        joined = "/".join(key_list)
        raise ValueError(f"missing configuration value for {joined}")
    return default


def parse_u256(value: Any, *, field: str) -> int:
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"{field} must be non-negative")
        return value
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string or integer value")

    trimmed = value.strip()
    if not trimmed:
        raise ValueError(f"{field} cannot be empty")
    try:
        if trimmed.lower().startswith("0x"):
            return int(trimmed, 16)
        return int(trimmed, 10)
    except ValueError as err:
        raise ValueError(f"{field} must be a hexadecimal or decimal number") from err


def canonical_u256(value: int) -> str:
    if value < 0:
        raise ValueError("u256 values cannot be negative")
    return hex(value)


def fetch_core_public_params(base_url: str, timeout: float = 10.0) -> JsonDict:
    url = f"{base_url.rstrip('/')}/core/public-params"
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return response.json()


def sign_payment_claim(
    *,
    params: JsonDict,
    private_key: str,
    scheme: str,
    user_address: str,
    recipient_address: str,
    asset_address: str,
    tab_id: int,
    amount: int,
    timestamp: int,
) -> str:
    try:
        from eth_account import Account
        from eth_account.messages import encode_typed_data
    except ImportError as err:
        raise RuntimeError(
            "eth-account is required for local signing. Install via "
            "pip install eth-account (matching the interpreter running this script)."
        ) from err

    if scheme != "eip712":
        raise ValueError(f"signing scheme {scheme!r} is not supported by the auto flow")

    chain_id = params.get("chain_id")
    if isinstance(chain_id, str):
        try:
            chain_id = int(chain_id, 0)
        except ValueError as err:
            raise ValueError("core public params chain_id must be numeric") from err
    if not isinstance(chain_id, int):
        raise ValueError("core public params missing numeric chain_id")

    typed_data: JsonDict = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "SolGuaranteeRequestClaimsV1": [
                {"name": "user", "type": "address"},
                {"name": "recipient", "type": "address"},
                {"name": "tabId", "type": "uint256"},
                {"name": "amount", "type": "uint256"},
                {"name": "asset", "type": "address"},
                {"name": "timestamp", "type": "uint64"},
            ],
        },
        "domain": {
            "name": params.get("eip712_name", ""),
            "version": params.get("eip712_version", ""),
            "chainId": chain_id,
        },
        "primaryType": "SolGuaranteeRequestClaimsV1",
        "message": {
            "user": user_address,
            "recipient": recipient_address,
            "tabId": tab_id,
            "amount": amount,
            "asset": asset_address,
            "timestamp": timestamp,
        },
    }

    signable = encode_typed_data(full_message=typed_data)
    signed = Account.sign_message(signable, private_key=private_key)
    return signed.signature.hex()


def _first_present(data: JsonDict, *options: str) -> Optional[Any]:
    for key in options:
        if key in data:
            return data[key]
    return None


def pretty_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def print_section(title: str, body: Optional[str] = None) -> None:
    line = "=" * len(title)
    print(f"\n{title}\n{line}")
    if body is not None:
        print(body)


def print_step(role: str, message: str) -> None:
    print(f"[{role}] {message}")


def load_json(path: str) -> JsonDict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


@dataclass
class PaymentRequirements:
    """x402 paymentRequirements payload issued by the resource server."""

    scheme: str
    network: str
    max_amount_required: str
    pay_to: str
    asset: str
    resource: Optional[str] = None
    description: Optional[str] = None
    mime_type: Optional[str] = None
    output_schema: Optional[JsonDict] = None
    max_timeout_seconds: Optional[int] = None
    extra: Optional[JsonDict] = None

    @classmethod
    def from_dict(cls, data: JsonDict) -> "PaymentRequirements":
        required = {
            "scheme": _first_present(data, "scheme"),
            "network": _first_present(data, "network"),
            "max_amount_required": _first_present(data, "maxAmountRequired", "max_amount_required"),
            "pay_to": _first_present(data, "payTo", "pay_to"),
            "asset": _first_present(data, "asset"),
        }
        missing = [field for field, value in required.items() if value is None]
        if missing:
            joined = ", ".join(sorted(missing))
            raise ValueError(f"payment requirements missing required fields: {joined}")
        max_timeout_raw = _first_present(data, "maxTimeoutSeconds", "max_timeout_seconds")
        max_timeout = int(max_timeout_raw) if max_timeout_raw is not None else None
        return cls(
            scheme=str(required["scheme"]),
            network=str(required["network"]),
            max_amount_required=str(required["max_amount_required"]),
            pay_to=str(required["pay_to"]),
            asset=str(required["asset"]),
            resource=_first_present(data, "resource"),
            description=_first_present(data, "description"),
            mime_type=_first_present(data, "mimeType", "mime_type"),
            output_schema=_first_present(data, "outputSchema", "output_schema"),
            max_timeout_seconds=max_timeout,
            extra=_first_present(data, "extra"),
        )

    def to_payload(self) -> JsonDict:
        payload: JsonDict = {
            "scheme": self.scheme,
            "network": self.network,
            "maxAmountRequired": self.max_amount_required,
            "payTo": self.pay_to,
            "asset": self.asset,
        }
        if self.resource is not None:
            payload["resource"] = self.resource
        if self.description is not None:
            payload["description"] = self.description
        if self.mime_type is not None:
            payload["mimeType"] = self.mime_type
        if self.output_schema is not None:
            payload["outputSchema"] = self.output_schema
        if self.max_timeout_seconds is not None:
            payload["maxTimeoutSeconds"] = self.max_timeout_seconds
        if self.extra is not None:
            payload["extra"] = self.extra
        return payload


@dataclass
class PaymentGuaranteeClaims:
    """Claims part of the guarantee payload that the user signs."""

    user_address: str
    recipient_address: str
    tab_id: str
    amount: str
    asset_address: str
    timestamp: int

    @classmethod
    def from_dict(cls, data: JsonDict) -> "PaymentGuaranteeClaims":
        try:
            timestamp_raw = data["timestamp"]
            timestamp = int(timestamp_raw)
        except KeyError as err:
            raise ValueError(f"claims missing required field: {err.args[0]}") from err

        return cls(
            user_address=str(data["user_address"]),
            recipient_address=str(data["recipient_address"]),
            tab_id=str(data["tab_id"]),
            amount=str(data["amount"]),
            asset_address=str(data["asset_address"]),
            timestamp=timestamp,
        )

    def to_json(self) -> JsonDict:
        return {
            "user_address": self.user_address,
            "recipient_address": self.recipient_address,
            "tab_id": self.tab_id,
            "amount": self.amount,
            "asset_address": self.asset_address,
            "timestamp": self.timestamp,
        }


def build_payment_header(
    *,
    claims: PaymentGuaranteeClaims,
    signature: str,
    scheme: str,
    network: str,
    version: int = 1,
    signing_scheme: str = "eip712",
) -> str:
    """Compose the base64 X-PAYMENT header to pass to the facilitator."""

    envelope = {
        "x402Version": version,
        "scheme": scheme,
        "network": network,
        "payload": {
            "claims": claims.to_json(),
            "signature": signature,
        },
    }
    if signing_scheme:
        envelope["payload"]["signingScheme"] = signing_scheme
    encoded = json.dumps(envelope, separators=(",", ":"), sort_keys=False)
    return base64.b64encode(encoded.encode("utf-8")).decode("utf-8")


ETH_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
ETH_SENTINEL_ADDRESS = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
DEPOSIT_SELECTOR = "0xd0e30db0"
DEPOSIT_STABLECOIN_SELECTOR = "0xa587f4f3"
ERC20_APPROVE_SELECTOR = "0x095ea7b3"
ERC20_ALLOWANCE_SELECTOR = "0xdd62ed3e"
DEFAULT_GAS_LIMIT = 200_000
ERC20_APPROVAL_GAS_LIMIT = 120_000
ERC20_DEPOSIT_GAS_LIMIT = 260_000


def ensure_collateral_for_request(
    *,
    core_url: str,
    rpc_url: str,
    contract_address: str,
    chain_id: int,
    signer: Any,
    asset_address: str,
    required_amount: int,
    timeout: float,
) -> None:
    """Ensure the caller has enough collateral recorded by 4Mica core."""

    if required_amount <= 0:
        return

    available, resolved_asset = _fetch_available_collateral(
        core_url=core_url,
        user_address=signer.address,
        asset_address=asset_address,
        timeout=timeout,
    )
    if available >= required_amount:
        print_step(
            "Collateral",
            f"Available collateral {canonical_u256(available)} already covers "
            f"required {canonical_u256(required_amount)}",
        )
        return

    missing = required_amount - available
    print_step(
        "Collateral",
        f"Insufficient collateral ({canonical_u256(available)} available) "
        f"– depositing {canonical_u256(missing)}",
    )

    resolved_contract = contract_address
    asset_for_chain = _normalize_asset_for_chain(resolved_asset)
    tx_hashes: Sequence[str]
    if _is_eth_asset(asset_for_chain):
        tx_hash = _send_eth_deposit(
            rpc_url=rpc_url,
            contract_address=resolved_contract,
            amount=missing,
            signer=signer,
            chain_id=chain_id,
            timeout=timeout,
        )
        tx_hashes = (tx_hash,)
    else:
        tx_hashes = _send_erc20_deposit(
            rpc_url=rpc_url,
            contract_address=resolved_contract,
            asset_address=asset_for_chain,
            amount=missing,
            signer=signer,
            chain_id=chain_id,
            timeout=timeout,
        )

    confirmations = []
    for tx_hash in tx_hashes:
        print_step("Collateral", f"Waiting for transaction {tx_hash} to finalize")
        receipt = _wait_for_receipt(rpc_url, tx_hash, timeout=timeout)
        confirmations.append(receipt.get("transactionHash", tx_hash))
    print_step("Collateral", f"Deposit confirmed ({', '.join(confirmations)})")

    updated, _ = _fetch_available_collateral(
        core_url=core_url,
        user_address=signer.address,
        asset_address=asset_address,
        timeout=timeout,
    )
    if updated < required_amount:
        raise RuntimeError(
            "deposit transaction confirmed but collateral is still below the required amount"
        )
    print_step(
        "Collateral",
        f"Collateral updated to {canonical_u256(updated)}; request requirement satisfied.",
    )


def _fetch_available_collateral(
    *,
    core_url: str,
    user_address: str,
    asset_address: str,
    timeout: float,
) -> Tuple[int, str]:
    candidates = _asset_aliases(asset_address)
    last_candidate = candidates[-1]
    base = core_url.rstrip("/")
    for candidate in candidates:
        url = f"{base}/core/users/{user_address}/assets/{candidate}"
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
        except requests.RequestException as err:
            raise RuntimeError(f"failed to query collateral via {url}: {err}") from err
        try:
            data = response.json()
        except ValueError as err:
            raise RuntimeError(f"invalid JSON returned by {url}") from err
        if not data:
            last_candidate = candidate
            continue
        total = parse_u256(data.get("total"), field="assetBalance.total")
        locked = parse_u256(data.get("locked", 0), field="assetBalance.locked")
        available = max(total - locked, 0)
        return available, candidate
    return 0, last_candidate


def _asset_aliases(asset_address: str) -> Sequence[str]:
    lowered = asset_address.lower()
    aliases = [asset_address]
    if lowered == ETH_SENTINEL_ADDRESS:
        aliases.append(ETH_ZERO_ADDRESS)
    elif lowered == ETH_ZERO_ADDRESS:
        aliases.append(ETH_SENTINEL_ADDRESS)
    return aliases


def _normalize_asset_for_chain(asset_address: str) -> str:
    if asset_address.lower() == ETH_SENTINEL_ADDRESS:
        return ETH_ZERO_ADDRESS
    return asset_address


def _is_eth_asset(asset_address: str) -> bool:
    lowered = asset_address.lower()
    return lowered in {ETH_ZERO_ADDRESS, ETH_SENTINEL_ADDRESS}


def _send_eth_deposit(
    *,
    rpc_url: str,
    contract_address: str,
    amount: int,
    signer: Any,
    chain_id: int,
    timeout: float,
) -> str:
    tx = {
        "to": contract_address,
        "value": amount,
        "gas": DEFAULT_GAS_LIMIT,
        "data": DEPOSIT_SELECTOR,
    }
    return _send_transaction(
        rpc_url=rpc_url,
        tx=tx,
        signer=signer,
        chain_id=chain_id,
        timeout=timeout,
    )


def _send_erc20_deposit(
    *,
    rpc_url: str,
    contract_address: str,
    asset_address: str,
    amount: int,
    signer: Any,
    chain_id: int,
    timeout: float,
) -> Sequence[str]:
    tx_hashes: list[str] = []
    allowance = _read_erc20_allowance(
        rpc_url=rpc_url,
        token_address=asset_address,
        owner=signer.address,
        spender=contract_address,
        timeout=timeout,
    )
    if allowance < amount:
        approval_data = _encode_call_data(
            ERC20_APPROVE_SELECTOR,
            ["address", "uint256"],
            [_encode_address(contract_address), amount],
        )
        approval_hash = _send_transaction(
            rpc_url=rpc_url,
            tx={
                "to": asset_address,
                "value": 0,
                "gas": ERC20_APPROVAL_GAS_LIMIT,
                "data": approval_data,
            },
            signer=signer,
            chain_id=chain_id,
            timeout=timeout,
        )
        tx_hashes.append(approval_hash)

    deposit_data = _encode_call_data(
        DEPOSIT_STABLECOIN_SELECTOR,
        ["address", "uint256"],
        [_encode_address(asset_address), amount],
    )
    deposit_hash = _send_transaction(
        rpc_url=rpc_url,
        tx={
            "to": contract_address,
            "value": 0,
            "gas": ERC20_DEPOSIT_GAS_LIMIT,
            "data": deposit_data,
        },
        signer=signer,
        chain_id=chain_id,
        timeout=timeout,
    )
    tx_hashes.append(deposit_hash)
    return tuple(tx_hashes)


def _read_erc20_allowance(
    *,
    rpc_url: str,
    token_address: str,
    owner: str,
    spender: str,
    timeout: float,
) -> int:
    data = _encode_call_data(
        ERC20_ALLOWANCE_SELECTOR,
        ["address", "address"],
        [_encode_address(owner), _encode_address(spender)],
    )
    call = {"to": token_address, "data": data}
    result = _rpc_request(
        rpc_url=rpc_url,
        method="eth_call",
        params=[call, "latest"],
        timeout=timeout,
    )
    if result is None:
        return 0
    return int(result, 16)


def _encode_call_data(signature: str, arg_types: Sequence[str], args: Sequence[Any]) -> str:
    try:
        from eth_abi import encode as abi_encode
    except ImportError as err:
        raise RuntimeError(
            "eth-abi is required for automatic collateral deposits. Install it via "
            "pip install eth-abi (matching this interpreter)."
        ) from err

    selector = signature[2:] if signature.startswith("0x") else signature
    encoded_args = abi_encode(arg_types, args)
    return "0x" + (bytes.fromhex(selector) + encoded_args).hex()


def _encode_address(value: str) -> bytes:
    clean = value.lower()
    if not clean.startswith("0x") or len(clean) != 42:
        raise ValueError(f"invalid address: {value}")
    return bytes.fromhex(clean[2:])


def _send_transaction(
    *,
    rpc_url: str,
    tx: Dict[str, Any],
    signer: Any,
    chain_id: int,
    timeout: float,
) -> str:
    gas_price_hex = _rpc_request(rpc_url, "eth_gasPrice", [], timeout=timeout)
    if gas_price_hex is None:
        raise RuntimeError("ethereum RPC returned null gas price")
    gas_price = int(gas_price_hex, 16)
    nonce_hex = _rpc_request(
        rpc_url,
        "eth_getTransactionCount",
        [signer.address, "pending"],
        timeout=timeout,
    )
    if nonce_hex is None:
        raise RuntimeError("ethereum RPC returned null nonce")
    nonce = int(nonce_hex, 16)
    tx_payload = {
        "chainId": chain_id,
        "nonce": nonce,
        "gas": tx.get("gas", DEFAULT_GAS_LIMIT),
        "gasPrice": tx.get("gasPrice", gas_price),
        "to": tx["to"],
        "value": tx.get("value", 0),
        "data": tx.get("data", "0x"),
    }
    signed = signer.sign_transaction(tx_payload)
    raw_tx = signed.raw_transaction.hex()
    tx_hash = _rpc_request(
        rpc_url,
        "eth_sendRawTransaction",
        [raw_tx],
        timeout=timeout,
    )
    if tx_hash is None:
        raise RuntimeError("ethereum RPC returned null for eth_sendRawTransaction")
    return tx_hash


def _wait_for_receipt(rpc_url: str, tx_hash: str, *, timeout: float) -> JsonDict:
    deadline = time.time() + max(30.0, timeout * 2)
    while time.time() < deadline:
        result = _rpc_request(
            rpc_url,
            "eth_getTransactionReceipt",
            [tx_hash],
            timeout=timeout,
        )
        if result:
            status_hex = result.get("status")
            if status_hex is not None and int(status_hex, 16) != 1:
                raise RuntimeError(f"transaction {tx_hash} failed with status {status_hex}")
            return result
        time.sleep(1.5)
    raise RuntimeError(f"timed out waiting for transaction {tx_hash} to be mined")


def _rpc_request(
    rpc_url: str,
    method: str,
    params: Sequence[Any],
    *,
    timeout: float,
) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    try:
        response = requests.post(rpc_url, json=payload, timeout=timeout)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as err:
        raise RuntimeError(f"ethereum RPC call {method} failed: {err}") from err
    except ValueError as err:
        raise RuntimeError(f"ethereum RPC call {method} returned invalid JSON") from err
    if "error" in data:
        error = data["error"]
        message = error.get("message", "unknown error") if isinstance(error, dict) else str(error)
        raise RuntimeError(f"ethereum RPC call {method} failed: {message}")
    return data.get("result")


# ---------------------------------------------------------------------------
# HTTP clients
# ---------------------------------------------------------------------------


class FacilitatorApi:
    """Minimal HTTP client for the x402-4Mica facilitator."""

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()

    def close(self) -> None:
        self._session.close()

    def supported(self) -> JsonDict:
        return self._get("/supported")

    def health(self) -> JsonDict:
        return self._get("/health")

    def verify(self, payload: JsonDict) -> JsonDict:
        return self._post("/verify", payload)

    def settle(self, payload: JsonDict) -> JsonDict:
        return self._post("/settle", payload)

    def _get(self, path: str) -> JsonDict:
        response = self._session.get(f"{self.base_url}{path}", timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, payload: JsonDict) -> JsonDict:
        response = self._session.post(
            f"{self.base_url}{path}",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()


class ResourceServerClient:
    """Helper to request a protected resource and capture its x402 payment instructions."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._session = requests.Session()

    def close(self) -> None:
        self._session.close()

    def fetch_requirements(self, url: str, method: str = "GET") -> Tuple[PaymentRequirements, JsonDict]:
        request_func = getattr(self._session, method.lower(), None)
        if request_func is None:
            raise ValueError(f"unsupported HTTP method: {method}")

        response = request_func(url, timeout=self.timeout)
        if response.status_code != 402:
            raise ValueError(
                f"expected 402 Payment Required, got {response.status_code} ({response.reason})"
            )

        payload = response.json()
        requirements_raw = payload.get("paymentRequirements")
        if requirements_raw is None:
            raise ValueError("response does not include paymentRequirements")
        requirements = PaymentRequirements.from_dict(requirements_raw)
        return requirements, payload


# ---------------------------------------------------------------------------
# CLI handlers
# ---------------------------------------------------------------------------


def run_supported(api: FacilitatorApi, _: argparse.Namespace) -> None:
    print_step("Client", "Querying facilitator for supported schemes")
    data = api.supported()
    print_section("Facilitator /supported", pretty_json(data))


def run_health(api: FacilitatorApi, _: argparse.Namespace) -> None:
    print_step("Client", "Checking facilitator health endpoint")
    data = api.health()
    print_section("Facilitator /health", pretty_json(data))


def _build_payment_payload(args: argparse.Namespace) -> Tuple[PaymentRequirements, str, JsonDict]:
    if args.requirements:
        requirements = PaymentRequirements.from_dict(load_json(args.requirements))
        print_step("Client", f"Loaded paymentRequirements from {args.requirements}")
    else:
        raise SystemExit("payment requirements are required (use --requirements)")

    if args.payment_header:
        header = args.payment_header.strip()
        print_step("Client", "Using pre-encoded payment header provided via CLI")
    else:
        if not args.claims or not args.signature:
            raise SystemExit("provide both --claims and --signature to build X-PAYMENT header")
        claims = PaymentGuaranteeClaims.from_dict(load_json(args.claims))
        header = build_payment_header(
            claims=claims,
            signature=args.signature,
            scheme=requirements.scheme,
            network=requirements.network,
            version=args.version,
            signing_scheme=args.signing_scheme,
        )
        print_step("Client", "Built X-PAYMENT header from claims + signature")

    payload = {
        "x402Version": args.version,
        "paymentHeader": header,
        "paymentRequirements": requirements.to_payload(),
    }
    return requirements, header, payload


def run_verify(api: FacilitatorApi, args: argparse.Namespace) -> None:
    print_step("Client", "Preparing verification request")
    _, header, payload = _build_payment_payload(args)

    print_section("X-PAYMENT Header (base64)", header)
    print_section("Request Body", pretty_json(payload))

    print_step("Client", "Submitting to facilitator /verify")
    response = api.verify(payload)
    print_section("Facilitator /verify response", pretty_json(response))


def run_settle(api: FacilitatorApi, args: argparse.Namespace) -> None:
    print_step("Client", "Preparing settlement request")
    _, header, payload = _build_payment_payload(args)

    print_section("X-PAYMENT Header (base64)", header)
    print_section("Request Body", pretty_json(payload))

    print_step("Client", "Submitting to facilitator /settle")
    response = api.settle(payload)
    print_section("Facilitator /settle response", pretty_json(response))


def run_discover(_: FacilitatorApi, args: argparse.Namespace) -> None:
    client = ResourceServerClient(timeout=args.timeout)
    try:
        print_step("Client", f"Calling paid API at {args.resource_url}")
        requirements, raw_payload = client.fetch_requirements(args.resource_url, args.method)

        print_section("Resource Server Response", pretty_json(raw_payload))
        print_section(
            "Extracted paymentRequirements",
            pretty_json(requirements.to_payload()),
        )

        if "paymentHeader" in raw_payload:
            print_section(
                "Pre-signed paymentHeader from server",
                raw_payload["paymentHeader"],
            )
        else:
            print_step(
                "Server",
                "Resource expects the client to sign claims locally (no paymentHeader provided)",
            )

        print_step(
            "Next",
            "Use --claims/--signature or --payment-header with the verify/settle commands to continue.",
        )
    finally:
        client.close()


def run_auto(api: FacilitatorApi, args: argparse.Namespace) -> None:
    try:
        try:
            from eth_account import Account
            from eth_utils import to_checksum_address
        except ImportError as err:
            import sys

            raise RuntimeError(
                "eth-account is required for the auto flow. Install it via "
                f"pip install eth-account using {sys.executable}."
            ) from err

        env_path = Path(args.env_file).expanduser()
        env_map = load_env_map(env_path)

        core_url = args.core_url or resolve_config_value(
            ("FOUR_MICA_RPC_URL", "4MICA_RPC_URL"),
            env_map,
            required=False,
            default="http://localhost:3000",
        )
        user_private_key = resolve_config_value("USER_PRIVATE_KEY", env_map)
        configured_user_address = resolve_config_value("USER_ADDRESS", env_map)
        signer = Account.from_key(user_private_key)
        signer_address = signer.address
        expected_user_address = to_checksum_address(configured_user_address)
        if signer_address.lower() != expected_user_address.lower():
            raise ValueError(
                "USER_PRIVATE_KEY does not match USER_ADDRESS. Update examples/.env with matching values."
            )

        client = ResourceServerClient(timeout=args.timeout)
        try:
            print_step("Client", f"Calling paid API at {args.resource_url}")
            requirements, discovery_payload = client.fetch_requirements(
                args.resource_url, args.method
            )
        finally:
            client.close()

        print_section("Resource Server Response", pretty_json(discovery_payload))
        print_section("Extracted paymentRequirements", pretty_json(requirements.to_payload()))

        if requirements.extra is None:
            raise ValueError("paymentRequirements.extra is required for the auto flow")

        extra = requirements.extra
        tab_id_raw = _first_present(extra, "tabId", "tab_id")
        user_from_requirements = _first_present(extra, "userAddress", "user_address")
        start_ts_raw = _first_present(extra, "startTimestamp", "start_timestamp")

        if tab_id_raw is None or user_from_requirements is None:
            raise ValueError("paymentRequirements.extra must include tabId and userAddress")

        requirement_user_address = to_checksum_address(str(user_from_requirements))
        if requirement_user_address.lower() != signer_address.lower():
            raise ValueError(
                f"Requirement userAddress {requirement_user_address} does not match signer {signer_address}"
            )

        recipient_address = to_checksum_address(requirements.pay_to)
        asset_address = to_checksum_address(requirements.asset)

        tab_id_int = parse_u256(tab_id_raw, field="requirements.extra.tabId")

        if args.amount:
            amount_source = args.amount
        else:
            amount_source = requirements.max_amount_required
        amount_int = parse_u256(amount_source, field="amount")

        if start_ts_raw is not None:
            timestamp = parse_u256(
                start_ts_raw, field="requirements.extra.startTimestamp"
            )
        elif args.timestamp:
            timestamp = args.timestamp
        else:
            timestamp = int(time.time())
        if timestamp <= 0:
            raise ValueError("timestamp must be a positive UNIX epoch value")

        claims = PaymentGuaranteeClaims(
            user_address=signer_address,
            recipient_address=recipient_address,
            tab_id=canonical_u256(tab_id_int),
            amount=canonical_u256(amount_int),
            asset_address=asset_address,
            timestamp=timestamp,
        )

        print_section("Prepared Claims", pretty_json(claims.to_json()))

        params = fetch_core_public_params(core_url, timeout=args.timeout)
        contract_address = params.get("contract_address")
        if not isinstance(contract_address, str):
            raise ValueError("core public params missing contract_address")
        ethereum_rpc_url = params.get("ethereum_http_rpc_url")
        if not isinstance(ethereum_rpc_url, str):
            raise ValueError("core public params missing ethereum_http_rpc_url")
        chain_id_value = params.get("chain_id")
        if isinstance(chain_id_value, str):
            try:
                chain_id_int = int(chain_id_value, 0)
            except ValueError as err:
                raise ValueError("core public params chain_id must be numeric") from err
        elif isinstance(chain_id_value, int):
            chain_id_int = chain_id_value
        else:
            raise ValueError("core public params missing numeric chain_id")

        ensure_collateral_for_request(
            core_url=core_url,
            rpc_url=ethereum_rpc_url,
            contract_address=to_checksum_address(contract_address),
            chain_id=chain_id_int,
            signer=signer,
            asset_address=asset_address,
            required_amount=amount_int,
            timeout=args.timeout,
        )

        signature = sign_payment_claim(
            params=params,
            private_key=user_private_key,
            scheme=args.signing_scheme,
            user_address=signer_address,
            recipient_address=recipient_address,
            asset_address=asset_address,
            tab_id=tab_id_int,
            amount=amount_int,
            timestamp=timestamp,
        )

        print_step("Client", f"Signed claims with scheme={args.signing_scheme}")
        print_section("Signature", signature)

        header = build_payment_header(
            claims=claims,
            signature=signature,
            scheme=requirements.scheme,
            network=requirements.network,
            version=args.version,
            signing_scheme=args.signing_scheme,
        )

        payload = {
            "x402Version": args.version,
            "paymentHeader": header,
            "paymentRequirements": requirements.to_payload(),
        }

        print_section("X-PAYMENT Header (base64)", header)
        print_section("Facilitator Request Payload", pretty_json(payload))

        pre_verify_response: Optional[JsonDict] = None
        if args.pre_verify:
            print_step("Client", "Submitting to facilitator /verify (pre-check)")
            pre_verify_response = api.verify(payload)
            print_section("Facilitator /verify response", pretty_json(pre_verify_response))
        else:
            print_step(
                "Client",
                "Skipping direct /verify (resource retry will trigger facilitator validation).",
            )

        resource_success = False
        if not args.skip_resource_retry:
            print_step("Client", "Retrying resource with generated X-PAYMENT header")
            try:
                retry = requests.request(
                    args.method,
                    args.resource_url,
                    headers={"X-PAYMENT": header},
                    timeout=args.timeout,
                )
            except requests.RequestException as err:
                print_step("Client", f"Resource retry failed: {err}")
                raise SystemExit("resource retry failed; see error above.") from err
            else:
                status_line = f"{retry.status_code} {retry.reason}"
                print_section("Resource Retry Status", status_line)
                body_text: Optional[str]
                payload_json: Optional[Any] = None
                try:
                    payload_json = retry.json()
                except ValueError:
                    body_text = retry.text
                else:
                    body_text = pretty_json(payload_json)
                print_section("Resource Response Body", body_text or "<empty>")
                resource_success = retry.status_code == 200
                if (
                    payload_json
                    and isinstance(payload_json, dict)
                    and "verify" in payload_json
                    and isinstance(payload_json["verify"], dict)
                ):
                    print_section(
                        "Facilitator /verify response (from resource)",
                        pretty_json(payload_json["verify"]),
                    )
                    if pre_verify_response is None:
                        pre_verify_response = payload_json["verify"]
        else:
            print_step("Client", "Skipping resource retry per --skip-resource-retry flag")
            resource_success = True

        if not resource_success:
            raise SystemExit(
                "resource retry returned a non-success status; inspect the output above for details."
            )

        if not args.skip_settle:
            print_step("Client", "Submitting to facilitator /settle")
            settle_response = api.settle(payload)
            print_section("Facilitator /settle response", pretty_json(settle_response))
        else:
            print_step("Client", "Skipping /settle per --skip-settle flag")

        print_step("Done", "Replayed resource with X-PAYMENT; copy the header above if you need it again.")
    except (ValueError, RuntimeError) as err:
        raise SystemExit(f"auto flow error: {err}") from err


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Client utilities for interacting with an x402-4Mica facilitator.",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8080",
        help="Facilitator base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds (default: %(default)s)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    supported_parser = subparsers.add_parser(
        "supported",
        help="Client ➜ Facilitator: read advertised (scheme, network) pairs.",
    )
    supported_parser.set_defaults(handler=run_supported)

    health_parser = subparsers.add_parser(
        "health",
        help="Client ➜ Facilitator: check readiness/health.",
    )
    health_parser.set_defaults(handler=run_health)

    discover_parser = subparsers.add_parser(
        "discover",
        help="Client ➜ Resource server: request the paid API and capture payment requirements.",
    )
    discover_parser.add_argument(
        "--resource-url",
        required=True,
        help="URL of the paid API endpoint.",
    )
    discover_parser.add_argument(
        "--method",
        default="GET",
        help="HTTP method to use (default: %(default)s).",
    )
    discover_parser.set_defaults(handler=run_discover)

    auto_parser = subparsers.add_parser(
        "auto",
        help="End-to-end: call the resource, sign locally, and submit verify/settle.",
    )
    auto_parser.add_argument(
        "--resource-url",
        required=True,
        help="URL of the paid API endpoint.",
    )
    auto_parser.add_argument(
        "--method",
        default="GET",
        help="HTTP method to use for discovery (default: %(default)s).",
    )
    auto_parser.add_argument(
        "--env-file",
        default=str(ENV_DEFAULT_PATH),
        help="Path to a .env file with USER_* credentials (default: %(default)s).",
    )
    auto_parser.add_argument(
        "--core-url",
        help="Override FOUR_MICA_RPC_URL / 4MICA_RPC_URL for fetching core public parameters.",
    )
    auto_parser.add_argument(
        "--amount",
        help="Override the signed payment amount (hex or decimal). Defaults to maxAmountRequired.",
    )
    auto_parser.add_argument(
        "--timestamp",
        type=int,
        help="Override the timestamp used in the signed claims (seconds since epoch).",
    )
    auto_parser.add_argument(
        "--skip-settle",
        action="store_true",
        help="Only invoke /verify and skip the facilitator /settle step.",
    )
    auto_parser.add_argument(
        "--skip-resource-retry",
        action="store_true",
        help="Do not retry the resource server with the generated X-PAYMENT header.",
    )
    auto_parser.add_argument(
        "--pre-verify",
        action="store_true",
        help="Submit /verify before hitting the resource (useful for debugging).",
    )
    auto_parser.add_argument(
        "--signing-scheme",
        default="eip712",
        choices=["eip712", "eip191"],
        help="Signing scheme to use for the guarantee (default: %(default)s).",
    )
    auto_parser.add_argument(
        "--version",
        type=int,
        default=1,
        help="x402Version to send (default: %(default)s).",
    )
    auto_parser.set_defaults(handler=run_auto)

    verify_parser = subparsers.add_parser(
        "verify",
        help="Client ➜ Facilitator: submit a verify request with signed header.",
    )
    _add_payment_args(verify_parser)
    verify_parser.set_defaults(handler=run_verify)

    settle_parser = subparsers.add_parser(
        "settle",
        help="Client ➜ Facilitator: perform the settlement acknowledgement.",
    )
    _add_payment_args(settle_parser)
    settle_parser.set_defaults(handler=run_settle)

    return parser


def _add_payment_args(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--requirements",
        help="Path to JSON file with paymentRequirements (from resource server).",
    )
    subparser.add_argument(
        "--claims",
        help="Path to JSON file with the guarantee claims to sign.",
    )
    subparser.add_argument(
        "--signature",
        help="Wallet signature (0x-prefixed string) over the claims.",
    )
    subparser.add_argument(
        "--payment-header",
        help="Pre-built base64 X-PAYMENT header. Overrides --claims/--signature.",
    )
    subparser.add_argument(
        "--signing-scheme",
        default="eip712",
        choices=["eip712", "eip191"],
        help="Signing scheme used for the guarantee (default: %(default)s).",
    )
    subparser.add_argument(
        "--version",
        type=int,
        default=1,
        help="x402Version to send (default: %(default)s).",
    )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "discover":
        run_discover(None, args)
        return

    api = FacilitatorApi(base_url=args.base_url, timeout=args.timeout)
    try:
        args.handler(api, args)
    except requests.RequestException as err:
        raise SystemExit(f"HTTP error: {err}") from err
    except ValueError as err:
        raise SystemExit(f"error: {err}") from err
    finally:
        api.close()


if __name__ == "__main__":
    main()
