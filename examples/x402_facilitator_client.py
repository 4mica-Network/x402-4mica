#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

JsonDict = Dict[str, Any]


def _first_present(data: JsonDict, *options: str) -> Optional[Any]:
    for key in options:
        if key in data:
            return data[key]
    return None


@dataclass
class PaymentRequirements:
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
        missing = [k for k, v in required.items() if v is None]
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
    user_address: str
    recipient_address: str
    tab_id: str
    req_id: str
    amount: str
    asset_address: str
    timestamp: int

    @classmethod
    def from_dict(cls, data: JsonDict) -> "PaymentGuaranteeClaims":
        try:
            timestamp_raw = data["timestamp"]
            timestamp = int(timestamp_raw)
            return cls(
                user_address=str(data["user_address"]),
                recipient_address=str(data["recipient_address"]),
                tab_id=str(data["tab_id"]),
                req_id=str(data["req_id"]),
                amount=str(data["amount"]),
                asset_address=str(data["asset_address"]),
                timestamp=timestamp,
            )
        except KeyError as err:
            raise ValueError(f"claims missing required field: {err.args[0]}") from err

    def to_json(self) -> JsonDict:
        return {
            "user_address": self.user_address,
            "recipient_address": self.recipient_address,
            "tab_id": self.tab_id,
            "req_id": self.req_id,
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


class X402FacilitatorClient:
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

    def verify(
        self,
        *,
        payment_header: str,
        requirements: PaymentRequirements,
        version: int = 1,
    ) -> JsonDict:
        payload = {
            "x402Version": version,
            "paymentHeader": payment_header,
            "paymentRequirements": requirements.to_payload(),
        }
        return self._post("/verify", payload)

    def settle(
        self,
        *,
        payment_header: str,
        requirements: PaymentRequirements,
        version: int = 1,
    ) -> JsonDict:
        payload = {
            "x402Version": version,
            "paymentHeader": payment_header,
            "paymentRequirements": requirements.to_payload(),
        }
        return self._post("/settle", payload)

    def _get(self, path: str) -> JsonDict:
        response = self._session.get(
            f"{self.base_url}{path}",
            timeout=self.timeout,
        )
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


def load_json(path: str) -> JsonDict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def cli_supported(client: X402FacilitatorClient, _: argparse.Namespace) -> None:
    result = client.supported()
    print(json.dumps(result, indent=2))


def cli_health(client: X402FacilitatorClient, _: argparse.Namespace) -> None:
    result = client.health()
    print(json.dumps(result, indent=2))


def _resolve_payment_header(args: argparse.Namespace, requirements: PaymentRequirements) -> str:
    if args.payment_header:
        return args.payment_header.strip()
    if not args.signature:
        raise SystemExit("either --payment-header or --signature must be provided")
    if not args.claims:
        raise SystemExit("--claims is required when building a payment header")
    claims_data = load_json(args.claims)
    claims = PaymentGuaranteeClaims.from_dict(claims_data)
    return build_payment_header(
        claims=claims,
        signature=args.signature,
        scheme=requirements.scheme,
        network=requirements.network,
        version=args.version,
        signing_scheme=args.signing_scheme,
    )


def _load_requirements(path: str) -> PaymentRequirements:
    data = load_json(path)
    return PaymentRequirements.from_dict(data)


def cli_verify(client: X402FacilitatorClient, args: argparse.Namespace) -> None:
    requirements = _load_requirements(args.requirements)
    payment_header = _resolve_payment_header(args, requirements)
    result = client.verify(
        payment_header=payment_header,
        requirements=requirements,
        version=args.version,
    )
    print(json.dumps(result, indent=2))


def cli_settle(client: X402FacilitatorClient, args: argparse.Namespace) -> None:
    requirements = _load_requirements(args.requirements)
    payment_header = _resolve_payment_header(args, requirements)
    result = client.settle(
        payment_header=payment_header,
        requirements=requirements,
        version=args.version,
    )
    print(json.dumps(result, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Interact with an x402-4Mica facilitator instance.",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8080",
        help="Base URL for the facilitator (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds (default: %(default)s)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    supported_parser = subparsers.add_parser("supported", help="Fetch supported (scheme, network) pairs.")
    supported_parser.set_defaults(handler=cli_supported)

    health_parser = subparsers.add_parser("health", help="Check facilitator health status.")
    health_parser.set_defaults(handler=cli_health)

    verify_parser = subparsers.add_parser("verify", help="Submit a payment verification request.")
    _add_payment_args(verify_parser)
    verify_parser.set_defaults(handler=cli_verify)

    settle_parser = subparsers.add_parser("settle", help="Submit a settlement (acknowledgement) request.")
    _add_payment_args(settle_parser)
    settle_parser.set_defaults(handler=cli_settle)

    return parser


def _add_payment_args(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument(
        "--requirements",
        required=True,
        help="Path to a JSON file containing paymentRequirements payload.",
    )
    subparser.add_argument(
        "--claims",
        help="Path to a JSON file with guarantee claims (ignored if --payment-header is provided).",
    )
    subparser.add_argument(
        "--signature",
        help="User signature for the guarantee payload (0x-prefixed).",
    )
    subparser.add_argument(
        "--payment-header",
        help="Pre-encoded base64 payment header. Skips local encoding.",
    )
    subparser.add_argument(
        "--signing-scheme",
        default="eip712",
        choices=["eip712", "eip191"],
        help="Signing scheme for the guarantee payload (default: %(default)s).",
    )
    subparser.add_argument(
        "--version",
        type=int,
        default=1,
        help="x402Version value to send (default: %(default)s).",
    )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    client = X402FacilitatorClient(base_url=args.base_url, timeout=args.timeout)
    try:
        args.handler(client, args)
    except requests.RequestException as err:
        raise SystemExit(f"HTTP error: {err}") from err
    finally:
        client.close()


if __name__ == "__main__":
    main()
