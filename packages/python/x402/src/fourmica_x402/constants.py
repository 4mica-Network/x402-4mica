"""Shared constants for 4mica x402 integration."""

from __future__ import annotations

from typing import Dict, List, TypedDict


SUPPORTED_NETWORKS: List[str] = ["eip155:11155111", "eip155:80002"]

DEFAULT_RPC_URLS: Dict[str, str] = {
    "eip155:11155111": "https://ethereum.sepolia.api.4mica.xyz",
    "eip155:80002": "https://api.4mica.xyz",
}


class DefaultAsset(TypedDict):
    address: str
    name: str
    version: str
    decimals: int


DEFAULT_ASSETS: Dict[str, DefaultAsset] = {
    "eip155:11155111": {
        "address": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
        "name": "USDC",
        "version": "2",
        "decimals": 6,
    },
    "eip155:80002": {
        "address": "0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582",
        "name": "USDC",
        "version": "2",
        "decimals": 6,
    },
}


class UnsupportedNetworkError(ValueError):
    """Raised when a network is not supported by 4mica defaults."""


def get_default_asset(network: str) -> DefaultAsset:
    try:
        return DEFAULT_ASSETS[network]
    except KeyError as exc:
        raise UnsupportedNetworkError(f"No default asset configured for network {network}") from exc
