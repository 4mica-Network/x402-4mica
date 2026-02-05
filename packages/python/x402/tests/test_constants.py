import pytest

from fourmica_x402.constants import (
    DEFAULT_ASSETS,
    DEFAULT_RPC_URLS,
    SUPPORTED_NETWORKS,
    UnsupportedNetworkError,
    get_default_asset,
)


def test_supported_networks_match_expected():
    assert SUPPORTED_NETWORKS == ["eip155:11155111", "eip155:80002"]


def test_default_rpc_urls_match_expected():
    assert DEFAULT_RPC_URLS["eip155:11155111"] == "https://ethereum.sepolia.api.4mica.xyz"
    assert DEFAULT_RPC_URLS["eip155:80002"] == "https://api.4mica.xyz"


def test_default_assets_match_expected():
    assert DEFAULT_ASSETS["eip155:11155111"]["address"] == "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
    assert DEFAULT_ASSETS["eip155:11155111"]["decimals"] == 6
    assert DEFAULT_ASSETS["eip155:80002"]["address"] == "0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582"
    assert DEFAULT_ASSETS["eip155:80002"]["decimals"] == 6


def test_get_default_asset_raises_on_unsupported_network():
    with pytest.raises(UnsupportedNetworkError):
        get_default_asset("eip155:1")
