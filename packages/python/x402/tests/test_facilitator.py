import json

import pytest

httpx = pytest.importorskip("httpx")

from fourmica_x402.facilitator import (
    FourMicaFacilitatorClient,
    FourMicaFacilitatorClientSync,
    OpenTabError,
)
from x402.http import FacilitatorConfig


@pytest.mark.asyncio
async def test_open_tab_async_success():
    base_url = "http://fac.test"

    def handler(request):
        assert request.url.path == "/tabs"
        body = json.loads(request.content.decode())
        assert body["userAddress"] == "0xabc"
        return httpx.Response(
            200,
            json={
                "tabId": "0x1",
                "userAddress": "0xabc",
                "recipientAddress": "0xdef",
                "assetAddress": "0x0",
                "startTimestamp": 123,
                "ttlSeconds": 3600,
                "nextReqId": "0x2",
            },
        )

    transport = httpx.MockTransport(handler)
    async_client = httpx.AsyncClient(transport=transport)
    client = FourMicaFacilitatorClient(
        FacilitatorConfig(url=base_url, http_client=async_client)
    )

    try:
        resp = await client.open_tab("0xabc", {"payTo": "0xdef"}, ttl_seconds=3600)
        assert resp.tab_id == "0x1"
        assert resp.next_req_id == "0x2"
    finally:
        await async_client.aclose()


@pytest.mark.asyncio
async def test_open_tab_async_error():
    base_url = "http://fac.test"

    def handler(request):
        return httpx.Response(
            400,
            json={
                "tabId": "0x1",
                "userAddress": "0xabc",
                "recipientAddress": "0xdef",
                "assetAddress": "0x0",
                "startTimestamp": 123,
                "ttlSeconds": 3600,
                "nextReqId": "0x2",
            },
        )

    transport = httpx.MockTransport(handler)
    async_client = httpx.AsyncClient(transport=transport)
    client = FourMicaFacilitatorClient(
        FacilitatorConfig(url=base_url, http_client=async_client)
    )

    try:
        with pytest.raises(OpenTabError):
            await client.open_tab("0xabc", {"payTo": "0xdef"})
    finally:
        await async_client.aclose()


def test_open_tab_sync_success():
    base_url = "http://fac.test"

    def handler(request):
        return httpx.Response(
            200,
            json={
                "tabId": "0x1",
                "userAddress": "0xabc",
                "recipientAddress": "0xdef",
                "assetAddress": "0x0",
                "startTimestamp": 123,
                "ttlSeconds": 3600,
            },
        )

    transport = httpx.MockTransport(handler)
    sync_client = httpx.Client(transport=transport)
    client = FourMicaFacilitatorClientSync(
        FacilitatorConfig(url=base_url, http_client=sync_client)
    )

    resp = client.open_tab("0xabc", {"payTo": "0xdef"})
    assert resp.tab_id == "0x1"

    sync_client.close()


def test_open_tab_sync_error():
    base_url = "http://fac.test"

    def handler(request):
        return httpx.Response(400, json={"error": "bad"})

    transport = httpx.MockTransport(handler)
    sync_client = httpx.Client(transport=transport)
    client = FourMicaFacilitatorClientSync(
        FacilitatorConfig(url=base_url, http_client=sync_client)
    )

    with pytest.raises(OpenTabError):
        client.open_tab("0xabc", {"payTo": "0xdef"})

    sync_client.close()
