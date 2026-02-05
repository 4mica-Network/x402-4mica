import pytest

pytest.importorskip("x402")
pytest.importorskip("fourmica_sdk")
pytest.importorskip("eth_account")

from fourmica_x402.client_scheme import FourMicaEvmScheme
from x402.schemas import PaymentRequirements
from x402.schemas.v1 import PaymentRequirementsV1


class StubSigned:
    def __init__(self, payload):
        self.payload = payload


class StubFlow:
    async def sign_payment_v2(self, payment_required, accepted, user_address):
        return StubSigned({"claims": {"tab_id": "0x1"}, "v": 2})

    async def sign_payment(self, requirements, user_address):
        return StubSigned({"claims": {"tab_id": "0x2"}, "v": 1})


class TestScheme(FourMicaEvmScheme):
    async def _create_flow(self, rpc_url: str):
        return StubFlow()


def test_create_payment_payload_v2():
    scheme = TestScheme("0x" + "1" * 64)
    req = PaymentRequirements(
        scheme="4mica-credit",
        network="eip155:11155111",
        asset="0xabc",
        amount="1",
        pay_to="0xdef",
        max_timeout_seconds=60,
        extra={},
    )
    payload = scheme.create_payment_payload(req)
    assert payload["v"] == 2
    assert payload["claims"]["tab_id"] == "0x1"


def test_create_payment_payload_v1():
    scheme = TestScheme("0x" + "1" * 64)
    req = PaymentRequirementsV1(
        scheme="4mica-credit",
        network="eip155:11155111",
        max_amount_required="1",
        resource="/",
        description=None,
        mime_type=None,
        pay_to="0xdef",
        max_timeout_seconds=60,
        asset="0xabc",
        output_schema=None,
        extra={},
    )
    payload = scheme.create_payment_payload(req)
    assert payload["v"] == 1
    assert payload["claims"]["tab_id"] == "0x2"
