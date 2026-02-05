import pytest

pytest.importorskip("x402")
fastapi = pytest.importorskip("fastapi")
flask = pytest.importorskip("flask")

from fourmica_x402.http import (
    fastapi_payment_middleware_from_config,
    flask_payment_middleware_from_config,
)


def test_fastapi_wrapper_builds():
    app = fastapi.FastAPI()
    routes = {
        "GET /protected": {
            "accepts": {
                "scheme": "4mica-credit",
                "payTo": "0xabc",
                "price": "$0.01",
                "network": "eip155:11155111",
            }
        }
    }

    middleware = fastapi_payment_middleware_from_config(
        routes,
        tab_endpoint="http://localhost:3000/payment/tab",
    )

    @app.middleware("http")
    async def x402_mw(request, call_next):
        return await middleware(request, call_next)

    assert middleware is not None


def test_flask_wrapper_builds():
    app = flask.Flask(__name__)
    routes = {
        "GET /protected": {
            "accepts": {
                "scheme": "4mica-credit",
                "payTo": "0xabc",
                "price": "$0.01",
                "network": "eip155:11155111",
            }
        }
    }

    middleware = flask_payment_middleware_from_config(
        app,
        routes,
        tab_endpoint="http://localhost:3000/payment/tab",
    )

    assert middleware is not None
