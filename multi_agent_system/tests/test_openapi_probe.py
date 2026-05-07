"""Tests for openapi_probe - extended paths + HTML extraction + rich metadata."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from multi_agent_system.agents.modules.openapi_probe import (
    probe_openapi,
    parse_openapi_spec,
    _extract_spec_url_from_html,
)


def test_parse_openapi_spec_includes_parameters():
    spec = {
        "paths": {
            "/api/BasketItems": {
                "post": {
                    "parameters": [
                        {"name": "basketId", "in": "body"},
                        {"name": "productId", "in": "body"},
                    ],
                    "consumes": ["application/json"],
                }
            },
            "/api/FileUpload": {
                "post": {
                    "consumes": ["multipart/form-data"],
                    "parameters": [],
                }
            },
        }
    }
    result = parse_openapi_spec(spec)
    basket_ep = next(e for e in result if e["path"] == "/api/BasketItems")
    assert basket_ep["method"] == "POST"
    assert "basketId" in basket_ep.get("response_signature", {}).get("sample_keys", [])

    upload_ep = next(e for e in result if e["path"] == "/api/FileUpload")
    assert upload_ep.get("response_signature", {}).get("content_type") == "multipart/form-data"


def test_extract_spec_url_from_swagger_ui_html():
    html = """
    <html><head><title>Swagger UI</title></head><body>
    <script>
    const ui = SwaggerUIBundle({ url: "/api-docs/swagger.json", dom_id: '#swagger-ui' })
    </script></body></html>
    """
    url = _extract_spec_url_from_html(html)
    assert url == "/api-docs/swagger.json"


def test_extract_spec_url_returns_none_for_plain_html():
    html = "<html><body><h1>Welcome</h1></body></html>"
    url = _extract_spec_url_from_html(html)
    assert url is None


@pytest.mark.asyncio
async def test_probe_openapi_follows_html_redirect_to_spec():
    """When /api-docs returns Swagger UI HTML, probe should follow embedded spec URL."""
    swagger_ui_html = (
        '<html><script>SwaggerUIBundle({ url: "/api-docs/swagger.json" })</script></html>'
    )
    spec_json = json.dumps({
        "paths": {
            "/rest/user/login": {"post": {}},
        }
    })

    call_count = {"n": 0}

    async def mock_get(url):
        call_count["n"] += 1
        resp = MagicMock()
        if url.endswith("/api-docs"):
            resp.status_code = 200
            resp.headers = {"content-type": "text/html"}
            resp.text = swagger_ui_html
            resp.json = MagicMock(side_effect=Exception("not json"))
        elif url.endswith("/api-docs/swagger.json"):
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            resp.text = spec_json
            resp.json = MagicMock(return_value=json.loads(spec_json))
        else:
            resp.status_code = 404
        return resp

    client = MagicMock()
    client.get = AsyncMock(side_effect=mock_get)
    result = await probe_openapi("http://juice-shop:3000", client)
    assert any(e["path"] == "/rest/user/login" for e in result), f"Got: {result}"
    assert call_count["n"] >= 2


@pytest.mark.asyncio
async def test_probe_openapi_tries_extended_paths():
    from multi_agent_system.agents.modules.openapi_probe import OPENAPI_PATHS
    assert "/api-docs/swagger.json" in OPENAPI_PATHS
    assert "/swagger/v1/swagger.json" in OPENAPI_PATHS
