import asyncio
import sys
import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

# information_gathering.py lives in information-gathering/ (a sibling of multi_agent_system/)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "information-gathering"))


def test_derive_api_prefixes_from_existing_endpoints():
    from information_gathering import _derive_api_prefixes
    endpoints = [
        "http://t/api/products",
        "http://t/rest/user/login",
        "http://t/graphql",
        "http://t/static/main.js",
    ]
    prefixes = _derive_api_prefixes("http://t", endpoints)
    paths = [p["path"] for p in prefixes]
    assert any("/api" in p for p in paths)
    assert any("/rest" in p for p in paths)
    assert any("graphql" in p for p in paths)
    assert "/static/" not in paths
    assert "/static/main.js" not in paths


def test_derive_api_prefixes_empty_existing():
    from information_gathering import _derive_api_prefixes
    prefixes = _derive_api_prefixes("http://t", [])
    paths = [p["path"] for p in prefixes]
    assert any("/api" in p for p in paths)


@pytest.mark.asyncio
async def test_discover_rest_endpoints_returns_dict_with_endpoints():
    from information_gathering import discover_rest_endpoints
    with patch("information_gathering.httpx") as mock_httpx:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.text = '{"data": []}'
        async_client = AsyncMock()
        async_client.get = AsyncMock(return_value=mock_resp)
        mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=async_client)
        mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)
        result = await discover_rest_endpoints("http://t", ["http://t/api/products"])
    assert isinstance(result, dict)
    assert "endpoints" in result
    assert "total_probed" in result
    assert "total_found" in result


@pytest.mark.asyncio
async def test_discover_rest_endpoints_skips_404():
    from information_gathering import discover_rest_endpoints
    with patch("information_gathering.httpx") as mock_httpx:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.headers = {}
        mock_resp.text = "Not Found"
        async_client = AsyncMock()
        async_client.get = AsyncMock(return_value=mock_resp)
        mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=async_client)
        mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)
        result = await discover_rest_endpoints("http://t", [])
    # 404 responses excluded
    assert result["total_found"] == 0
