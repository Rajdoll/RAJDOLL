import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock


# ── Fix 2: CORS wildcard detection ──────────────────────────────────────────

def make_cors_response(acao: str, acac: str = "") -> MagicMock:
    resp = MagicMock()
    resp.headers = {"Access-Control-Allow-Origin": acao,
                    "Access-Control-Allow-Credentials": acac}
    return resp


def _load_cors_func():
    import importlib.util, os
    spec = importlib.util.spec_from_file_location(
        "client_side",
        os.path.join(os.path.dirname(__file__), "../../../client-side-testing/client-side.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.test_cors_misconfiguration


@pytest.mark.asyncio
async def test_cors_detects_wildcard_without_credentials():
    """ACAO: * without credentials must be flagged as MEDIUM."""
    test_cors_misconfiguration = _load_cors_func()

    mock_resp = make_cors_response("*", "")
    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.options = AsyncMock(return_value=MagicMock(
            headers={"Access-Control-Allow-Methods": "GET"}))
        result = await test_cors_misconfiguration("http://juice-shop:3000")

    assert result["status"] == "success"
    assert result["data"]["vulnerable"] is True
    findings = result["data"]["findings"]
    assert any(f["type"] == "CORS_WILDCARD" for f in findings)
    assert any(f["severity"] == "MEDIUM" for f in findings)


@pytest.mark.asyncio
async def test_cors_no_false_positive_on_specific_origin():
    """When ACAO reflects only a trusted origin and no wildcard, not vulnerable."""
    test_cors_misconfiguration = _load_cors_func()

    mock_resp = make_cors_response("https://trusted.example.com", "")
    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.options = AsyncMock(return_value=MagicMock(
            headers={"Access-Control-Allow-Methods": "GET"}))
        result = await test_cors_misconfiguration("http://example.com")

    assert result["status"] == "success"
    assert result["data"]["vulnerable"] is False


# ── Fix 3: XSS alias INPV-01 ↔ CLNT-01 ────────────────────────────────────

def test_inpv01_matches_clnt01():
    """WSTG-INPV-01 GT entry must match a WSTG-CLNT-01 finding."""
    import sys
    sys.path.insert(0, "/mnt/d/MCP/RAJDOLL")
    from multi_agent_system.evaluation.compute_metrics import matches
    assert matches("WSTG-CLNT-01", "WSTG-INPV-01"), \
        "CLNT-01 (DOM XSS) must match INPV-01 (Reflected XSS) — same vulnerability class"


def test_inpv01_still_matches_inpv02():
    """Existing INPV-01 ↔ INPV-02 alias must still work."""
    from multi_agent_system.evaluation.compute_metrics import matches
    assert matches("WSTG-INPV-02", "WSTG-INPV-01")
