"""Tests for 4 evidence-quality defects in reconnaissance_agent.py (Task 5):

1. emails_found regex over-matches asset filenames (e.g. pkg_headbg_modifysearch@2x.jpg)
   as email addresses -- fixed in information-gathering/information_gathering.py
   (analyze_webpage_content), which feeds ReconnaissanceAgent._handle_content_leaks.
2. JS-secrets regex over-matches generic JS tokens ("register", "componentDidMount")
   as hardcoded secrets -- fixed in information_gathering.analyze_javascript_routes.
3/4. SPA-routes and outdated-JS-library findings mis-stamped with auto-trusted
   proof_types ("sensitive_data_exposure" / "data_exposure") in reconnaissance_agent.py's
   _perform_endpoint_discovery -- corrected to NON_REPORTABLE_PROOF_TYPES members.
"""
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

# information_gathering.py lives in information-gathering/ (a sibling of multi_agent_system/)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "information-gathering"))

from multi_agent_system.agents.reconnaissance_agent import ReconnaissanceAgent
import multi_agent_system.core.config as config_mod


def _resp(status_code=200, text=""):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    return r


def _mock_client(get_side_effect):
    mock_httpx = MagicMock()
    client = AsyncMock()
    client.get = AsyncMock(side_effect=get_side_effect)
    mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=client)
    mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock_httpx


# --- 1. emails_found regex over-match (analyze_webpage_content) ---

async def test_analyze_webpage_content_rejects_asset_filenames_but_keeps_real_email():
    import information_gathering as ig

    html = (
        "<html><body>"
        "<img src='pkg_headbg_modifysearch@2x.jpg'>"
        "<img src='image-place-holder@2x.png'>"
        "Contact us at admin@example.com"
        "</body></html>"
    )
    mock_httpx = _mock_client(get_side_effect=[_resp(200, text=html)])
    with patch("information_gathering.httpx", mock_httpx):
        result = await ig.analyze_webpage_content("example.com")

    emails = result["data"]["information_leakage"]["emails_found"]
    assert "admin@example.com" in emails, f"expected real email to be matched, got {emails}"
    assert "pkg_headbg_modifysearch@2x.jpg" not in emails, f"image filename matched as email: {emails}"
    assert "image-place-holder@2x.png" not in emails, f"image filename matched as email: {emails}"


# --- 2. JS-secrets over-broad regex (analyze_javascript_routes) ---

async def test_analyze_javascript_routes_rejects_generic_tokens_but_keeps_real_secret_shape():
    import information_gathering as ig

    js_content = (
        "function App() {}\n"
        "var config = {};\n"
        "const registerRoute = { key: 'register' };\n"
        "function componentDidMount() { var token = 'componentDidMount'; }\n"
        "const apiKey = \"sk_live_abcdef1234567890abcdef\";\n"
        + ("// padding line to exceed content-length threshold\n" * 30)
    )
    base_url = "http://example.com"

    async def get_side_effect(url, *args, **kwargs):
        if url == base_url:
            return _resp(200, text="<html></html>")
        if url.endswith("/main.js"):
            return _resp(200, text=js_content)
        return _resp(404, text="")

    mock_httpx = _mock_client(get_side_effect=get_side_effect)
    with patch("information_gathering.httpx", mock_httpx):
        result = await ig.analyze_javascript_routes(base_url)

    findings = result["data"]["findings"]
    secret_evidence = [f.get("evidence") for f in findings if f.get("type", "").startswith("js_")]
    assert "register" not in secret_evidence, f"generic token matched as secret: {secret_evidence}"
    assert "componentDidMount" not in secret_evidence, f"generic token matched as secret: {secret_evidence}"
    assert any("sk_live_" in (v or "") for v in secret_evidence), f"real secret shape not matched: {secret_evidence}"
    assert result["data"]["secrets_found"] >= 1


# --- 3/4. proof_type mismatches for SPA-routes and outdated-JS-library findings ---

def _agent():
    a = ReconnaissanceAgent.__new__(ReconnaissanceAgent)
    a.log = lambda *args, **kw: None
    a._shared_context_snapshot = {}
    a.context_manager = MagicMock()
    a.context_manager.read = MagicMock(return_value=None)
    a.context_manager.write = MagicMock()
    a.findings = []
    a.add_finding = lambda *args, **kw: a.findings.append((args, kw))
    a._discover_endpoints = AsyncMock(return_value=[])

    routes = [{"path": f"/route{i}", "framework": "angular"} for i in range(20)]
    a.js_bundle_analyzer = MagicMock()
    a.js_bundle_analyzer.analyze = AsyncMock(return_value={"routes": routes})
    return a


async def test_spa_routes_and_outdated_library_findings_use_non_reportable_proof_types():
    agent = _agent()

    orig_use_framework = config_mod.settings.use_framework
    orig_use_js_analyzer = config_mod.settings.use_js_analyzer
    orig_recon_mode = config_mod.settings.recon_mode
    config_mod.settings.use_framework = True
    config_mod.settings.use_js_analyzer = True
    config_mod.settings.recon_mode = "polite"  # skip aggressive-mode ffuf/param-miner branches

    base_url = "https://example.com"
    js_lib_text = "/*! jQuery v1.2.1 */\nfunction(){}"

    async def get_side_effect(url, *args, **kwargs):
        if url.endswith(".js"):
            return _resp(200, text=js_lib_text)
        return _resp(404, text="")

    try:
        with patch("httpx.AsyncClient") as mock_cls, \
             patch(
                 "multi_agent_system.agents.reconnaissance_agent.build_endpoint_inventory",
                 AsyncMock(return_value={"endpoints": [], "by_tag": {}, "stats": {}}),
             ), \
             patch(
                 "multi_agent_system.agents.modules.openapi_probe.probe_openapi",
                 AsyncMock(return_value=[]),
             ), \
             patch(
                 "multi_agent_system.agents.modules.openapi_probe.probe_graphql_introspection",
                 AsyncMock(return_value=[]),
             ):
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=get_side_effect)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            await agent._perform_endpoint_discovery(base_url, {})
    finally:
        config_mod.settings.use_framework = orig_use_framework
        config_mod.settings.use_js_analyzer = orig_use_js_analyzer
        config_mod.settings.recon_mode = orig_recon_mode

    spa_calls = [(args, kw) for args, kw in agent.findings if "SPA exposes" in args[1]]
    lib_calls = [(args, kw) for args, kw in agent.findings if "Outdated JS library detected" in args[1]]

    assert spa_calls, f"expected SPA-routes finding, got {agent.findings}"
    assert lib_calls, f"expected outdated-JS-library finding, got {agent.findings}"

    from multi_agent_system.utils.finding_policy import NON_REPORTABLE_PROOF_TYPES

    spa_proof_type = spa_calls[0][1]["evidence"]["proof_type"]
    lib_proof_type = lib_calls[0][1]["evidence"]["proof_type"]

    assert spa_proof_type != "sensitive_data_exposure", "SPA-routes finding still auto-trusted as sensitive_data_exposure"
    assert spa_proof_type in NON_REPORTABLE_PROOF_TYPES, f"unexpected proof_type: {spa_proof_type}"

    assert lib_proof_type != "data_exposure", "outdated-JS-library finding still auto-trusted as data_exposure"
    assert lib_proof_type in NON_REPORTABLE_PROOF_TYPES, f"unexpected proof_type: {lib_proof_type}"
