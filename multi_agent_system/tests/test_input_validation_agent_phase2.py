"""
Task 8 (evidence-quality phase2): 3 fixes in HTTP verb tampering, XXE inline
probe, and ReDoS timing -- all baseline/differential-comparison bugs.
"""
import importlib.util
import pathlib
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from multi_agent_system.agents import input_validation_agent
from multi_agent_system.agents.input_validation_agent import InputValidationAgent

_IV_PATH = pathlib.Path(__file__).parent.parent.parent / "input-validation-testing" / "input-validation.py"
_spec = importlib.util.spec_from_file_location("input_validation_mod_phase2", _IV_PATH)
iv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(iv)


def _resp(status_code=200, text="", headers=None):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.headers = headers or {}
    return r


# ============================================================================
# (a) HTTP verb tampering -- non_standard_method must be gated by baseline_status,
# same as the neighboring dangerous_method_allowed check.
# ============================================================================

NON_STANDARD = ["PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "ARBITRARY"]


def _mock_verb_client(non_standard_status, other_status=200, baseline_status=200):
    client = AsyncMock()
    client.get = AsyncMock(return_value=_resp(baseline_status))

    async def request_side_effect(method, url, **kwargs):
        if method in NON_STANDARD:
            return _resp(non_standard_status)
        return _resp(other_status)

    client.request = AsyncMock(side_effect=request_side_effect)
    mock_httpx = MagicMock()
    mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=client)
    mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock_httpx


async def test_verb_tampering_spa_catchall_yields_no_non_standard_finding(monkeypatch):
    # SPA catch-all: every method, including baseline GET, returns 200.
    # Today (no baseline gate) this fires a finding for all 7 non-standard
    # methods; once gated against baseline_status, it must fire none.
    # test_http_verb_tampering does a LOCAL `import httpx`, which shadows a
    # module-attribute patch -- swap sys.modules["httpx"] instead so the
    # local import picks up the mock.
    mock_httpx = _mock_verb_client(non_standard_status=200, other_status=200, baseline_status=200)
    monkeypatch.setitem(sys.modules, "httpx", mock_httpx)
    result = await iv.test_http_verb_tampering("http://example.com/app")

    findings = result["data"]["findings"]
    non_standard_findings = [f for f in findings if f["type"] == "non_standard_method"]
    assert non_standard_findings == [], f"expected no non_standard_method findings, got {non_standard_findings}"


async def test_verb_tampering_real_anomaly_still_fires(monkeypatch):
    # Baseline GET is 200, but non-standard methods get a genuinely different
    # status (500) that isn't in the safe-rejection set (400/405/501) --
    # must still be flagged.
    mock_httpx = _mock_verb_client(non_standard_status=500, other_status=200, baseline_status=200)
    monkeypatch.setitem(sys.modules, "httpx", mock_httpx)
    result = await iv.test_http_verb_tampering("http://example.com/app")

    findings = result["data"]["findings"]
    non_standard_findings = [f for f in findings if f["type"] == "non_standard_method"]
    assert len(non_standard_findings) == len(NON_STANDARD), findings


# ============================================================================
# (b) XXE inline SVG probe -- drop the generic "xxe" substring match (collides
# with the uploaded filename "xxe.svg" being echoed back), keep only real
# /etc/passwd content markers, and require a differential control upload.
# ============================================================================

def _iv_agent():
    a = InputValidationAgent.__new__(InputValidationAgent)
    a.log = lambda *args, **kw: None
    a._shared_context_snapshot = {"endpoint_inventory": {}}

    async def _execute_tool(*args, **kwargs):
        return {"status": "success", "data": {"vulnerable": False}}

    a.execute_tool = _execute_tool
    return a


def _mock_xxe_httpx(responses):
    client = AsyncMock()
    client.post = AsyncMock(side_effect=responses)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    factory = MagicMock(return_value=cm)
    return factory


async def test_xxe_filename_echo_does_not_trigger_finding():
    # Server just confirms the upload by echoing the filename -- no real
    # /etc/passwd content anywhere. Today the "xxe" in r.text.lower() branch
    # fires on this because the filename IS "xxe.svg".
    responses = [_resp(text="Uploaded xxe.svg successfully")]
    factory = _mock_xxe_httpx(responses)
    agent = _iv_agent()

    with patch.object(input_validation_agent.httpx, "AsyncClient", factory):
        all_findings = {"xxe": []}
        await agent._execute_xxe_test("http://example.com/file-upload", all_findings)

    svg_findings = [f for f in all_findings["xxe"] if f.get("technique") == "SVG file upload XXE"]
    assert svg_findings == [], f"expected no SVG XXE finding, got {svg_findings}"


async def test_xxe_real_file_content_triggers_finding():
    # Real /etc/passwd content in the response, and the differential control
    # upload (distinct benign filename) does NOT reproduce it -- genuine XXE.
    responses = [
        _resp(text="root:x:0:0:root:/root:/bin/bash\nUploaded xxe.svg successfully"),
        _resp(text="Uploaded raj_control_benign.svg successfully"),
    ]
    factory = _mock_xxe_httpx(responses)
    agent = _iv_agent()

    with patch.object(input_validation_agent.httpx, "AsyncClient", factory):
        all_findings = {"xxe": []}
        await agent._execute_xxe_test("http://example.com/file-upload", all_findings)

    svg_findings = [f for f in all_findings["xxe"] if f.get("technique") == "SVG file upload XXE"]
    assert len(svg_findings) == 1, f"expected one SVG XXE finding, got {svg_findings}"


async def test_xxe_control_also_matching_suppresses_finding():
    # Differential guard: if the control (non-XXE) upload ALSO contains the
    # "real file content" markers (e.g. a page that unconditionally includes
    # "root:" boilerplate), the signal isn't proof of XXE -- must not fire.
    responses = [
        _resp(text="root:x:0:0:root:/root:/bin/bash always present in footer"),
        _resp(text="root:x:0:0:root:/root:/bin/bash always present in footer"),
    ]
    factory = _mock_xxe_httpx(responses)
    agent = _iv_agent()

    with patch.object(input_validation_agent.httpx, "AsyncClient", factory):
        all_findings = {"xxe": []}
        await agent._execute_xxe_test("http://example.com/file-upload", all_findings)

    svg_findings = [f for f in all_findings["xxe"] if f.get("technique") == "SVG file upload XXE"]
    assert svg_findings == [], f"expected differential guard to suppress finding, got {svg_findings}"


# ============================================================================
# (c) ReDoS -- flag only when payload timing is a large multiple of a
# same-endpoint baseline timing, not just an absolute >5.0s threshold.
# ============================================================================

def _redos_client(clock, baseline_delay, payload_delay):
    async def get_side_effect(url, params=None, **kwargs):
        value = list(params.values())[0] if params else None
        if "/rest/products/search" in url:
            if value == "__redos_baseline_probe__":
                clock["t"] += baseline_delay
            elif value is not None:
                clock["t"] += payload_delay
        return _resp(200)

    async def post_side_effect(*args, **kwargs):
        return _resp(200)

    client = AsyncMock()
    client.get = AsyncMock(side_effect=get_side_effect)
    client.post = AsyncMock(side_effect=post_side_effect)
    mock_httpx = MagicMock()
    mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=client)
    mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock_httpx


async def test_redos_naturally_slow_endpoint_marginal_payload_no_finding(monkeypatch):
    # Baseline already 5.5s (naturally slow endpoint), payload only 5.6s
    # (marginally slower, NOT a large multiple). Old absolute->5.0s threshold
    # would flag this as ReDoS; baseline-relative comparison must not.
    clock = {"t": 0.0}
    monkeypatch.setattr(iv.time, "monotonic", lambda: clock["t"])
    mock_httpx = _redos_client(clock, baseline_delay=5.5, payload_delay=5.6)

    with patch.object(iv, "httpx", mock_httpx):
        result = await iv.test_redos("http://example.com/rest/products/search")

    redos_findings = [f for f in result["data"]["findings"] if f["type"].startswith("ReDoS:")]
    assert redos_findings == [], f"expected no ReDoS finding, got {redos_findings}"


async def test_redos_genuine_exponential_blowup_still_fires(monkeypatch):
    # Baseline fast (0.1s), payload 6.0s -- both > 5.0s absolute floor AND a
    # large (60x) multiple of baseline -- genuine ReDoS, must still fire.
    clock = {"t": 0.0}
    monkeypatch.setattr(iv.time, "monotonic", lambda: clock["t"])
    mock_httpx = _redos_client(clock, baseline_delay=0.1, payload_delay=6.0)

    with patch.object(iv, "httpx", mock_httpx):
        result = await iv.test_redos("http://example.com/rest/products/search")

    redos_findings = [f for f in result["data"]["findings"] if f["type"].startswith("ReDoS:")]
    assert len(redos_findings) >= 1, f"expected at least one ReDoS finding, got {result['data']['findings']}"
