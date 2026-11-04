"""Tool/agent-level tests for the injection-family checks fixed to use
differential_verify (task 11):

- client-side-testing/client-side.py: test_dom_xss, test_html_injection,
  test_css_injection, test_client_side_template_injection
- multi_agent_system/agents/client_side_agent.py: _run_xss_probe (used by the
  aggressive-mode reflected-XSS probe)

Prior to this fix, all 5 sites concluded "vulnerable" from a single-response
pattern/regex match with no baseline request -- a response that happens to
contain the "vulnerable" signal for reasons unrelated to the payload (e.g. the
literal payload text or a coincidental number/word already on the page) would
false-positive. This suite pins down the fixed behavior: a same-page baseline
(no payload sent) that already contains the signal must suppress the finding.

client-side.py has a hyphen in its filename, so it can't be `import`ed
normally -- it's loaded via importlib, same approach as
test_business_logic_tool_phase2.py uses for its sibling tool file.
"""
import importlib.util
import itertools
import random as random_module
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from multi_agent_system.agents.client_side_agent import _run_xss_probe
from multi_agent_system.utils.differential_verify import verify_differential


def _load_client_side():
    path = Path(__file__).resolve().parents[2] / "client-side-testing" / "client-side.py"
    spec = importlib.util.spec_from_file_location("client_side_tool", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


client_side = _load_client_side()


def _resp(text):
    r = MagicMock()
    r.text = text
    return r


def _client(get):
    c = MagicMock()
    c.get = get
    return c


def _mock_client_ctx(client):
    """Wraps a bare client mock so `async with httpx.AsyncClient(...) as client` works."""
    mock_httpx = MagicMock()
    mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=client)
    mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock_httpx


# ---------------------------------------------------------------------------
# 1) test_dom_xss (WSTG-CLNT-01)
# ---------------------------------------------------------------------------

async def test_dom_xss_no_finding_when_signal_also_in_baseline():
    # Same body returned for the baseline GET and every payload GET: a sink
    # (eval) plus the exact text of one DOM-XSS payload are already present
    # "naturally" -- there's no way a real payload caused this.
    same = _resp("<html><script>eval(x); <script>alert(document.domain)</script></script></html>")
    client_side.httpx = _mock_client_ctx(_client(get=AsyncMock(return_value=same)))

    result = await client_side.test_dom_xss("https://example.com/page")

    assert result["status"] == "success"
    assert result["data"]["vulnerable"] is False, result["data"]
    assert result["data"].get("findings", []) == []


async def test_dom_xss_confirms_when_baseline_differs():
    baseline = _resp("<html>benign app shell</html>")
    vuln = _resp("<html><script>eval(x); <script>alert(document.domain)</script></script></html>")
    client_side.httpx = _mock_client_ctx(
        _client(get=AsyncMock(side_effect=itertools.chain([baseline], itertools.repeat(vuln))))
    )

    result = await client_side.test_dom_xss("https://example.com/page")

    assert result["data"]["vulnerable"] is True
    assert any(f["type"] == "DOM_XSS" for f in result["data"]["findings"])


# ---------------------------------------------------------------------------
# 2) test_html_injection (WSTG-CLNT-03)
# ---------------------------------------------------------------------------

async def test_html_injection_no_finding_when_signal_also_in_baseline():
    payload = '<img src=x onerror=alert(1)>'
    same = _resp(f"<div>innerHTML = '{payload}'</div>")
    client_side.httpx = _mock_client_ctx(_client(get=AsyncMock(return_value=same)))

    result = await client_side.test_html_injection("https://example.com/page", param="q")

    assert result["data"]["vulnerable"] is False, result["data"]
    assert result["data"].get("findings", []) == []


async def test_html_injection_confirms_when_baseline_differs():
    payload = '<img src=x onerror=alert(1)>'
    baseline = _resp("<html>benign app shell</html>")
    vuln = _resp(f"<div>innerHTML = '{payload}'</div>")
    client_side.httpx = _mock_client_ctx(
        _client(get=AsyncMock(side_effect=itertools.chain([baseline], itertools.repeat(vuln))))
    )

    result = await client_side.test_html_injection("https://example.com/page", param="q")

    assert result["data"]["vulnerable"] is True
    findings = result["data"]["findings"]
    assert any(f["type"] == "HTML_INJECTION" and f["parameter"] == "q" for f in findings)


# ---------------------------------------------------------------------------
# 3) test_css_injection (WSTG-CLNT-05)
# ---------------------------------------------------------------------------

async def test_css_injection_no_finding_when_signal_also_in_baseline():
    payload = '{background:red}'
    same = _resp(f"<style>body{payload}</style>")
    client_side.httpx = _mock_client_ctx(_client(get=AsyncMock(return_value=same)))

    result = await client_side.test_css_injection("https://example.com/page")

    assert result["data"]["vulnerable"] is False, result["data"]
    assert result["data"].get("findings", []) == []


async def test_css_injection_confirms_when_baseline_differs():
    payload = '{background:red}'
    baseline = _resp("<html>benign app shell</html>")
    vuln = _resp(f"<style>body{payload}</style>")
    client_side.httpx = _mock_client_ctx(
        _client(get=AsyncMock(side_effect=itertools.chain([baseline], itertools.repeat(vuln))))
    )

    result = await client_side.test_css_injection("https://example.com/page")

    assert result["data"]["vulnerable"] is True
    assert any(f["type"] == "CSS_INJECTION" for f in result["data"]["findings"])


# ---------------------------------------------------------------------------
# 4) test_client_side_template_injection (WSTG-CLNT-15) -- CSTI
# ---------------------------------------------------------------------------

def test_csti_payloads_use_random_product_not_fixed_49_or_alert():
    payloads = client_side._csti_payloads(37, 41, "rajmarker1")
    assert ("{{37*41}}", "AngularJS/Vue expression", "1517", "{{37*41}}") in payloads
    signals = {sig for _, _, sig, _ in payloads}
    assert "49" not in signals
    assert "alert" not in signals
    assert "1517" in signals
    assert "rajmarker1" in signals


@pytest.fixture
def deterministic_random(monkeypatch):
    """Pin down the CSTI probe's random operands/marker for reproducible assertions.
    a=b=37 -> product '1369'; marker -> 'rajabcdefgh'."""
    monkeypatch.setattr(random_module, "randint", lambda a, b: 37)
    monkeypatch.setattr(random_module, "choices", lambda population, k=1: list("abcdefgh"[:k]))


async def test_csti_no_finding_when_signal_also_in_baseline(deterministic_random):
    # "1369" (the product of the fixed 37*37 operands) occurs naturally on this
    # page regardless of any payload -- e.g. a price or reference number.
    same = _resp("<p>Order reference: 1369</p>")
    client_side.httpx = _mock_client_ctx(_client(get=AsyncMock(return_value=same)))

    result = await client_side.test_client_side_template_injection("https://example.com/page")

    assert result["data"]["vulnerable"] is False, result["data"]
    assert not any(f["type"] == "TEMPLATE_INJECTION" for f in result["data"].get("findings", []))


async def test_csti_confirms_when_baseline_differs(deterministic_random):
    baseline = _resp("<html>benign app shell</html>")
    vuln = _resp("<p>Computed result: 1369</p>")
    client_side.httpx = _mock_client_ctx(
        _client(get=AsyncMock(side_effect=itertools.chain([baseline], itertools.repeat(vuln))))
    )

    result = await client_side.test_client_side_template_injection("https://example.com/page")

    assert result["data"]["vulnerable"] is True
    assert any(f["type"] == "TEMPLATE_INJECTION" for f in result["data"]["findings"])


# ---------------------------------------------------------------------------
# 5) _run_xss_probe (aggressive-mode reflected-XSS probe, client_side_agent.py)
# ---------------------------------------------------------------------------

async def test_run_xss_probe_no_finding_when_marker_also_in_baseline():
    marker = "rajdoll-xss-probe-7791"
    same = _resp(f"<html>{marker}</html>")
    client = _client(get=AsyncMock(return_value=same))

    confirmed = await _run_xss_probe(
        client,
        [("https://example.com/search", "q")],
        [f"<script>alert('{marker}')</script>"],
        marker,
    )

    assert confirmed == []


async def test_run_xss_probe_confirms_when_baseline_differs():
    marker = "rajdoll-xss-probe-7791"
    baseline = _resp("<html>benign app shell</html>")
    vuln = _resp(f"<html>{marker}</html>")
    client = _client(get=AsyncMock(side_effect=itertools.chain([baseline], itertools.repeat(vuln))))

    confirmed = await _run_xss_probe(
        client,
        [("https://example.com/search", "q")],
        [f"<script>alert('{marker}')</script>"],
        marker,
    )

    assert len(confirmed) == 1
    assert confirmed[0]["parameter"] == "q"


def test_run_xss_probe_reuses_verify_differential():
    """Guard against re-hand-rolling a baseline check -- the fix must reuse
    differential_verify.verify_differential rather than a bespoke comparison."""
    import inspect
    src = inspect.getsource(_run_xss_probe)
    assert "verify_differential" in src
