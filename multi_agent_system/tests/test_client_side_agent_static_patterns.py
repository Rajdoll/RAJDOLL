"""Tool-level tests for the static-pattern-only checks downgraded to
severity="info" (task 12), matching the existing precedent already in
client-side.py: test_csp_bypass's reflection sub-check and
test_open_redirect's allowlisted-redirect case.

These 5 sub-checks inspect static JS/HTML source (regex on markup) with no
request/response cycle to make genuinely differential -- unlike task 11's
injection-family sites, there's no baseline-vs-payload comparison possible
here, so the fix is a straight severity downgrade + (where the tool's own
"vulnerable" gate isn't already severity-based) a gate fix so an info-only
match no longer flags "vulnerable": True.

- test_clickjacking (WSTG-CLNT-09): CLICKJACKING_POSSIBLE asserted purely
  from absent headers (tool's own comment admits no browser automation is
  performed). Sibling MISSING_X_FRAME_OPTIONS/MISSING_FRAME_ANCESTORS
  (genuine header-absence facts) are untouched.
- test_prototype_pollution (WSTG-CLNT-13): generic VULNERABLE_PATTERN
  regex entries (JSON.parse, for-in, Object.assign, etc.) downgraded;
  PROTOTYPE_POLLUTION (testPolluted marker genuinely reflected) untouched.
- test_postmessage_vulnerabilities (WSTG-CLNT-14): entirely static regex,
  fully downgraded.
- test_web_messaging (WSTG-CLNT-11): entirely static regex, fully
  downgraded.
- test_resource_manipulation (WSTG-CLNT-06): only the "resource_manipulation"
  JS-pattern sub-check downgraded; "open_redirect" (real 3xx/Location
  inspection) and "iframe_manipulation" (real regex-on-actual-rendered-src)
  sub-checks in the same function are untouched.

client-side.py has a hyphen in its filename, so it can't be `import`ed
normally -- loaded via importlib, same approach as
test_client_side_agent_injection.py uses.
"""
import importlib.util
import itertools
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock


def _load_client_side():
    path = Path(__file__).resolve().parents[2] / "client-side-testing" / "client-side.py"
    spec = importlib.util.spec_from_file_location("client_side_tool_static", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


client_side = _load_client_side()


def _resp(text="", status_code=200, headers=None):
    r = MagicMock()
    r.text = text
    r.status_code = status_code
    r.headers = headers or {}
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
# 1) test_clickjacking (WSTG-CLNT-09)
# ---------------------------------------------------------------------------

async def test_clickjacking_possible_is_info_not_high():
    # No X-Frame-Options, no CSP at all -- the tool's own comment admits this
    # is asserted "based on headers" alone, no browser automation performed.
    resp = _resp(headers={})
    client_side.httpx = _mock_client_ctx(_client(get=AsyncMock(return_value=resp)))

    result = await client_side.test_clickjacking("https://example.com/")

    findings = result["data"]["findings"]
    ck = [f for f in findings if f["type"] == "CLICKJACKING_POSSIBLE"]
    assert len(ck) == 1
    assert ck[0]["severity"] == "info", ck[0]


async def test_clickjacking_missing_header_findings_unaffected():
    # Sibling checks are genuine header-absence facts (not a browser-automation
    # claim) -- must keep their existing severities.
    resp = _resp(headers={})
    client_side.httpx = _mock_client_ctx(_client(get=AsyncMock(return_value=resp)))

    result = await client_side.test_clickjacking("https://example.com/")

    findings = result["data"]["findings"]
    xfo = [f for f in findings if f["type"] == "MISSING_X_FRAME_OPTIONS"]
    fa = [f for f in findings if f["type"] == "MISSING_FRAME_ANCESTORS"]
    assert xfo and xfo[0]["severity"] == "MEDIUM"
    assert fa and fa[0]["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# 2) test_prototype_pollution (WSTG-CLNT-13)
# ---------------------------------------------------------------------------

async def test_prototype_pollution_generic_pattern_is_info_and_not_vulnerable():
    # Object.assign is a static regex hit on JS source with zero runtime
    # confirmation -- this exact false-positive class matched benign webpack
    # polyfill code in a real scan (job 164). No 'testPolluted' anywhere, so
    # the genuinely-confirmed PROTOTYPE_POLLUTION check must NOT fire either.
    html = "<html><script>var x = Object.assign(target, source);</script></html>"
    resp = _resp(text=html)
    client_side.httpx = _mock_client_ctx(_client(get=AsyncMock(return_value=resp)))

    result = await client_side.test_prototype_pollution("https://example.com/page")

    findings = result["data"]["findings"]
    vp = [f for f in findings if f["type"] == "VULNERABLE_PATTERN"]
    assert vp, findings
    assert all(f["severity"] == "info" for f in vp), vp
    assert result["data"]["vulnerable"] is False, result["data"]


async def test_prototype_pollution_testpolluted_marker_still_critical_and_vulnerable():
    # The genuinely-confirmed check: testPolluted is reflected back in the
    # response for a pollution payload. Must remain a real, CRITICAL finding.
    html = "<html>testPolluted marker reflected here, no script tags</html>"
    resp = _resp(text=html)
    client_side.httpx = _mock_client_ctx(_client(get=AsyncMock(return_value=resp)))

    result = await client_side.test_prototype_pollution("https://example.com/page")

    findings = result["data"]["findings"]
    pp = [f for f in findings if f["type"] == "PROTOTYPE_POLLUTION"]
    assert pp, findings
    assert all(f["severity"] == "CRITICAL" for f in pp), pp
    assert result["data"]["vulnerable"] is True, result["data"]


# ---------------------------------------------------------------------------
# 3) test_postmessage_vulnerabilities (WSTG-CLNT-14)
# ---------------------------------------------------------------------------

async def test_postmessage_vulnerabilities_all_info_and_not_vulnerable():
    # Entirely static regex on JS source: origin-check absence + eval on
    # event.data. No headless browser confirmation performed.
    html = (
        "<html><script>"
        "window.addEventListener('message', function(event){ eval(event.data); });"
        "</script></html>"
    )
    resp = _resp(text=html)
    client_side.httpx = _mock_client_ctx(_client(get=AsyncMock(return_value=resp)))

    result = await client_side.test_postmessage_vulnerabilities("https://example.com/page")

    findings = result["data"]["findings"]
    real = [f for f in findings if f["type"] != "POSTMESSAGE_FOUND"]
    assert real, findings
    assert all(f["severity"] == "info" for f in real), real
    assert result["data"]["vulnerable"] is False, result["data"]


# ---------------------------------------------------------------------------
# 4) test_web_messaging (WSTG-CLNT-11)
# ---------------------------------------------------------------------------

async def test_web_messaging_all_info_and_not_vulnerable():
    # Same static-pattern-only shape as postMessage: wildcard send + listener
    # without an origin check, both regex on JS source only.
    html = (
        "<html><script>"
        "function send(win){ win.postMessage(myData, '*'); }\n"
        "window.addEventListener('message', function(e){ console.log(e.data); });"
        "</script></html>"
    )
    resp = _resp(text=html)
    client_side.httpx = _mock_client_ctx(_client(get=AsyncMock(return_value=resp)))

    result = await client_side.test_web_messaging("https://example.com/page")

    findings = result["data"]["findings"]
    assert findings, result["data"]
    assert all(f["severity"] == "info" for f in findings), findings
    assert result["data"]["vulnerable"] is False, result["data"]


# ---------------------------------------------------------------------------
# 5) test_resource_manipulation (WSTG-CLNT-06)
# ---------------------------------------------------------------------------

async def test_resource_manipulation_js_pattern_is_info():
    # document.write(location.hash) is a static regex hit on JS source, no
    # confirmation that it actually executes with attacker-controlled data.
    html = "<html><script>document.write(location.hash);</script></html>"
    resp = _resp(text=html, status_code=200, headers={})
    client_side.httpx = _mock_client_ctx(_client(get=AsyncMock(return_value=resp)))

    result = await client_side.test_resource_manipulation("https://example.com/page")

    findings = result["data"]["findings"]
    rm = [f for f in findings if f["type"] == "resource_manipulation"]
    assert rm, findings
    assert all(f["severity"] == "info" for f in rm), rm
    assert result["data"]["vulnerable"] is False, result["data"]


async def test_resource_manipulation_open_redirect_and_iframe_unaffected():
    # open_redirect (real 3xx/Location header inspection) and
    # iframe_manipulation (real regex on an actually-rendered iframe src) are
    # genuinely checked -- must keep their existing severities and still
    # drive "vulnerable" via the real iframe_manipulation HIGH finding.
    html = '<html><iframe src="{{evilFrame}}"></iframe></html>'
    html_resp = _resp(text=html, status_code=200, headers={})
    redirect_resp = _resp(text="", status_code=302, headers={"location": "https://evil.example.com/x"})
    get = AsyncMock(side_effect=itertools.chain([html_resp], itertools.repeat(redirect_resp)))
    client_side.httpx = _mock_client_ctx(_client(get=get))

    result = await client_side.test_resource_manipulation("https://example.com/page")

    findings = result["data"]["findings"]
    iframe = [f for f in findings if f["type"] == "iframe_manipulation"]
    redirects = [f for f in findings if f["type"] == "open_redirect"]
    assert iframe and iframe[0]["severity"] == "HIGH"
    assert redirects and all(f["severity"] == "MEDIUM" for f in redirects)
    assert result["data"]["vulnerable"] is True, result["data"]
