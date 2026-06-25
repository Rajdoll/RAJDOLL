import importlib.util, pathlib, re
_p = pathlib.Path(__file__).parent / "input-validation.py"
_s = importlib.util.spec_from_file_location("iv_mod", _p)
iv = importlib.util.module_from_spec(_s); _s.loader.exec_module(iv)


def test_boundary_matrix_is_generic_and_ordered():
    m = iv._sqli_boundary_matrix()
    suffixes = [b["suffix"] for b in m]
    # enumerates quote x paren-depth x comment (generic contexts)
    assert "'" in suffixes
    assert "'--" in suffixes
    assert "')--" in suffixes
    assert "'))--" in suffixes
    # bare-quote context comes before deeper paren contexts (prevalence order)
    assert suffixes.index("'--") < suffixes.index("'))--")
    # no target-specific literal anywhere in the matrix
    blob = " ".join(suffixes).lower()
    assert "juice" not in blob


def test_error_regex_matches_real_dbms_errors_not_generic_5xx():
    assert iv._SQLI_ERROR_RE.search("Error: SQLITE_ERROR: incomplete input")
    assert iv._SQLI_ERROR_RE.search("You have an error in your SQL syntax near")
    assert iv._SQLI_ERROR_RE.search("ORA-00933: SQL command not properly ended")
    # generic server errors must NOT match
    assert not iv._SQLI_ERROR_RE.search("500 Internal Server Error")
    assert not iv._SQLI_ERROR_RE.search("B2B customer complaints have been deprecated")


def test_error_regex_rejects_benign_substring_collisions():
    assert not iv._SQLI_ERROR_RE.search("psql: connection refused")
    assert not iv._SQLI_ERROR_RE.search("mysql_fetcher is a great metaphor")
    assert not iv._SQLI_ERROR_RE.search('near "the end": syntax error free zone')
    assert not iv._SQLI_ERROR_RE.search("PG::connection pooling guide")


def _probe(suffix, body):
    return {"suffix": suffix, "body": body}

ERR = "Error: SQLITE_ERROR: incomplete input"

def test_valid_when_error_toggles_across_boundaries():
    # live-observed: baseline clean, ')-- errors, '))-- clean again
    v = iv._sqli_error_signal(
        baseline_body="ok normal results",
        probes=[_probe("')--", ERR), _probe("'))--", "ok normal results")],
    )
    assert v["valid"] is True
    assert v["boundary"] == "')--"

def test_invalid_when_error_constant_regardless_of_boundary():
    # error present everywhere incl. shapes -> not caused by our structure
    v = iv._sqli_error_signal(
        baseline_body="ok",
        probes=[_probe("'", ERR), _probe("'--", ERR), _probe("'))--", ERR)],
    )
    assert v["valid"] is False

def test_invalid_when_error_present_in_baseline():
    v = iv._sqli_error_signal(
        baseline_body=ERR,
        probes=[_probe("')--", ERR)],
    )
    assert v["valid"] is False

def test_reflection_guard_token_echoed_in_suffix_is_not_a_signal():
    # suffix literally contains the token; response echoes it -> not backend error
    v = iv._sqli_error_signal(
        baseline_body="ok",
        probes=[_probe("SQLITE_ERROR", "you searched for SQLITE_ERROR")],
    )
    assert v["valid"] is False

def test_real_error_with_suffix_substring_is_still_valid():
    # suffix '"' is a short boundary that coincidentally appears inside the
    # quotes of a genuine DBMS error span (near "x": syntax error); naively
    # stripping the suffix from body destroys the real match's quote chars.
    v = iv._sqli_error_signal(
        baseline_body="ok",
        probes=[
            _probe('"', 'near "x": syntax error'),
            _probe("'))--", "ok"),
        ],
    )
    assert v["valid"] is True
    assert v["boundary"] == '"'

def test_no_signal_when_no_token_anywhere():
    v = iv._sqli_error_signal(
        baseline_body="ok",
        probes=[_probe("')--", "500 Internal Server Error"), _probe("'--", "ok")],
    )
    assert v["valid"] is False


import asyncio, types

class _FakeResp:
    def __init__(self, text): self.text = text; self.status_code = 200

def test_screen_signals_on_toggling_error(monkeypatch):
    ERR = "Error: SQLITE_ERROR: incomplete input"
    async def fake_send(method, url, **kw):
        # baseline benign -> clean; ')-- -> error; deeper -> clean
        q = url + str(kw.get("params")) + str(kw.get("json")) + str(kw.get("data"))
        if "')--" in q and "'))--" not in q:
            return _FakeResp(ERR)
        return _FakeResp("normal results")
    monkeypatch.setattr(iv, "_sqli_screen_send", fake_send, raising=False)
    out = asyncio.run(
        iv._sqli_screen("http://t/rest/products/search?q=apple", param="q")
    )
    assert out["signal"] is True
    assert out["boundary"] == "')--"

def test_screen_no_signal_when_all_clean(monkeypatch):
    async def fake_send(method, url, **kw):
        return _FakeResp("normal results")
    monkeypatch.setattr(iv, "_sqli_screen_send", fake_send, raising=False)
    out = asyncio.run(
        iv._sqli_screen("http://t/rest/products/search?q=apple", param="q")
    )
    assert out["signal"] is False


def test_gate_skips_sqlmap_when_screen_has_no_signal(monkeypatch):
    called = {"sqlmap": 0}
    async def fake_screen(*a, **k):
        return {"signal": False, "boundary": None, "param": "q", "reason": "no validated signal"}
    async def fake_sqlmap(*a, **k):
        called["sqlmap"] += 1
        return {"status": "success", "findings": []}
    monkeypatch.setattr(iv, "_sqli_screen", fake_screen)
    monkeypatch.setattr(iv, "run_sqlmap_scan", fake_sqlmap)
    monkeypatch.setattr(iv, "_manual_sqli_detection",
                        lambda *a, **k: _async_return({"findings": []}), raising=False)
    out = asyncio.run(
        iv.test_sqli("http://t/rest/products/search?q=apple", param="q")
    )
    assert called["sqlmap"] == 0
    assert out["status"] == "success"

def test_gate_runs_sqlmap_when_screen_signals(monkeypatch):
    called = {"sqlmap": 0}
    async def fake_screen(*a, **k):
        return {"signal": True, "boundary": "')--", "param": "q", "reason": "toggle"}
    async def fake_sqlmap(*a, **k):
        called["sqlmap"] += 1
        return {"status": "success", "findings": [{"type": "sqli"}]}
    monkeypatch.setattr(iv, "_sqli_screen", fake_screen)
    monkeypatch.setattr(iv, "run_sqlmap_scan", fake_sqlmap)
    asyncio.run(
        iv.test_sqli("http://t/rest/products/search?q=apple", param="q")
    )
    assert called["sqlmap"] == 1

def _async_return(v):
    async def _f(*a, **k): return v
    return _f()
