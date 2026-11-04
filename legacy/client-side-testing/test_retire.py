import importlib.util, pathlib

_p = pathlib.Path(__file__).parent / "client-side.py"
_spec = importlib.util.spec_from_file_location("client_side_mod", _p)
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)


def test_parse_retire_output_basic():
    data = {"data": [
        {"file": "/tmp/x/0.js", "results": [
            {"version": "1.12.4", "component": "jquery", "vulnerabilities": [
                {"severity": "medium", "identifiers": {"summary": "CORS exec", "CVE": ["CVE-2015-9251"],
                                                       "githubID": "GHSA-rmxg-73gg-4p98"}},
                {"severity": "low", "identifiers": {"summary": "jQuery 1.x EOL"}},
            ]},
        ]},
    ]}
    out = cs._parse_retire_output(data)
    assert len(out) == 2
    a, b = out
    assert a["library"] == "jquery" and a["version"] == "1.12.4"
    assert a["severity"] == "medium" and a["cve"] == "CVE-2015-9251"
    assert a["source"] == "/tmp/x/0.js" and a["detection"] == "retirejs"
    assert b["cve"] == "jQuery 1.x EOL"


def test_parse_retire_output_githubid_fallback():
    data = {"data": [{"file": "f", "results": [
        {"version": "4.17.0", "component": "lodash", "vulnerabilities": [
            {"severity": "high", "identifiers": {"githubID": "GHSA-x", "summary": "proto pollution"}}]}]}]}
    out = cs._parse_retire_output(data)
    assert out[0]["cve"] == "GHSA-x"


def test_parse_retire_output_empty():
    assert cs._parse_retire_output({}) == []
    assert cs._parse_retire_output({"data": []}) == []
    assert cs._parse_retire_output({"data": [{"file": "f", "results": [
        {"version": "9.9", "component": "safe", "vulnerabilities": []}]}]}) == []
    assert cs._parse_retire_output({"data": [{"file": "f"}]}) == []
    assert cs._parse_retire_output({"data": [{"file": "f", "results": [
        {"version": "1", "component": "x"}]}]}) == []


def test_parse_retire_output_cve_as_string():
    data = {"data": [{"file": "f", "results": [
        {"version": "1.0", "component": "x", "vulnerabilities": [
            {"severity": "high", "identifiers": {"CVE": "CVE-2015-9251", "summary": "s"}}]}]}]}
    out = cs._parse_retire_output(data)
    assert out[0]["cve"] == "CVE-2015-9251"     # bare-string CVE not split into chars


import asyncio


def _run(coro):
    return asyncio.run(coro)


def test_scan_surfaces_findings_when_retire_reports(monkeypatch):
    async def fake_dl(url, auth_session, tmpdir):
        return 2
    monkeypatch.setattr(cs, "_fetch_and_download_js", fake_dl)
    async def fake_retire(path, timeout=120):
        return {"data": [{"file": "0.js", "results": [
            {"version": "1.12.4", "component": "jquery", "vulnerabilities": [
                {"severity": "medium", "identifiers": {"summary": "x", "CVE": ["CVE-2015-9251"]}}]}]}]}
    monkeypatch.setattr(cs, "_run_retire", fake_retire)
    res = _run(cs.scan_vulnerable_components("http://t/"))
    assert res["status"] == "success"
    d = res["data"]
    assert d["vulnerable"] is True and d["scripts_checked"] == 2
    assert d["findings"][0]["library"] == "jquery" and d["findings"][0]["cve"] == "CVE-2015-9251"


def test_scan_empty_when_no_js(monkeypatch):
    async def fake_dl(url, auth_session, tmpdir):
        return 0
    monkeypatch.setattr(cs, "_fetch_and_download_js", fake_dl)
    called = {"retire": False}
    async def fake_retire(path, timeout=120):
        called["retire"] = True
        return {}
    monkeypatch.setattr(cs, "_run_retire", fake_retire)
    res = _run(cs.scan_vulnerable_components("http://t/"))
    assert res["status"] == "success" and res["data"]["findings"] == []
    assert called["retire"] is False


def test_scan_failsafe_when_retire_unavailable(monkeypatch):
    async def fake_dl(url, auth_session, tmpdir):
        return 1
    monkeypatch.setattr(cs, "_fetch_and_download_js", fake_dl)
    async def fake_retire(path, timeout=120):
        return {}
    monkeypatch.setattr(cs, "_run_retire", fake_retire)
    res = _run(cs.scan_vulnerable_components("http://t/"))
    assert res["status"] == "success" and res["data"]["findings"] == []
    assert res["data"]["vulnerable"] is False
