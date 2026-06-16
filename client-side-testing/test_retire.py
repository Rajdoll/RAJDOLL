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
