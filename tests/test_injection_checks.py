"""Input Validation probes and the request toolkit, against testapp in-process (IPD F6).

Each probe must find testapp's planted weakness and stay silent on the other endpoints, in
particular where a value is only reflected (the classic false positive of naive scanners).
"""

import importlib.util
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from rajdoll.modules import httpkit, injection_checks
from tests.helpers import REPO

BASE = "http://testserver"


def _testapp() -> Any:
    spec = importlib.util.spec_from_file_location("testapp_app", REPO / "testapp" / "app.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(_testapp().app, raise_server_exceptions=False) as test_client:
        yield test_client


def _point(method: str, path: str, parameter: str, location: str = "query") -> httpkit.Injection:
    if location == "query":
        return httpkit.Injection(method, BASE + path, parameter, "query", {parameter: "rajdoll"})
    return httpkit.Injection(
        method, BASE + path, parameter, location, {}, {parameter: "rajdoll"}, location
    )


def _sender(client: TestClient, point: httpkit.Injection, sent: list[str] | None = None) -> Any:
    def send(value: str, note: str | None) -> Any:
        if sent is not None:
            sent.append(value)
        return point.send(client, value, {"Cookie": "sid=rahasia"}, note)

    return send


POINTS = {
    "katalog": ("GET", "/katalog", "nama", "query"),
    "sapa": ("GET", "/sapa", "nama", "query"),
    "ping": ("POST", "/alat/ping", "host", "form"),
    "pratinjau": ("GET", "/pratinjau", "templat", "query"),
    "kontak": ("POST", "/kontak", "pesan", "form"),
}


def _run(client: TestClient, name: str, probe: str) -> injection_checks.Hit | None:
    point = _point(*POINTS[name])
    send = _sender(client, point)
    baseline, _ = send("rajdoll", "nilai normal")
    if probe == "sqli":
        return injection_checks.sqli_error(
            send, "rajdoll", baseline.text
        ) or injection_checks.sqli_boolean(send, "rajdoll")
    if probe == "ssti":
        return injection_checks.ssti(send, "rajdoll", baseline.text)
    if probe == "cmdi":
        return injection_checks.cmdi(send, "rajdoll")
    return injection_checks.xss(send, "rajdoll", None)


@pytest.mark.parametrize(
    ("probe", "vulnerable"),
    [("sqli", "katalog"), ("ssti", "pratinjau"), ("cmdi", "ping"), ("xss", "sapa")],
)
def test_each_probe_finds_only_its_weakness(
    client: TestClient, probe: str, vulnerable: str
) -> None:
    for name in POINTS:
        hit = _run(client, name, probe)
        if name == vulnerable:
            assert hit is not None, f"{probe} missed {name}"
            assert hit.evidence and hit.note
        else:
            assert hit is None, f"{probe} false positive on {name}: {hit and hit.note}"


def test_sqli_error_needs_the_balanced_quote_to_succeed(client: TestClient) -> None:
    hit = _run(client, "katalog", "sqli")
    assert hit is not None and hit.params == {"technique": "error"}
    assert "sqlite3.OperationalError" in hit.note
    assert [e.note for e in hit.evidence] == [
        "kutip tunggal tidak seimbang",
        "kutip ganda (seimbang)",
    ]


def test_sqli_boolean_ignores_reflected_values(client: TestClient) -> None:
    katalog, sapa = _point(*POINTS["katalog"]), _point(*POINTS["sapa"])
    hit = injection_checks.sqli_boolean(_sender(client, katalog), "rajdoll")
    assert hit is not None and hit.params["technique"] == "boolean"
    assert len(hit.evidence) == 3
    # /sapa echoes the value, so the true and false pages differ only by the reflection.
    assert injection_checks.sqli_boolean(_sender(client, sapa), "rajdoll") is None


def test_shell_quote_errors_are_not_sql_errors() -> None:
    errors = injection_checks.SQL_ERRORS
    assert not errors.search("sh: 1: Syntax error: Unterminated quoted string")
    assert errors.search('ERROR:  unterminated quoted string at or near "\'"')
    assert errors.search('sqlite3.OperationalError: unrecognized token: "\'"')
    assert errors.search("You have an error in your SQL syntax; check the manual")


def test_cmdi_and_ssti_use_fresh_numbers(client: TestClient) -> None:
    sent: list[str] = []
    point = _point(*POINTS["ping"])
    hit = injection_checks.cmdi(_sender(client, point, sent), "rajdoll")
    assert hit is not None and hit.params["separator"] == ";"
    a, b = (int(x) for x in sent[-1].split("$((")[1].rstrip(")").split("*"))
    assert str(a * b) in hit.note
    assert 100 <= a < 900 and 1000 <= b < 9000

    sent.clear()
    hit = injection_checks.ssti(_sender(client, _point(*POINTS["pratinjau"]), sent), "rajdoll", "")
    assert hit is not None and hit.params["syntax"] == "{{%d*%d}}"


def _ssrf_app(request: httpx.Request) -> httpx.Response:
    page = "<html><title>Portal Kepegawaian</title></html>"
    value = request.url.params.get("url") or request.url.params.get("next", "")
    if request.url.path == "/ambil":  # fetches the URL
        if value.startswith("http://portal.test/"):
            return httpx.Response(200, text=page)
        return httpx.Response(502, text="Gagal mengambil")
    if request.url.path == "/login":  # same title on every page, value only reflected
        return httpx.Response(200, text=page + f"<a href='{value}'>lanjut</a>")
    return httpx.Response(200, text=page)


@pytest.mark.parametrize(
    ("path", "parameter", "expected"),
    [("/ambil", "url", True), ("/login", "next", False), ("/ambil", "nama", False)],
)
def test_ssrf_needs_the_page_fetched_by_the_server(
    path: str, parameter: str, expected: bool
) -> None:
    client = httpx.Client(transport=httpx.MockTransport(_ssrf_app))
    point = httpkit.Injection("GET", "http://portal.test" + path, parameter, "query", {})
    marker = injection_checks.page_marker(client.get("http://portal.test/").text)
    assert marker == "Portal Kepegawaian"
    hit = injection_checks.ssrf(_sender(client, point), point, "http://portal.test/", marker)
    assert (hit is not None) is expected
    if hit:
        assert [e.note for e in hit.evidence] == [
            "URL ke host yang tidak ada",
            "URL ke halaman target",
        ]
    assert injection_checks.ssrf(_sender(client, point), point, "http://portal.test/", "") is None


def test_differs_ignores_numbers_and_small_changes() -> None:
    assert not injection_checks._differs("2 produk", "2 produk")
    assert not injection_checks._differs("<p>dibuat 12:01:33</p>", "<p>dibuat 12:01:34</p>")
    assert injection_checks._differs("<li>Kopi</li><li>Teh</li>", "")
    page = "<h1>Halo, rajdoll&#x27; OR 1=1 -- x!</h1>"
    assert injection_checks._without(page, "rajdoll' OR 1=1 -- x") == "<h1>Halo, !</h1>"


# --- httpkit --------------------------------------------------------------------------------


def test_evidence_masks_sessions(client: TestClient) -> None:
    point = _point("POST", "/login", "username", "form")
    response, exchange = point.send(
        client, "budi", {"Cookie": "sid=rahasia", "Authorization": "Bearer t0ken"}, "uji"
    )
    assert exchange.request.startswith("POST /login HTTP/1.1\r\nHost: testserver\r\n")
    assert "cookie: [sesi akun]" in exchange.request.lower()
    assert "authorization: [sesi akun]" in exchange.request.lower()
    assert "rahasia" not in exchange.request and "t0ken" not in exchange.request
    assert exchange.request.endswith("username=budi")
    assert (exchange.status, exchange.note) == (response.status_code, "uji")


def test_multipart_requests_are_recorded(client: TestClient) -> None:
    point = _point("POST", "/kontak", "pesan", "multipart")
    _, exchange = point.send(client, "halo", None)
    assert 'name="pesan"' in exchange.request and "halo" in exchange.request


def test_set_cookie_is_masked_in_responses() -> None:
    response = httpx.Response(
        200, headers={"Set-Cookie": "sid=rahasia; HttpOnly"}, text="ok",
        request=httpx.Request("GET", "http://a.test/"),
    )  # fmt: skip
    raw = httpkit.raw_response(response)
    assert "set-cookie: sid=[sesi akun]" in raw.lower() and "rahasia" not in raw


def test_injections_cover_every_parameter() -> None:
    endpoint = {
        "method": "POST",
        "url": "https://app.test/akun/{id}/unggah",
        "query_params": ["redirect"],
        "body_params": [
            {"name": "judul", "location": "multipart"},
            {"name": "file", "location": "multipart"},
            {"name": "", "location": "multipart"},
        ],
    }
    points = httpkit.injections(endpoint)
    assert [(p.parameter, p.location) for p in points] == [
        ("redirect", "query"),
        ("judul", "multipart"),
    ]
    assert points[0].url == "https://app.test/akun/1/unggah"
    assert points[0].query == {"redirect": "/"}
    assert points[0].body == {"judul": "rajdoll", "file": "rajdoll"}
    assert points[1].body_location == "multipart"
    assert httpkit.default_value("user_id") == "1"
    assert httpkit.default_value("email") == "rajdoll@contoh.test"


@pytest.mark.parametrize(
    ("location", "encoding", "curl_part"),
    [
        ("query", "none", "'https://app.test/cari?q=x%27&page=1'"),
        ("form", "form", "--data 'q=x%27&page=1'"),
        ("json", "json", '--data \'{"q": "x\'"\'"\'", "page": "1"}\''),
        ("multipart", "multipart", "-F 'q=x'\"'\"''"),
    ],
)
def test_poc_round_trip_and_curl(location: str, encoding: str, curl_part: str) -> None:
    method = "GET" if location == "query" else "POST"
    if location == "query":
        point = httpkit.Injection(
            method, "https://app.test/cari", "q", location, {"q": "", "page": "1"}
        )
    else:
        point = httpkit.Injection(
            method, "https://app.test/cari", "q", location, {}, {"q": "", "page": "1"}, location
        )
    poc = point.poc("x'", "sqli", base="x", technique="error")
    assert poc["path"] == "/cari" and poc["account"] is None and poc["body_encoding"] == encoding
    assert poc["validator_params"] == {
        "parameter": "q", "location": location, "base": "x", "technique": "error",
    }  # fmt: skip
    rebuilt = httpkit.from_poc("https://app.test", poc)
    assert rebuilt.request_parts("y") == point.request_parts("y")
    assert (rebuilt.method, rebuilt.url, rebuilt.body_location) == (
        method,
        "https://app.test/cari",
        point.body_location,
    )
    assert curl_part in httpkit.curl("https://app.test", poc)
