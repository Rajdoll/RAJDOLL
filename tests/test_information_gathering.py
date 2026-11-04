"""Information Gathering: plans, result handling, and the custom recon checks (IPD F5)."""

import json
import shutil
import threading
from pathlib import Path
from typing import Any

import httpx
import pytest

from rajdoll.core.enums import ScanStage
from rajdoll.modules.base import EndpointSeen, PlanContext, TaskContext, TransientTaskError
from rajdoll.modules.information_gathering import InformationGathering
from rajdoll.modules.recon import js_analysis, known_files, openapi, waf
from tools.runner.adapters import RunContext
from tools.runner.adapters.browser import BrowserAdapter
from tools.runner.adapters.ffuf import FfufAdapter
from tools.runner.adapters.katana import KatanaAdapter

FIXTURES = Path(__file__).resolve().parent / "fixtures"
TESTAPP = Path(__file__).resolve().parent.parent / "testapp" / "app.py"


def _plan(stage: ScanStage, endpoints: list[dict] | None = None) -> PlanContext:
    return PlanContext(
        1, 1, "http://testapp:8080/", ["testapp"], {}, stage, endpoints=endpoints or []
    )


def test_recon_plan_runs_every_source() -> None:
    specs = InformationGathering().plan(_plan(ScanStage.RECON))
    engines = [s.engine for s in specs]
    assert engines == [
        "httpx",
        "katana",
        "browser",
        "ffuf",
        "nmap",
        "custom:openapi",
        "custom:known_files",
        "custom:waf",
    ]
    by_engine = {s.engine: s for s in specs}
    assert by_engine["nmap"].target == {"host": "testapp"}
    assert by_engine["ffuf"].target == {"url": "http://testapp:8080/"}
    assert by_engine["custom:openapi"].target == {"base": "http://testapp:8080"}
    assert InformationGathering().plan(_plan(ScanStage.TESTING)) == []


def _endpoint(method: str, path: str, **extra: Any) -> dict[str, Any]:
    return {
        "method": method,
        "path_template": path,
        "url": "http://testapp:8080" + path,
        "query_params": [],
        "excluded": False,
        **extra,
    }


def test_planning_wave_analyses_scripts_and_discovers_parameters() -> None:
    endpoints = [
        _endpoint("GET", "/static/app.js"),
        _endpoint("GET", "/produk"),
        _endpoint("GET", "/cari", query_params=["q"]),
        _endpoint("GET", "/produk/{id}"),
        _endpoint("POST", "/kontak"),
        _endpoint("GET", "/openapi.json"),
        _endpoint("GET", "/logout", excluded=True),
    ]
    specs = InformationGathering().plan(_plan(ScanStage.PLANNING, endpoints))
    js, *params = specs
    assert js.engine == "custom:js"
    assert js.target == {
        "pages": ["http://testapp:8080/"],
        "scripts": ["http://testapp:8080/static/app.js"],
    }
    assert [(s.engine, s.target["url"], s.params) for s in params] == [
        ("ffuf", "http://testapp:8080/cari", {"mode": "parameter"}),  # has parameters: first
        ("ffuf", "http://testapp:8080/produk", {"mode": "parameter"}),
    ]


class FakeCtx:
    """TaskContext pieces a test can inspect."""

    def __init__(self, engine: str, target: dict, params: dict | None = None, **settings: Any):
        self.seen: list[EndpointSeen] = []
        self.recon: list[dict] = []
        self.logs: list[str] = []
        self.tool_calls: list[tuple[str, dict, int]] = []
        self.tool_result: dict[str, Any] = {"status": "completed", "normalized": {}}
        self.transport: httpx.MockTransport | None = None
        self.engine, self.target, self.params, self.settings = (
            engine,
            target,
            params or {},
            settings,
        )

    def context(self) -> TaskContext:
        def run_tool(tool: str, params: dict, timeout_s: int = 600) -> dict:
            self.tool_calls.append((tool, params, timeout_s))
            return self.tool_result

        def add(seen: list[EndpointSeen]) -> int:
            self.seen.extend(seen)
            return len(seen)

        return TaskContext(
            task_id=9,
            scan_id=1,
            engagement_id=1,
            target_url="http://testapp:8080/",
            scope=["testapp"],
            settings=self.settings,
            engine=self.engine,
            target=self.target,
            params=self.params,
            cancel_event=threading.Event(),
            run_tool=run_tool,
            log=self.logs.append,
            add_endpoints=add,
            add_recon=self.recon.append,
            http=lambda purpose: httpx.Client(transport=self.transport),
            session_headers=lambda label=None: {"Cookie": "sid=abc"},
        )


def _normalized(adapter: Any, fixture: str, out: str, tmp_path: Path) -> dict[str, Any]:
    shutil.copy(FIXTURES / fixture, tmp_path / out)
    ctx = RunContext("http://x", tmp_path, tmp_path, tmp_path)
    return adapter.parse(ctx, "")


def test_katana_results_become_endpoints_and_forms(tmp_path: Path) -> None:
    fake = FakeCtx(
        "katana", {"urls": ["http://testapp:8080/"]}, excluded_patterns=["logout", "a b"]
    )
    fake.tool_result["normalized"] = _normalized(
        KatanaAdapter(), "katana_testapp.jsonl", "out.jsonl", tmp_path
    )
    summary = InformationGathering().run(fake.context())
    tool, params, timeout = fake.tool_calls[0]
    assert tool == "katana" and timeout == 700
    assert params["exclude"] == ["logout"]  # unsafe patterns are dropped
    assert params["headers"] == {"Cookie": "sid=abc"}
    seen = {(s.method, s.url): s for s in fake.seen}
    assert ("GET", "http://testapp:8080/akun/1") in seen
    upload = seen[("POST", "http://testapp:8080/upload")]
    assert upload.body_params == ({"name": "berkas", "location": "multipart"},)
    assert upload.content_type == "multipart/form-data"
    assert seen[("GET", "http://testapp:8080/cari")].query_params == ("q",)
    assert summary["added"] == len(fake.seen)


def test_browser_results_keep_runtime_calls_and_unfollowed_links(tmp_path: Path) -> None:
    fake = FakeCtx("browser", {"urls": ["http://testapp:8080/"]})
    fake.tool_result["normalized"] = _normalized(
        BrowserAdapter(), "browser_testapp.jsonl", "out.jsonl", tmp_path
    )
    InformationGathering().run(fake.context())
    by_url = {s.url: s for s in fake.seen}
    assert by_url["http://testapp:8080/api/v1/ringkasan"].source == "js"
    assert by_url["http://testapp:8080/static/app.js"].source == "crawl"
    assert "http://cdn.luar.test/lib.js" in by_url  # the inventory counts it out of scope
    assert any(s.method == "POST" and s.url.endswith("/kontak") for s in fake.seen)


def test_ffuf_directory_and_parameter_results(tmp_path: Path) -> None:
    fake = FakeCtx("ffuf", {"url": "http://testapp:8080/"}, {"mode": "directory"})
    fake.tool_result["normalized"] = _normalized(
        FfufAdapter(), "ffuf_directories.json", "out.json", tmp_path
    )
    InformationGathering().run(fake.context())
    assert fake.tool_calls[0][1]["wordlist"] == "directories"
    assert {s.url for s in fake.seen} >= {"http://testapp:8080/admin", "http://testapp:8080/.env"}
    assert {s.source for s in fake.seen} == {"fuzz"}

    fake = FakeCtx("ffuf", {"url": "http://testapp:8080/cari"}, {"mode": "parameter"})
    fake.tool_result["normalized"] = _normalized(
        FfufAdapter(), "ffuf_parameters.json", "out.json", tmp_path
    )
    assert InformationGathering().run(fake.context()) == {"params": ["debug"]}
    assert fake.tool_calls[0][1]["wordlist"] == "parameters"
    (seen,) = fake.seen
    assert (seen.url, seen.query_params) == ("http://testapp:8080/cari", ("debug",))


def test_nmap_ports_go_to_the_recon_summary() -> None:
    fake = FakeCtx("nmap", {"host": "testapp"}, rate_limit_rps=4)
    fake.tool_result["normalized"] = {"ports": [{"port": 8080, "service": "http"}]}
    InformationGathering().run(fake.context())
    assert fake.tool_calls[0][1] == {"host": "testapp", "max_rate": 20}
    assert fake.recon == [{"open_ports": [{"port": 8080, "service": "http"}]}]


def test_tool_timeouts_are_transient() -> None:
    fake = FakeCtx("katana", {"urls": ["http://testapp:8080/"]})
    fake.tool_result = {"status": "timeout"}
    with pytest.raises(TransientTaskError):
        InformationGathering().run(fake.context())
    fake.tool_result = {"status": "scope_rejected", "stderr_tail": ""}
    with pytest.raises(RuntimeError, match="scope_rejected"):
        InformationGathering().run(fake.context())


# Custom checks against testapp's real responses (served by its FastAPI app in-process).


@pytest.fixture
def testapp_transport() -> httpx.MockTransport:
    import importlib.util

    from fastapi.testclient import TestClient

    spec = importlib.util.spec_from_file_location("testapp_app", TESTAPP)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    client = TestClient(module.app, base_url="http://testapp:8080")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host != "testapp":
            return httpx.Response(403, headers={"X-Rajdoll-Blocked": "scope"})
        response = client.request(
            request.method,
            str(request.url),
            headers={k: v for k, v in request.headers.items() if k != "host"},
            content=request.content,
            follow_redirects=False,
        )
        return httpx.Response(
            response.status_code, headers=response.headers, content=response.content
        )

    return httpx.MockTransport(handler)


def test_openapi_check_reads_the_spec(testapp_transport: httpx.MockTransport) -> None:
    fake = FakeCtx("custom:openapi", {"base": "http://testapp:8080"})
    fake.transport = testapp_transport
    summary = InformationGathering().run(fake.context())
    assert summary["spec"] == "http://testapp:8080/openapi.json"
    seen = {(s.method, s.url): s for s in fake.seen}
    transfer = seen[("POST", "http://testapp:8080/api/v1/transfer")]
    assert [p["name"] for p in transfer.body_params] == ["ke_rekening", "jumlah"]
    assert transfer.source == "openapi" and transfer.content_type == "application/json"
    assert ("GET", "http://testapp:8080/api/v1/pengguna/{id}") in seen
    assert fake.recon == [{"api_specs": ["http://testapp:8080/openapi.json"]}]


def test_known_files_check_reads_robots(testapp_transport: httpx.MockTransport) -> None:
    fake = FakeCtx("custom:known_files", {"base": "http://testapp:8080"})
    fake.transport = testapp_transport
    InformationGathering().run(fake.context())
    assert {s.url for s in fake.seen} == {
        "http://testapp:8080/robots.txt",
        "http://testapp:8080/internal/laporan",
    }


def test_javascript_check_finds_source_only_endpoints(
    testapp_transport: httpx.MockTransport,
) -> None:
    fake = FakeCtx("custom:js", {"pages": ["http://testapp:8080/"], "scripts": []})
    fake.transport = testapp_transport
    InformationGathering().run(fake.context())
    found = {(s.method, s.url): s for s in fake.seen}
    for key in [
        ("GET", "http://testapp:8080/api/v1/ringkasan"),
        ("GET", "http://testapp:8080/api/v1/pesanan"),
        ("GET", "http://testapp:8080/api/v1/pesanan/{id}"),
        ("POST", "http://testapp:8080/api/v1/keranjang"),
    ]:
        assert key in found, key
    cart = found[("POST", "http://testapp:8080/api/v1/keranjang")]
    assert [p["name"] for p in cart.body_params] == ["produk_id", "jumlah"]
    assert {s.source for s in fake.seen} == {"js"}


def test_waf_check_on_an_unprotected_target(testapp_transport: httpx.MockTransport) -> None:
    fake = FakeCtx("custom:waf", {"url": "http://testapp:8080/"})
    fake.transport = testapp_transport
    assert InformationGathering().run(fake.context())["detected"] is False
    assert fake.recon[0]["waf"]["detected"] is False


# Pure helpers ----------------------------------------------------------------------------


def test_js_extract_patterns() -> None:
    source = r"""
        const API = "/api/v2";
        axios.post("/api/v2/login", data);
        $.get("/rest/items?limit=10");
        xhr.open("DELETE", API + "/items/" + id);
        const re = /\/g/; var date = "2024/01/02"; var s = "/"; var css = "/a/b.css";
        fetch(window.location.origin + "/api/v2/me", {credentials: "include"});
        fetch(`/api/v3/users/${user.id}/orders?page=${p}`);
        fetch("/api/v2/cart", {method: "PUT", headers: {"X-A": "1"},
                               body: JSON.stringify({sku: s, qty: 2})});
    """
    found = {(e.method, e.path): e for e in js_analysis.extract(source)}
    assert set(found) == {
        ("POST", "/api/v2/login"),
        ("GET", "/rest/items"),
        ("DELETE", "/api/v2/items/{id}"),
        ("GET", "/api/v2/me"),
        ("GET", "/api/v3/users/{id}/orders"),
        ("PUT", "/api/v2/cart"),
    }
    assert found[("PUT", "/api/v2/cart")].body_params == ["sku", "qty"]


def test_js_source_maps_and_html_scripts() -> None:
    assert (
        js_analysis.source_map_url("x\n//# sourceMappingURL=app.js.map", "https://a.test/s/app.js")
        == "https://a.test/s/app.js.map"
    )
    assert js_analysis.source_map_url("//# sourceMappingURL=data:abc", "https://a.test/") is None
    mapped = js_analysis.extract_from_source_map(
        {"sourcesContent": ['fetch("/api/hidden/one")', None]}
    )
    assert [e.path for e in mapped] == ["/api/hidden/one"]
    external, inline = js_analysis.scripts_in_html(
        '<script src="/a.js"></script><script>fetch("/api/x/y")</script>', "https://a.test/p/"
    )
    assert external == ["https://a.test/a.js"]
    assert inline == ['fetch("/api/x/y")']


def test_openapi_helpers_handle_swagger_2_and_yaml() -> None:
    spec = openapi.load_spec(
        json.dumps(
            {
                "swagger": "2.0",
                "basePath": "/api",
                "definitions": {"Login": {"properties": {"user": {}, "pass": {}}}},
                "paths": {
                    "/login": {
                        "post": {
                            "parameters": [
                                {"in": "body", "schema": {"$ref": "#/definitions/Login"}},
                                {"in": "query", "name": "next"},
                            ]
                        }
                    }
                },
            }
        )
    )
    assert spec is not None
    (op,) = openapi.endpoints_from_spec(spec)
    assert op["path"] == "/api/login" and op["query_params"] == ["next"]
    assert [p["name"] for p in op["body_params"]] == ["user", "pass"]
    assert openapi.load_spec("openapi: 3.0.0\npaths:\n  /x:\n    get: {}\n") is not None
    assert openapi.load_spec("<html>") is None
    assert openapi.spec_url_in_html('SwaggerUIBundle({url: "/v3/spec.yaml"})') == "/v3/spec.yaml"


def test_known_files_helpers() -> None:
    paths, sitemaps = known_files.robots_paths(
        "User-agent: *\nDisallow: /admin/\nDisallow: /*.pdf$\nAllow: /public$\nDisallow: /\n"
        "Sitemap: https://a.test/s.xml\n"
    )
    assert paths == ["/admin/", "/public"]
    assert sitemaps == ["https://a.test/s.xml"]
    assert known_files.sitemap_urls(
        "<urlset><url><loc> /a </loc></url></urlset>", "https://a.test/"
    ) == ["https://a.test/a"]


@pytest.mark.parametrize(
    ("attack", "name"),
    [
        (waf.Sample(403, {"server": "cloudflare"}, [], ""), "Cloudflare"),
        (waf.Sample(403, {}, ["incap_ses_1_2"], ""), "Imperva Incapsula"),
        (
            waf.Sample(403, {}, [], "The requested URL was rejected. Support ID is 1"),
            "F5 BIG-IP ASM",
        ),
        (
            waf.Sample(406, {"server": "Apache"}, [], "Not Acceptable! ... Mod_Security"),
            "ModSecurity",
        ),
        (waf.Sample(403, {}, [], "Forbidden"), None),
    ],
)
def test_waf_signatures(attack: waf.Sample, name: str | None) -> None:
    baseline = waf.Sample(200, {"server": "nginx"}, [], "<html>")
    result = waf.detect(baseline, attack)
    assert result["detected"] is True
    assert result["name"] == name
    assert result["blocks_attacks"] is True
