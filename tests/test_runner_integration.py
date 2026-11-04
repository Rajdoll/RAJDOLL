"""Runner with the real tool binaries, the real egress proxy, and testapp.

F3 exit criterion: running nuclei through /run against testapp produces an audit row for
every request, and out-of-scope targets are refused. F5 adds katana, ffuf, nmap, and the
Playwright `browser` crawler. Needs mitmproxy (tools requirements) and the tool binaries; point
RAJDOLL_TOOL_BIN_DIR at a directory containing `nuclei`, `httpx`, `katana`, `ffuf`, and `nmap`.
The browser test also needs Playwright's Chromium (PLAYWRIGHT_BROWSERS_PATH). In CI the same
flow runs inside the real containers (tests/integration/smoke_tools.py).
"""

import json
import os
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url

from rajdoll.core.bootstrap import enable_tools_login
from tests.helpers import MITMDUMP, REPO, clean_env, free_port, start_mitmdump, wait_for_port

BIN_DIR = Path(os.environ.get("RAJDOLL_TOOL_BIN_DIR", "/opt/tools/bin"))
TOKEN = "runner-integration-token"
TOOLS_PASSWORD = "runner-integration-password"

_missing = [p for p in (MITMDUMP, BIN_DIR / "nuclei", BIN_DIR / "httpx") if not p.exists()]
if _missing:
    if os.environ.get("RAJDOLL_REQUIRE_TOOL_TESTS") == "1":
        pytest.fail(f"missing for tool tests: {_missing}", pytrace=False)
    pytest.skip(f"tool binaries not available: {_missing}", allow_module_level=True)

from tools.runner.app import RunnerConfig, create_app  # noqa: E402


def _needs(*names: str) -> pytest.MarkDecorator:
    missing = [n for n in names if not (BIN_DIR / n).exists()]
    if missing and os.environ.get("RAJDOLL_REQUIRE_TOOL_TESTS") == "1":
        pytest.fail(f"missing for tool tests: {missing}", pytrace=False)
    return pytest.mark.skipif(bool(missing), reason=f"not available: {missing}")


def _playwright_ready() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as playwright:
            return Path(playwright.chromium.executable_path).exists()
    except Exception:  # noqa: BLE001
        return False


@dataclass
class Env:
    engine: Engine
    client: TestClient
    testapp: str
    task_id: int
    scan_id: int
    engagement_id: int

    def run(self, tool: str, params: dict[str, Any], scope: list[str] | None = None) -> dict:
        response = self.client.post(
            "/run",
            json={
                "run_id": f"it-{uuid.uuid4().hex[:12]}",
                "task_id": self.task_id,
                "scan_id": self.scan_id,
                "tool": tool,
                "timeout_s": 120,
                "scope": scope or ["127.0.0.1"],
                "params": params,
            },
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        assert response.status_code == 200, response.text
        return response.json()

    def audit(self, tool: str, minimum: int) -> list[Any]:
        deadline = time.monotonic() + 15
        query = text("SELECT * FROM request_log WHERE task_id = :t AND tool = :tool ORDER BY id")
        while True:
            with self.engine.connect() as conn:
                rows = conn.execute(query, {"t": self.task_id, "tool": tool}).mappings().all()
            if len(rows) >= minimum or time.monotonic() > deadline:
                return list(rows)
            time.sleep(0.3)


@pytest.fixture(scope="module")
def env(db_engine: Engine, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Env]:
    tmp = tmp_path_factory.mktemp("runner")
    enable_tools_login(db_engine, TOOLS_PASSWORD)
    with db_engine.begin() as conn:
        engagement_id = conn.execute(
            text(
                "INSERT INTO engagement (name, target_url, key_id) "
                "VALUES ('testapp', 'http://127.0.0.1/', :k) RETURNING id"
            ),
            {"k": uuid.uuid4()},
        ).scalar_one()
        conn.execute(
            text("INSERT INTO scope_rule (engagement_id, pattern) VALUES (:e, '127.0.0.1')"),
            {"e": engagement_id},
        )
        scan_id = conn.execute(
            text(
                "INSERT INTO scan (engagement_id, kind, number, profile, status, "
                "settings_snapshot) VALUES (:e, 'scan', 1, 'full', 'running', "
                "CAST(:s AS jsonb)) RETURNING id"
            ),
            {"e": engagement_id, "s": json.dumps({"rate_limit_rps": 100})},
        ).scalar_one()
        task_id = conn.execute(
            text(
                "INSERT INTO task (scan_id, stage, module, engine) "
                "VALUES (:s, 'testing', 'configuration', 'nuclei') RETURNING id"
            ),
            {"s": scan_id},
        ).scalar_one()

    app_port = free_port()
    testapp = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(app_port),
            "--no-server-header",
        ],
        cwd=REPO / "testapp",
        env=clean_env(),
    )
    db_url = make_url(db_engine.url).set(
        drivername="postgresql", username="rajdoll_tools", password=TOOLS_PASSWORD
    )
    proxy, proxy_port = start_mitmdump(
        db_url.render_as_string(hide_password=False), TOKEN, tmp / "mitm"
    )
    try:
        wait_for_port(app_port)
        config = RunnerConfig(
            token=TOKEN,
            proxy_port=proxy_port,
            bin_dir=BIN_DIR,
            template_dir=REPO / "templates" / "nuclei",
            wordlist_dir=REPO / "tools" / "wordlists",
            tool_home=tmp / "home",
            audit_dsn=db_url.render_as_string(hide_password=False),
            work_root=tmp,
        )
        with TestClient(create_app(config)) as client:
            yield Env(
                engine=db_engine,
                client=client,
                testapp=f"http://127.0.0.1:{app_port}",
                task_id=task_id,
                scan_id=scan_id,
                engagement_id=engagement_id,
            )
    finally:
        proxy.terminate()
        testapp.terminate()
        proxy.wait(timeout=10)
        testapp.wait(timeout=10)


def test_nuclei_finds_exposed_env_and_every_request_is_audited(env: Env) -> None:
    body = env.run("nuclei", {"targets": [env.testapp], "templates": ["rajdoll"]})
    assert body["status"] == "completed", body["stderr_tail"]
    (candidate,) = body["normalized"]["candidates"]
    assert candidate["template_id"] == "rajdoll-exposed-env-file"
    assert candidate["matched_at"] == f"{env.testapp}/.env"
    assert "DB_PASSWORD" in candidate["response"]

    rows = env.audit("nuclei", 1)
    assert rows, "nuclei traffic must pass through the egress proxy"
    assert all(r["outcome"] == "forwarded" for r in rows)
    assert all(r["engagement_id"] == env.engagement_id for r in rows)
    assert any(r["url"] == f"{env.testapp}/.env" and r["status"] == 200 for r in rows)


def test_httpx_probes_through_the_proxy(env: Env) -> None:
    urls = [env.testapp, f"{env.testapp}/profil"]
    body = env.run("httpx", {"urls": urls})
    assert body["status"] == "completed", body["stderr_tail"]
    endpoints = {e["url"]: e for e in body["normalized"]["endpoints"]}
    assert endpoints[env.testapp]["title"] == "RAJDOLL testapp"
    assert endpoints[env.testapp]["server"] == "rajdoll-testapp/1.0"
    assert endpoints[f"{env.testapp}/profil"]["redirect_chain"] == [302, 200]
    assert len(env.audit("httpx", 3)) >= 3  # two probes plus the followed redirect


def test_out_of_scope_target_never_starts_a_tool(env: Env) -> None:
    before = len(env.audit("nuclei", 0))
    body = env.run("nuclei", {"targets": ["http://localhost:1/"]})
    assert body["status"] == "scope_rejected"
    assert body["out_of_scope"] == ["localhost"]
    assert len(env.audit("nuclei", 0)) == before


@_needs("katana")
def test_katana_crawls_links_and_forms_through_the_proxy(env: Env) -> None:
    body = env.run("katana", {"urls": [env.testapp + "/"], "depth": 3, "exclude": ["logout"]})
    assert body["status"] == "completed", body["stderr_tail"]
    found = {(e["method"], e["url"]) for e in body["normalized"]["endpoints"]}
    for path in ("/", "/produk", "/produk/1", "/login", "/static/app.js"):
        assert ("GET", env.testapp + path) in found, path
    forms = {(f["method"], f["url"]): f["params"] for f in body["normalized"]["forms"]}
    assert forms[("POST", env.testapp + "/kontak")] == ["nama", "pesan"]
    assert forms[("GET", env.testapp + "/cari")] == ["q"]
    assert len(env.audit("katana", 5)) >= 5


@_needs("ffuf")
def test_ffuf_finds_hidden_paths_and_parameters(env: Env) -> None:
    body = env.run("ffuf", {"url": env.testapp + "/", "exclude": ["logout"]})
    assert body["status"] == "completed", body["stderr_tail"]
    found = {r["url"]: r["status"] for r in body["normalized"]["results"]}
    assert found[env.testapp + "/admin"] == 403
    assert found[env.testapp + "/.env"] == 200
    assert found[env.testapp + "/robots.txt"] == 200

    body = env.run(
        "ffuf", {"url": env.testapp + "/cari?q=a", "mode": "parameter", "wordlist": "parameters"}
    )
    assert body["status"] == "completed", body["stderr_tail"]
    assert [r["param"] for r in body["normalized"]["results"]] == ["debug"]
    assert env.audit("ffuf", 100)


@_needs("nmap")
def test_nmap_scans_ports_and_writes_one_audit_row(env: Env) -> None:
    port = int(env.testapp.rsplit(":", 1)[1])
    body = env.run("nmap", {"host": "127.0.0.1", "ports": [port, 1]})
    assert body["status"] == "completed", body["stderr_tail"]
    assert [p["port"] for p in body["normalized"]["ports"]] == [port]
    rows = env.audit("nmap", 1)
    assert len(rows) == 1
    assert (rows[0]["kind"], rows[0]["host"]) == ("tool_exec", "127.0.0.1")
    assert rows[0]["url"] == f"nmap -sT 127.0.0.1 ports=1,{port}"

    refused = env.run("nmap", {"host": "localhost"})
    assert refused["status"] == "scope_rejected"
    assert len(env.audit("nmap", 1)) == 1


@pytest.mark.skipif(not _playwright_ready(), reason="Playwright Chromium not installed")
def test_browser_records_runtime_requests_and_blocked_hosts(env: Env) -> None:
    body = env.run("browser", {"urls": [env.testapp + "/"], "exclude": ["logout"]})
    assert body["status"] == "completed", body["stderr_tail"]
    normalized = body["normalized"]
    requested = {(r["method"], r["url"]) for r in normalized["requests"]}
    assert ("GET", env.testapp + "/api/v1/ringkasan") in requested  # only in JavaScript
    assert ("GET", "http://cdn.luar.test/lib.js") in requested
    assert {p["url"] for p in normalized["pages"]} >= {env.testapp + "/", env.testapp + "/produk"}
    rows = env.audit("browser", 3)
    blocked = [r for r in rows if r["outcome"] == "blocked_scope"]
    assert {r["host"] for r in blocked} == {"cdn.luar.test"}
