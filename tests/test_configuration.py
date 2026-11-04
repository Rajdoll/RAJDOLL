"""Configuration & Deployment (IPD F8b): security headers, versions, TRACE, backup files, and the
nuclei exposure templates, against testapp and against applications without these weaknesses.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.testclient import TestClient

from rajdoll.core.enums import ScanStage
from rajdoll.modules import config_checks
from rajdoll.modules.base import Candidate, EndpointSeen, PlanContext, TaskContext
from rajdoll.modules.configuration import Configuration
from rajdoll.services import planning, tagging
from rajdoll.validators import configuration  # noqa: F401  (registers the validators)
from rajdoll.validators.base import VALIDATORS
from tests.test_injection_checks import _testapp

BASE = "http://testserver"
TESTAPP = _testapp()


def _ctx(app: FastAPI, engine: str, target: dict, **hooks: Any) -> TaskContext:
    return TaskContext(
        task_id=1,
        scan_id=1,
        engagement_id=1,
        target_url=BASE + "/",
        scope=["testserver"],
        settings={},
        engine=engine,
        target=target,
        params={},
        cancel_event=threading.Event(),
        run_tool=hooks.pop("run_tool", lambda *_a, **_k: {"status": "completed"}),
        log=hooks.pop("log", lambda _m: None),
        http=lambda _purpose: TestClient(app, raise_server_exceptions=False),
        **hooks,
    )


def _run(app: FastAPI, engine: str, target: dict, **hooks: Any) -> tuple[list, list]:
    reported: list[Candidate] = []
    added: list[EndpointSeen] = []
    ctx = _ctx(
        app, engine, target, report_candidate=lambda c: reported.append(c) or 1,
        add_endpoints=lambda seen: added.extend(seen) or len(seen), **hooks,
    )  # fmt: skip
    Configuration().run(ctx)
    return reported, added


def _finding(candidate: Candidate) -> dict[str, Any]:
    return {"id": 9, "vuln_type": candidate.vuln_type, "poc": candidate.poc, "base_url": BASE}


def _validate(app: FastAPI, candidate: Candidate, **hooks: Any) -> Any:
    return VALIDATORS[candidate.vuln_type](_ctx(app, "v", {}, **hooks), _finding(candidate))


# -- planning ---------------------------------------------------------------------------------


def test_plan_runs_once_per_host_and_backups_for_server_side_files() -> None:
    rows = []
    for number, (method, path) in enumerate(
        [("GET", "/index.php"), ("GET", "/static/app.js"), ("GET", "/akun/{id}.php"),
         ("POST", "/login.php"), ("GET", "/config.yml"), ("GET", "/hapus.php")], 1,
    ):  # fmt: skip
        row: dict[str, Any] = {
            "id": number, "method": method, "path_template": path, "url": BASE + path,
            "scheme": "http", "host": "testserver", "query_params": [], "body_params": [],
            "excluded": path == "/hapus.php",
        }  # fmt: skip
        row["tags"] = tagging.rule_tags(row)
        row["modules"] = planning.modules_for(row, ["configuration"])
        rows.append(row)
    ctx = PlanContext(1, 1, BASE + "/", [], {}, ScanStage.TESTING, endpoints=rows)
    specs = Configuration().plan(ctx)
    assert [s.engine for s in specs] == [
        "nuclei:config", "custom:headers", "custom:trace", "custom:backups",
    ]  # fmt: skip
    assert specs[0].target == {"origin": BASE}
    assert specs[-1].target == {"urls": [BASE + "/index.php", BASE + "/config.yml"]}


# -- headers and versions ---------------------------------------------------------------------


def test_testapp_headers_and_version() -> None:
    reported, added = _run(TESTAPP.app, "custom:headers", {"origin": BASE})
    found = {(c.vuln_type, c.parameter): c for c in reported}
    assert set(found) == {("missing_security_headers", None), ("version_disclosure", "Server")}
    headers = found[("missing_security_headers", None)]
    assert headers.poc["validator_params"]["missing"] == [
        "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
    ]  # fmt: skip
    assert added == []  # the root page is already in the inventory
    for candidate in reported:
        verdict = _validate(TESTAPP.app, candidate)
        assert verdict.confirmed and "2 kali" in verdict.note


def _hardened() -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def headers(request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers.update({
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff", "Server": "nginx",
        })  # fmt: skip
        return response

    app.get("/")(lambda: HTMLResponse("<h1>Beranda</h1>"))
    app.get("/index.php")(lambda: HTMLResponse("<h1>Beranda</h1>"))
    return app


def test_a_hardened_app_gives_no_header_candidates_and_validators_do_not_confirm() -> None:
    assert _run(_hardened(), "custom:headers", {"origin": BASE})[0] == []
    for candidate in _run(TESTAPP.app, "custom:headers", {"origin": BASE})[0]:
        verdict = _validate(_hardened(), candidate)
        assert not verdict.confirmed and "cek manual" in verdict.note


def test_missing_headers_rules() -> None:
    import httpx

    full = httpx.Headers(
        {
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
        }
    )
    assert config_checks.missing_headers(full, https=False) == []
    assert config_checks.missing_headers(full, https=True) == ["Strict-Transport-Security"]
    framed = httpx.Headers({"content-security-policy": "frame-ancestors 'self'",
                            "x-content-type-options": "nosniff"})  # fmt: skip
    assert config_checks.missing_headers(framed, https=False) == []
    assert config_checks.version_headers(
        httpx.Headers({"server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "Express"})
    ) == {"Server": "Apache/2.4.41 (Ubuntu)"}


# -- TRACE --------------------------------------------------------------------------------------


def test_trace_echo_is_reported_and_validated() -> None:
    (candidate,), _added = _run(TESTAPP.app, "custom:trace", {"origin": BASE})
    assert (candidate.vuln_type, candidate.poc["method"]) == ("http_trace", "TRACE")
    assert candidate.evidence[0].request.startswith("TRACE / HTTP/1.1")
    assert _validate(TESTAPP.app, candidate).confirmed
    plain = _hardened()
    assert _run(plain, "custom:trace", {"origin": BASE})[0] == []
    assert not _validate(plain, candidate).confirmed


# -- backup files ------------------------------------------------------------------------------


def test_testapp_backup_file_is_found_registered_and_validated() -> None:
    reported, added = _run(TESTAPP.app, "custom:backups", {"urls": [BASE + "/index.php"]})
    (candidate,) = reported
    assert (candidate.vuln_type, candidate.url) == ("backup_file", BASE + "/index.php.bak")
    assert candidate.poc["validator_params"] == {
        "source": "backup", "original_path": "/index.php", "suffix": ".bak",
    }  # fmt: skip
    assert [(s.method, s.url, s.source) for s in added] == [
        ("GET", BASE + "/index.php.bak", "fuzz")
    ]
    assert "<?php" in candidate.evidence[1].response
    assert _validate(TESTAPP.app, candidate).confirmed
    assert not _validate(_hardened(), candidate).confirmed


def _catch_all(mode: str) -> FastAPI:
    """A server that answers every path: a soft-404 page, or the page itself for any suffix."""
    app = FastAPI()

    @app.get("/{path:path}")
    def anything(path: str) -> Response:
        if mode == "soft404" and path != "index.php":
            return HTMLResponse("<h1>Halaman tidak ditemukan</h1><p>Kembali ke beranda</p>")
        if mode == "same":
            return HTMLResponse("<h1>Beranda</h1><p>Selamat datang di aplikasi</p>")
        return PlainTextResponse("teks biasa tanpa kode")

    return app


@pytest.mark.parametrize("mode", ["soft404", "same"])
def test_soft_404_and_ignored_suffixes_are_not_backups(mode: str) -> None:
    reported, _added = _run(_catch_all(mode), "custom:backups", {"urls": [BASE + "/index.php"]})
    assert reported == []


# -- nuclei ------------------------------------------------------------------------------------


def _hit(template_path: str, matched: str, template_id: str = "git-config") -> dict[str, Any]:
    return {
        "template_id": template_id,
        "name": "Git Configuration - Detect",
        "template_path": template_path,
        "matched_at": matched,
        "extracted": ["deploy:rahasia"],
        "request": f"GET {matched[len(BASE) :]} HTTP/1.1\r\nHost: testserver\r\n\r\n",
        "response": "HTTP/1.1 200 OK\r\n\r\n[core]\nurl = https://deploy:rahasia@git.test",
    }


def test_nuclei_hits_become_findings_with_their_endpoints() -> None:
    calls: list[dict] = []

    def run_tool(tool: str, params: dict, timeout_s: int) -> dict:
        calls.append(params)
        hits = [
            _hit("config/sensitive_file/git-config.yaml", BASE + "/.git/config"),
            _hit("rajdoll/exposure/exposed-env-file.yaml", BASE + "/.env", "rajdoll-env"),
            _hit("config/debug_exposed/phpinfo-files.yaml", BASE + "/info.php", "phpinfo"),
            _hit("config/sensitive_file/git-config.yaml", "http://lain.test/.git/config"),
            _hit("dast/sqli/x.yaml", BASE + "/cari?q=1"),
        ]
        return {"status": "completed", "normalized": {"candidates": hits}}

    reported, added = _run(TESTAPP.app, "nuclei:config", {"origin": BASE}, run_tool=run_tool)
    assert calls == [{"targets": [BASE], "templates": ["config", "rajdoll/exposure"]}]
    assert [(c.vuln_type, c.url) for c in reported] == [
        ("sensitive_file", BASE + "/.git/config"),
        ("sensitive_file", BASE + "/.env"),
        ("debug_exposed", BASE + "/info.php"),
    ]
    assert [s.url for s in added] == [c.url for c in reported]
    # Values the template extracted (credentials) never go into a note: notes are plaintext.
    assert all("rahasia" not in (e.note or "") for c in reported for e in c.evidence)
    assert reported[0].poc["validator_params"] == {
        "source": "nuclei_template",
        "template": "config/sensitive_file/git-config.yaml",
        "template_id": "git-config",
    }


@pytest.mark.parametrize(("matched", "confirmed"), [("/.git/config", True), ("/lain", False)])
def test_template_validator_needs_the_same_template_on_the_same_path(
    matched: str, confirmed: bool
) -> None:
    candidate = Candidate(
        "sensitive_file", "GET", BASE + "/.git/config", None,
        {"method": "GET", "path": "/.git/config", "validator_params": {
            "source": "nuclei_template", "template": "config/sensitive_file/git-config.yaml",
            "template_id": "git-config"}},
    )  # fmt: skip

    def run_tool(tool: str, params: dict, timeout_s: int) -> dict:
        assert params["templates"] == ["config/sensitive_file/git-config.yaml"]
        hit = _hit("config/sensitive_file/git-config.yaml", BASE + matched)
        return {"status": "completed", "normalized": {"candidates": [hit]}}

    verdict = _validate(TESTAPP.app, candidate, run_tool=run_tool)
    assert verdict.confirmed is confirmed


def test_vendored_templates_name_known_types() -> None:
    from pathlib import Path

    from rajdoll.data.vuln_types import CATALOG

    root = Path(__file__).resolve().parent.parent / "templates" / "nuclei" / "config"
    types = {p.parent.name for p in root.glob("*/*.yaml")}
    assert types == {"sensitive_file", "backup_file", "debug_exposed"}
    assert types <= set(CATALOG)
    assert config_checks.nuclei_vuln_type("rajdoll/exposure/exposed-env-file.yaml") == (
        "sensitive_file"
    )
    assert config_checks.nuclei_vuln_type("dast/sqli/x.yaml") is None
