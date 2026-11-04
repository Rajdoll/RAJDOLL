"""Error Handling (IPD F8b): stack traces, debug pages, and server paths in error responses.

testapp's `/laporan?limit=` shows a Python traceback for a value that is not a number; its other
parameters fail without leaking (SQL errors are Input Validation's evidence, not this module's).
"""

from __future__ import annotations

import threading
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.testclient import TestClient

from rajdoll.core.enums import ScanStage
from rajdoll.llm.tasks import Judgement
from rajdoll.modules import error_checks
from rajdoll.modules.base import Candidate, PlanContext, TaskContext
from rajdoll.modules.error_handling import ErrorHandling
from rajdoll.services import planning, tagging
from rajdoll.validators import errors  # noqa: F401  (registers the validator)
from rajdoll.validators.base import VALIDATORS
from tests.test_injection_checks import _testapp

BASE = "http://testserver"
TESTAPP = _testapp()


def _endpoint(path: str, query: list[str]) -> dict[str, Any]:
    return {"method": "GET", "url": BASE + path, "query_params": query, "body_params": []}


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
        run_tool=lambda *_a, **_k: {"status": "completed"},
        log=lambda _m: None,
        http=lambda _purpose: TestClient(app, raise_server_exceptions=False),
        session_headers=lambda _label=None: {"Cookie": "sid=x"},
        **hooks,
    )


def _run(app: FastAPI, engine: str, target: dict, **hooks: Any) -> list[Candidate]:
    reported: list[Candidate] = []
    ctx = _ctx(app, engine, target, report_candidate=lambda c: reported.append(c) or 1, **hooks)
    ErrorHandling().run(ctx)
    return reported


def _validate(app: FastAPI, candidate: Candidate) -> Any:
    finding = {"id": 4, "vuln_type": candidate.vuln_type, "poc": candidate.poc, "base_url": BASE}
    return VALIDATORS["error_disclosure"](_ctx(app, "v", {}), finding)


# -- planning ---------------------------------------------------------------------------------


def test_plan_tests_parameters_and_each_host_once() -> None:
    rows = []
    for number, (path, query) in enumerate([("/laporan", ["limit"]), ("/profil", [])], 1):
        row: dict[str, Any] = {
            "id": number, "method": "GET", "path_template": path, "url": BASE + path,
            "scheme": "http", "host": "testserver", "query_params": query, "body_params": [],
            "excluded": False,
        }  # fmt: skip
        row["tags"] = tagging.rule_tags(row)
        row["modules"] = planning.modules_for(row, ["error_handling"])
        rows.append(row)
    ctx = PlanContext(1, 1, BASE + "/", [], {}, ScanStage.TESTING, endpoints=rows)
    specs = ErrorHandling().plan(ctx)
    assert [(s.engine, s.target.get("url") or s.target.get("origin")) for s in specs] == [
        ("custom:errors", BASE + "/laporan"),
        ("custom:not_found", BASE),
    ]


# -- testapp ----------------------------------------------------------------------------------


def test_testapp_traceback_is_reported_and_validated() -> None:
    (candidate,) = _run(TESTAPP.app, "custom:errors", _endpoint("/laporan", ["limit"]))
    assert (candidate.vuln_type, candidate.parameter) == ("error_disclosure", "limit")
    assert candidate.poc["validator_params"]["base"] == "1"
    assert "stack trace Python" in candidate.poc["validator_params"]["patterns"]
    normal, error = candidate.evidence
    assert (normal.status, error.status) == (200, 500)
    assert "Traceback (most recent call last)" in error.response
    assert "cookie: [sesi akun]" in error.request.lower()
    verdict = _validate(TESTAPP.app, candidate)
    assert verdict.confirmed and "terulang 2 kali" in verdict.note


@pytest.mark.parametrize(
    ("path", "query"),
    [("/katalog", ["nama"]), ("/sapa", ["nama"]), ("/pratinjau", ["templat"]), ("/cari", ["q"])],
)
def test_other_testapp_errors_do_not_leak(path: str, query: list[str]) -> None:
    # /katalog shows SQL errors (Input Validation's evidence); /pratinjau fails with a bare 500.
    assert _run(TESTAPP.app, "custom:errors", _endpoint(path, query)) == []


def test_testapp_not_found_page_is_plain() -> None:
    assert _run(TESTAPP.app, "custom:not_found", {"origin": BASE}) == []


# -- other applications -----------------------------------------------------------------------


def _debug_app(fixed: bool = False) -> FastAPI:
    app = FastAPI()

    @app.get("/")
    def index() -> HTMLResponse:
        return HTMLResponse('<h1>Beranda</h1><script src="/opt/app.js"></script>')

    @app.get("/laporan")
    def report(limit: str = "10") -> Response:
        if not limit.isdigit():
            if fixed:
                return JSONResponse({"detail": "Parameter tidak valid"}, status_code=400)
            return PlainTextResponse(
                "Warning: Division by zero in /var/www/html/laporan.php on line 12",
                status_code=500,
            )
        return HTMLResponse("<ul><li>1</li></ul>")

    @app.get("/{missing:path}")
    def not_found(missing: str) -> Response:
        if fixed:
            return HTMLResponse("<h1>Tidak ditemukan</h1>", status_code=404)
        return HTMLResponse(
            "<p>Using the URLconf defined in <code>proyek.urls</code>, Django tried these "
            "URL patterns</p><p>You're seeing this error because you have <code>DEBUG = True"
            "</code></p>",
            status_code=404,
        )

    return app


def test_debug_404_and_php_warnings_are_found_and_fixed_apps_are_not() -> None:
    (page,) = _run(_debug_app(), "custom:not_found", {"origin": BASE})
    assert (page.url, page.poc["validator_params"]["source"]) == (BASE + "/", "not_found")
    assert set(page.poc["validator_params"]["patterns"]) == {"halaman debug Django"}
    (param,) = _run(_debug_app(), "custom:errors", _endpoint("/laporan", ["limit"]))
    assert set(param.poc["validator_params"]["patterns"]) == {"error PHP", "path file server"}
    for candidate in (page, param):
        assert _validate(_debug_app(), candidate).confirmed
        assert not _validate(_debug_app(fixed=True), candidate).confirmed
    assert _run(_debug_app(fixed=True), "custom:not_found", {"origin": BASE}) == []
    assert _run(_debug_app(fixed=True), "custom:errors", _endpoint("/laporan", ["limit"])) == []


def _bare_500_app() -> FastAPI:
    app = FastAPI()

    @app.get("/data")
    def data(id: str = "1") -> Response:  # noqa: A002
        if not id.isdigit():
            return PlainTextResponse("Kesalahan internal: kolom pegawai.nip tidak ditemukan", 500)
        return JSONResponse({"id": id})

    return app


@pytest.mark.parametrize(("answer", "reported"), [("ya", True), ("ragu", False)])
def test_the_llm_only_steers_an_unmatched_500(answer: str, reported: bool) -> None:
    asked: list[str] = []

    class Outcome:
        ok = True
        value = Judgement(answer=answer, reason="nama tabel dan kolom terlihat")

    def llm(task: Any, messages: list[dict[str, str]], **_ids: Any) -> Outcome:
        asked.append(task.kind)
        return Outcome()

    found = _run(_bare_500_app(), "custom:errors", _endpoint("/data", ["id"]), llm=llm)
    assert bool(found) is reported
    assert 1 <= len(asked) <= 3
    if found:
        assert "Penilaian LLM" in found[0].note
        # No pattern matches, so the validator cannot confirm it (TRD P3).
        assert not _validate(_bare_500_app(), found[0]).confirmed


def test_patterns() -> None:
    samples = {
        "stack trace Java": "at com.instansi.app.Controller.show(Controller.java:42)",
        "stack trace .NET": "[NullReferenceException: Object reference not set]",
        "halaman error ASP.NET": "Server Error in '/' Application.",
        "stack trace Node.js": "Error: boom\n    at Object.<anonymous> (/srv/app/index.js:3:9)",
        "stack trace Ruby": "app/models/user.rb:12:in `find'",
        "halaman debug Laravel": "Whoops, looks like something went wrong.",
        "panic Go": "goroutine 1 [running]:",
    }
    for name, text in samples.items():
        assert name in error_checks.leaks(text), name
    for text in (
        "Terjadi error saat memuat data, silakan coba lagi.",
        "You have an error in your SQL syntax near ''' at line 1",
        '<a href="/home/profil/index.php">Profil</a>',
    ):
        assert error_checks.leaks(text) == [], text
    assert error_checks.new_leaks("goroutine 1 [running]", "goroutine 1 [running]") == []
