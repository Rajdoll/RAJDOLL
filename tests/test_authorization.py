"""Authorization with two accounts (IPD F8a): IDOR and privilege escalation against testapp,
silence against fixed applications, and the validators.

testapp's `/akun/{id}` shows any account's private data to any logged-in user (IDOR) and
`/admin/pengguna` checks only the login while `/admin` checks the admin role (privilege
escalation). Akun A is budi (admin), Akun B is sari (user).
"""

from __future__ import annotations

import threading
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.testclient import TestClient

from rajdoll.core.enums import ScanStage
from rajdoll.llm.tasks import Judgement
from rajdoll.modules import authz_checks
from rajdoll.modules.authorization import Authorization
from rajdoll.modules.authz_checks import Fetched, IdorRound, Reference, Target
from rajdoll.modules.base import Candidate, Exchange, PlanContext, TaskContext
from rajdoll.services import planning, tagging
from rajdoll.services.findings import poc_accounts
from rajdoll.validators import authorization  # noqa: F401  (registers the validators)
from rajdoll.validators.base import VALIDATORS
from tests.test_injection_checks import _testapp

BASE = "http://testserver"
TESTAPP = _testapp()
ENDPOINTS = [
    ("GET", "/"),
    ("GET", "/profil"),
    ("GET", "/akun/{id}"),
    ("GET", "/produk/{id}"),
    ("GET", "/api/v1/pesanan/{id}"),
    ("GET", "/api/v1/pengguna/{id}"),
    ("GET", "/admin"),
    ("GET", "/admin/pengguna"),
    ("GET", "/logout"),
    ("POST", "/api/v1/transfer"),
]


def _endpoints(rows: list[tuple[str, str]] = ENDPOINTS) -> list[dict[str, Any]]:
    result = []
    for number, (method, path) in enumerate(rows, start=1):
        row: dict[str, Any] = {
            "id": number,
            "method": method,
            "path_template": path,
            "url": BASE + path,
            "query_params": [],
            "body_params": [],
            "excluded": path == "/logout",
        }
        row["tags"] = tagging.rule_tags(row)
        row["modules"] = planning.modules_for(row, ["authorization", "input_validation"])
        result.append(row)
    return result


def _login(app: FastAPI, user: str, password: str) -> dict[str, str]:
    with TestClient(app) as client:
        response = client.post(
            "/login", data={"username": user, "password": password}, follow_redirects=False
        )
    return {"Cookie": f"sid={response.cookies['sid']}"}


def _plan(accounts: list[str], endpoints: list[dict[str, Any]] | None = None) -> list:
    ctx = PlanContext(
        scan_id=1,
        engagement_id=1,
        target_url=BASE + "/",
        scope=["testserver"],
        settings={},
        stage=ScanStage.TESTING,
        endpoints=_endpoints() if endpoints is None else endpoints,
        accounts=accounts,
    )
    return Authorization().plan(ctx)


def _ctx(app: FastAPI, sessions: dict[str, dict[str, str]], **hooks: Any) -> TaskContext:
    (spec,) = _plan(list(sessions))
    logs: list[str] = hooks.pop("logs", [])
    return TaskContext(
        task_id=1,
        scan_id=1,
        engagement_id=1,
        target_url=BASE + "/",
        scope=["testserver"],
        settings={},
        engine=spec.engine,
        target=spec.target,
        params={},
        cancel_event=threading.Event(),
        run_tool=lambda *_a, **_k: {"status": "completed"},
        log=logs.append,
        http=lambda _purpose: TestClient(app, raise_server_exceptions=False),
        session_headers=lambda label=None: sessions.get(label, {}),
        **hooks,
    )


@pytest.fixture(scope="module")
def sessions() -> dict[str, dict[str, str]]:
    return {
        "Akun A": _login(TESTAPP.app, "budi", "budi123"),
        "Akun B": _login(TESTAPP.app, "sari", "sari123"),
    }


def _run(app: FastAPI, sessions: dict[str, dict[str, str]], **hooks: Any) -> list[Candidate]:
    reported: list[Candidate] = []
    ctx = _ctx(app, sessions, report_candidate=lambda c: reported.append(c) or 1, **hooks)
    Authorization().run(ctx)
    return reported


# -- planning ---------------------------------------------------------------------------------


def test_plan_needs_two_accounts() -> None:
    assert _plan([]) == []
    assert _plan(["Akun A"]) == []
    (spec,) = _plan(["Akun A", "Akun B", "Akun C", "Akun D"])
    assert spec.engine == "custom:authz"
    assert spec.target["accounts"] == ["Akun A", "Akun B", "Akun C"]
    paths = {e["path_template"] for e in spec.target["endpoints"]}
    # GET endpoints tagged idor_candidate, admin, or profile; never a write, never excluded.
    assert paths == {
        "/profil",
        "/akun/{id}",
        "/produk/{id}",
        "/api/v1/pesanan/{id}",
        "/api/v1/pengguna/{id}",
        "/admin",
        "/admin/pengguna",
    }
    # Own pages where object references are looked up: profile pages without a placeholder.
    assert spec.target["pages"] == [BASE + "/profil", BASE + "/admin/pengguna"]


def test_plan_only_in_testing() -> None:
    ctx = PlanContext(1, 1, BASE, [], {}, ScanStage.RECON, accounts=["Akun A", "Akun B"])
    assert Authorization().plan(ctx) == []


# -- detection against testapp ----------------------------------------------------------------


def test_testapp_idor_and_privilege_escalation(sessions: dict[str, dict[str, str]]) -> None:
    logs: list[str] = []
    found = {c.vuln_type: c for c in _run(TESTAPP.app, sessions, logs=logs)}
    assert set(found) == {"idor", "privilege_escalation"}

    idor = found["idor"]
    assert (idor.method, idor.url, idor.parameter) == ("GET", BASE + "/akun/1", "id")
    assert idor.poc["account"] == "Akun B"
    assert idor.poc["validator_params"] == {
        "parameter": "id",
        "location": "path",
        "owner_account": "Akun A",
        "control_path": "/akun/2",
        "control_query": {},
    }
    notes = [e.note for e in idor.evidence]
    assert notes[0] == "halaman Akun A merujuk objek /akun/1"
    assert "Akun B membuka objek milik Akun A" in notes and "tanpa sesi" in notes
    cross = idor.evidence[notes.index("Akun B membuka objek milik Akun A")]
    assert "cookie: [sesi Akun B]" in cross.request and "198801012010011001" in cross.response
    assert "sid=" not in "".join(e.request for e in idor.evidence)
    assert idor.note.startswith("Akun B menerima 100% nilai khas objek milik Akun A")

    escalation = found["privilege_escalation"]
    assert (escalation.url, escalation.parameter) == (BASE + "/admin/pengguna", None)
    assert escalation.poc["account"] == "Akun B"
    assert escalation.poc["validator_params"] == {
        "privileged_account": "Akun A",
        "reference_path": "/admin",
    }
    assert [e.status for e in escalation.evidence] == [200, 403, 200, 200, 302]
    assert "/admin menolak Akun B" in escalation.note
    # Objects whose owner no account page names are left for a manual check, not guessed.
    assert any("/api/v1/pengguna/{id}" in line for line in logs)


def test_roles_follow_the_accounts_not_their_labels(sessions: dict[str, dict[str, str]]) -> None:
    swapped = {"Akun A": sessions["Akun B"], "Akun B": sessions["Akun A"]}
    found = {c.vuln_type: c for c in _run(TESTAPP.app, swapped)}
    assert found["idor"].url == BASE + "/akun/2"  # Akun B (budi) reads Akun A's (sari) data
    assert found["idor"].poc["account"] == "Akun B"
    assert found["idor"].poc["validator_params"]["owner_account"] == "Akun A"
    escalation = found["privilege_escalation"].poc
    assert escalation["account"] == "Akun A"
    assert escalation["validator_params"]["privileged_account"] == "Akun B"


def test_an_account_without_a_session_is_not_used(sessions: dict[str, dict[str, str]]) -> None:
    logs: list[str] = []
    reported: list[Candidate] = []
    ctx = _ctx(
        TESTAPP.app,
        {"Akun A": sessions["Akun A"], "Akun B": {}},
        logs=logs,
        report_candidate=reported.append,
    )
    assert Authorization().run(ctx) == {"skipped": "needs_two_accounts"}
    assert reported == [] and "dua akun" in logs[0]


def _fixed_app(mode: str) -> FastAPI:
    """testapp's accounts with the weaknesses fixed in different ways."""
    app = FastAPI()
    users = {"budi": ("budi123", 1, "admin"), "sari": ("sari123", 2, "pengguna")}
    profiles = {1: ("Budi Santoso", "198801012010011001"), 2: ("Sari Wulandari", "1990020220150")}
    tokens: dict[str, str] = {}

    def user(request: Request) -> str | None:
        return tokens.get(request.cookies.get("sid", ""))

    @app.post("/login")
    async def login(request: Request) -> Response:
        form = await request.form()
        name = str(form["username"])
        tokens[f"t-{name}"] = name
        response = RedirectResponse("/profil", status_code=303)
        response.set_cookie("sid", f"t-{name}")
        return response

    @app.get("/")
    def index() -> HTMLResponse:
        return HTMLResponse('<a href="/profil">Profil</a>')

    @app.get("/profil")
    def profile(request: Request) -> Response:
        name = user(request)
        if name is None:
            return RedirectResponse("/login", status_code=302)
        return HTMLResponse(f'<p>Halo {name}</p><a href="/akun/{users[name][1]}">Akun saya</a>')

    @app.get("/akun/{user_id}")
    def account(user_id: int, request: Request) -> Response:
        name = user(request)
        if mode != "public" and name is None:
            return RedirectResponse("/login", status_code=302)
        if mode == "own":  # ignores the id and shows the caller's data
            user_id = users[name][1]
        elif mode == "checked" and users[name][1] != user_id:
            return JSONResponse({"detail": "Bukan akun Anda"}, status_code=403)
        nama, nip = profiles.get(user_id, ("?", "?"))
        return HTMLResponse(f"<h1>Akun #{user_id}</h1><p>{nama}</p><p>NIP {nip}</p>")

    @app.get("/admin")
    def admin(request: Request) -> Response:
        name = user(request)
        if name is None or users[name][2] != "admin":
            return JSONResponse({"detail": "Butuh hak admin"}, status_code=403)
        return HTMLResponse('<a href="/admin/pengguna">Daftar pengguna</a>')

    @app.get("/admin/pengguna")
    def admin_users(request: Request) -> Response:
        name = user(request)
        if name is None:
            return RedirectResponse("/login", status_code=302)
        if mode != "public" and users[name][2] != "admin":  # "public": login checked only
            return JSONResponse({"detail": "Butuh hak admin"}, status_code=403)
        return HTMLResponse("<h1>Daftar pengguna</h1><p>Budi, Sari</p>")

    return app


@pytest.mark.parametrize("mode", ["checked", "own", "public"])
def test_fixed_applications_give_no_candidates(mode: str) -> None:
    app = _fixed_app(mode)
    sessions = {"Akun A": _login(app, "budi", "budi123"), "Akun B": _login(app, "sari", "")}
    reported = _run(app, sessions)
    if mode == "public":
        # /admin/pengguna admits both accounts with the same page: only the login is checked.
        assert [c.vuln_type for c in reported] == ["privilege_escalation"]
    else:
        assert reported == []


def test_public_objects_are_not_idor() -> None:
    """An object every visitor can open is not an IDOR between accounts."""
    app = _fixed_app("public")
    sessions = {"Akun A": _login(app, "budi", "budi123"), "Akun B": _login(app, "sari", "")}
    assert "idor" not in {c.vuln_type for c in _run(app, sessions)}


# -- the LLM only steers an ambiguous comparison ----------------------------------------------


def _round(share: float) -> IdorRound:
    exchanges = [Exchange(f"GET /akun/1 #{n}", "x", 200) for n in range(4)]
    return IdorRound(share, exchanges, "Akun B menerima 50% nilai khas", ["Budi"], "a", "b")


@pytest.mark.parametrize(
    ("share", "answer", "reported", "asked"),
    [(0.9, None, True, False), (0.1, None, False, False), (0.5, "ya", True, True),
     (0.5, "ragu", False, True), (0.5, "tidak", False, True)],
)  # fmt: skip
def test_ambiguous_idor_asks_the_llm(
    share: float, answer: str | None, reported: bool, asked: bool
) -> None:
    calls: list[str] = []

    class Outcome:
        ok = True
        value = Judgement(answer=answer or "ya", reason="data Budi terlihat")

    def llm(task: Any, messages: list[dict[str, str]], **_ids: Any) -> Outcome:
        calls.append(task.kind)
        return Outcome()

    ctx = _ctx(TESTAPP.app, {"Akun A": {"x": "1"}, "Akun B": {"x": "2"}}, llm=llm)
    note = Authorization()._idor_decision(ctx, _round(share), Target(BASE + "/akun/1"), "A", "B")
    assert (note is not None) == reported
    assert bool(calls) == asked
    if asked and reported:
        assert "Penilaian LLM: data Budi terlihat" in note


# -- validators -------------------------------------------------------------------------------


def _finding(candidate: Candidate) -> dict[str, Any]:
    return {"id": 5, "vuln_type": candidate.vuln_type, "poc": candidate.poc, "base_url": BASE}


def test_validators_confirm_testapp_twice(sessions: dict[str, dict[str, str]]) -> None:
    for candidate in _run(TESTAPP.app, sessions):
        ctx = _ctx(TESTAPP.app, sessions)
        verdict = VALIDATORS[candidate.vuln_type](ctx, _finding(candidate))
        assert verdict.confirmed, verdict.note
        assert "terulang 2 kali" in verdict.note
        assert all("sid=" not in e.request for e in verdict.evidence)


def test_validators_do_not_confirm_after_a_fix(sessions: dict[str, dict[str, str]]) -> None:
    candidates = _run(TESTAPP.app, sessions)
    fixed = _fixed_app("checked")
    fixed_sessions = {"Akun A": _login(fixed, "budi", "x"), "Akun B": _login(fixed, "sari", "x")}
    for candidate in candidates:
        verdict = VALIDATORS[candidate.vuln_type](_ctx(fixed, fixed_sessions), _finding(candidate))
        assert not verdict.confirmed
        assert verdict.note.endswith("perlu cek manual.")


@pytest.mark.parametrize(
    ("vuln_type", "poc", "note"),
    [
        ("idor", {"path": "/akun/1", "account": "Akun B", "validator_params": {}}, "akun"),
        ("idor", {"path": "/akun/1", "account": "Akun B",
                  "validator_params": {"owner_account": "Akun C"}}, "Sesi"),
        ("privilege_escalation", {"path": "/admin/pengguna", "account": "Akun B",
                                  "validator_params": {"privileged_account": "Akun A"}},
         "pembanding"),
    ],
)  # fmt: skip
def test_validators_need_the_accounts_and_a_reference(
    sessions: dict[str, dict[str, str]], vuln_type: str, poc: dict, note: str
) -> None:
    finding = {"id": 5, "vuln_type": vuln_type, "poc": poc, "base_url": BASE}
    verdict = VALIDATORS[vuln_type](_ctx(TESTAPP.app, sessions), finding)
    assert not verdict.confirmed and note in verdict.note


# -- helpers ----------------------------------------------------------------------------------


def _fetched(text: str, content_type: str = "text/html") -> Fetched:
    return Fetched(200, text, content_type, Exchange("GET / HTTP/1.1", text, 200))


def test_references_of_endpoints() -> None:
    assert authz_checks.references({"method": "GET", "url": BASE + "/akun/{id}"}) == [
        Reference(BASE + "/akun/{id}", "id", "path")
    ]
    endpoint = {"method": "GET", "url": BASE + "/pesanan", "query_params": ["id", "q", "user_id"]}
    assert authz_checks.references(endpoint) == [
        Reference(BASE + "/pesanan", "id", "query"),
        Reference(BASE + "/pesanan", "user_id", "query"),
    ]
    assert authz_checks.references({"method": "POST", "url": BASE + "/akun/{id}"}) == []
    assert authz_checks.references({"method": "GET", "url": BASE + "/a/{id}/b/{id}"}) == []


def test_find_objects_in_links_and_json() -> None:
    page = Target(BASE + "/profil")
    path_ref = Reference(BASE + "/akun/{id}", "id", "path")
    text = (
        '<a href="/akun/7">saya</a> <a href="http://testserver/akun/8/">x</a> '
        "<a href='http://lain.test/akun/9'>luar</a> <a href=\"/akun/10/foto\">foto</a>"
    )
    assert set(authz_checks.find_objects(path_ref, page, _fetched(text))) == {"7"}
    query_ref = Reference(BASE + "/pesanan", "id", "query")
    found = authz_checks.find_objects(
        query_ref, page, _fetched('<a href="/pesanan?tab=1&amp;id=42">p</a>')
    )
    assert found == {"42": Target(BASE + "/pesanan", {"tab": "1", "id": "42"})}
    data = '{"pengguna": {"id": 31, "nama": "Budi"}, "aktif": true}'
    found = authz_checks.find_objects(path_ref, page, _fetched(data, "application/json"))
    assert found == {"31": Target(BASE + "/akun/31")}


def test_owned_objects_exclude_shared_references() -> None:
    ref = Reference(BASE + "/akun/{id}", "id", "path")
    page = Target(BASE + "/profil")
    pages = {
        "A": [(page, _fetched('<a href="/akun/1"></a><a href="/akun/5"></a>'))],
        "B": [(page, _fetched('<a href="/akun/2"></a><a href="/akun/5"></a>'))],
    }
    owned = authz_checks.owned_objects(ref, pages)
    assert {account: set(objects) for account, objects in owned.items()} == {
        "A": {"1"},
        "B": {"2"},
    }


def test_comparisons_ignore_random_tokens() -> None:
    owner = "Budi Santoso NIP 198801012010011001 csrf 9f8e7d6c5b4a39281706f5e4d3c2b1a0"
    control = "Sari Wulandari NIP 199002022015022002 csrf 0a1b2c3d4e5f60718293a4b5c6d7e8f9"
    assert authz_checks.specific_values(owner, control) == [
        "198801012010011001",
        "Budi",
        "Santoso",
    ]
    assert authz_checks.share(["Budi", "Santoso"], "<p>Budi</p>") == 0.5
    assert authz_checks.similarity("a b c daftar pengguna", "daftar pengguna") == 1.0
    assert authz_checks.admin_area("/api/Admin/users") == "/api/admin"
    assert authz_checks.admin_area("/dashboard") == "/dashboard"
    assert authz_checks.admin_area("/profil") is None


def test_fetch_sends_one_session_and_masks_it() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("cookie"))
        return httpx.Response(200, text="ok", headers={"set-cookie": "sid=baru"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        fetch = authz_checks.fetcher(client, {"Akun A": {"Cookie": "sid=a"}}, lambda: None)
        first = fetch(Target(BASE + "/x"), "Akun A", "A")
        second = fetch(Target(BASE + "/x"), None, "tanpa sesi")
    assert seen == ["sid=a", None]  # the cookie the response set is never sent on
    assert "cookie: [sesi Akun A]" in first.exchange.request
    assert "sid=baru" not in first.exchange.response and second.ok


def test_poc_accounts_sentence() -> None:
    assert poc_accounts({}) is None
    assert poc_accounts({"account": "Akun B", "validator_params": {"owner_account": "Akun A"}}) == (
        "Kirim dengan sesi Akun B; objeknya milik Akun A."
    )
    assert "hak seperti Akun A" in poc_accounts(
        {"account": "Akun B", "validator_params": {"privileged_account": "Akun A"}}
    )
