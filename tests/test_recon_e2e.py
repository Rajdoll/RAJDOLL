"""IPD F5 and F6 exit criteria, end to end with the real tools:

- recon against testapp finds every endpoint testapp registers (testapp.RECON_ENDPOINTS),
  including the ones that exist only in JavaScript, and its hidden parameter;
- testapp's logout endpoint is excluded automatically and never requested;
- after the checkpoint, Input Validation, Authorization, and the validators turn every weakness
  of testapp (testapp.EXPECTED_FINDINGS) into a `confirmed` finding, with encrypted evidence.

Runs the real engine with the real modules, the runner (uvicorn), the egress proxy (mitmdump),
and testapp, with two logged-in accounts (Akun A = budi, admin; Akun B = sari). Needs
PostgreSQL, mitmproxy, the tool binaries in RAJDOLL_TOOL_BIN_DIR (katana, ffuf, httpx, nmap), and
Playwright's Chromium. In CI the same check runs inside the containers
(tests/integration/smoke_scan.py).
"""

import importlib.util
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from rajdoll.core.bootstrap import enable_tools_login
from rajdoll.core.crypto import KeyStore
from rajdoll.core.models import Endpoint, Evidence, Finding, RequestLog, Scan
from rajdoll.services import engagements, findings, inventory, scans
from tests.helpers import MITMDUMP, REPO, clean_env, free_port, start_mitmdump, wait_for_port

BIN_DIR = Path(os.environ.get("RAJDOLL_TOOL_BIN_DIR", "/opt/tools/bin"))
TOKEN = "recon-e2e-token"
TOOLS_PASSWORD = "recon-e2e-password"

_missing = [
    p
    for p in (MITMDUMP, *(BIN_DIR / t for t in ("katana", "ffuf", "httpx", "nmap")))
    if not p.exists()
]
try:
    import playwright  # noqa: F401
except ImportError:
    _missing.append(Path("playwright"))
if _missing:
    if os.environ.get("RAJDOLL_REQUIRE_TOOL_TESTS") == "1":
        pytest.fail(f"missing for recon e2e: {_missing}", pytrace=False)
    pytest.skip(f"recon e2e needs {_missing}", allow_module_level=True)

from rajdoll.worker.engine import Engine as WorkflowEngine  # noqa: E402
from rajdoll.worker.tools_client import ToolsClient  # noqa: E402


def _testapp_module():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("testapp_app", REPO / "testapp" / "app.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def stack(db_engine: Engine, tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict]:
    tmp = tmp_path_factory.mktemp("recon")
    enable_tools_login(db_engine, TOOLS_PASSWORD)
    tools_url = make_url(db_engine.url).set(
        drivername="postgresql", username="rajdoll_tools", password=TOOLS_PASSWORD
    )
    tools_dsn = tools_url.render_as_string(hide_password=False)
    app_port, tls_port, runner_port = free_port(), free_port(), free_port()
    processes = []
    proxy, proxy_port = start_mitmdump(tools_dsn, TOKEN, tmp / "mitm")
    processes.append(proxy)
    processes.append(
        subprocess.Popen(  # noqa: S603
            [sys.executable, "serve.py", "--host", "127.0.0.1", "--port", str(app_port),
             "--tls-port", str(tls_port)],
            cwd=REPO / "testapp",
            env=clean_env(),
        )
    )  # fmt: skip
    runner_env = clean_env(
        PYTHONPATH=str(REPO),
        RAJDOLL_TOOLS_TOKEN=TOKEN,
        RAJDOLL_PROXY_PORT=str(proxy_port),
        RAJDOLL_TOOL_BIN_DIR=str(BIN_DIR),
        RAJDOLL_TEMPLATE_DIR=str(REPO / "templates" / "nuclei"),
        RAJDOLL_WORDLIST_DIR=str(REPO / "tools" / "wordlists"),
        RAJDOLL_TOOL_HOME=str(tmp / "home"),
        RAJDOLL_PROXY_DATABASE_URL=tools_dsn,
    )
    processes.append(
        subprocess.Popen(  # noqa: S603
            [sys.executable, "-m", "uvicorn", "tools.runner.app:app", "--host", "127.0.0.1",
             "--port", str(runner_port)],
            cwd=tmp,
            env=runner_env,
        )
    )  # fmt: skip
    try:
        wait_for_port(app_port)
        wait_for_port(tls_port)
        wait_for_port(runner_port)
        yield {
            "app": f"http://127.0.0.1:{app_port}",
            "runner": f"http://127.0.0.1:{runner_port}",
            "proxy": f"http://127.0.0.1:{proxy_port}",
            "secrets": tmp / "secrets",
        }
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            process.wait(timeout=15)


def _run(engine: WorkflowEngine, factory: sessionmaker, scan_id: int, until: tuple) -> str:
    deadline = time.monotonic() + 900
    status = None
    while time.monotonic() < deadline:
        engine.tick()
        with factory() as session:
            status = session.scalar(select(Scan.status).where(Scan.id == scan_id))
        if status in until:
            break
        engine.wait(0.5)
    return str(status)


@pytest.fixture(scope="module")
def scan_run(stack: dict, db_engine: Engine) -> Iterator[dict]:
    """One scan of testapp: recon up to the checkpoint (the rest runs in the findings test)."""
    factory = sessionmaker(bind=db_engine, expire_on_commit=False)
    keystore = KeyStore(stack["secrets"])

    def login(user: str, password: str) -> str:
        """The account's pasted session: the `sid` cookie and a JWT for the API."""
        form = {"username": user, "password": password}
        sid = httpx.post(stack["app"] + "/login", data=form, trust_env=False).cookies["sid"]
        api = httpx.post(stack["app"] + "/api/v1/token", json=form, trust_env=False)
        return f"Cookie: sid={sid}\nAuthorization: Bearer {api.json()['token']}"

    with factory() as session, session.begin():
        engagement = engagements.create(
            session, keystore, {"name": "Scan e2e", "target_url": stack["app"] + "/"}
        )
        engagements.update_overrides(session, engagement, {"rate_limit_rps": 100})
        for label, user, password in [("Akun A", "budi", "budi123"), ("Akun B", "sari", "sari123")]:
            account = {"label": label, "session_text": login(user, password)}
            engagements.add_account(session, keystore, engagement, account)
        modules = [
            "information_gathering",
            "configuration",
            "authentication",
            "authorization",
            "session",
            "input_validation",
            "error_handling",
            "cryptography",
        ]
        scan = scans.start(session, engagement, "custom", modules)
        scan_id, engagement_id = scan.id, engagement.id

    engine = WorkflowEngine(
        factory,
        ToolsClient(stack["runner"], TOKEN),
        keystore=keystore,
        proxy_base=stack["proxy"],
        proxy_token=TOKEN,
        worker_id="scan-e2e",
    )
    try:
        status = _run(engine, factory, scan_id, ("awaiting_checkpoint", "failed", "cancelled"))
        yield {
            "engine": engine,
            "factory": factory,
            "keystore": keystore,
            "scan_id": scan_id,
            "engagement_id": engagement_id,
            "checkpoint_status": status,
        }
    finally:
        engine.shutdown(grace_seconds=5)
        with factory() as session:
            session.execute(text("DELETE FROM engagement WHERE id = :e"), {"e": engagement_id})
            session.commit()


def test_recon_finds_every_testapp_endpoint_and_excludes_logout(scan_run: dict) -> None:
    testapp = _testapp_module()
    factory, scan_id, engagement_id = (
        scan_run["factory"],
        scan_run["scan_id"],
        scan_run["engagement_id"],
    )
    assert scan_run["checkpoint_status"] == "awaiting_checkpoint"

    with factory() as session:
        failed = session.execute(
            text("SELECT engine, error FROM task WHERE scan_id = :s AND status <> 'done'"),
            {"s": scan_id},
        ).all()
        assert failed == [], failed
        rows = {(e.method, e.path_template): e for e in inventory.list_for(session, engagement_id)}
        scan = session.get(Scan, scan_id)
        logout_requests = session.scalar(
            select(RequestLog.id).where(
                RequestLog.engagement_id == engagement_id, RequestLog.url.like("%/logout%")
            )
        )

    missing = [(m, p, how) for m, p, how in testapp.RECON_ENDPOINTS if (m, p) not in rows]
    assert missing == [], f"recon missed: {missing}"
    for path, params in testapp.HIDDEN_PARAMS.items():
        assert set(params) <= set(rows[("GET", path)].query_params), path
    logout = rows[("GET", "/logout")]
    assert (logout.excluded, logout.exclude_reason) == (True, "pattern:logout")
    assert logout_requests is None, "logout must never be requested"
    assert rows[("POST", "/api/v1/keranjang")].source == "js"
    assert rows[("POST", "/api/v1/transfer")].source == "openapi"

    summary = scan.recon_summary
    assert summary["out_of_scope_hosts"].keys() >= set(testapp.OUT_OF_SCOPE_HOSTS)
    assert summary["waf"]["detected"] is False
    # nmap scans the top 1000 ports; the test app listens on a random high port, so only check
    # that the scan ran and reported its list.
    assert isinstance(summary["open_ports"], list)


def test_testapp_weaknesses_become_confirmed_findings(scan_run: dict) -> None:
    testapp = _testapp_module()
    factory, scan_id, engagement_id = (
        scan_run["factory"],
        scan_run["scan_id"],
        scan_run["engagement_id"],
    )
    assert scan_run["checkpoint_status"] == "awaiting_checkpoint"
    with factory() as session, session.begin():
        scans.checkpoint_continue(session, session.get(Scan, scan_id))
    status = _run(scan_run["engine"], factory, scan_id, ("completed", "failed", "cancelled"))
    assert status == "completed"

    with factory() as session:
        failed = session.execute(
            text("SELECT engine, error FROM task WHERE scan_id = :s AND status <> 'done'"),
            {"s": scan_id},
        ).all()
        assert failed == [], failed
        rows = list(session.scalars(select(Finding).where(Finding.engagement_id == engagement_id)))
        found = {}
        for finding in rows:
            endpoint = session.get(Endpoint, finding.endpoint_id)
            found[(finding.vuln_type, endpoint.path_template, finding.parameter)] = finding
        expected = {tuple(item) for item in testapp.EXPECTED_FINDINGS}
        confirmed = {key for key, f in found.items() if f.validation == "confirmed"}
        assert expected <= confirmed, f"not confirmed: {expected - confirmed}; found {found.keys()}"
        # Nothing beyond the planted weaknesses (no false positives on testapp).
        assert set(found) == expected, f"unexpected: {set(found) - expected}"

        sqli = found[("sqli", "/katalog", "nama")]
        assert (sqli.severity, float(sqli.cvss31_score)) == ("critical", 9.8)
        kinds = set(session.scalars(select(Evidence.kind).where(Evidence.finding_id == sqli.id)))
        assert kinds == {"detection", "validation"}
        raw = session.scalar(select(Evidence.request_enc).where(Evidence.finding_id == sqli.id))
        assert b"katalog" not in raw  # evidence is encrypted at rest
        evidence = findings.evidence_rows(session, scan_run["keystore"], sqli)
        assert "GET /katalog?nama=" in evidence[0]["request"]
        assert "sid=" not in "".join(e["request"] for e in evidence)  # session masked
        poc = findings.poc(session, scan_run["keystore"], sqli)
        assert (poc["path"], poc["validator"]) == ("/katalog", "sqli")

        # The tools found the same weaknesses as the probes and added their evidence to the
        # same findings (one finding per fingerprint). commix is not run against a loopback
        # target (it bypasses proxies there); the compose smoke scan covers it.
        def notes(key: tuple[str, str, str]) -> str:
            rows = findings.evidence_rows(session, scan_run["keystore"], found[key])
            return " | ".join(r["note"] or "" for r in rows)

        assert "payload sqlmap" in notes(("sqli", "/katalog", "nama"))
        assert "nuclei sqli-error-based" in notes(("sqli", "/katalog", "nama"))
        assert "payload dalfox" in notes(("xss_reflected", "/sapa", "nama"))

        # Authorization: Akun B reads Akun A's account page and opens an admin function that
        # /admin refuses it; the evidence names the account of every request.
        idor = found[("idor", "/akun/{id}", "id")]
        poc = findings.poc(session, scan_run["keystore"], idor)
        assert (poc["path"], poc["account"]) == ("/akun/1", "Akun B")
        assert poc["validator_params"]["owner_account"] == "Akun A"
        rows = findings.evidence_rows(session, scan_run["keystore"], idor)
        requests = " ".join(r["request"] for r in rows)
        assert "[sesi Akun B]" in requests and "[sesi Akun A]" in requests
        assert "sid=" not in requests
        escalation = found[("privilege_escalation", "/admin/pengguna", None)]
        poc = findings.poc(session, scan_run["keystore"], escalation)
        assert poc["validator_params"] == {
            "privileged_account": "Akun A",
            "reference_path": "/admin",
        }
        assert "nuclei reflection-ssti" in notes(("ssti", "/pratinjau", "templat"))
        tasks = dict(
            session.execute(
                text("SELECT engine, count(*) FROM task WHERE scan_id = :s GROUP BY engine"),
                {"s": scan_id},
            ).all()
        )
        assert {"sqlmap", "commix", "dalfox", "nuclei:dast", "custom:inpv"} <= set(tasks)
