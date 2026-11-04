"""IPD F5 exit criteria, end to end with the real tools:

- recon against testapp finds every endpoint testapp registers (testapp.RECON_ENDPOINTS),
  including the ones that exist only in JavaScript, and its hidden parameter;
- testapp's logout endpoint is excluded automatically and never requested.

Runs the real engine with the real Information Gathering module, the runner (uvicorn), the egress
proxy (mitmdump), and testapp, as a logged-in account. Needs PostgreSQL, mitmproxy, the tool
binaries in RAJDOLL_TOOL_BIN_DIR (katana, ffuf, httpx, nmap), and Playwright's Chromium. In CI the
same check runs inside the containers (tests/integration/smoke_scan.py).
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
from rajdoll.core.models import RequestLog, Scan
from rajdoll.services import engagements, inventory, scans
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
    app_port, runner_port = free_port(), free_port()
    processes = []
    proxy, proxy_port = start_mitmdump(tools_dsn, TOKEN, tmp / "mitm")
    processes.append(proxy)
    processes.append(
        subprocess.Popen(  # noqa: S603
            [sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1",
             "--port", str(app_port), "--no-server-header"],
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


def test_recon_finds_every_testapp_endpoint_and_excludes_logout(
    stack: dict, db_engine: Engine
) -> None:
    testapp = _testapp_module()
    factory = sessionmaker(bind=db_engine, expire_on_commit=False)
    keystore = KeyStore(stack["secrets"])
    login = httpx.post(
        stack["app"] + "/login", data={"username": "budi", "password": "budi123"}, trust_env=False
    )
    sid = login.cookies["sid"]

    with factory() as session, session.begin():
        engagement = engagements.create(
            session, keystore, {"name": "Recon e2e", "target_url": stack["app"] + "/"}
        )
        engagements.update_overrides(session, engagement, {"rate_limit_rps": 100})
        engagements.add_account(session, keystore, engagement, {"session_text": f"sid={sid}"})
        scan = scans.start(session, engagement, "custom", ["information_gathering"])
        scan_id, engagement_id = scan.id, engagement.id

    engine = WorkflowEngine(
        factory,
        ToolsClient(stack["runner"], TOKEN),
        keystore=keystore,
        proxy_base=stack["proxy"],
        proxy_token=TOKEN,
        worker_id="recon-e2e",
    )
    try:
        deadline = time.monotonic() + 600
        status = None
        while time.monotonic() < deadline:
            engine.tick()
            with factory() as session:
                status = session.scalar(select(Scan.status).where(Scan.id == scan_id))
            if status not in ("queued", "running"):
                break
            engine.wait(0.5)
    finally:
        engine.shutdown(grace_seconds=5)
    assert status == "awaiting_checkpoint"

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
        session.execute(text("DELETE FROM engagement WHERE id = :e"), {"e": engagement_id})
        session.commit()

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
