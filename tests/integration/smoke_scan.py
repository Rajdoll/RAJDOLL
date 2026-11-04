"""CI smoke test of the workflow engine and recon inside the running stack (piped into the api
container):

    docker compose exec -T api python - < tests/integration/smoke_scan.py

Starts a real scan of testapp as a logged-in account. The worker runs recon (httpx, katana, the
Playwright browser, ffuf, nmap, and the custom checks through the runner and the egress proxy),
then the planning wave (JavaScript analysis, parameter discovery), and stops at the checkpoint.
IPD F5 exit criteria: every endpoint testapp registers is in the inventory, including those only
in JavaScript, and logout is excluded and never requested. After the checkpoint, Input Validation
and the validators run; IPD F6: every Input Validation weakness of testapp becomes a `confirmed`
finding. Not collected by pytest.
"""

import sys
import time
import uuid
from collections.abc import Callable

import httpx
from sqlalchemy import select

from rajdoll.core.config import get_settings
from rajdoll.core.crypto import KeyStore
from rajdoll.core.db import get_sessionmaker
from rajdoll.core.models import Endpoint, Finding, RequestLog, Scan, ScanEvent, Task
from rajdoll.services import engagements, inventory, scans

# Copy of testapp.RECON_ENDPOINTS (the api image does not contain testapp); kept equal by
# tests/test_testapp.py.
EXPECTED = [
    ("GET", "/"),
    ("GET", "/login"),
    ("POST", "/login"),
    ("GET", "/profil"),
    ("GET", "/produk"),
    ("GET", "/produk/{id}"),
    ("GET", "/cari"),
    ("POST", "/kontak"),
    ("GET", "/logout"),
    ("GET", "/upload"),
    ("POST", "/upload"),
    ("GET", "/akun/{id}"),
    ("GET", "/static/app.js"),
    ("GET", "/api/v1/ringkasan"),
    ("GET", "/api/v1/pesanan"),
    ("GET", "/api/v1/pesanan/{id}"),
    ("POST", "/api/v1/keranjang"),
    ("GET", "/api/v1/pengguna/{id}"),
    ("POST", "/api/v1/transfer"),
    ("GET", "/openapi.json"),
    ("GET", "/admin"),
    ("GET", "/robots.txt"),
    ("GET", "/internal/laporan"),
    ("GET", "/.env"),
    ("GET", "/katalog"),
    ("GET", "/sapa"),
    ("POST", "/alat/ping"),
    ("GET", "/pratinjau"),
    ("GET", "/ambil"),
]
# Copy of testapp.EXPECTED_FINDINGS, kept equal by tests/test_testapp.py.
EXPECTED_FINDINGS = [
    ("sqli", "/katalog", "nama"),
    ("xss_reflected", "/sapa", "nama"),
    ("cmdi", "/alat/ping", "host"),
    ("ssti", "/pratinjau", "templat"),
    ("ssrf", "/ambil", "url"),
]
TARGET = "http://testapp:8080"

settings = get_settings()
Session = get_sessionmaker()
failures: list[str] = []


def check(condition: bool, message: str) -> None:
    print(("ok   " if condition else "FAIL ") + message)
    if not condition:
        failures.append(message)


def scan_state(scan_id: int) -> Scan:
    with Session() as db:
        return db.get(Scan, scan_id)


def wait_for(condition: Callable[[Scan], bool], scan_id: int, timeout: float) -> Scan:
    deadline = time.monotonic() + timeout
    scan = scan_state(scan_id)
    while time.monotonic() < deadline and not condition(scan):
        time.sleep(2)
        scan = scan_state(scan_id)
    return scan


# Test setup only: log in to testapp directly to get a session for the account.
sid = httpx.post(
    TARGET + "/login", data={"username": "budi", "password": "budi123"}, trust_env=False
).cookies["sid"]

with Session() as db:
    keystore = KeyStore(settings.secrets_dir)
    engagement = engagements.create(
        db, keystore, {"name": f"smoke-scan-{uuid.uuid4().hex[:6]}", "target_url": TARGET + "/"}
    )
    engagements.update_overrides(db, engagement, {"rate_limit_rps": 100})
    engagements.add_account(db, keystore, engagement, {"session_text": f"sid={sid}"})
    scan = scans.start(db, engagement, "custom", ["information_gathering", "input_validation"])
    db.commit()
    scan_id, engagement_id = scan.id, engagement.id

scan = wait_for(lambda s: s.status not in ("queued", "running"), scan_id, timeout=900)
check(scan.status == "awaiting_checkpoint", f"scan stops at the checkpoint (status={scan.status})")
check(scan.checkpoint_deadline is not None, "checkpoint countdown is set")

with Session() as db:
    tasks = list(db.scalars(select(Task).where(Task.scan_id == scan_id).order_by(Task.id)))
    not_done = [(t.engine, t.status, t.error) for t in tasks if t.status != "done"]
    check(not not_done, f"all recon and planning tasks done ({not_done})")
    rows = {(e.method, e.path_template): e for e in inventory.list_for(db, engagement_id)}
    missing = [key for key in EXPECTED if key not in rows]
    check(
        not missing, f"inventory has every testapp endpoint ({len(rows)} rows, missing {missing})"
    )
    cari = rows.get(("GET", "/cari"))
    check(cari is not None and "debug" in cari.query_params, "hidden parameter found")
    logout = rows.get(("GET", "/logout"))
    check(
        logout is not None and logout.excluded and logout.exclude_reason == "pattern:logout",
        "logout excluded automatically",
    )
    logout_hits = db.scalar(
        select(RequestLog.id).where(
            RequestLog.engagement_id == engagement_id, RequestLog.url.like("%/logout%")
        )
    )
    check(logout_hits is None, "logout never requested")
    summary = scan_state(scan_id).recon_summary or {}
    check("cdn.luar.test" in (summary.get("out_of_scope_hosts") or {}), "out-of-scope host noted")
    check(8080 in {p["port"] for p in summary.get("open_ports", [])}, "nmap found port 8080")
    tool_exec = db.scalar(
        select(RequestLog.id).where(
            RequestLog.engagement_id == engagement_id, RequestLog.kind == "tool_exec"
        )
    )
    check(tool_exec is not None, "nmap run audited as tool_exec")
    audited = db.scalar(
        select(RequestLog.id).where(
            RequestLog.engagement_id == engagement_id, RequestLog.tool == "browser"
        )
    )
    check(audited is not None, "browser traffic went through the proxy")

    scans.checkpoint_continue(db, db.get(Scan, scan_id))
    db.commit()

scan = wait_for(lambda s: s.status not in ("running", "queued"), scan_id, timeout=900)
check(scan.status == "completed", f"scan completes after the checkpoint (status={scan.status})")
check(scan.checkpoint_resolution == "user_continued", "checkpoint resolution recorded")

with Session() as db:
    not_done = [
        (t.engine, t.status, t.error)
        for t in db.scalars(select(Task).where(Task.scan_id == scan_id))
        if t.status != "done"
    ]
    check(not not_done, f"all testing and validation tasks done ({not_done})")
    found = {
        (f.vuln_type, path, f.parameter): f.validation
        for f, path in db.execute(
            select(Finding, Endpoint.path_template)
            .join(Endpoint, Finding.endpoint_id == Endpoint.id)
            .where(Finding.engagement_id == engagement_id)
        )
    }
    for key in EXPECTED_FINDINGS:
        check(found.get(key) == "confirmed", f"finding {key} confirmed ({found.get(key)})")
    extra = sorted(set(found) - set(EXPECTED_FINDINGS))
    check(not extra, f"no findings beyond testapp's weaknesses ({extra})")

with Session() as db:
    types = list(
        db.scalars(
            select(ScanEvent.type).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.id)
        )
    )
    check(types.count("stage_changed") == 5, "every stage was entered")
    check(types[-1] == "completed", "completion event recorded")
    check(
        engagements.get(db, engagement_id).status == "ready", "engagement is ready again after scan"
    )

if failures:
    print(f"{len(failures)} check(s) failed", file=sys.stderr)
    sys.exit(1)
print("scan smoke test passed")
