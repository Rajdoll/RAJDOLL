"""CI smoke test inside the running stack (piped into the api container):

    docker compose --profile test up -d --build --wait
    docker compose exec -T api python - < tests/integration/smoke_tools.py

It creates an engagement for testapp, runs nuclei and httpx through the real runner and egress
proxy, and checks the findings and the audit log. Not collected by pytest.
"""

import sys
import time
import uuid

import httpx
from sqlalchemy import select

from rajdoll.core.config import get_settings
from rajdoll.core.crypto import KeyStore
from rajdoll.core.db import get_sessionmaker
from rajdoll.core.models import RequestLog, Scan, Task
from rajdoll.services import engagements as svc

settings = get_settings()
Session = get_sessionmaker()
failures: list[str] = []


def check(condition: bool, message: str) -> None:
    print(("ok   " if condition else "FAIL ") + message)
    if not condition:
        failures.append(message)


with Session() as db:
    engagement = svc.create(
        db,
        KeyStore(settings.secrets_dir),
        {"name": f"smoke-{uuid.uuid4().hex[:6]}", "target_url": "http://testapp:8080/"},
    )
    # Only the runner and proxy are exercised here, so the scan is created finished: the live
    # worker must not pick it up (smoke_scan.py covers the worker).
    scan = Scan(
        engagement_id=engagement.id,
        kind="scan",
        number=1,
        profile="full",
        status="completed",
        settings_snapshot={"rate_limit_rps": 50},
    )
    db.add(scan)
    db.flush()
    task = Task(scan_id=scan.id, stage="testing", module="configuration", engine="nuclei")
    db.add(task)
    db.commit()
    task_id, scan_id = task.id, scan.id

client = httpx.Client(
    base_url=settings.tools_url,
    headers={"Authorization": f"Bearer {settings.tools_token}"},
    timeout=300,
)


def run(tool: str, params: dict, scope: list[str]) -> dict:
    response = client.post(
        "/run",
        json={
            "run_id": f"smoke-{uuid.uuid4().hex[:12]}",
            "task_id": task_id,
            "scan_id": scan_id,
            "tool": tool,
            "timeout_s": 240,
            "scope": scope,
            "params": params,
        },
    )
    response.raise_for_status()
    return response.json()


health = httpx.get(f"{settings.tools_url}/health", timeout=60).json()
print("tools:", health["tools"])
check(health["tools"].get("nuclei") == "3.11.1", "nuclei 3.11.1 installed")
check(health["tools"].get("httpx") == "1.12.0", "httpx 1.12.0 installed")
check(health["tools"].get("katana") == "1.8.0", "katana 1.8.0 installed")
# ffuf v2.2.1 still reports the version constant of its previous release.
check(health["tools"].get("ffuf") == "2.1.0", "ffuf v2.2.1 installed (reports 2.1.0)")
check(health["tools"].get("nmap", "missing") not in ("missing", "unknown"), "nmap installed")
check(health["tools"].get("browser") == "1.63.0", "Playwright 1.63.0 installed")
check(health["tools"].get("sqlmap") == "1.10.10", "sqlmap 1.10.10 installed")
check(health["tools"].get("commix") == "4.1", "commix v4.1 installed")
check(health["tools"].get("dalfox") == "2.13.0", "dalfox 2.13.0 installed")
check(health["tools"].get("sslyze") == "6.3.1", "sslyze 6.3.1 installed")

# sslyze through a passthrough tunnel: it must see testapp's own certificate, not the proxy's.
tls = run("sslyze", {"host": "testapp", "port": 8443}, ["testapp"])
tls_result = tls.get("normalized") or {}
check(tls["status"] == "completed" and tls_result.get("connected"), f"sslyze ran ({tls['status']})")
check(tls_result.get("legacy_protocols") == ["TLS 1.0", "TLS 1.1"], "sslyze saw TLS 1.0 and 1.1")
subject = (tls_result.get("certificate") or {}).get("subject")
check(subject == "CN=testapp", f"sslyze saw testapp's own certificate ({subject})")

nuclei = run("nuclei", {"targets": ["http://testapp:8080"]}, ["testapp"])
ids = [c["template_id"] for c in nuclei.get("normalized", {}).get("candidates", [])]
check(nuclei["status"] == "completed", f"nuclei completed (status={nuclei['status']})")
check("rajdoll-exposed-env-file" in ids, f"nuclei found the exposed .env (found {ids})")

probe = run("httpx", {"urls": ["http://testapp:8080"]}, ["testapp"])
titles = [e["title"] for e in probe.get("normalized", {}).get("endpoints", [])]
check("RAJDOLL testapp" in titles, f"httpx read the page title (got {titles})")

rejected = run("nuclei", {"targets": ["http://example.com"]}, ["testapp"])
check(rejected["status"] == "scope_rejected", "out-of-scope target refused before running")

deadline = time.monotonic() + 20
rows: list = []
while time.monotonic() < deadline:
    with Session() as db:
        rows = list(db.scalars(select(RequestLog).where(RequestLog.task_id == task_id)))
    if any(r.url == "http://testapp:8080/.env" for r in rows):
        break
    time.sleep(1)
check(len(rows) > 0, f"tool traffic was audited ({len(rows)} rows)")
check(all(r.outcome == "forwarded" for r in rows), "all audited requests were in scope")
check(
    any(r.url == "http://testapp:8080/.env" and r.status == 200 for r in rows),
    ".env request logged",
)

if failures:
    print(f"{len(failures)} check(s) failed", file=sys.stderr)
    sys.exit(1)
print("smoke test passed")
