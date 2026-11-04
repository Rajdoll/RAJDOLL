"""CI smoke test of the workflow engine inside the running stack (piped into the api container):

    docker compose exec -T api python - < tests/integration/smoke_scan.py

Starts a real scan of testapp. The worker runs the recon stage (httpx through the runner and the
egress proxy), stops at the checkpoint, and finishes after the checkpoint is continued.
Not collected by pytest.
"""

import sys
import time
import uuid
from collections.abc import Callable

from sqlalchemy import select

from rajdoll.core.config import get_settings
from rajdoll.core.crypto import KeyStore
from rajdoll.core.db import get_sessionmaker
from rajdoll.core.models import RequestLog, Scan, ScanEvent, Task
from rajdoll.services import engagements, scans

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
        time.sleep(1)
        scan = scan_state(scan_id)
    return scan


with Session() as db:
    engagement = engagements.create(
        db,
        KeyStore(settings.secrets_dir),
        {"name": f"smoke-scan-{uuid.uuid4().hex[:6]}", "target_url": "http://testapp:8080/"},
    )
    scan = scans.start(db, engagement, "custom", ["information_gathering"])
    db.commit()
    scan_id, engagement_id = scan.id, engagement.id

scan = wait_for(lambda s: s.status not in ("queued", "running"), scan_id, timeout=180)
check(scan.status == "awaiting_checkpoint", f"scan stops at the checkpoint (status={scan.status})")
check(scan.checkpoint_deadline is not None, "checkpoint countdown is set")

with Session() as db:
    recon = list(db.scalars(select(Task).where(Task.scan_id == scan_id, Task.stage == "recon")))
    check(len(recon) == 1 and recon[0].status == "done", f"recon task done ({recon[0].status})")
    titles = [e.get("title") for e in (recon[0].result_summary or {}).get("endpoints", [])]
    check("RAJDOLL testapp" in titles, f"httpx probe reached testapp (titles={titles})")
    audited = list(db.scalars(select(RequestLog).where(RequestLog.task_id == recon[0].id)))
    check(len(audited) > 0, f"recon traffic went through the proxy ({len(audited)} rows)")
    check(all(r.scan_id == scan_id for r in audited), "audit rows carry the scan")

    scans.checkpoint_continue(db, db.get(Scan, scan_id))
    db.commit()

scan = wait_for(lambda s: s.status == "completed", scan_id, timeout=60)
check(scan.status == "completed", f"scan completes after the checkpoint (status={scan.status})")
check(scan.checkpoint_resolution == "user_continued", "checkpoint resolution recorded")

with Session() as db:
    types = list(
        db.scalars(
            select(ScanEvent.type).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.id)
        )
    )
    print("events:", types)
    check(types.count("stage_changed") == 5, "every stage was entered")
    check(types[-1] == "completed", "completion event recorded")
    check(
        engagements.get(db, engagement_id).status == "ready", "engagement is ready again after scan"
    )

if failures:
    print(f"{len(failures)} check(s) failed", file=sys.stderr)
    sys.exit(1)
print("scan smoke test passed")
