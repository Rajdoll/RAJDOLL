"""IPD F4 exit criterion: a worker killed during testing is restarted and the scan completes
without duplicate tasks. Runs the real `python -m rajdoll.worker` process with the dummy module.
"""

import signal
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine as SqlEngine
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from rajdoll.core.crypto import KeyStore
from rajdoll.core.models import Engagement, Scan, ScanEvent, Task
from rajdoll.services import engagements, scans
from tests.helpers import REPO, clean_env


@pytest.fixture(scope="module")
def factory(db_engine: SqlEngine) -> sessionmaker[Session]:
    return sessionmaker(bind=db_engine, expire_on_commit=False)


@pytest.fixture
def scan_id(factory: sessionmaker[Session], tmp_path: Path) -> Iterator[int]:
    with factory() as session, session.begin():
        engagement = engagements.create(
            session,
            KeyStore(tmp_path / "secrets"),
            {"name": "Restart", "target_url": "https://app.test/"},
        )
        engagement_id = engagement.id
        scan = scans.start(session, engagement, "full")
        scan.settings_snapshot = {
            **scan.settings_snapshot,
            "checkpoint_enabled": False,
            "concurrency": 2,
        }
        new_id = scan.id
    yield new_id
    with factory() as session, session.begin():
        session.execute(delete(Engagement).where(Engagement.id == engagement_id))


class Worker:
    def __init__(self, db_engine: SqlEngine, tmp_path: Path, name: str) -> None:
        self.log_path = tmp_path / "dummy.log"
        self.output = (tmp_path / f"{name}.out").open("w")
        env = clean_env(
            PYTHONPATH=str(REPO),
            RAJDOLL_DATABASE_URL=db_engine.url.render_as_string(hide_password=False),
            RAJDOLL_SECRETS_DIR=str(tmp_path / "secrets"),
            RAJDOLL_PROFILES_DIR=str(REPO / "profiles"),
            RAJDOLL_TOOLS_URL="http://127.0.0.1:9",
            RAJDOLL_PROXY_URL="http://127.0.0.1:9",
            RAJDOLL_WORKER_POLL_SECONDS="0.2",
            RAJDOLL_WORKER_LEASE_SECONDS="2",
            RAJDOLL_EXTRA_MODULES="tests.dummy_module",
            RAJDOLL_DUMMY_SLEEP="1.5",
            RAJDOLL_DUMMY_LOG=str(self.log_path),
        )
        self.process = subprocess.Popen(  # noqa: S603
            [sys.executable, "-m", "rajdoll.worker"],
            cwd=tmp_path,  # no stray .env
            env=env,
            stdout=self.output,
            stderr=subprocess.STDOUT,
        )

    def stop(self, sig: int) -> int:
        if self.process.poll() is None:
            self.process.send_signal(sig)
        code = self.process.wait(timeout=30)
        self.output.close()
        return code


def wait_for(condition: Callable[[], bool], timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {what}")


def tasks(factory: sessionmaker[Session], scan_id: int) -> list[Task]:
    with factory() as session:
        return list(session.scalars(select(Task).where(Task.scan_id == scan_id).order_by(Task.id)))


def running_testing_tasks(factory: sessionmaker[Session], scan_id: int) -> list[Task]:
    return [t for t in tasks(factory, scan_id) if t.stage == "testing" and t.status == "running"]


def scan_status(factory: sessionmaker[Session], scan_id: int) -> str:
    with factory() as session:
        return session.scalar(select(Scan.status).where(Scan.id == scan_id))


def test_killed_worker_is_recovered_without_duplicate_tasks(
    db_engine: SqlEngine, factory: sessionmaker[Session], scan_id: int, tmp_path: Path
) -> None:
    first = Worker(db_engine, tmp_path, "first")
    second = None
    try:
        wait_for(
            lambda: len(running_testing_tasks(factory, scan_id)) == 2,
            timeout=30,
            what="two running testing tasks",
        )
        assert first.stop(signal.SIGKILL) == -signal.SIGKILL
        orphaned = {t.id for t in running_testing_tasks(factory, scan_id)}
        assert len(orphaned) == 2

        second = Worker(db_engine, tmp_path, "second")
        wait_for(
            lambda: scan_status(factory, scan_id) == "completed", timeout=60, what="completion"
        )
    finally:
        for worker in (first, second):
            if worker is not None:
                worker.stop(signal.SIGKILL)

    rows = tasks(factory, scan_id)
    assert Counter(t.stage for t in rows) == {
        "recon": 1,
        "planning": 1,
        "testing": 6,
        "validation": 1,
        "ai_triage": 1,
    }
    assert {t.status for t in rows} == {"done"}
    assert {t.id for t in rows if t.attempt == 2} == orphaned
    assert all(t.attempt == 1 for t in rows if t.id not in orphaned)

    lines = first.log_path.read_text().split()
    starts = Counter(
        int(n) for kind, n in zip(lines[::2], lines[1::2], strict=True) if kind == "start"
    )
    ends = Counter(int(n) for kind, n in zip(lines[::2], lines[1::2], strict=True) if kind == "end")
    assert ends == Counter({t.id: 1 for t in rows})
    assert {task_id for task_id, count in starts.items() if count == 2} == orphaned

    with factory() as session:
        messages = session.scalars(select(ScanEvent.message).where(ScanEvent.scan_id == scan_id))
        assert any(m.startswith("2 tugas dikembalikan ke antrean") for m in messages)


def test_sigterm_returns_running_tasks_without_waiting_for_the_lease(
    db_engine: SqlEngine, factory: sessionmaker[Session], scan_id: int, tmp_path: Path
) -> None:
    worker = Worker(db_engine, tmp_path, "worker")
    try:
        wait_for(
            lambda: len(running_testing_tasks(factory, scan_id)) == 2,
            timeout=30,
            what="two running testing tasks",
        )
        started = time.monotonic()
        assert worker.stop(signal.SIGTERM) == 0
        assert time.monotonic() - started < 10
    finally:
        worker.stop(signal.SIGKILL)

    testing = [t for t in tasks(factory, scan_id) if t.stage == "testing"]
    assert "running" not in {t.status for t in testing}
    assert all(t.locked_by is None for t in testing)
    assert scan_status(factory, scan_id) == "running"
    log = (tmp_path / "worker.out").read_text()
    assert "worker stopped" in log
