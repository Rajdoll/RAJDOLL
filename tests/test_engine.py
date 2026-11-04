"""Workflow engine against PostgreSQL with the dummy module (IPD F4; AFD 3.2, 3.3, A5, A6)."""

import threading
import time
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine as SqlEngine
from sqlalchemy import delete, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from rajdoll.core.crypto import KeyStore
from rajdoll.core.db import listen_dsn
from rajdoll.core.enums import ScanStage, ScanStatus, SessionStatus, TaskStatus
from rajdoll.core.models import Engagement, Scan, ScanEvent, TargetAccount, Task
from rajdoll.services import engagements, scans
from rajdoll.services.errors import Conflict
from rajdoll.services.session_check import CheckResult
from rajdoll.worker.engine import Engine
from tests.dummy_module import DummyModule

FINISHED = {ScanStatus.COMPLETED, ScanStatus.CANCELLED, ScanStatus.FAILED}


class FakeTools:
    """Runner stand-in. With `block`, a run waits until it is cancelled."""

    def __init__(self, block: bool = False) -> None:
        self.block = block
        self.calls: list[dict[str, Any]] = []
        self.cancelled: list[str] = []
        self._events: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def _event(self, run_id: str) -> threading.Event:
        with self._lock:
            return self._events.setdefault(run_id, threading.Event())

    def run(self, run_id: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append({"run_id": run_id, **kwargs})
        if self.block:
            self._event(run_id).wait(20)
            return {"status": "cancelled", "normalized": {}, "stderr_tail": ""}
        return {"status": "completed", "normalized": {"endpoints": []}, "stderr_tail": ""}

    def cancel(self, run_id: str) -> bool:
        self.cancelled.append(run_id)
        self._event(run_id).set()
        return True


@pytest.fixture(scope="module")
def factory(db_engine: SqlEngine) -> sessionmaker[Session]:
    return sessionmaker(bind=db_engine, expire_on_commit=False)


@pytest.fixture
def keystore(tmp_path: Path) -> KeyStore:
    return KeyStore(tmp_path)


@pytest.fixture
def engagement_id(factory: sessionmaker[Session], keystore: KeyStore) -> Iterator[int]:
    with factory() as session, session.begin():
        engagement = engagements.create(
            session, keystore, {"name": "Uji engine", "target_url": "https://app.test/"}
        )
        engagement_id = engagement.id
    yield engagement_id
    with factory() as session, session.begin():
        session.execute(delete(Engagement).where(Engagement.id == engagement_id))


@pytest.fixture
def engines() -> Iterator[list[Engine]]:
    created: list[Engine] = []
    yield created
    for engine in created:
        engine.shutdown(grace_seconds=5)


def make_engine(
    engines: list[Engine],
    factory: sessionmaker[Session],
    *modules: DummyModule,
    tools: FakeTools | None = None,
    **kwargs: Any,
) -> Engine:
    engine = Engine(
        factory,
        tools or FakeTools(),
        modules={module.name: module for module in modules},
        worker_id=kwargs.pop("worker_id", "worker-a"),
        **kwargs,
    )
    engines.append(engine)
    return engine


def start_scan(factory: sessionmaker[Session], engagement_id: int, **snapshot: Any) -> int:
    with factory() as session, session.begin():
        scan = scans.start(session, session.get(Engagement, engagement_id), "full")
        scan.settings_snapshot = {**scan.settings_snapshot, **snapshot}
        return scan.id


def load_scan(factory: sessionmaker[Session], scan_id: int) -> Scan:
    with factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        return scan


def tasks_of(factory: sessionmaker[Session], scan_id: int, stage: str | None = None) -> list[Task]:
    with factory() as session:
        query = select(Task).where(Task.scan_id == scan_id).order_by(Task.id)
        if stage:
            query = query.where(Task.stage == stage)
        return list(session.scalars(query))


def events_of(factory: sessionmaker[Session], scan_id: int) -> list[ScanEvent]:
    with factory() as session:
        return list(
            session.scalars(
                select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.id)
            )
        )


def drive(
    factory: sessionmaker[Session],
    scan_id: int,
    *engines: Engine,
    until: Any,
    timeout: float = 15.0,
) -> Scan:
    """Tick the engines until `until(scan)` holds (or the scan reaches that status)."""
    check = until if callable(until) else (lambda scan: scan.status == until)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for engine in engines:
            engine.tick()
        scan = load_scan(factory, scan_id)
        if check(scan):
            return scan
        engines[0].wait(0.05)
    raise AssertionError(f"scan {scan_id} stuck at {scan.status}/{scan.stage}")


def running_in(factory: sessionmaker[Session], scan_id: int, count: int) -> Any:
    def check(_scan: Scan) -> bool:
        running = [t for t in tasks_of(factory, scan_id) if t.status == TaskStatus.RUNNING]
        return len(running) >= count

    return check


def test_scan_runs_every_stage_in_order(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    dummy = DummyModule()
    engine = make_engine(engines, factory, dummy)
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False)

    scan = drive(factory, scan_id, engine, until=ScanStatus.COMPLETED)

    assert dummy.planned == [
        ScanStage.RECON,
        ScanStage.PLANNING,
        ScanStage.TESTING,
        ScanStage.VALIDATION,
        ScanStage.AI_TRIAGE,
    ]
    tasks = tasks_of(factory, scan_id)
    assert len(tasks) == 8
    assert {t.status for t in tasks} == {TaskStatus.DONE}
    assert all(t.attempt == 1 and t.locked_by is None for t in tasks)
    assert tasks[0].result_summary == {"n": 0, "attempt": 1}
    assert scan.checkpoint_resolution == "disabled"
    assert scan.started_at is not None and scan.finished_at is not None
    assert scan.stats == {"tasks": {"done": 8}}

    events = events_of(factory, scan_id)
    types = [e.type for e in events]
    assert types.count("stage_changed") == 5
    assert types[-1] == "completed"
    unavailable = next(e for e in events if e.data and "modules" in e.data)
    assert "Configuration & Deployment" in unavailable.message
    assert "information_gathering" not in unavailable.data["modules"]
    with factory() as session:
        assert session.get(Engagement, engagement_id).status == "ready"


def test_checkpoint_waits_then_continues_automatically(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    engine = make_engine(engines, factory, DummyModule())
    scan_id = start_scan(factory, engagement_id, checkpoint_timeout_min=15)

    scan = drive(factory, scan_id, engine, until=ScanStatus.AWAITING_CHECKPOINT)
    remaining = scan.checkpoint_deadline - scans.utcnow()
    assert timedelta(minutes=14) < remaining <= timedelta(minutes=15)
    assert tasks_of(factory, scan_id, ScanStage.TESTING) == []
    assert events_of(factory, scan_id)[-1].type == "checkpoint_waiting"

    engine.tick()
    assert load_scan(factory, scan_id).status == ScanStatus.AWAITING_CHECKPOINT

    engine.clock = lambda: scans.utcnow() + timedelta(minutes=16)
    scan = drive(factory, scan_id, engine, until=ScanStatus.COMPLETED)
    assert scan.checkpoint_resolution == "auto_continued"
    assert scan.checkpoint_deadline is None
    assert len(tasks_of(factory, scan_id, ScanStage.TESTING)) == 4


def test_checkpoint_hold_stops_the_countdown_until_continue(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    engine = make_engine(engines, factory, DummyModule())
    scan_id = start_scan(factory, engagement_id)
    drive(factory, scan_id, engine, until=ScanStatus.AWAITING_CHECKPOINT)

    with factory() as session, session.begin():
        scans.checkpoint_hold(session, session.get(Scan, scan_id))
    engine.clock = lambda: scans.utcnow() + timedelta(days=1)
    for _ in range(3):
        engine.tick()
    scan = load_scan(factory, scan_id)
    assert scan.status == ScanStatus.AWAITING_CHECKPOINT
    assert scan.checkpoint_deadline is None

    with factory() as session, session.begin():
        scans.checkpoint_continue(session, session.get(Scan, scan_id))
    scan = drive(factory, scan_id, engine, until=ScanStatus.COMPLETED)
    assert scan.checkpoint_resolution == "user_continued"


def test_pause_returns_running_tasks_and_resume_finishes(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    dummy = DummyModule(params={ScanStage.TESTING: {"sleep": 30}})
    engine = make_engine(engines, factory, dummy)
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False)
    drive(factory, scan_id, engine, until=running_in(factory, scan_id, 2))

    with factory() as session, session.begin():
        scans.pause(session, session.get(Scan, scan_id))
    drive(factory, scan_id, engine, until=lambda _s: not engine.running, timeout=5)

    testing = tasks_of(factory, scan_id, ScanStage.TESTING)
    assert {t.status for t in testing} == {TaskStatus.PENDING}
    assert all(t.attempt == 0 and t.locked_by is None for t in testing)
    for _ in range(3):
        engine.tick()
    assert all(t.status == TaskStatus.PENDING for t in tasks_of(factory, scan_id, "testing"))
    assert load_scan(factory, scan_id).paused_reason == "manual"

    with factory() as session, session.begin():
        session.execute(update(Task).where(Task.scan_id == scan_id).values(params={}))
        scans.resume(session, session.get(Scan, scan_id))
    drive(factory, scan_id, engine, until=ScanStatus.COMPLETED)
    testing = tasks_of(factory, scan_id, ScanStage.TESTING)
    assert {t.status for t in testing} == {TaskStatus.DONE}
    assert all(t.attempt == 1 for t in testing)


def test_cancel_stops_running_tools_and_skips_the_rest(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    tools = FakeTools(block=True)
    dummy = DummyModule(params={ScanStage.TESTING: {"behaviour": "tool"}})
    engine = make_engine(engines, factory, dummy, tools=tools)
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False)
    drive(factory, scan_id, engine, until=lambda _s: len(tools.calls) >= 2)
    assert tools.calls[0]["scope"] == ["app.test"]
    assert tools.calls[0]["tool"] == "httpx"

    with factory() as session, session.begin():
        scans.cancel(session, session.get(Scan, scan_id))
    drive(factory, scan_id, engine, until=lambda _s: not engine.running, timeout=5)

    assert sorted(tools.cancelled) == sorted(c["run_id"] for c in tools.calls)
    testing = tasks_of(factory, scan_id, ScanStage.TESTING)
    assert {t.status for t in testing} == {TaskStatus.SKIPPED}
    scan = load_scan(factory, scan_id)
    assert scan.status == ScanStatus.CANCELLED
    assert events_of(factory, scan_id)[-1].type == "cancelled"
    with factory() as session:
        assert session.get(Engagement, engagement_id).status == "ready"


def test_transient_errors_retry_once_and_failures_do_not_fail_the_scan(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    flaky = DummyModule(
        "information_gathering", params={ScanStage.TESTING: {"behaviour": "transient_once"}}
    )
    broken = DummyModule(
        "configuration", params={ScanStage.TESTING: {"behaviour": "transient_always"}}
    )
    buggy = DummyModule(
        "identity", tasks={ScanStage.TESTING: 1}, params={ScanStage.TESTING: {"behaviour": "error"}}
    )
    walled = DummyModule(
        "authentication",
        tasks={ScanStage.TESTING: 1},
        params={ScanStage.TESTING: {"behaviour": "blocked"}},
    )
    engine = make_engine(engines, factory, flaky, broken, buggy, walled)
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False, concurrency=4)

    scan = drive(factory, scan_id, engine, until=ScanStatus.COMPLETED)

    by_module: dict[str, list[Task]] = {}
    for task in tasks_of(factory, scan_id, ScanStage.TESTING):
        by_module.setdefault(task.module, []).append(task)
    assert {(t.status, t.attempt) for t in by_module["information_gathering"]} == {("done", 2)}
    assert {(t.status, t.attempt) for t in by_module["configuration"]} == {("failed", 2)}
    assert by_module["configuration"][0].error == "connection reset"
    assert by_module["identity"][0].status == "failed"
    assert by_module["identity"][0].attempt == 1
    assert by_module["identity"][0].error == "ValueError: module bug"
    assert by_module["authentication"][0].status == "blocked"
    assert scan.stats["tasks"]["failed"] == 5

    messages = [e.message for e in events_of(factory, scan_id)]
    assert sum("diulang sekali" in m for m in messages) == 8
    assert any(
        m == "Identity Management · dummy: gagal (ValueError: module bug)." for m in messages
    )
    assert any("terblokir WAF" in m for m in messages)


def test_plan_errors_are_reported_and_the_scan_goes_on(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    engine = make_engine(
        engines, factory, DummyModule(params={ScanStage.RECON: {"plan_error": True}})
    )
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False)
    drive(factory, scan_id, engine, until=ScanStatus.COMPLETED)
    assert tasks_of(factory, scan_id, ScanStage.RECON) == []
    warning = next(e for e in events_of(factory, scan_id) if "gagal merencanakan" in e.message)
    assert warning.level == "warning"
    assert warning.data == {"module": "information_gathering", "stage": "recon"}


def test_database_refusing_a_plan_fails_only_that_scan(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine], keystore: KeyStore
) -> None:
    with factory() as session, session.begin():
        other = engagements.create(
            session, keystore, {"name": "Lain", "target_url": "https://other.test/"}
        )
        other_id = other.id
    try:
        engine = make_engine(
            engines, factory, DummyModule(params={ScanStage.TESTING: {"plan_bad": True}})
        )
        bad = start_scan(factory, engagement_id, checkpoint_enabled=False)
        good = start_scan(factory, other_id, checkpoint_enabled=True)
        scan = drive(factory, bad, engine, until=ScanStatus.FAILED)
        assert "IntegrityError" in scan.error
        assert scan.stage == "planning"  # the failed transition was rolled back
        drive(factory, good, engine, until=ScanStatus.AWAITING_CHECKPOINT)
    finally:
        with factory() as session, session.begin():
            session.execute(delete(Engagement).where(Engagement.id == other_id))


def test_unstorable_results_fail_the_task_instead_of_sticking(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    nan = DummyModule(
        "information_gathering",
        tasks={ScanStage.TESTING: 1},
        params={ScanStage.TESTING: {"behaviour": "nan"}},
    )
    nul = DummyModule(
        "configuration",
        tasks={ScanStage.TESTING: 1},
        params={ScanStage.TESTING: {"behaviour": "nul"}},
    )
    engine = make_engine(engines, factory, nan, nul)
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False)
    drive(factory, scan_id, engine, until=ScanStatus.COMPLETED)
    errors = {t.module: t.error for t in tasks_of(factory, scan_id, ScanStage.TESTING)}
    assert errors["information_gathering"].startswith("ValueError: Out of range float")
    assert errors["configuration"] == "Hasil tugas tidak bisa disimpan."


def test_per_scan_concurrency_limit(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    dummy = DummyModule(tasks={ScanStage.TESTING: 6}, params={ScanStage.TESTING: {"sleep": 0.2}})
    engine = make_engine(engines, factory, dummy, max_parallel=8)
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False, concurrency=2)
    drive(factory, scan_id, engine, until=ScanStatus.COMPLETED)
    assert dummy.max_concurrent == 2


def test_worker_limit_caps_parallel_tasks(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    dummy = DummyModule(tasks={ScanStage.TESTING: 6}, params={ScanStage.TESTING: {"sleep": 0.2}})
    engine = make_engine(engines, factory, dummy, max_parallel=1)
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False, concurrency=4)
    drive(factory, scan_id, engine, until=ScanStatus.COMPLETED)
    assert dummy.max_concurrent == 1


def test_tasks_of_a_dead_worker_are_reclaimed_after_the_lease(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    dummy = DummyModule()
    engine = make_engine(engines, factory, dummy, lease_seconds=60)
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False)
    with factory() as session, session.begin():
        scan = session.get(Scan, scan_id)
        scan.status, scan.stage, scan.started_at = "running", "testing", scans.utcnow()
        for n, (age, attempt) in enumerate([(600, 1), (600, 3), (5, 1)]):
            session.add(
                Task(
                    scan_id=scan_id,
                    stage="testing",
                    module="information_gathering",
                    engine="dummy",
                    target={"n": n},
                    status="running",
                    attempt=attempt,
                    locked_by="dead-worker",
                    locked_at=scans.utcnow() - timedelta(seconds=age),
                )
            )

    assert engine.reclaim_expired() == 2
    stale, crashed_often, fresh = tasks_of(factory, scan_id)
    assert (stale.status, stale.locked_by) == ("pending", None)
    assert crashed_often.status == "failed"
    assert "berulang kali" in crashed_often.error
    assert (fresh.status, fresh.locked_by) == ("running", "dead-worker")
    notice = events_of(factory, scan_id)[-1]
    assert notice.message.startswith("1 tugas dikembalikan ke antrean")

    with factory() as session, session.begin():
        session.execute(
            text("UPDATE task SET locked_at = now() - interval '10 minutes' WHERE id = :id"),
            {"id": fresh.id},
        )
    drive(factory, scan_id, engine, until=ScanStatus.COMPLETED)
    stale, crashed_often, fresh = tasks_of(factory, scan_id, ScanStage.TESTING)
    assert (stale.status, stale.attempt) == ("done", 2)
    assert (fresh.status, fresh.attempt) == ("done", 2)


def test_reclaim_skips_tasks_of_a_cancelled_scan(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    engine = make_engine(engines, factory, DummyModule())
    scan_id = start_scan(factory, engagement_id)
    with factory() as session, session.begin():
        scans.cancel(session, session.get(Scan, scan_id))
        session.add(
            Task(
                scan_id=scan_id,
                stage="recon",
                module="information_gathering",
                engine="dummy",
                status="running",
                attempt=1,
                locked_by="dead-worker",
                locked_at=scans.utcnow() - timedelta(hours=1),
            )
        )
    engine.reclaim_expired()
    assert [t.status for t in tasks_of(factory, scan_id)] == ["skipped"]


def test_two_workers_never_run_the_same_task(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    dummy = DummyModule(tasks={ScanStage.TESTING: 12}, params={ScanStage.TESTING: {"sleep": 0.05}})
    first = make_engine(engines, factory, dummy, worker_id="worker-a")
    second = make_engine(engines, factory, dummy, worker_id="worker-b")
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False, concurrency=4)

    drive(factory, scan_id, first, second, until=ScanStatus.COMPLETED)

    assert len(dummy.runs) == 12
    assert set(dummy.runs.values()) == {1}


def test_shutdown_returns_running_tasks_to_the_queue(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    engine = make_engine(engines, factory, DummyModule(params={ScanStage.TESTING: {"sleep": 30}}))
    scan_id = start_scan(factory, engagement_id, checkpoint_enabled=False)
    drive(factory, scan_id, engine, until=running_in(factory, scan_id, 2))

    started = time.monotonic()
    engine.shutdown(grace_seconds=5)
    assert time.monotonic() - started < 3
    testing = tasks_of(factory, scan_id, ScanStage.TESTING)
    assert {t.status for t in testing} == {TaskStatus.PENDING}
    assert all(t.attempt == 0 and t.locked_by is None for t in testing)
    assert load_scan(factory, scan_id).status == ScanStatus.RUNNING


def test_unrecoverable_error_fails_the_scan_and_resume_continues(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine]
) -> None:
    engine = make_engine(engines, factory, DummyModule())
    scan_id = start_scan(factory, engagement_id, checkpoint_timeout_min="lima belas")

    scan = drive(factory, scan_id, engine, until=ScanStatus.FAILED)
    assert scan.error.startswith("ValueError")
    assert scan.stage == "planning"
    assert events_of(factory, scan_id)[-1].type == "failed"
    with factory() as session:
        assert session.get(Engagement, engagement_id).status == "ready"

    with factory() as session, session.begin():
        failed = session.get(Scan, scan_id)
        failed.settings_snapshot = {**failed.settings_snapshot, "checkpoint_timeout_min": 15}
        scans.resume(session, failed)
        assert session.get(Engagement, engagement_id).status == "active"
    scan = drive(factory, scan_id, engine, until=ScanStatus.AWAITING_CHECKPOINT)
    assert scan.error is None and scan.finished_at is None
    assert len(tasks_of(factory, scan_id, ScanStage.RECON)) == 1


def test_expired_session_pauses_the_scan(
    factory: sessionmaker[Session],
    engagement_id: int,
    engines: list[Engine],
    keystore: KeyStore,
) -> None:
    with factory() as session, session.begin():
        engagement = session.get(Engagement, engagement_id)
        engagement.session_check_url = "https://app.test/profile"
        engagement.session_check_marker = "Keluar"
        engagements.add_account(
            session, keystore, engagement, {"label": "A", "session_text": "sid=abc"}
        )
    valid = {"A": False}
    checks: list[str] = []

    def check_account(session: Session, _engagement: Engagement, account: TargetAccount):
        checks.append(account.label)
        ok = valid[account.label]
        account.session_status = SessionStatus.VALID if ok else SessionStatus.INVALID
        return CheckResult(True, ok, "Sesi valid." if ok else "Penanda login tidak ditemukan.")

    engine = make_engine(
        engines,
        factory,
        DummyModule(params={ScanStage.RECON: {"sleep": 30}}),
        check_account=check_account,
        session_check_seconds=300,
    )
    scan_id = start_scan(factory, engagement_id)
    drive(factory, scan_id, engine, until=running_in(factory, scan_id, 1))

    assert engine.check_sessions() == [scan_id]
    scan = load_scan(factory, scan_id)
    assert (scan.status, scan.paused_reason) == ("paused", "session_expired")
    types = [e.type for e in events_of(factory, scan_id)]
    assert types[-2:] == ["session_expired", "paused"]
    drive(factory, scan_id, engine, until=lambda _s: not engine.running, timeout=5)
    assert tasks_of(factory, scan_id, ScanStage.RECON)[0].status == "pending"

    with factory() as session, session.begin(), pytest.raises(Conflict, match="Perbarui"):
        scans.resume(session, session.get(Scan, scan_id))

    valid["A"] = True
    with factory() as session, session.begin():
        account = session.scalar(
            select(TargetAccount).where(TargetAccount.engagement_id == engagement_id)
        )
        account.session_status = SessionStatus.VALID
        session.execute(update(Task).where(Task.scan_id == scan_id).values(params={}))
        scans.resume(session, session.get(Scan, scan_id))
    drive(factory, scan_id, engine, until=lambda s: s.status == "running" and s.stage == "recon")
    assert engine.check_sessions() == []
    assert engine.check_sessions() == []  # not again before session_check_seconds
    assert checks == ["A", "A"]


def test_session_check_skips_engagements_without_configuration(
    factory: sessionmaker[Session], engagement_id: int, engines: list[Engine], keystore: KeyStore
) -> None:
    with factory() as session, session.begin():
        engagements.add_account(
            session,
            keystore,
            session.get(Engagement, engagement_id),
            {"label": "A", "session_text": "sid=abc"},
        )
    calls: list[int] = []
    engine = make_engine(
        engines,
        factory,
        DummyModule(params={ScanStage.RECON: {"sleep": 30}}),
        check_account=lambda *_args: calls.append(1),
    )
    scan_id = start_scan(factory, engagement_id)
    drive(factory, scan_id, engine, until=running_in(factory, scan_id, 1))
    assert engine.check_sessions() == []
    assert calls == []


def test_wait_wakes_on_notify(
    factory: sessionmaker[Session], db_engine: SqlEngine, engines: list[Engine]
) -> None:
    engine = make_engine(
        engines,
        factory,
        DummyModule(),
        listen_dsn=listen_dsn(db_engine.url.render_as_string(hide_password=False)),
    )
    engine.wait(0.3)  # opens the LISTEN connection

    def notify() -> None:
        time.sleep(0.3)
        with factory() as session, session.begin():
            scans.wake_worker(session)

    sender = threading.Thread(target=notify)
    started = time.monotonic()
    sender.start()
    engine.wait(10)
    sender.join()
    assert time.monotonic() - started < 3


def test_wait_wakes_on_stop(factory: sessionmaker[Session], engines: list[Engine]) -> None:
    engine = make_engine(engines, factory, DummyModule())
    threading.Timer(0.2, engine.stop).start()
    started = time.monotonic()
    engine.run_forever(poll_seconds=10)
    assert time.monotonic() - started < 3
