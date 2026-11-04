"""Workflow engine: stages, task queue, checkpoint, pause and recovery (TRD 3; AFD 3.2, 3.3).

One loop per worker process. Each pass (`tick`):

1. reclaims `running` tasks whose lease ran out (their worker died),
2. refreshes the lease of the tasks this worker runs,
3. stops tasks whose scan left `running` (pause, cancel) through the runner's cancel,
4. records the outcome of finished tasks,
5. moves scans between stages, including the checkpoint and its auto-continue,
6. claims pending tasks with `FOR UPDATE SKIP LOCKED`, within the per-scan and worker limits.

Tasks run in a thread pool; everything else happens on the loop thread. Between passes the
worker sleeps until a NOTIFY on `rajdoll_worker` or the poll timeout. Modules only plan and run
tasks: the order of stages is fixed here (TRD P1).
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import wait as wait_futures
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

import psycopg
from sqlalchemy import func, or_, select
from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from rajdoll.core.enums import (
    CheckpointResolution,
    EventLevel,
    EventType,
    PausedReason,
    ScanKind,
    ScanStage,
    ScanStatus,
    TaskStatus,
)
from rajdoll.core.models import Engagement, Scan, TargetAccount, Task
from rajdoll.modules.base import (
    Module,
    PlanContext,
    TaskBlocked,
    TaskCancelled,
    TaskContext,
    TransientTaskError,
)
from rajdoll.modules.registry import available_modules, label
from rajdoll.services import engagements, scans
from rajdoll.services.events import emit
from rajdoll.services.session_check import CheckResult

log = logging.getLogger("rajdoll.worker.engine")

STAGES: dict[str, tuple[ScanStage, ...]] = {
    ScanKind.SCAN: (
        ScanStage.RECON,
        ScanStage.PLANNING,
        ScanStage.TESTING,
        ScanStage.VALIDATION,
        ScanStage.AI_TRIAGE,
    ),
    ScanKind.RETEST: (ScanStage.RETEST,),
}
# A task runs at most twice when it hits a transient error (AFD 3.3).
MAX_TRANSIENT_ATTEMPTS = 2
# A task whose worker died this many times is marked failed instead of retried forever.
MAX_RECLAIMS = 3
MAX_ERROR_LENGTH = 2000
_CHECKPOINT = "checkpoint"
# Lost or unusable database connection: retry the whole pass later instead of blaming a scan.
_CONNECTION_ERRORS = (OperationalError, InterfaceError)

AccountChecker = Callable[[Session, Engagement, TargetAccount], CheckResult]


class ToolRunner(Protocol):
    def run(
        self,
        run_id: str,
        *,
        task_id: int,
        scan_id: int,
        tool: str,
        params: dict[str, Any],
        scope: list[str],
        timeout_s: int,
    ) -> dict[str, Any]: ...

    def cancel(self, run_id: str) -> bool: ...


@dataclass(frozen=True)
class Outcome:
    kind: str  # done | cancelled | transient | blocked | failed
    summary: dict[str, Any] | None = None
    error: str | None = None


@dataclass
class Job:
    """A claimed task, as the thread that runs it sees it."""

    task_id: int
    scan_id: int
    engagement_id: int
    module: str
    engine: str
    target: dict[str, Any]
    params: dict[str, Any]
    target_url: str
    scope: list[str]
    settings: dict[str, Any]
    cancel_event: threading.Event = field(default_factory=threading.Event)
    run_ids: set[str] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)
    future: Future[Outcome] | None = None


def _clip(message: str) -> str:
    return message if len(message) <= MAX_ERROR_LENGTH else message[: MAX_ERROR_LENGTH - 1] + "…"


def default_worker_id() -> str:
    # The random part keeps a restarted process (same host, often the same PID in a container)
    # from mistaking the dead process's tasks for its own.
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


class Engine:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        tools: ToolRunner,
        *,
        modules: dict[str, Module] | None = None,
        worker_id: str | None = None,
        lease_seconds: float = 60.0,
        max_parallel: int = 4,
        session_check_seconds: float = 300.0,
        check_account: AccountChecker | None = None,
        listen_dsn: str | None = None,
        clock: Callable[[], datetime] = scans.utcnow,
    ) -> None:
        self.session_factory = session_factory
        self.tools = tools
        self.modules = modules if modules is not None else available_modules()
        self.worker_id = worker_id or default_worker_id()
        self.lease = timedelta(seconds=lease_seconds)
        self.max_parallel = max_parallel
        self.session_check_seconds = session_check_seconds
        self.check_account = check_account
        self.listen_dsn = listen_dsn
        self.clock = clock
        self.running: dict[int, Job] = {}
        self._pool = ThreadPoolExecutor(max_workers=max_parallel, thread_name_prefix="task")
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._listener: psycopg.Connection | None = None
        self._session_checked: dict[int, float] = {}

    # ------------------------------------------------------------------ loop

    @contextmanager
    def _transaction(self) -> Iterator[Session]:
        with self.session_factory() as session, session.begin():
            yield session

    def tick(self) -> None:
        self.reclaim_expired()
        self.heartbeat()
        self.stop_interrupted()
        self.collect_finished()
        self.advance_scans()
        self.dispatch()

    def stop(self) -> None:
        """Ask `run_forever` to finish (safe to call from a signal handler)."""
        self._stop.set()
        self._wake.set()

    def run_forever(self, poll_seconds: float = 5.0) -> None:
        log.info("engine %s started", self.worker_id)
        watcher = threading.Thread(target=self._watch_sessions, name="session-watch", daemon=True)
        if self.check_account is not None:
            watcher.start()
        while not self._stop.is_set():
            try:
                self.tick()
            except DBAPIError as exc:
                log.warning("database error, retrying: %s", exc.__class__.__name__)
            except Exception:
                log.exception("engine pass failed")
            self.wait(poll_seconds)
        self.shutdown()
        log.info("engine %s stopped", self.worker_id)

    def wait(self, timeout: float) -> None:
        """Sleep until a NOTIFY, a finished task, `stop()`, or the timeout."""
        deadline = time.monotonic() + timeout
        while not self._wake.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if self._listen(min(remaining, 0.25)):
                break
        self._wake.clear()

    def _listen(self, timeout: float) -> bool:
        if not self.listen_dsn:
            return self._wake.wait(timeout)
        try:
            if self._listener is None or self._listener.closed:
                self._listener = psycopg.connect(self.listen_dsn, autocommit=True)
                self._listener.execute(f"LISTEN {scans.WORKER_CHANNEL}")
            notified = False
            for _ in self._listener.notifies(timeout=timeout):
                notified = True
            return notified
        except psycopg.Error:
            self._listener = None
            return self._wake.wait(timeout)

    def shutdown(self, grace_seconds: float = 10.0) -> None:
        """Stop running tasks and return them to the queue for the next worker."""
        for job in list(self.running.values()):
            self._interrupt(job)
        # Tasks still running after the grace period keep their lease and return to the queue
        # when it expires.
        futures = [job.future for job in self.running.values() if job.future is not None]
        if futures:
            wait_futures(futures, timeout=grace_seconds)
        try:
            self.collect_finished()
        except DBAPIError:
            log.warning("could not record interrupted tasks; their lease will expire")
        self._pool.shutdown(wait=False, cancel_futures=True)
        if self._listener is not None:
            self._listener.close()

    # ------------------------------------------------------------- recovery

    def reclaim_expired(self) -> int:
        """Return tasks of dead workers to the queue (TRD 3.3)."""
        now = self.clock()
        with self._transaction() as session:
            tasks = session.scalars(
                select(Task)
                .where(
                    Task.status == TaskStatus.RUNNING,
                    Task.locked_at < func.now() - self.lease,
                    or_(Task.locked_by.is_(None), Task.locked_by != self.worker_id),
                )
                .with_for_update(skip_locked=True)
            ).all()
            per_scan: dict[int, int] = {}
            for task in tasks:
                scan_status = session.scalar(select(Scan.status).where(Scan.id == task.scan_id))
                task.locked_by = None
                task.locked_at = None
                if scan_status == ScanStatus.CANCELLED:
                    task.status = TaskStatus.SKIPPED
                    task.finished_at = now
                elif task.attempt >= MAX_RECLAIMS:
                    task.status = TaskStatus.FAILED
                    task.finished_at = now
                    task.error = "Worker berhenti berulang kali saat menjalankan tugas ini."
                else:
                    task.status = TaskStatus.PENDING
                    per_scan[task.scan_id] = per_scan.get(task.scan_id, 0) + 1
            for scan_id, count in per_scan.items():
                emit(
                    session,
                    scan_id,
                    EventType.NOTICE,
                    f"{count} tugas dikembalikan ke antrean karena worker sebelumnya berhenti.",
                    level=EventLevel.WARNING,
                )
            return len(tasks)

    def heartbeat(self) -> None:
        if not self.running:
            return
        with self._transaction() as session:
            for task in session.scalars(
                select(Task).where(
                    Task.id.in_(list(self.running)),
                    Task.locked_by == self.worker_id,
                    Task.status == TaskStatus.RUNNING,
                )
            ):
                task.locked_at = func.now()

    def stop_interrupted(self) -> None:
        """Cancel tasks whose scan stopped running, or that this worker no longer owns."""
        if not self.running:
            return
        with self._transaction() as session:
            rows = session.execute(
                select(Task.id, Task.status, Task.locked_by, Scan.status)
                .join(Scan, Scan.id == Task.scan_id)
                .where(Task.id.in_(list(self.running)))
            ).all()
        alive = {
            task_id
            for task_id, task_status, locked_by, scan_status in rows
            if scan_status == ScanStatus.RUNNING
            and task_status == TaskStatus.RUNNING
            and locked_by == self.worker_id
        }
        for task_id, job in self.running.items():
            if task_id not in alive or job.cancel_event.is_set():
                # Repeated every pass: a tool that started after the first cancel is caught too.
                self._interrupt(job)

    def _interrupt(self, job: Job) -> None:
        job.cancel_event.set()
        with job.lock:
            run_ids = list(job.run_ids)
        for run_id in run_ids:
            self.tools.cancel(run_id)

    # ---------------------------------------------------------- task results

    def collect_finished(self) -> None:
        for task_id, job in list(self.running.items()):
            if job.future is None or not job.future.done():
                continue
            outcome = job.future.result()
            try:
                self._finalize(job, outcome)
            except _CONNECTION_ERRORS:
                raise  # keep the job and record it on the next pass
            except Exception:
                # For example a summary the database refuses: never leave the task running.
                log.exception("could not record task %s", task_id)
                self._finalize(job, Outcome("failed", error="Hasil tugas tidak bisa disimpan."))
            del self.running[task_id]

    def _finalize(self, job: Job, outcome: Outcome) -> None:
        now = self.clock()
        with self._transaction() as session:
            task = session.get(Task, job.task_id, with_for_update=True)
            if task is None or task.status != TaskStatus.RUNNING:
                return
            if task.locked_by != self.worker_id:
                return  # reclaimed by another worker after our lease ran out
            scan = session.get(Scan, task.scan_id)
            task.locked_by = None
            task.locked_at = None
            data = {"task_id": task.id, "module": task.module, "engine": task.engine}
            name = f"{label(task.module)} · {task.engine}"

            if outcome.kind == "cancelled":
                if scan is not None and scan.status == ScanStatus.CANCELLED:
                    task.status = TaskStatus.SKIPPED
                    task.finished_at = now
                else:
                    # Paused or the worker is stopping: run it again later, as a fresh attempt.
                    task.status = TaskStatus.PENDING
                    task.attempt = max(task.attempt - 1, 0)
                return
            if outcome.kind == "transient" and task.attempt < MAX_TRANSIENT_ATTEMPTS:
                task.status = TaskStatus.PENDING
                emit(
                    session,
                    task.scan_id,
                    EventType.NOTICE,
                    f"{name}: galat sementara ({outcome.error}), diulang sekali.",
                    level=EventLevel.WARNING,
                    data=data,
                )
                return

            task.finished_at = now
            if outcome.kind == "done":
                task.status = TaskStatus.DONE
                task.result_summary = outcome.summary
                task.error = None
                message, level = f"{name}: selesai.", EventLevel.INFO
            elif outcome.kind == "blocked":
                task.status = TaskStatus.BLOCKED
                task.error = _clip(outcome.error or "")
                message, level = f"{name}: terblokir WAF.", EventLevel.WARNING
            else:
                task.status = TaskStatus.FAILED
                task.error = _clip(outcome.error or "galat tidak diketahui")
                message, level = f"{name}: gagal ({task.error}).", EventLevel.WARNING
            emit(
                session,
                task.scan_id,
                EventType.TASK_FINISHED,
                _clip(message),
                level=level,
                data={**data, "status": task.status},
            )

    # ---------------------------------------------------------------- stages

    def advance_scans(self) -> None:
        with self._transaction() as session:
            unfinished = session.scalars(
                select(Scan)
                .where(
                    Scan.status.in_(
                        (ScanStatus.QUEUED, ScanStatus.RUNNING, ScanStatus.AWAITING_CHECKPOINT)
                    )
                )
                .order_by(Scan.id)
                .with_for_update(skip_locked=True)
            ).all()
            for scan in unfinished:
                try:
                    with session.begin_nested():
                        self._advance(session, scan)
                except _CONNECTION_ERRORS:
                    raise
                except Exception as exc:
                    log.exception("scan %s failed", scan.id)
                    self._fail(session, scan, f"{type(exc).__name__}: {exc}")

    def _advance(self, session: Session, scan: Scan) -> None:
        now = self.clock()
        if scan.status == ScanStatus.QUEUED:
            first_start = scan.started_at is None
            scan.status = ScanStatus.RUNNING
            scan.started_at = scan.started_at or now
            if first_start:
                self._notice_unavailable(session, scan)
            if scan.stage is None:
                self._enter(session, scan, STAGES[scan.kind][0])
        elif scan.status == ScanStatus.AWAITING_CHECKPOINT:
            if scan.checkpoint_deadline is None or scan.checkpoint_deadline > now:
                return  # still waiting, or held by the assessor
            scan.status = ScanStatus.RUNNING
            scan.checkpoint_deadline = None
            scan.checkpoint_resolution = CheckpointResolution.AUTO_CONTINUED
            emit(
                session,
                scan.id,
                EventType.RESUMED,
                "Batas waktu checkpoint habis; scan lanjut dengan rencana apa adanya.",
            )

        stages = STAGES[scan.kind]
        for _ in range(len(stages) + 1):
            if self._outstanding(session, scan):
                return
            following = self._next_stage(scan)
            if following is None:
                self._complete(session, scan)
                return
            if following == _CHECKPOINT:
                self._await_checkpoint(session, scan)
                return
            self._enter(session, scan, ScanStage(following))

    def _outstanding(self, session: Session, scan: Scan) -> bool:
        count = session.scalar(
            select(func.count())
            .select_from(Task)
            .where(
                Task.scan_id == scan.id,
                Task.stage == scan.stage,
                Task.status.in_((TaskStatus.PENDING, TaskStatus.RUNNING)),
            )
        )
        return bool(count)

    def _next_stage(self, scan: Scan) -> str | None:
        stages = STAGES[scan.kind]
        if scan.stage == ScanStage.PLANNING and scan.checkpoint_resolution is None:
            if scan.settings_snapshot.get("checkpoint_enabled", True):
                return _CHECKPOINT
            scan.checkpoint_resolution = CheckpointResolution.DISABLED
        index = stages.index(ScanStage(scan.stage))
        return stages[index + 1] if index + 1 < len(stages) else None

    def _await_checkpoint(self, session: Session, scan: Scan) -> None:
        minutes = int(scan.settings_snapshot.get("checkpoint_timeout_min", 15))
        scan.status = ScanStatus.AWAITING_CHECKPOINT
        scan.checkpoint_deadline = self.clock() + timedelta(minutes=minutes)
        emit(
            session,
            scan.id,
            EventType.CHECKPOINT_WAITING,
            f"Rencana pengujian siap ditinjau. Scan lanjut otomatis dalam {minutes} menit.",
            data={"deadline": scan.checkpoint_deadline.isoformat()},
        )

    def _enter(self, session: Session, scan: Scan, stage: ScanStage) -> None:
        scan.stage = stage
        emit(
            session,
            scan.id,
            EventType.STAGE_CHANGED,
            f"Tahap {scans.STAGE_LABELS[stage]} dimulai.",
            data={"stage": str(stage)},
        )
        engagement = session.get(Engagement, scan.engagement_id)
        assert engagement is not None  # noqa: S101 (scan rows cascade with their engagement)
        ctx = PlanContext(
            scan_id=scan.id,
            engagement_id=scan.engagement_id,
            target_url=scan.base_url or engagement.target_url,
            scope=engagements.scope_patterns(session, scan.engagement_id),
            settings=dict(scan.settings_snapshot),
            stage=stage,
        )
        for name in scan.modules:
            module = self.modules.get(name)
            if module is None:
                continue
            try:
                specs = module.plan(ctx)
            except Exception as exc:  # noqa: BLE001 (one module's bug must not stop the scan)
                log.exception("module %s failed to plan %s", name, stage)
                emit(
                    session,
                    scan.id,
                    EventType.NOTICE,
                    _clip(f"Modul {label(name)} gagal merencanakan tahap ini: {exc}"),
                    level=EventLevel.WARNING,
                    data={"module": name, "stage": str(stage)},
                )
                continue
            for spec in specs:
                session.add(
                    Task(
                        scan_id=scan.id,
                        stage=stage,
                        module=name,
                        engine=spec.engine,
                        target=spec.target,
                        params=spec.params,
                    )
                )
        session.flush()

    def _notice_unavailable(self, session: Session, scan: Scan) -> None:
        missing = [name for name in scan.modules if name not in self.modules]
        if missing:
            emit(
                session,
                scan.id,
                EventType.NOTICE,
                "Modul berikut belum tersedia di versi ini dan dilewati: "
                + ", ".join(label(name) for name in missing)
                + ".",
                level=EventLevel.WARNING,
                data={"modules": missing},
            )

    def _complete(self, session: Session, scan: Scan) -> None:
        counts = dict(
            session.execute(
                select(Task.status, func.count())
                .where(Task.scan_id == scan.id)
                .group_by(Task.status)
            ).all()
        )
        tasks = {str(status): count for status, count in counts.items()}
        scan.status = ScanStatus.COMPLETED
        scan.finished_at = self.clock()
        scan.stats = {**(scan.stats or {}), "tasks": tasks}
        emit(session, scan.id, EventType.COMPLETED, "Scan selesai.", data={"tasks": tasks})
        scans.release_engagement(session, scan.engagement_id)

    def _fail(self, session: Session, scan: Scan, error: str) -> None:
        scan.status = ScanStatus.FAILED
        scan.paused_reason = None
        scan.checkpoint_deadline = None
        scan.error = _clip(error)
        scan.finished_at = self.clock()
        emit(
            session,
            scan.id,
            EventType.FAILED,
            _clip(f"Scan gagal: {error}. Scan bisa dilanjutkan dari tugas terakhir."),
            level=EventLevel.ERROR,
        )
        scans.release_engagement(session, scan.engagement_id)

    # -------------------------------------------------------------- dispatch

    def dispatch(self) -> int:
        free = self.max_parallel - len(self.running)
        if free <= 0:
            return 0
        jobs: list[Job] = []
        with self._transaction() as session:
            running_per_scan = dict(
                session.execute(
                    select(Task.scan_id, func.count())
                    .where(Task.status == TaskStatus.RUNNING)
                    .group_by(Task.scan_id)
                ).all()
            )
            active = session.scalars(
                select(Scan)
                .where(Scan.status == ScanStatus.RUNNING)
                .order_by(Scan.id)
                .with_for_update(read=True, skip_locked=True)
            ).all()
            for scan in active:
                allowed = int(scan.settings_snapshot.get("concurrency", 2))
                room = min(allowed - running_per_scan.get(scan.id, 0), free - len(jobs))
                if room <= 0:
                    continue
                tasks = session.scalars(
                    select(Task)
                    .where(
                        Task.scan_id == scan.id,
                        Task.stage == scan.stage,
                        Task.status == TaskStatus.PENDING,
                    )
                    .order_by(Task.id)
                    .limit(room)
                    .with_for_update(skip_locked=True)
                ).all()
                if not tasks:
                    continue
                engagement = session.get(Engagement, scan.engagement_id)
                assert engagement is not None  # noqa: S101
                scope = engagements.scope_patterns(session, scan.engagement_id)
                for task in tasks:
                    task.status = TaskStatus.RUNNING
                    task.locked_by = self.worker_id
                    task.locked_at = func.now()
                    task.started_at = func.now()
                    task.attempt = task.attempt + 1
                    jobs.append(
                        Job(
                            task_id=task.id,
                            scan_id=scan.id,
                            engagement_id=scan.engagement_id,
                            module=task.module,
                            engine=task.engine,
                            target=dict(task.target),
                            params=dict(task.params),
                            target_url=scan.base_url or engagement.target_url,
                            scope=scope,
                            settings=dict(scan.settings_snapshot),
                        )
                    )
        for job in jobs:
            self.running[job.task_id] = job
            job.future = self._pool.submit(self._execute, job)
            job.future.add_done_callback(lambda _f: self._wake.set())
        return len(jobs)

    # ------------------------------------------------------- task execution

    def _execute(self, job: Job) -> Outcome:
        """Run one task in a pool thread. Never raises."""
        module = self.modules.get(job.module)
        if module is None:
            return Outcome("failed", error=f"Modul {job.module} tidak tersedia di worker ini.")
        ctx = TaskContext(
            task_id=job.task_id,
            scan_id=job.scan_id,
            engagement_id=job.engagement_id,
            target_url=job.target_url,
            scope=job.scope,
            settings=job.settings,
            engine=job.engine,
            target=job.target,
            params=job.params,
            cancel_event=job.cancel_event,
            run_tool=lambda tool, params, timeout_s=600: self._run_tool(
                job, tool, params, timeout_s
            ),
            log=lambda message: self._task_log(job, message),
        )
        try:
            ctx.check_cancelled()
            summary = module.run(ctx)
            json.dumps(summary, allow_nan=False)  # must be storable as jsonb
            outcome = Outcome("done", summary=summary)
        except TaskCancelled:
            outcome = Outcome("cancelled")
        except TransientTaskError as exc:
            outcome = Outcome("transient", error=str(exc))
        except TaskBlocked as exc:
            outcome = Outcome("blocked", error=str(exc))
        except Exception as exc:  # noqa: BLE001 (a failed task never fails the scan, PRD F-16)
            log.exception("task %s failed", job.task_id)
            outcome = Outcome("failed", error=f"{type(exc).__name__}: {exc}")
        if job.cancel_event.is_set() and outcome.kind != "done":
            return Outcome("cancelled")
        if outcome.kind == "cancelled":
            # Stopped from outside the engine (for example the runner restarted): retry once.
            return Outcome("transient", error="tool dihentikan dari luar worker")
        return outcome

    def _run_tool(
        self, job: Job, tool: str, params: dict[str, Any], timeout_s: int
    ) -> dict[str, Any]:
        if job.cancel_event.is_set():
            raise TaskCancelled
        run_id = uuid.uuid4().hex
        with job.lock:
            job.run_ids.add(run_id)
        try:
            result = self.tools.run(
                run_id,
                task_id=job.task_id,
                scan_id=job.scan_id,
                tool=tool,
                params=params,
                scope=job.scope,
                timeout_s=timeout_s,
            )
        finally:
            with job.lock:
                job.run_ids.discard(run_id)
        if job.cancel_event.is_set():
            raise TaskCancelled
        return result

    def _task_log(self, job: Job, message: str) -> None:
        with self._transaction() as session:
            emit(
                session,
                job.scan_id,
                EventType.NOTICE,
                _clip(f"{label(job.module)}: {message}"),
                data={"task_id": job.task_id, "module": job.module},
            )

    # --------------------------------------------------------- session watch

    def _watch_sessions(self) -> None:
        while not self._stop.is_set():
            try:
                self.check_sessions()
            except Exception:
                log.exception("session check failed")
            self._stop.wait(min(self.session_check_seconds, 30.0))

    def check_sessions(self) -> list[int]:
        """Check the target accounts of running scans; pause scans whose session expired.

        Each running scan is checked when it starts running and then every
        `session_check_seconds` (TRD 3.5, AFD A6). Returns the IDs of the scans paused.
        """
        if self.check_account is None:
            return []
        with self._transaction() as session:
            rows = session.execute(
                select(Scan.id, Scan.engagement_id).where(Scan.status == ScanStatus.RUNNING)
            ).all()
        now = time.monotonic()
        running_ids = {scan_id for scan_id, _ in rows}
        for scan_id in list(self._session_checked):
            if scan_id not in running_ids:
                del self._session_checked[scan_id]
        paused = []
        for scan_id, engagement_id in rows:
            last = self._session_checked.get(scan_id)
            if last is not None and now - last < self.session_check_seconds:
                continue
            self._session_checked[scan_id] = now
            if self._check_scan_sessions(scan_id, engagement_id):
                paused.append(scan_id)
                # Checked again as soon as the assessor resumes it with a fresh session.
                del self._session_checked[scan_id]
        return paused

    def _check_scan_sessions(self, scan_id: int, engagement_id: int) -> bool:
        assert self.check_account is not None  # noqa: S101
        with self._transaction() as session:
            engagement = session.get(Engagement, engagement_id)
            if (
                engagement is None
                or not engagement.session_check_url
                or not engagement.session_check_marker
            ):
                return False
            expired = []
            for account in engagements.accounts(session, engagement_id):
                result = self.check_account(session, engagement, account)
                if result.checked and not result.valid:
                    expired.append(account.label)
            if not expired:
                return False
            scan = session.get(Scan, scan_id, with_for_update=True)
            if scan is None or scan.status not in (
                ScanStatus.QUEUED,
                ScanStatus.RUNNING,
                ScanStatus.AWAITING_CHECKPOINT,
            ):
                return False
            emit(
                session,
                scan_id,
                EventType.SESSION_EXPIRED,
                f"Sesi akun {', '.join(expired)} tidak valid lagi. Perbarui sesi, lalu lanjutkan.",
                level=EventLevel.WARNING,
                data={"accounts": expired},
            )
            scans.pause(session, scan, PausedReason.SESSION_EXPIRED)
            return True
