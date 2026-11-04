"""PostgreSQL access for the egress proxy, as the least-privilege `rajdoll_tools` role (BSD 8).

Reads (task, engagement settings, scope) happen on demand from a worker thread. Audit rows are
queued and inserted in batches by a background thread so a slow database never stalls traffic.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any

import psycopg

log = logging.getLogger("rajdoll.proxy.store")

BATCH_SIZE = 200
FLUSH_SECONDS = 0.5
_COLUMNS = (
    "engagement_id",
    "scan_id",
    "task_id",
    "kind",
    "tool",
    "method",
    "url",
    "host",
    "status",
    "response_bytes",
    "duration_ms",
    "outcome",
)
_INSERT = (
    f"INSERT INTO request_log ({', '.join(_COLUMNS)}) "  # noqa: S608 (fixed column list)
    f"VALUES ({', '.join(['%s'] * len(_COLUMNS))})"
)


class PostgresStore:
    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo
        self._read_lock = threading.Lock()
        self._read_conn: psycopg.Connection | None = None
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=100_000)
        self._writer = threading.Thread(target=self._write_loop, name="audit-writer", daemon=True)
        self._writer.start()

    # Reads ----------------------------------------------------------------------------

    def _query(self, sql: str, params: tuple[Any, ...]) -> list[tuple[Any, ...]]:
        with self._read_lock:
            for attempt in (1, 2):
                try:
                    if self._read_conn is None or self._read_conn.closed:
                        self._read_conn = psycopg.connect(self._conninfo, autocommit=True)
                    return self._read_conn.execute(sql, params).fetchall()
                except psycopg.OperationalError:
                    self._read_conn = None
                    if attempt == 2:
                        raise
        return []

    def task(self, task_id: int) -> tuple[int, int, dict[str, Any]] | None:
        rows = self._query(
            "SELECT s.engagement_id, s.id, s.settings_snapshot "
            "FROM task t JOIN scan s ON s.id = t.scan_id WHERE t.id = %s",
            (task_id,),
        )
        if not rows:
            return None
        engagement_id, scan_id, snapshot = rows[0]
        return engagement_id, scan_id, snapshot or {}

    def engagement_settings(self, engagement_id: int) -> dict[str, Any] | None:
        rows = self._query("SELECT settings FROM engagement WHERE id = %s", (engagement_id,))
        return (rows[0][0] or {}) if rows else None

    def scope(self, engagement_id: int) -> list[str]:
        rows = self._query(
            "SELECT pattern FROM scope_rule WHERE engagement_id = %s", (engagement_id,)
        )
        return [row[0] for row in rows]

    # Audit writes ---------------------------------------------------------------------

    def write(self, row: dict[str, Any]) -> None:
        try:
            self._queue.put_nowait(row)
        except queue.Full:
            log.error("audit queue full; dropping a request_log row")

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until every queued row has been written. Returns False on timeout."""
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.05)
        return not self._queue.unfinished_tasks

    def _write_loop(self) -> None:
        conn: psycopg.Connection | None = None
        while True:
            batch = [self._queue.get()]
            deadline = time.monotonic() + FLUSH_SECONDS
            while len(batch) < BATCH_SIZE:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    batch.append(self._queue.get(timeout=remaining))
                except queue.Empty:
                    break
            rows = [row for row in batch if row is not None]
            while rows:
                try:
                    if conn is None or conn.closed:
                        conn = psycopg.connect(self._conninfo, autocommit=True)
                    with conn.cursor() as cur:
                        cur.executemany(_INSERT, [tuple(r[c] for c in _COLUMNS) for r in rows])
                    break
                except psycopg.Error:
                    log.exception("audit insert failed; retrying in 2 s")
                    conn = None
                    time.sleep(2)
            for _ in batch:
                self._queue.task_done()
