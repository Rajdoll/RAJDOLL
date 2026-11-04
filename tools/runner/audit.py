"""Audit rows for tools that do not go through the egress proxy (TRD 4.2: nmap, testssl.sh).

One `request_log` row per run, written as the least-privilege `rajdoll_tools` role, which may
read `task` and `scan` and insert into `request_log`.
"""

import psycopg

_LOOKUP = "SELECT s.engagement_id, s.id FROM task t JOIN scan s ON s.id = t.scan_id WHERE t.id = %s"
_INSERT = (
    "INSERT INTO request_log (engagement_id, scan_id, task_id, kind, tool, url, host, outcome) "
    "VALUES (%s, %s, %s, 'tool_exec', %s, %s, %s, 'forwarded')"
)


class AuditUnavailable(RuntimeError):
    """The row could not be written; the tool must not run unaudited."""


class ExecAudit:
    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo

    def record(self, task_id: int, tool: str, summary: str, host: str) -> None:
        try:
            with psycopg.connect(self._conninfo, autocommit=True, connect_timeout=5) as conn:
                row = conn.execute(_LOOKUP, (task_id,)).fetchone()
                if row is None:
                    raise AuditUnavailable(f"task {task_id} not found")
                engagement_id, scan_id = row
                conn.execute(_INSERT, (engagement_id, scan_id, task_id, tool, summary, host))
        except psycopg.Error as exc:
            raise AuditUnavailable(str(exc)) from exc
