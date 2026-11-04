"""Server-sent events for the scan monitor (BSD 10.4; TRD 8).

Each client gets its own LISTEN connection on `scan_events` (the trigger on `scan_event` inserts).
On every notification for its scan, and at least every heartbeat, the stream re-renders the
monitor fragments and sends only those that changed, plus the new log lines. When the scan has
finished it sends `done`, which the page uses as `sse-close`, so the browser does not reconnect.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass

import psycopg
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request

# Channel of the scan_event NOTIFY trigger (migration 0001); payload is "<scan_id>:<event_id>".
EVENT_CHANNEL = "scan_events"
DEBOUNCE_SECONDS = 0.3


def format_event(name: str, data: str, event_id: int | None = None) -> str:
    lines = [] if event_id is None else [f"id: {event_id}"]
    lines.append(f"event: {name}")
    lines.extend(f"data: {line}" for line in (data.splitlines() or [""]))
    return "\n".join(lines) + "\n\n"


@dataclass
class Frame:
    """One render of the monitor: fragments by SSE event name, new log lines, and state."""

    fragments: dict[str, str]
    log_html: str = ""
    last_event_id: int = 0
    finished: bool = False


Renderer = Callable[[int], Frame]


async def scan_stream(
    request: Request,
    dsn: str,
    scan_id: int,
    after_id: int,
    render: Renderer,
    *,
    heartbeat_seconds: float = 15.0,
    max_seconds: float = 600.0,
) -> AsyncIterator[str]:
    yield "retry: 3000\n\n"
    sent: dict[str, str] = {}
    last_id = after_id
    started = time.monotonic()
    async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
        await conn.execute(f"LISTEN {EVENT_CHANNEL}")
        while True:
            frame = await run_in_threadpool(render, last_id)
            changed = False
            for name, html in frame.fragments.items():
                if sent.get(name) != html:
                    sent[name] = html
                    changed = True
                    yield format_event(name, html)
            if frame.log_html:
                changed = True
                yield format_event("notice", frame.log_html, frame.last_event_id)
            last_id = max(last_id, frame.last_event_id)
            if frame.finished:
                yield format_event("done", "")
                return
            if not changed:
                yield ": ping\n\n"  # lets a closed connection surface as a disconnect
            if time.monotonic() - started > max_seconds or await request.is_disconnected():
                return  # the browser reconnects with Last-Event-ID
            await _wait_for_scan(conn, scan_id, heartbeat_seconds)


async def _wait_for_scan(conn: psycopg.AsyncConnection, scan_id: int, timeout: float) -> None:
    """Return after a notification for `scan_id` (plus a short debounce) or the timeout."""
    deadline = time.monotonic() + timeout
    prefix = f"{scan_id}:"
    while (remaining := deadline - time.monotonic()) > 0:
        relevant = False
        async for notify in conn.notifies(timeout=remaining, stop_after=1):
            relevant = notify.payload.startswith(prefix)
        if relevant:
            async for _ in conn.notifies(timeout=DEBOUNCE_SECONDS):
                pass
            return
