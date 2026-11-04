"""Run one tool process: no shell, minimal environment, capped output, timeout and cancel."""

import asyncio
import contextlib
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path

MAX_STDOUT_BYTES = 1_000_000
MAX_STDERR_BYTES = 64_000
KILL_GRACE_SECONDS = 5.0


@dataclass
class ExecResult:
    status: str  # completed | failed | timeout | cancelled
    exit_code: int | None
    duration_ms: int
    stdout: str
    stdout_truncated: bool
    stderr_tail: str


async def _drain(stream: asyncio.StreamReader | None, limit: int, keep: str) -> tuple[bytes, bool]:
    """Read a stream to EOF, keeping the first (`keep="head"`) or last `limit` bytes."""
    if stream is None:
        return b"", False
    buffer = bytearray()
    truncated = False
    while chunk := await stream.read(65536):
        buffer += chunk
        if len(buffer) > limit:
            truncated = True
            buffer = buffer[:limit] if keep == "head" else buffer[-limit:]
    return bytes(buffer), truncated


def tool_environment(bin_dir: Path, home: Path) -> dict[str, str]:
    """Only what tools need. Proxy variables are deliberately absent: adapters pass the
    egress proxy explicitly, so nothing can bypass it through an inherited setting."""
    return {
        "PATH": f"{bin_dir}:/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home),
        "LANG": "C.UTF-8",
    }


class Executor:
    def __init__(self) -> None:
        self._running: dict[str, asyncio.subprocess.Process] = {}
        self._cancelled: set[str] = set()

    def is_running(self, run_id: str) -> bool:
        return run_id in self._running

    def _kill_group(self, proc: asyncio.subprocess.Process, sig: int) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, sig)

    async def _terminate(self, proc: asyncio.subprocess.Process) -> None:
        self._kill_group(proc, signal.SIGTERM)
        try:
            await asyncio.wait_for(proc.wait(), KILL_GRACE_SECONDS)
        except TimeoutError:
            self._kill_group(proc, signal.SIGKILL)
            await proc.wait()

    def cancel(self, run_id: str) -> bool:
        proc = self._running.get(run_id)
        if proc is None:
            return False
        self._cancelled.add(run_id)
        self._kill_group(proc, signal.SIGTERM)
        return True

    async def run(
        self,
        run_id: str,
        argv: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout_s: float,
    ) -> ExecResult:
        started = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd),
            env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # own process group, so cancel kills children too
        )
        self._running[run_id] = proc
        out_task = asyncio.create_task(_drain(proc.stdout, MAX_STDOUT_BYTES, "head"))
        err_task = asyncio.create_task(_drain(proc.stderr, MAX_STDERR_BYTES, "tail"))
        status = "completed"
        try:
            await asyncio.wait_for(proc.wait(), timeout_s)
        except TimeoutError:
            status = "timeout"
            await self._terminate(proc)
        finally:
            self._running.pop(run_id, None)
        (stdout, truncated), (stderr, _) = await asyncio.gather(out_task, err_task)
        if run_id in self._cancelled:
            self._cancelled.discard(run_id)
            status = "cancelled"
        elif status == "completed" and proc.returncode != 0:
            status = "failed"
        return ExecResult(
            status=status,
            exit_code=proc.returncode,
            duration_ms=int((time.monotonic() - started) * 1000),
            stdout=stdout.decode("utf-8", errors="replace"),
            stdout_truncated=truncated,
            stderr_tail=stderr.decode("utf-8", errors="replace"),
        )
