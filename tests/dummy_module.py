"""A configurable stand-in module for exercising the workflow engine (IPD F4).

Task params choose the behaviour of each run:
  sleep       seconds to work (interruptible by pause/cancel)
  behaviour   ok | transient_once | transient_always | error | blocked | nan | nul | tool
The worker subprocess test loads `MODULES` through RAJDOLL_EXTRA_MODULES=tests.dummy_module and
configures it with RAJDOLL_DUMMY_SLEEP (testing-stage task duration) and RAJDOLL_DUMMY_LOG
(a file where every run writes `start <task_id>` and `end <task_id>` lines).
"""

import os
import threading
from collections import Counter
from typing import Any

from rajdoll.core.enums import ScanStage
from rajdoll.modules.base import (
    PlanContext,
    TaskBlocked,
    TaskCancelled,
    TaskContext,
    TaskSpec,
    TransientTaskError,
)

DEFAULT_TASKS = {
    ScanStage.RECON: 1,
    ScanStage.PLANNING: 1,
    ScanStage.TESTING: 4,
    ScanStage.VALIDATION: 1,
    ScanStage.AI_TRIAGE: 1,
}


class DummyModule:
    label = "Dummy"

    def __init__(
        self,
        name: str = "information_gathering",
        tasks: dict[ScanStage, int] | None = None,
        params: dict[ScanStage, dict[str, Any]] | None = None,
        log_path: str | None = None,
    ) -> None:
        self.name = name
        self.tasks = DEFAULT_TASKS if tasks is None else tasks
        self.params = params or {}
        self.log_path = log_path
        self.runs: Counter[int] = Counter()
        self.planned: list[ScanStage] = []
        self.concurrent = 0
        self.max_concurrent = 0
        self.lock = threading.Lock()

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        self.planned.append(ctx.stage)
        params = self.params.get(ctx.stage, {})
        if params.get("plan_error"):
            raise ValueError("plan exploded")
        if params.get("plan_bad"):
            return [TaskSpec(engine=None)]  # type: ignore[arg-type]  (violates NOT NULL)
        return [
            TaskSpec(engine="dummy", target={"n": n}, params=dict(params))
            for n in range(self.tasks.get(ctx.stage, 0))
        ]

    def _write(self, line: str) -> None:
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        with self.lock:
            self.runs[ctx.task_id] += 1
            attempt = self.runs[ctx.task_id]
            self.concurrent += 1
            self.max_concurrent = max(self.max_concurrent, self.concurrent)
        self._write(f"start {ctx.task_id}")
        try:
            if ctx.cancel_event.wait(float(ctx.params.get("sleep", 0))):
                raise TaskCancelled
            behaviour = ctx.params.get("behaviour", "ok")
            if behaviour == "transient_once" and attempt == 1:
                raise TransientTaskError("connection reset")
            if behaviour == "transient_always":
                raise TransientTaskError("connection reset")
            if behaviour == "error":
                raise ValueError("module bug")
            if behaviour == "blocked":
                raise TaskBlocked("90% of requests answered 403")
            if behaviour == "nan":
                return {"score": float("nan")}
            if behaviour == "nul":
                return {"text": "a\x00b"}  # valid JSON, refused by jsonb
            if behaviour == "tool":
                result = ctx.run_tool("httpx", {"urls": [ctx.target_url]}, timeout_s=30)
                return {"tool_status": result["status"]}
            ctx.log(f"tugas {ctx.target['n']} selesai")
            self._write(f"end {ctx.task_id}")
            return {"n": ctx.target["n"], "attempt": attempt}
        finally:
            with self.lock:
                self.concurrent -= 1


def _from_environment() -> DummyModule:
    sleep = float(os.environ.get("RAJDOLL_DUMMY_SLEEP", "0"))
    return DummyModule(
        tasks={**DEFAULT_TASKS, ScanStage.TESTING: 6},
        params={ScanStage.TESTING: {"sleep": sleep}},
        log_path=os.environ.get("RAJDOLL_DUMMY_LOG") or None,
    )


MODULES = [_from_environment()]
