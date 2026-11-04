"""Contract between the workflow engine and test modules (TRD 6.1).

A module plans tasks for a pipeline stage and runs one task at a time. It never decides the
pipeline order (TRD P1): the engine asks each active module for its tasks, stage by stage.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol

from rajdoll.core.enums import ScanStage


class TaskCancelled(Exception):  # noqa: N818 (control-flow signal, not an error)
    """The scan was paused or cancelled while the task ran."""


class TransientTaskError(Exception):
    """A failure worth one retry (timeout, connection reset)."""


class TaskBlocked(Exception):  # noqa: N818
    """Most of the task's requests were blocked by a WAF (PRD F-49)."""


@dataclass(frozen=True)
class TaskSpec:
    """A task a module wants created for a stage."""

    engine: str
    target: dict[str, Any] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class PlanContext:
    """What a module may look at while planning a stage."""

    scan_id: int
    engagement_id: int
    target_url: str
    scope: list[str]
    settings: dict[str, Any]
    stage: ScanStage


@dataclass
class TaskContext:
    """What a module gets while running one task."""

    task_id: int
    scan_id: int
    engagement_id: int
    target_url: str
    scope: list[str]
    settings: dict[str, Any]
    engine: str
    target: dict[str, Any]
    params: dict[str, Any]
    cancel_event: threading.Event
    run_tool: Callable[..., dict[str, Any]]
    log: Callable[[str], None]

    def check_cancelled(self) -> None:
        if self.cancel_event.is_set():
            raise TaskCancelled


class Module(Protocol):
    name: ClassVar[str]
    label: ClassVar[str]

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        """Tasks for `ctx.stage`; an empty list means nothing to do in that stage."""

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        """Run one task and return a JSON-serializable summary.

        Raise TaskCancelled, TransientTaskError, or TaskBlocked to report those outcomes;
        any other exception marks the task failed without failing the scan (PRD F-16).
        """
