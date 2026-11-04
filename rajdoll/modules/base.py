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
class EndpointSeen:
    """An endpoint a module observed; the engine normalizes and stores it (BSD 4.4)."""

    method: str
    url: str
    source: str  # EndpointSource value
    query_params: tuple[str, ...] = ()
    body_params: tuple[dict[str, str], ...] = ()  # {"name", "location": query|form|json|multipart}
    content_type: str | None = None


@dataclass(frozen=True)
class Exchange:
    """One HTTP request and its response as raw text: the unit of evidence (BSD 6.3)."""

    request: str
    response: str | None
    status: int | None
    note: str | None = None


@dataclass(frozen=True)
class Candidate:
    """A possible vulnerability a module found; the engine stores it as a finding (BSD 6.1)."""

    vuln_type: str  # key of rajdoll.data.vuln_types.CATALOG
    method: str
    url: str  # the URL that was tested
    parameter: str | None
    poc: dict[str, Any]  # BSD 6.2: method, path, query, headers, body, body_encoding, ...
    evidence: tuple[Exchange, ...] = ()
    note: str | None = None


@dataclass(frozen=True)
class Verdict:
    """A validator's answer for one finding (TRD 6.3)."""

    confirmed: bool
    evidence: tuple[Exchange, ...] = ()
    note: str | None = None


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
    # The engagement's endpoint inventory, from PLANNING on (dicts of BSD 4.4 columns + "url").
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    has_session: bool = False
    # Labels of the engagement's target accounts, in the order they were added ("Akun A", ...).
    accounts: list[str] = field(default_factory=list)
    # The engagement's session-check URL (a page only a logged-in account can open), if set.
    session_check_url: str | None = None
    # Findings of this scan that still need validation (VALIDATION stage): {"id", "vuln_type"};
    # all findings the scan saw (AI_TRIAGE stage): {"id", "vuln_type", "title"}.
    findings: list[dict[str, Any]] = field(default_factory=list)
    # Whether the scan may use the LLM (its settings snapshot); off means rule-based fallbacks.
    llm_enabled: bool = False


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
    # Store endpoints in the engagement inventory; returns how many were new.
    add_endpoints: Callable[[list[EndpointSeen]], int] = lambda _seen: 0
    # Merge facts into scan.recon_summary (lists are merged without duplicates).
    add_recon: Callable[[dict[str, Any]], None] = lambda _data: None
    # httpx.Client through the egress proxy as `task.<id>.<purpose>`, for custom checks.
    http: Callable[[str], Any] = lambda _purpose: None
    # Session headers (Cookie and others) of a target account; the first account by default.
    session_headers: Callable[[str | None], dict[str, str]] = lambda _label=None: {}
    # The username the assessor gave for an account ("" when none); decrypted at run time so
    # it never lands in a task's plaintext target.
    account_username: Callable[[str], str] = lambda _label: ""
    # Store a candidate finding (deduplicated by fingerprint); returns the finding id.
    report_candidate: Callable[[Candidate], int] = lambda _candidate: 0
    # A finding for validators: {"id", "vuln_type", "parameter", "url", "poc"} (PoC decrypted).
    finding: Callable[[int], dict[str, Any]] = lambda _id: {}
    # Store a validator's verdict and its evidence.
    record_verdict: Callable[[int, Verdict], None] = lambda _id, _verdict: None
    # Run an LLM task for this task's scan (rajdoll/llm/gateway.py): llm(task, messages,
    # finding_id=..., endpoint_id=...) -> LlmOutcome, or None without an LLM. Callers always
    # have a rule-based fallback for an outcome that is None or not ok (TRD P2).
    llm: Callable[..., Any] = lambda *_args, **_kwargs: None
    # Add LLM tags to an inventory endpoint (never one the assessor tagged); True if changed.
    tag_endpoint: Callable[[int, list[str]], bool] = lambda _id, _tags: False
    # Store extra evidence of a finding (for example `verification_round`).
    add_evidence: Callable[[int, list[Exchange], str], None] = lambda _id, _ex, _kind: None
    # Merge AI notes into a finding (`verification_rounds` are appended, the rest replaced).
    save_llm_notes: Callable[[int, dict[str, Any]], None] = lambda _id, _notes: None

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
