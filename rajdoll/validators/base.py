"""Validation stage: one validator per vulnerability type (TRD 6.3).

The engine runs this built-in module in the VALIDATION stage for every finding of the scan that is
not confirmed yet. A validator re-sends requests through the egress proxy and decides
deterministically; the LLM never confirms a finding (TRD P3). What the validator does not confirm
stays `needs_manual_check` (and goes to the mini-loop in F7).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, ClassVar
from urllib.parse import urlsplit

from rajdoll.core.enums import ScanStage
from rajdoll.modules.base import PlanContext, TaskContext, TaskSpec, Verdict

Validator = Callable[[TaskContext, dict[str, Any]], Verdict]
VALIDATORS: dict[str, Validator] = {}


def validator(vuln_type: str) -> Callable[[Validator], Validator]:
    def register(func: Validator) -> Validator:
        VALIDATORS[vuln_type] = func
        return func

    return register


def base_url(ctx: TaskContext, finding: dict[str, Any] | None = None) -> str:
    """Where a PoC path is sent: the finding's endpoint host, else the scan target."""
    if finding and finding.get("base_url"):
        return str(finding["base_url"])
    parts = urlsplit(ctx.target_url)
    return f"{parts.scheme}://{parts.netloc}"


class ValidationModule:
    name: ClassVar[str] = "validation"
    label: ClassVar[str] = "Validasi"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage != ScanStage.VALIDATION:
            return []
        # Every finding gets a task: a type without its own validator may still be confirmed by
        # a second run of the tool that found it (rajdoll/validators/tools.py).
        return [
            TaskSpec(f"validator:{f['vuln_type']}", {"finding_id": f["id"]}) for f in ctx.findings
        ]

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        finding = ctx.finding(int(ctx.target["finding_id"]))
        if not finding:
            return {"skipped": "finding no longer exists"}
        verdict = validate(ctx, finding)
        if verdict is None:
            ctx.log(f"{finding['vuln_type']} #{finding['id']}: belum ada validator; cek manual.")
            return {"finding_id": finding["id"], "skipped": "no validator"}
        if not verdict.confirmed:
            # The LLM proposes follow-up requests; only the validator may confirm (TRD 6.4).
            from rajdoll.validators import miniloop

            verdict = miniloop.run(ctx, finding, verdict, _round_validator)
        ctx.record_verdict(finding["id"], verdict)
        state = "terkonfirmasi" if verdict.confirmed else "perlu cek manual"
        ctx.log(f"{finding['vuln_type']} #{finding['id']}: {state}. {verdict.note or ''}".strip())
        return {"finding_id": finding["id"], "confirmed": verdict.confirmed, "note": verdict.note}


def _round_validator(ctx: TaskContext, finding: dict[str, Any]) -> Verdict | None:
    """In a mini-loop round only the type's own (fast) validator runs, else the full chain."""
    _load()
    own = VALIDATORS.get(finding["vuln_type"])
    return own(ctx, finding) if own is not None else validate(ctx, finding)


def validate(ctx: TaskContext, finding: dict[str, Any]) -> Verdict | None:
    """The type's validator first; if it does not confirm, a second run of the finding's tool.

    None when nothing applies (the finding stays `needs_manual_check`).
    """
    _load()
    from rajdoll.validators import tools

    verdicts: list[Verdict] = []
    own = VALIDATORS.get(finding["vuln_type"])
    if own is not None:
        verdicts.append(own(ctx, finding))
    if not (verdicts and verdicts[0].confirmed):
        second = tools.rerun(ctx, finding)
        if second is not None:
            verdicts.append(second)
    if not verdicts:
        return None
    evidence = tuple(e for v in verdicts for e in v.evidence)
    decisive = next((v for v in verdicts if v.confirmed), None)
    if decisive is not None:
        return Verdict(True, evidence, decisive.note)
    return Verdict(False, evidence, " ".join(v.note or "" for v in verdicts).strip())


def _load() -> None:
    """Import the validator modules so they register themselves."""
    from rajdoll.validators import authentication, authorization, injection, session  # noqa: F401
