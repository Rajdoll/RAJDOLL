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
        _load()
        return [
            TaskSpec(f"validator:{f['vuln_type']}", {"finding_id": f["id"]})
            for f in ctx.findings
            if f["vuln_type"] in VALIDATORS
        ]

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        _load()
        finding = ctx.finding(int(ctx.target["finding_id"]))
        if not finding:
            return {"skipped": "finding no longer exists"}
        verdict = VALIDATORS[finding["vuln_type"]](ctx, finding)
        ctx.record_verdict(finding["id"], verdict)
        state = "terkonfirmasi" if verdict.confirmed else "perlu cek manual"
        ctx.log(f"{finding['vuln_type']} #{finding['id']}: {state}. {verdict.note or ''}".strip())
        return {"finding_id": finding["id"], "confirmed": verdict.confirmed, "note": verdict.note}


def _load() -> None:
    """Import the validator modules so they register themselves."""
    from rajdoll.validators import injection  # noqa: F401
