"""Built-in LLM steps of the pipeline (TRD 5.2): endpoint tags and triage notes.

- PLANNING: `classify_endpoint` adds tags to inventory endpoints in batches (PRD F-17). The rule
  tags stay; an endpoint the assessor tagged is never touched; without an LLM the rule tags are
  the plan (fallback).
- AI_TRIAGE: `triage_finding` writes AI notes for each finding the scan saw (PRD F-21):
  explanation, impact, fix, manual-test suggestions, and possible duplicates among the scan's
  findings. Notes are marked as AI output in the UI and never change a finding's status.

The engine plans this module for every scan; it plans nothing when the scan's LLM is off.
"""

from __future__ import annotations

from typing import Any, ClassVar
from urllib.parse import urlsplit

from rajdoll.core.enums import ScanStage
from rajdoll.llm import tasks
from rajdoll.llm.context import data_block, trim_response
from rajdoll.modules.base import PlanContext, TaskContext, TaskSpec

CLASSIFY_BATCH = 8
MAX_TRIAGE = 100


def _ok(outcome: Any) -> bool:
    return outcome is not None and getattr(outcome, "ok", False)


class AiModule:
    name: ClassVar[str] = "ai"
    label: ClassVar[str] = "Asisten AI"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if not ctx.llm_enabled:
            return []
        if ctx.stage == ScanStage.PLANNING:
            candidates = [
                {
                    "id": e["id"],
                    "method": e["method"],
                    "path": urlsplit(e["url"]).path or "/",
                    "query_params": list(e.get("query_params") or []),
                    "body_params": [p.get("name") for p in e.get("body_params") or []],
                    "tags": list(e.get("tags") or []),
                }
                for e in ctx.endpoints
                if not e.get("excluded") and e.get("tag_source") != "user"
            ]
            return [
                TaskSpec("llm:classify_endpoint", {"endpoints": candidates[i : i + CLASSIFY_BATCH]})
                for i in range(0, len(candidates), CLASSIFY_BATCH)
            ]
        if ctx.stage == ScanStage.AI_TRIAGE:
            chosen = ctx.findings[:MAX_TRIAGE]
            others = [{"id": f["id"], "title": f["title"]} for f in chosen]
            return [
                TaskSpec(
                    "llm:triage_finding",
                    {"finding_id": f["id"], "others": [o for o in others if o["id"] != f["id"]]},
                )
                for f in chosen
            ]
        return []

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        if ctx.engine == "llm:classify_endpoint":
            return self._classify(ctx)
        if ctx.engine == "llm:triage_finding":
            return self._triage(ctx)
        raise ValueError(f"unknown engine {ctx.engine}")

    # -- classify_endpoint ----------------------------------------------------------------

    def _classify(self, ctx: TaskContext) -> dict[str, Any]:
        endpoints = list(ctx.target["endpoints"])
        outcome = ctx.llm(tasks.CLASSIFY, tasks.messages("classify_endpoint", endpoints=endpoints))
        if not _ok(outcome):
            status = getattr(outcome, "status", "none")
            return {"fallback": "rule_tags", "status": status, "endpoints": len(endpoints)}
        tagged = []
        for item in outcome.value.endpoints:
            if item.index >= len(endpoints) or not item.tags:
                continue
            endpoint = endpoints[item.index]
            if ctx.tag_endpoint(endpoint["id"], list(item.tags)):
                tagged.append(endpoint["id"])
        if tagged:
            ctx.log(f"LLM menambah tanda pada {len(tagged)} endpoint.")
        return {"tagged": tagged, "status": outcome.status}

    # -- triage_finding -------------------------------------------------------------------

    def _triage(self, ctx: TaskContext) -> dict[str, Any]:
        finding_id = int(ctx.target["finding_id"])
        finding = ctx.finding(finding_id)
        if not finding:
            return {"skipped": "finding no longer exists"}
        others = list(ctx.target.get("others") or [])
        evidence = "\n\n".join(
            data_block(
                f"evidence {row.get('kind')} {row.get('note') or ''}",
                (row.get("request") or "")[:1500]
                + "\n\n"
                + trim_response(row.get("response"), [], max_chars=1200),
            )
            for row in (finding.get("evidence") or [])[-2:]
        )
        endpoint = finding.get("endpoint_label")
        messages = tasks.messages(
            "triage_finding",
            finding=finding,
            endpoint=endpoint,
            evidence=evidence or "-",
            others=others,
        )
        outcome = ctx.llm(tasks.TRIAGE, messages, finding_id=finding_id)
        if not _ok(outcome):
            return {"finding_id": finding_id, "fallback": "no_notes",
                    "status": getattr(outcome, "status", "none")}  # fmt: skip
        known = {o["id"] for o in others}
        value = outcome.value
        ctx.save_llm_notes(
            finding_id,
            {
                "explanation": value.explanation,
                "impact": value.impact,
                "fix": value.fix,
                "manual_test_suggestions": value.manual_test_suggestions,
                "possible_duplicates": [i for i in value.possible_duplicates if i in known],
            },
        )
        return {"finding_id": finding_id, "status": outcome.status}
