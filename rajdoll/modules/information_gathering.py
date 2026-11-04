"""Information Gathering (WSTG-INFO), first increment.

F4 only probes the target URL with httpx in the recon stage, so a real scan exercises the whole
path (engine → runner → egress proxy → audit log). Crawling, directory fuzzing, port scanning,
JavaScript analysis, and WAF detection arrive in F5.
"""

from typing import Any, ClassVar

from rajdoll.core.enums import ScanStage
from rajdoll.modules.base import PlanContext, TaskContext, TaskSpec, TransientTaskError


class InformationGathering:
    name: ClassVar[str] = "information_gathering"
    label: ClassVar[str] = "Information Gathering"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage != ScanStage.RECON:
            return []
        return [TaskSpec(engine="httpx", target={"urls": [ctx.target_url]})]

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        result = ctx.run_tool("httpx", {"urls": ctx.target["urls"]}, timeout_s=300)
        if result["status"] == "timeout":
            raise TransientTaskError("httpx timed out")
        if result["status"] != "completed":
            raise RuntimeError(f"httpx {result['status']}: {result.get('stderr_tail', '')[-300:]}")
        endpoints = result["normalized"].get("endpoints", [])
        technologies = result["normalized"].get("technologies", [])
        ctx.log(f"httpx: {len(endpoints)} endpoint menjawab, {len(technologies)} teknologi")
        return {"endpoints": endpoints, "technologies": technologies}
