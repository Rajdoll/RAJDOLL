"""Input Validation (WSTG-INPV): SQLi, reflected XSS, command injection, SSTI, and SSRF (IPD F6).

Testing stage, per endpoint the plan assigns to Input Validation:
- `custom:inpv`: RAJDOLL's own probes on every parameter (rajdoll/modules/injection_checks.py);
- `sqlmap`, `commix`, `dalfox`: the tools on every query, form, and JSON parameter
  (rajdoll/modules/injection_tools.py);
and `nuclei:dast` tasks that run the pinned DAST templates over batches of endpoints.

Hits become candidate findings (`needs_manual_check`); a tool and a probe that find the same
weakness add evidence to one finding (same fingerprint). The validation stage confirms them.
"""

from __future__ import annotations

from typing import Any, ClassVar

from rajdoll.core.enums import ScanStage
from rajdoll.modules import httpkit, injection_checks, injection_tools
from rajdoll.modules.base import Candidate, PlanContext, TaskContext, TaskSpec

MAX_ENDPOINTS = 200
NUCLEI_BATCH = 50
TOOL_ENGINES = ("sqlmap", "commix", "dalfox")


class InputValidation:
    name: ClassVar[str] = "input_validation"
    label: ClassVar[str] = "Input Validation"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage != ScanStage.TESTING:
            return []
        specs: list[TaskSpec] = []
        batch: list[dict[str, Any]] = []
        chosen = [
            e for e in ctx.endpoints if self.name in e.get("modules", []) and httpkit.injections(e)
        ][:MAX_ENDPOINTS]
        for endpoint in chosen:
            target = {
                "endpoint_id": endpoint["id"],
                "method": endpoint["method"],
                "url": endpoint["url"],
                "query_params": endpoint.get("query_params", []),
                "body_params": endpoint.get("body_params", []),
                "content_type": endpoint.get("content_type"),
            }
            specs.append(TaskSpec("custom:inpv", target))
            if injection_tools.tool_points(target):
                specs += [TaskSpec(engine, target) for engine in TOOL_ENGINES]
                batch.append(target)
        for start in range(0, len(batch), NUCLEI_BATCH):
            chunk = batch[start : start + NUCLEI_BATCH]
            specs.append(TaskSpec("nuclei:dast", {"endpoints": chunk}))
        return specs

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        if ctx.engine == "custom:inpv":
            return self._run_probes(ctx)
        if ctx.engine == "nuclei:dast":
            found = list(injection_tools.nuclei_dast(ctx, list(ctx.target["endpoints"])))
        elif ctx.engine in TOOL_ENGINES:
            found = list(getattr(injection_tools, ctx.engine)(ctx, dict(ctx.target)))
        else:
            raise ValueError(f"unknown engine {ctx.engine}")
        reported = []
        for item in found:
            ctx.report_candidate(item.candidate)
            reported.append(f"{item.candidate.vuln_type}:{item.point.parameter}")
        if reported:
            ctx.log(f"{ctx.engine}: kandidat {', '.join(reported)}")
        return {"candidates": reported}

    def _run_probes(self, ctx: TaskContext) -> dict[str, Any]:
        endpoint = dict(ctx.target)
        headers = ctx.session_headers(None)
        reported: list[str] = []
        with ctx.http("inpv") as client:
            root = client.get(ctx.target_url, headers=headers)
            marker = injection_checks.page_marker(root.text)
            for point in httpkit.injections(endpoint):
                ctx.check_cancelled()
                hits = self._probe(ctx, client, point, headers, marker)
                for hit in hits:
                    ctx.report_candidate(
                        Candidate(
                            vuln_type=hit.vuln_type,
                            method=point.method,
                            url=point.url,
                            parameter=point.parameter,
                            poc=point.poc(hit.payload, hit.vuln_type, **hit.params),
                            evidence=tuple(hit.evidence),
                            note=hit.note,
                        )
                    )
                    reported.append(f"{hit.vuln_type}:{point.parameter}")
        if reported:
            ctx.log(f"{endpoint['method']} {endpoint['url']}: kandidat {', '.join(reported)}")
        return {"candidates": reported}

    def _probe(
        self,
        ctx: TaskContext,
        client: Any,
        point: httpkit.Injection,
        headers: dict[str, str],
        marker: str,
    ) -> list[injection_checks.Hit]:
        def send(value: str, note: str | None) -> Any:
            ctx.check_cancelled()
            return point.send(client, value, headers, note)

        defaults = point.query if point.location == "query" else point.body
        base_value = defaults.get(point.parameter) or httpkit.default_value(point.parameter)
        baseline, _ = send(base_value, "nilai normal")
        hits: list[injection_checks.Hit] = []
        sqli = injection_checks.sqli_error(send, base_value, baseline.text)
        hits.append(sqli or injection_checks.sqli_boolean(send, base_value))
        hits.append(injection_checks.ssti(send, base_value, baseline.text))
        hits.append(injection_checks.cmdi(send, base_value))
        hits.append(injection_checks.xss(send, base_value, ctx.target.get("content_type")))
        hits.append(injection_checks.ssrf(send, point, ctx.target_url, marker))
        found = [hit for hit in hits if hit is not None]
        for hit in found:
            hit.params["base"] = base_value  # validators start from the same normal value
        return found
