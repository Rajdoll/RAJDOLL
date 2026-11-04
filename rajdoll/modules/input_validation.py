"""Input Validation (WSTG-INPV), first increment: SQLi, reflected XSS, command injection, SSTI,
and SSRF with RAJDOLL's own probes (IPD F6). sqlmap, dalfox, commix, and nuclei DAST join in F6b.

Testing stage: one task per endpoint the plan assigns to Input Validation; every parameter of
the endpoint is probed. Hits become candidate findings (`needs_manual_check`); the validation
stage confirms them.
"""

from __future__ import annotations

from typing import Any, ClassVar

from rajdoll.core.enums import ScanStage
from rajdoll.modules import httpkit, injection_checks
from rajdoll.modules.base import Candidate, PlanContext, TaskContext, TaskSpec

MAX_ENDPOINTS = 200


class InputValidation:
    name: ClassVar[str] = "input_validation"
    label: ClassVar[str] = "Input Validation"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage != ScanStage.TESTING:
            return []
        specs = []
        for endpoint in ctx.endpoints:
            if self.name not in endpoint.get("modules", []):
                continue
            if not httpkit.injections(endpoint):
                continue
            specs.append(
                TaskSpec(
                    "custom:inpv",
                    {
                        "endpoint_id": endpoint["id"],
                        "method": endpoint["method"],
                        "url": endpoint["url"],
                        "query_params": endpoint.get("query_params", []),
                        "body_params": endpoint.get("body_params", []),
                        "content_type": endpoint.get("content_type"),
                    },
                )
            )
        return specs[:MAX_ENDPOINTS]

    def run(self, ctx: TaskContext) -> dict[str, Any]:
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
