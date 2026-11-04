"""Error Handling (WSTG-ERRH) (IPD F8b).

Testing stage:
- `custom:errors`, one task per endpoint the plan assigns to Error Handling (endpoints with
  parameters): each parameter gets the error-inducing values of `error_checks.PAYLOADS`, with the
  account's session, and is compared with its normal value. The first parameter that leaks a
  stack trace, a debug page, or a server file path becomes the endpoint's candidate.
- `custom:not_found`, once per host: a random path that cannot exist, without a session.

A 5xx response that matches no pattern but differs from the normal one may be shown to the
LLM (`judge_response`, at most a few per task); its "ya" only reports a candidate, which the
pattern-based validator alone can confirm (TRD P3).
"""

from __future__ import annotations

from typing import Any, ClassVar

from rajdoll.core.enums import ScanStage
from rajdoll.llm import tasks
from rajdoll.modules import error_checks, httpkit
from rajdoll.modules.authz_checks import similarity
from rajdoll.modules.base import Candidate, PlanContext, TaskContext, TaskSpec
from rajdoll.modules.config_checks import fetch, origin_of

MAX_ENDPOINTS = 100
MAX_HOSTS = 5
MAX_LLM_QUESTIONS = 3
QUESTION = (
    "Respons A adalah jawaban aplikasi untuk nilai uji yang memicu error. Apakah respons ini "
    "membocorkan informasi internal, misalnya stack trace, path file di server, potongan kode "
    "atau query, nama tabel, atau konfigurasi?"
)


class ErrorHandling:
    name: ClassVar[str] = "error_handling"
    label: ClassVar[str] = "Error Handling"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage != ScanStage.TESTING:
            return []
        specs: list[TaskSpec] = []
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
            }
            specs.append(TaskSpec("custom:errors", target))
        origins = [origin_of(ctx.target_url)] + [
            f"{e['scheme']}://{e['host']}" for e in ctx.endpoints if not e.get("excluded")
        ]
        for origin in list(dict.fromkeys(origins))[:MAX_HOSTS]:
            specs.append(TaskSpec("custom:not_found", {"origin": origin}))
        return specs

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        if ctx.engine == "custom:errors":
            return self._errors(ctx)
        if ctx.engine == "custom:not_found":
            return self._not_found(ctx)
        raise ValueError(f"unknown engine {ctx.engine}")

    # -- parameters --------------------------------------------------------------------------------

    def _errors(self, ctx: TaskContext) -> dict[str, Any]:
        endpoint = dict(ctx.target)
        headers = ctx.session_headers(None)
        questions = 0
        with ctx.http("errors") as client:
            for point in httpkit.injections(endpoint):
                defaults = point.query if point.location == "query" else point.body
                base = defaults.get(point.parameter) or httpkit.default_value(point.parameter)
                ctx.check_cancelled()
                normal, normal_exchange = point.send(client, base, headers, "nilai normal")
                for name, payload in error_checks.PAYLOADS:
                    ctx.check_cancelled()
                    response, exchange = point.send(client, payload, headers, f"nilai uji: {name}")
                    found = error_checks.new_leaks(response.text, normal.text)
                    note = None
                    if found:
                        note = f"Nilai uji ({name}) memunculkan {', '.join(found)}."
                    elif (
                        response.status_code >= 500
                        and questions < MAX_LLM_QUESTIONS
                        and similarity(response.text, normal.text) < 0.9
                    ):
                        questions += 1
                        judgement = tasks.judge_response(
                            ctx.llm, QUESTION, exchange.request, response.text
                        )
                        if judgement.answer == "ya":
                            note = (
                                f"Nilai uji ({name}) memicu HTTP {response.status_code}. Penilaian "
                                f"LLM: {judgement.reason} (pola tidak cocok; perlu cek manual)."
                            )
                    if note is None:
                        continue
                    ctx.report_candidate(
                        Candidate(
                            vuln_type="error_disclosure",
                            method=point.method,
                            url=point.url,
                            parameter=point.parameter,
                            poc=point.poc(payload, "error_disclosure", base=base, patterns=found),
                            evidence=(normal_exchange, exchange),
                            note=note,
                        )
                    )
                    ctx.log(
                        f"{point.method} {point.url}: kandidat error_disclosure:{point.parameter}"
                    )
                    return {"candidates": [f"error_disclosure:{point.parameter}"]}
        return {"candidates": []}

    # -- not-found page ----------------------------------------------------------------------------

    def _not_found(self, ctx: TaskContext) -> dict[str, Any]:
        origin = ctx.target["origin"]
        with ctx.http("not_found") as client:
            normal = fetch(client, origin + "/", "halaman root")
            missing = fetch(client, origin + error_checks.random_path(), "path acak yang tidak ada")
        found = error_checks.new_leaks(missing.text, normal.text)
        if not found:
            return {"candidates": []}
        ctx.report_candidate(
            Candidate(
                vuln_type="error_disclosure",
                method="GET",
                url=origin + "/",
                parameter=None,
                poc={
                    "method": "GET",
                    "path": missing.response.request.url.path or "/",
                    "query": {},
                    "headers": {},
                    "body": None,
                    "body_encoding": "none",
                    "account": None,
                    "validator": "error_disclosure",
                    "validator_params": {"source": "not_found", "patterns": found},
                },
                evidence=(normal.exchange, missing.exchange),
                note=f"Halaman untuk path yang tidak ada memunculkan {', '.join(found)}.",
            )
        )
        return {"candidates": ["error_disclosure:/"]}
