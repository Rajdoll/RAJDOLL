"""Validator for error messages that leak internal details (TRD 6.3).

`error_disclosure`: the finding's test value is sent again with the normal value, twice; each
round the error response must show one of the runtime patterns (stack trace, debug page, server
file path) that the normal response does not. A not-found finding requests a new random path
each round. Candidates reported only on the LLM's judgement match no pattern and stay
`needs_manual_check`.
"""

from __future__ import annotations

from typing import Any

from rajdoll.modules import error_checks, httpkit
from rajdoll.modules.base import Exchange, TaskContext, Verdict
from rajdoll.modules.config_checks import fetch, origin_of
from rajdoll.validators.base import base_url, validator

ROUNDS = 2


@validator("error_disclosure")
def error_disclosure(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    poc = finding["poc"]
    params = poc.get("validator_params") or {}
    root = base_url(ctx, finding)
    evidence: list[Exchange] = []
    found: list[str] = []
    with ctx.http("validator") as client:
        for _ in range(ROUNDS):
            ctx.check_cancelled()
            if params.get("source") == "not_found":
                origin = origin_of(root)
                normal = fetch(client, origin + "/", "halaman root")
                error = fetch(client, origin + error_checks.random_path(), "path acak")
                normal_text, error_text = normal.text, error.text
                evidence.append(error.exchange)
            else:
                point = httpkit.from_poc(root, poc)
                headers = ctx.session_headers(None)
                value = (poc.get("query") or {}).get(point.parameter)
                if value is None:
                    value = (poc.get("body") or {}).get(point.parameter, "")
                base = str(params.get("base") or httpkit.default_value(point.parameter))
                normal_response, _ = point.send(client, base, headers, "nilai normal")
                error_response, exchange = point.send(client, str(value), headers, "nilai uji")
                normal_text, error_text = normal_response.text, error_response.text
                evidence.append(exchange)
            found = error_checks.new_leaks(error_text, normal_text)
            if not found:
                note = "Respons error tidak lagi membocorkan detail internal; perlu cek manual."
                return Verdict(False, tuple(evidence), note)
    note = f"Respons error memunculkan {', '.join(found)} (terulang {ROUNDS} kali)."
    return Verdict(True, tuple(evidence), note)
