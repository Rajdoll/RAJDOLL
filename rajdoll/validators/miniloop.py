"""Verification mini-loop for findings the validators did not confirm (TRD 6.4, PRD F-20).

Up to three rounds: the LLM proposes 1–3 follow-up requests (and possibly a better normal value
for the tested parameter); RAJDOLL sends them through the egress proxy (scope and rate limit
apply) to the finding's own host only, never to a path matching the engagement's exclusion
patterns; their exchanges become `verification_round` evidence; then the deterministic validator
runs again, with the proposed normal value if there is one. Only the validator can confirm; the
LLM's text never does (TRD P3). Every round is kept in the finding's AI notes.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit

from rajdoll.llm import tasks
from rajdoll.llm.context import data_block, trim_response
from rajdoll.modules import httpkit
from rajdoll.modules.base import Exchange, TaskContext, Verdict

MAX_ROUNDS = 3


def _evidence_text(rows: list[dict[str, Any]]) -> str:
    return (
        "\n\n".join(
            data_block(
                f"evidence {row.get('note') or ''}",
                (row.get("request") or "")[:1200]
                + "\n\n"
                + trim_response(row.get("response"), [], 900),
            )
            for row in rows[-2:]
        )
        or "-"
    )


def _excluded(path: str, patterns: list[str]) -> bool:
    lowered = path.lower()
    return any(p and re.search(re.escape(p.lower()), lowered) for p in patterns)


def _with_base(finding: dict[str, Any], base: str) -> dict[str, Any]:
    poc = dict(finding.get("poc") or {})
    params = {**(poc.get("validator_params") or {}), "base": base}
    return {**finding, "poc": {**poc, "validator_params": params}}


def run(
    ctx: TaskContext,
    finding: dict[str, Any],
    verdict: Verdict,
    validate: Any,
) -> Verdict:
    """The mini-loop after `verdict` (not confirmed). `validate(ctx, finding)` is the validator
    chain; returns the final verdict. Without an LLM the verdict is returned unchanged."""
    from rajdoll.validators.base import base_url

    root = base_url(ctx, finding)
    host = urlsplit(root).netloc
    patterns = list(ctx.settings.get("excluded_patterns") or [])
    evidence_rows = list(finding.get("evidence") or [])
    current = finding
    previous: list[dict[str, Any]] = []
    rounds: list[dict[str, Any]] = []
    gathered: list[Exchange] = list(verdict.evidence)
    note = verdict.note
    for number in range(1, MAX_ROUNDS + 1):
        ctx.check_cancelled()
        messages = tasks.messages(
            "verification_step",
            title=finding.get("title", ""),
            vuln_type=finding["vuln_type"],
            parameter=finding.get("parameter"),
            round=number,
            max_rounds=MAX_ROUNDS,
            validator_note=note,
            evidence=_evidence_text(evidence_rows),
            previous=previous,
        )
        outcome = ctx.llm(tasks.VERIFY, messages, finding_id=finding["id"])
        if outcome is None or not outcome.ok:
            break
        step = outcome.value
        sent: list[dict[str, Any]] = []
        exchanges: list[Exchange] = []
        with ctx.http("verification") as client:
            for request in step.requests:
                if _excluded(request.path, patterns):
                    sent.append({"method": request.method, "path": request.path,
                                 "skipped": "cocok dengan pola endpoint berisiko"})  # fmt: skip
                    continue
                ctx.check_cancelled()
                response = client.request(
                    request.method,
                    f"{urlsplit(root).scheme}://{host}{request.path}",
                    params=request.query or None,
                    data=request.body or None,
                    headers=ctx.session_headers(None),
                )
                exchanges.append(
                    Exchange(
                        httpkit.raw_request(response.request),
                        httpkit.raw_response(response),
                        response.status_code,
                        f"putaran verifikasi {number}: {request.expect[:120]}",
                    )
                )
                sent.append({"method": request.method, "path": request.path,
                             "status": response.status_code})  # fmt: skip
        if exchanges:
            ctx.add_evidence(finding["id"], exchanges, "verification_round")
            gathered += exchanges
            evidence_rows = [
                {"note": e.note, "request": e.request, "response": e.response} for e in exchanges
            ]
        if step.base_value:
            current = _with_base(current, step.base_value)
        again = validate(ctx, current)
        record = {
            "round": number,
            "requests": sent,
            "base_value": step.base_value,
            "reasoning": step.reasoning,
            "validator_note": again.note if again else None,
            "confirmed": bool(again and again.confirmed),
        }
        rounds.append(record)
        if again is not None and again.confirmed:
            ctx.save_llm_notes(finding["id"], {"verification_rounds": rounds})
            return Verdict(
                True,
                tuple(gathered) + tuple(again.evidence),
                f"Terkonfirmasi validator setelah putaran verifikasi {number}: {again.note}",
            )
        note = again.note if again else note
        previous.append(
            {"round": number, "summary": f"{len(sent)} request; validator: {note or '-'}"}
        )
    if rounds:
        ctx.save_llm_notes(finding["id"], {"verification_rounds": rounds})
        note = f"{verdict.note or ''} Mini-loop {len(rounds)} putaran tanpa konfirmasi.".strip()
        return replace(verdict, evidence=tuple(gathered), note=note)
    return verdict
