"""Second runs of the tool that found a finding (TRD 6.3).

Used after the vulnerability type's own validator did not confirm: sqlmap confirms SQL injection
with the technique it reported, commix repeats its command-injection check, and a nuclei template
must match the same parameter again ("ulangan kedua"). A nuclei XSS template only checks that the
payload is reflected, so it never confirms XSS; Chromium does (xss_check).
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from rajdoll.modules import httpkit, injection_tools
from rajdoll.modules.base import Exchange, TaskContext, Verdict
from rajdoll.validators.base import base_url

# Types a nuclei template match may not confirm on its own.
NUCLEI_NEVER_CONFIRMS = {"xss_reflected"}


def _setup(ctx: TaskContext, finding: dict[str, Any]) -> tuple[httpkit.Injection, str, dict]:
    poc = finding["poc"]
    params = poc.get("validator_params") or {}
    point = httpkit.from_poc(base_url(ctx, finding), poc)
    base = str(params.get("base", "rajdoll"))
    query, body = point.request_parts(base)
    return replace(point, query=query, body=body), base, params


def _resend(ctx: TaskContext, point: httpkit.Injection, value: str, note: str) -> list[Exchange]:
    with ctx.http("validator") as client:
        _, exchange = point.send(client, value, ctx.session_headers(None), note)
    return [exchange]


def _tool_params(point: httpkit.Injection, ctx: TaskContext) -> dict[str, Any]:
    return {
        "request": point.request_spec(),
        "parameter": point.parameter,
        "location": point.tool_location,
        "headers": ctx.session_headers(None),
    }


def sqlmap(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    point, _base, params = _setup(ctx, finding)
    techniques = params.get("techniques") or "BEUST"
    run = {**_tool_params(point, ctx), "smart": False, "techniques": techniques}
    result = ctx.run_tool("sqlmap", run, timeout_s=injection_tools.SQLMAP_TIMEOUT_S)
    hits = [h for h in (result.get("normalized") or {}).get("candidates", []) if h.get("value")]
    if not hits:
        return Verdict(False, (), f"sqlmap tidak mengonfirmasi ulang ({result.get('status')}).")
    found = ", ".join(h["technique"] for h in hits)
    evidence = _resend(ctx, point, hits[0]["value"], f"ulangan sqlmap ({hits[0]['technique']})")
    return Verdict(True, tuple(evidence), f"sqlmap mengonfirmasi ulang: {found}.")


def commix(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    point, _base, _params = _setup(ctx, finding)
    timeout = injection_tools.COMMIX_TIMEOUT_S
    result = ctx.run_tool("commix", _tool_params(point, ctx), timeout_s=timeout)
    hits = [h for h in (result.get("normalized") or {}).get("candidates", []) if h.get("value")]
    if not hits:
        return Verdict(False, (), f"commix tidak mengonfirmasi ulang ({result.get('status')}).")
    technique = hits[0].get("technique")
    evidence = _resend(ctx, point, hits[0]["value"], f"ulangan commix ({technique})")
    return Verdict(True, tuple(evidence), f"commix mengonfirmasi ulang: {technique}.")


def nuclei(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    point, _base, params = _setup(ctx, finding)
    template = params.get("template")
    if not template:
        return Verdict(False, (), "PoC tidak menyebut template nuclei.")
    spec = point.request_spec()
    run = {
        "requests": [spec],
        "templates": [template],
        "dast": True,
        "headers": ctx.session_headers(None),
    }
    result = ctx.run_tool("nuclei", run, timeout_s=injection_tools.NUCLEI_TIMEOUT_S)
    points = {injection_tools.request_key(spec["url"], spec["query"]): [point]}
    for hit in (result.get("normalized") or {}).get("candidates", []):
        found = injection_tools.nuclei_hit(hit, points)
        if found and found.point.parameter == point.parameter:
            note = f"Template {hit.get('template_id')} cocok lagi pada ulangan kedua."
            return Verdict(True, found.candidate.evidence, note)
    return Verdict(False, (), f"Template {template} tidak cocok pada ulangan kedua.")


def rerun(ctx: TaskContext, finding: dict[str, Any]) -> Verdict | None:
    """The second run that applies to this finding, if any."""
    vuln_type = finding["vuln_type"]
    source = ((finding.get("poc") or {}).get("validator_params") or {}).get("source")
    if source == "sqlmap" and vuln_type == "sqli":
        return sqlmap(ctx, finding)
    if source == "commix" and vuln_type == "cmdi":
        return commix(ctx, finding)
    if source == "nuclei" and vuln_type not in NUCLEI_NEVER_CONFIRMS:
        return nuclei(ctx, finding)
    return None
