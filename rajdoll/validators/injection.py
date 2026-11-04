"""Validators for SQLi, reflected XSS, command injection, SSTI, and SSRF (TRD 6.3).

Each re-sends the finding's request through the egress proxy with fresh values and confirms only
on deterministic evidence: the SQL error differential or the boolean differential reproduces;
a new arithmetic expression is computed by the target (SSTI, command injection); the server fetches
the target's own page again (SSRF); the payload runs in Chromium (XSS).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from rajdoll.modules import httpkit, injection_checks
from rajdoll.modules.base import Exchange, TaskContext, Verdict
from rajdoll.validators.base import base_url, validator

XSS_PAYLOADS = (
    "\"><img src=x onerror=alert('{m}')>",
    "<script>alert('{m}')</script>",
    "'><svg onload=alert('{m}')>",
    "</textarea><script>alert('{m}')</script>",
)


def _setup(ctx: TaskContext, finding: dict[str, Any]) -> tuple[httpkit.Injection, str]:
    poc = finding["poc"]
    point = httpkit.from_poc(base_url(ctx, finding), poc)
    base = str((poc.get("validator_params") or {}).get("base", "rajdoll"))
    return point, base


def _repeat(ctx: TaskContext, finding: dict[str, Any], check: Any, times: int = 2) -> Verdict:
    point, base = _setup(ctx, finding)
    headers = ctx.session_headers(None)
    evidence: list[Exchange] = []
    with ctx.http("validator") as client:

        def send(value: str, note: str | None) -> Any:
            ctx.check_cancelled()
            return point.send(client, value, headers, note)

        baseline, _ = send(base, "nilai normal")
        hits = []
        for _ in range(times):
            hit = check(send, point, base, baseline.text)
            if hit is None:
                break
            hits.append(hit)
            evidence.extend(hit.evidence)
    if len(hits) == times:
        return Verdict(True, tuple(evidence), f"{hits[-1].note} (terulang {times} kali)")
    return Verdict(False, tuple(evidence), "Bukti tidak berulang; perlu cek manual.")


@validator("sqli")
def sqli(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    def check(send: Any, point: Any, base: str, baseline: str) -> Any:
        return injection_checks.sqli_error(send, base, baseline) or injection_checks.sqli_boolean(
            send, base
        )

    return _repeat(ctx, finding, check)


@validator("ssti")
def ssti(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    return _repeat(
        ctx,
        finding,
        lambda send, point, base, baseline: injection_checks.ssti(send, base, baseline),
    )


@validator("cmdi")
def cmdi(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    return _repeat(
        ctx, finding, lambda send, point, base, baseline: injection_checks.cmdi(send, base)
    )


@validator("ssrf")
def ssrf(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    headers = ctx.session_headers(None)
    with ctx.http("validator") as client:
        marker = injection_checks.page_marker(client.get(ctx.target_url, headers=headers).text)

    def check(send: Any, point: Any, base: str, baseline: str) -> Any:
        return injection_checks.ssrf(send, point, ctx.target_url, marker)

    return _repeat(ctx, finding, check)


@validator("xss_reflected")
def xss_reflected(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    point, base = _setup(ctx, finding)
    if point.method not in ("GET", "POST") or point.body_location in ("json", "multipart"):
        # A browser navigation can only send a GET or a form POST.
        return Verdict(False, (), "Reflected XSS lewat body JSON/multipart perlu cek manual.")
    marker = injection_checks.nonce().upper()
    attempts = []
    for template in XSS_PAYLOADS:
        query, body = point.request_parts(base + template.format(m=marker))
        url = point.url + ("?" + urlencode(query) if query else "")
        if point.method == "GET":
            attempts.append({"method": "GET", "url": url})
        else:
            attempts.append({"method": "POST", "url": url, "form": body})
    result = ctx.run_tool(
        "xss_check",
        {"attempts": attempts, "marker": marker, "headers": ctx.session_headers(None)},
        timeout_s=180,
    )
    if result.get("status") != "completed":
        return Verdict(False, (), f"Chromium tidak bisa dijalankan: {result.get('status')}")
    normalized = result.get("normalized", {})
    evidence = []
    for attempt in normalized.get("attempts", []):
        sent = attempts[attempt["attempt"]]
        request = f"{sent['method']} {sent['url']}"
        if sent.get("form"):
            request += "\n\n" + urlencode(sent["form"])
        dialogs = attempt.get("dialogs") or []
        observed = "Dialog di Chromium: " + (", ".join(dialogs) if dialogs else "tidak ada")
        if attempt.get("error"):
            observed += f"\nGalat Chromium: {attempt['error']}"
        note = "dijalankan di Chromium lewat egress proxy"
        evidence.append(Exchange(request, observed, attempt.get("status"), note))
    if normalized.get("executed"):
        return Verdict(True, tuple(evidence), f"Payload menjalankan alert('{marker}') di Chromium.")
    return Verdict(False, tuple(evidence), "Payload tidak tereksekusi di Chromium.")
