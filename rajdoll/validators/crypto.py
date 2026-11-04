"""Validators for Weak Cryptography findings (TRD 6.3).

TLS findings (`weak_tls_protocol`, `weak_cipher`, `certificate_problem`, `tls_vulnerability`):
a second sslyze scan of the same host and port must report at least one of the same details.
`cleartext_credentials`: a failed login over HTTP, sent twice, is answered without a redirect to
HTTPS both times.
"""

from __future__ import annotations

from typing import Any

from rajdoll.modules import weak_cryptography
from rajdoll.modules.base import Exchange, TaskContext, Verdict
from rajdoll.validators.base import base_url, validator

ROUNDS = 2


def _tls(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    params = finding["poc"].get("validator_params") or {}
    host, port = params.get("host"), params.get("port")
    if not host or not port:
        return Verdict(False, (), "PoC tanpa host dan port TLS; perlu cek manual.")
    result = ctx.run_tool(
        "sslyze", {"host": host, "port": int(port)}, timeout_s=weak_cryptography.SSLYZE_TIMEOUT_S
    )
    normalized = result.get("normalized") or {}
    if result.get("status") != "completed" or not normalized.get("connected"):
        return Verdict(False, (), "Pemindaian TLS kedua gagal; perlu cek manual.")
    vuln_type = finding["vuln_type"]
    current = weak_cryptography.tls_issues(normalized).get(vuln_type, [])
    still = [d for d in params.get("details") or [] if d in current]
    label = weak_cryptography.DETAIL_LABELS[vuln_type]
    note = f"{label}: {', '.join(still or current)}."
    exchange = weak_cryptography.tls_exchange(host, int(port), normalized, "pemindaian kedua")
    if still:
        return Verdict(True, (exchange,), f"{note} Terulang pada pemindaian kedua.")
    return Verdict(False, (exchange,), "Pemindaian kedua tidak lagi menunjukkannya; cek manual.")


for _kind in weak_cryptography.DETAIL_LABELS:
    validator(_kind)(_tls)


@validator("cleartext_credentials")
def cleartext_credentials(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    poc = finding["poc"]
    params = poc.get("validator_params") or {}
    endpoint = {
        "method": poc.get("method", "POST"),
        "url": base_url(ctx, finding).rstrip("/") + str(poc.get("path", "/")),
        "body_params": params.get("body_params") or [],
    }
    evidence: list[Exchange] = []
    with ctx.http("validator") as client:
        for _ in range(ROUNDS):
            ctx.check_cancelled()
            outcome = weak_cryptography.login_over_http(client, endpoint)
            if outcome is None:
                return Verdict(False, (), "Endpoint bukan login lewat HTTP; perlu cek manual.")
            evidence.append(outcome[1])
            if not outcome[0]:
                return Verdict(False, tuple(evidence), "Login kini dialihkan ke HTTPS.")
    note = f"Login dijawab lewat HTTP tanpa dialihkan ke HTTPS ({ROUNDS} kali)."
    return Verdict(True, tuple(evidence), note)
