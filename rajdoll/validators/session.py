"""Validator for session cookies without security attributes (TRD 6.3).

`cookie_flags`: the page that set the cookie is fetched again in the same way (without a session,
or with the account's session), twice; each time it must set the same cookie still lacking
HttpOnly, Secure (on HTTPS), or SameSite.
"""

from __future__ import annotations

from typing import Any

from rajdoll.modules import authz_checks, httpkit
from rajdoll.modules.authz_checks import Target
from rajdoll.modules.base import Exchange, TaskContext, Verdict
from rajdoll.modules.session_management import cookie_issues
from rajdoll.validators.base import base_url, validator

ROUNDS = 2


@validator("cookie_flags")
def cookie_flags(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    poc = finding["poc"]
    params = poc.get("validator_params") or {}
    name = str(params.get("cookie") or finding.get("parameter") or "")
    if not name:
        return Verdict(False, (), "PoC tanpa nama cookie; perlu cek manual.")
    account = poc.get("account")
    headers = ctx.session_headers(account) if account else {}
    if account and not headers:
        return Verdict(False, (), f"Sesi {account} tidak tersedia; perlu cek manual.")
    url = base_url(ctx, finding).rstrip("/") + str(poc.get("path", "/"))
    mask = f"[sesi {account}]" if account else httpkit.MASK
    evidence: list[Exchange] = []
    missing: tuple[str, ...] = ()
    with ctx.http("validator") as client:
        for _ in range(ROUNDS):
            ctx.check_cancelled()
            fetched = authz_checks.send(client, Target(url), headers, mask, "ulang validasi")
            evidence.append(fetched.exchange)
            issue = next((i for i in cookie_issues(fetched, url, {name}) if i.name == name), None)
            if issue is None:
                note = f"Cookie {name} tidak lagi dibuat tanpa atribut keamanan; perlu cek manual."
                return Verdict(False, tuple(evidence), note)
            missing = issue.missing
    note = f"Cookie sesi {name} dibuat tanpa {', '.join(missing)} (terulang {ROUNDS} kali)."
    return Verdict(True, tuple(evidence), note)
