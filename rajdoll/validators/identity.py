"""Validator for account enumeration (TRD 6.3).

`account_enumeration`: with two new unknown usernames, which must be answered alike, the
finding's username (from the encrypted PoC) is still answered differently. One round: each round
costs the real account a failed login, and the detection already made the first comparison.
"""

from __future__ import annotations

from typing import Any

from rajdoll.modules import identity_checks
from rajdoll.modules.base import TaskContext, Verdict
from rajdoll.validators.base import base_url, validator


@validator("account_enumeration")
def account_enumeration(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    poc = finding["poc"]
    params = poc.get("validator_params") or {}
    username = str(params.get("username") or "")
    form = identity_checks.login_form_from_poc(base_url(ctx, finding), poc)
    if not username or not form.user_field or not form.password_field:
        return Verdict(False, (), "PoC tanpa username atau field login; perlu cek manual.")
    with ctx.http("validator") as client:
        ok, evidence = identity_checks.still_enumerable(client, form, username)
    if ok:
        note = "Username terdaftar tetap dijawab berbeda dari dua username acak (terulang)."
        return Verdict(True, tuple(evidence), note)
    return Verdict(False, tuple(evidence), "Jawaban login tidak lagi berbeda; perlu cek manual.")
