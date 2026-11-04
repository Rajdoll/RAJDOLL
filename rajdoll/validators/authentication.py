"""Validators for the JWT weaknesses and missing login attempt limits (TRD 6.3).

JWT (`jwt_signature_not_verified`, `jwt_alg_none`, `jwt_weak_secret`): the account's current
token is changed again the same way (a fresh claim for a forged token) and sent to the protected
endpoint, twice; each round must show the real token accepted, the request without it refused,
and the changed token accepted with the real token's content.

`weak_lockout`: another burst of failed logins with a new random username; together with the
detection burst, two bursts in a row were not limited.
"""

from __future__ import annotations

import secrets
from typing import Any

from rajdoll.modules import auth_checks
from rajdoll.modules.base import Exchange, TaskContext, Verdict
from rajdoll.validators.base import base_url, validator

ROUNDS = 2


def _changed(vuln_type: str, slot: auth_checks.TokenSlot, params: dict[str, Any]) -> str | None:
    if vuln_type == "jwt_signature_not_verified":
        return auth_checks.bad_signature(slot.token)
    if vuln_type == "jwt_alg_none":
        return auth_checks.alg_none(slot.token, str(params.get("variant") or "none"))
    secret = str(params.get("secret") or "")
    if not secret or auth_checks.crack(slot.token, [secret]) is None:
        return None  # the account's token is no longer signed with that secret
    return auth_checks.forge(slot.token, secret, secrets.token_hex(4))


def _jwt(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    poc = finding["poc"]
    params = poc.get("validator_params") or {}
    account = poc.get("account")
    headers = ctx.session_headers(account) if account else {}
    slot = next(
        (
            s
            for s in auth_checks.find_tokens(headers)
            if (s.location, s.name) == (params.get("location"), params.get("name"))
        ),
        None,
    )
    if slot is None or auth_checks.decode(slot.token) is None:
        return Verdict(False, (), f"Sesi {account} tidak lagi membawa token JWT; perlu cek manual.")
    url = base_url(ctx, finding).rstrip("/") + str(params.get("protected_path") or poc["path"])
    evidence: list[Exchange] = []
    with ctx.http("validator") as client:
        for _ in range(ROUNDS):
            probe = auth_checks.find_protected(
                client, headers, slot, [url], account, ctx.check_cancelled
            )
            if probe is None:
                note = "Token asli ditolak atau endpoint tidak butuh token lagi; perlu cek manual."
                return Verdict(False, tuple(evidence), note)
            token = _changed(finding["vuln_type"], slot, params)
            if token is None:
                return Verdict(
                    False,
                    tuple(evidence),
                    "Token tidak lagi diteken dengan secret itu; cek manual.",
                )
            ok, forged = auth_checks.try_forged(
                client, headers, slot, probe, account, token, finding["vuln_type"]
            )
            evidence += [probe.real.exchange, probe.without.exchange, forged.exchange]
            if not ok:
                return Verdict(
                    False, tuple(evidence), "Token yang diubah ditolak; perlu cek manual."
                )
    note = f"Token yang diubah diterima di {probe.target.label}, token asli diterima, tanpa token "
    note += f"ditolak (terulang {ROUNDS} kali)."
    if finding["vuln_type"] == "jwt_weak_secret":
        note = f"Secret HMAC {params.get('secret')!r} cocok. " + note
    return Verdict(True, tuple(evidence), note)


for _kind in ("jwt_signature_not_verified", "jwt_alg_none", "jwt_weak_secret"):
    validator(_kind)(_jwt)


@validator("weak_lockout")
def weak_lockout(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    poc = finding["poc"]
    params = poc.get("validator_params") or {}
    if not params.get("user_field") or not params.get("password_field"):
        return Verdict(False, (), "PoC tanpa nama field login; perlu cek manual.")
    form = auth_checks.LoginForm(
        method=str(poc.get("method", "POST")),
        url=base_url(ctx, finding).rstrip("/") + str(poc.get("path", "/")),
        user_field=str(params["user_field"]),
        password_field=str(params["password_field"]),
        location=str(poc.get("body_encoding") or "form"),
        other_fields=tuple(params.get("other_fields") or ()),
        csrf_field=params.get("csrf_field"),
    )
    attempts = int(params.get("attempts") or auth_checks.ATTEMPTS)
    with ctx.http("validator") as client:
        burst = auth_checks.login_burst(client, form, ctx.check_cancelled, attempts)
    if burst.limited is False:
        note = f"Ulangan: {burst.note}; dua rangkaian percobaan berturut-turut tidak dibatasi."
        return Verdict(True, tuple(burst.evidence), note)
    return Verdict(False, tuple(burst.evidence), f"Ulangan: {burst.note} Perlu cek manual.")
