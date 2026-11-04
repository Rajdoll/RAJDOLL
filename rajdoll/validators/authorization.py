"""Validators for IDOR and privilege escalation (TRD 6.3).

Both repeat the detection round (rajdoll/modules/authz_checks.py) twice with the accounts the PoC
names, GET only:
- `idor`: the other account receives the owner's specific values (words of the owner's object
  that the other account's own object lacks) and a request without a session does not;
- `privilege_escalation`: the reference admin function still refuses the lower account and
  admits the higher one, and the finding's function gives the lower account the same content as
  the higher one while refusing a request without a session.

A missing account session, or a candidate without a reference function (reported only on the
LLM's judgement), stays `needs_manual_check`.
"""

from __future__ import annotations

from typing import Any

from rajdoll.modules import authz_checks
from rajdoll.modules.authz_checks import Target
from rajdoll.modules.base import Exchange, TaskContext, Verdict
from rajdoll.validators.base import base_url, validator

ROUNDS = 2


def _sessions(ctx: TaskContext, accounts: list[str]) -> dict[str, dict[str, str]] | None:
    headers = {account: ctx.session_headers(account) for account in accounts}
    return headers if all(headers.values()) else None


def _target(root: str, path: str, query: dict[str, Any] | None) -> Target:
    return Target(root.rstrip("/") + path, {k: str(v) for k, v in (query or {}).items()})


@validator("idor")
def idor(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    poc = finding["poc"]
    params = poc.get("validator_params") or {}
    owner, other = params.get("owner_account"), poc.get("account")
    if not owner or not other:
        return Verdict(
            False, (), "PoC tidak menyebut akun pemilik dan akun lain; perlu cek manual."
        )
    headers = _sessions(ctx, [owner, other])
    if headers is None:
        return Verdict(False, (), f"Sesi {owner} atau {other} tidak tersedia; perlu cek manual.")
    root = base_url(ctx, finding)
    obj = _target(root, poc.get("path", "/"), poc.get("query"))
    control = _target(
        root, params.get("control_path") or poc.get("path", "/"), params.get("control_query")
    )
    evidence: list[Exchange] = []
    with ctx.http("validator") as client:
        fetch = authz_checks.fetcher(client, headers, ctx.check_cancelled)
        for _ in range(ROUNDS):
            result = authz_checks.idor_round(fetch, obj, control, owner, other)
            evidence += result.evidence
            if result.share < authz_checks.SHARE_CONFIRM:
                return Verdict(
                    False, tuple(evidence), f"{result.note.rstrip('.')}; perlu cek manual."
                )
    return Verdict(True, tuple(evidence), f"{result.note} (terulang {ROUNDS} kali).")


@validator("privilege_escalation")
def privilege_escalation(ctx: TaskContext, finding: dict[str, Any]) -> Verdict:
    poc = finding["poc"]
    params = poc.get("validator_params") or {}
    high, low = params.get("privileged_account"), poc.get("account")
    if not params.get("reference_path"):
        return Verdict(
            False, (), "Tidak ada fungsi admin pembanding yang menolak akun ini; perlu cek manual."
        )
    if not high or not low:
        return Verdict(False, (), "PoC tidak menyebut kedua akun; perlu cek manual.")
    headers = _sessions(ctx, [high, low])
    if headers is None:
        return Verdict(False, (), f"Sesi {high} atau {low} tidak tersedia; perlu cek manual.")
    root = base_url(ctx, finding)
    target = _target(root, poc.get("path", "/"), poc.get("query"))
    reference = _target(root, params["reference_path"], None)
    evidence: list[Exchange] = []
    with ctx.http("validator") as client:
        fetch = authz_checks.fetcher(client, headers, ctx.check_cancelled)
        for _ in range(ROUNDS):
            result = authz_checks.escalation_round(fetch, target, reference, high, low)
            evidence += result.evidence
            if not result.confirmed:
                return Verdict(
                    False, tuple(evidence), f"{result.note.rstrip('.')}; perlu cek manual."
                )
    return Verdict(True, tuple(evidence), f"{result.note} (terulang {ROUNDS} kali).")
