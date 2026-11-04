"""Authentication (WSTG-ATHN, and JWT from WSTG-SESS-10): JWT weaknesses and login attempt
limits (IPD F8a).

Testing stage:
- `custom:jwt`: one task when the engagement has accounts. The first account whose pasted
  session carries a JWT is used; its protected endpoint is the session-check URL, the target
  root, or a GET endpoint tagged `api` or `profile`. GET only.
- `custom:lockout`: one task per login endpoint the plan assigns to Authentication (a POST with
  a password field), with failed logins for a random username that does not exist.

Password reset and logout flows match the default exclusion patterns (`reset`, `logout`) and are
never requested; they stay on the assessor's manual checklist, as do checks that need a fresh
login with credentials (auto-login is F9).
"""

from __future__ import annotations

from typing import Any, ClassVar
from urllib.parse import urlsplit

from rajdoll.core.enums import ScanStage
from rajdoll.modules import auth_checks
from rajdoll.modules.base import Candidate, PlanContext, TaskContext, TaskSpec

MAX_PROBES = 15
MAX_LOGINS = 5
MAX_ACCOUNTS = 3


class Authentication:
    name: ClassVar[str] = "authentication"
    label: ClassVar[str] = "Authentication"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage != ScanStage.TESTING:
            return []
        specs: list[TaskSpec] = []
        logins = [
            e
            for e in ctx.endpoints
            if self.name in e.get("modules", []) and auth_checks.login_form(e) is not None
        ][:MAX_LOGINS]
        for endpoint in logins:
            target = {
                "endpoint_id": endpoint["id"],
                "method": endpoint["method"],
                "url": endpoint["url"],
                "body_params": endpoint.get("body_params", []),
            }
            specs.append(TaskSpec("custom:lockout", target))
        if ctx.accounts:
            probes = [ctx.session_check_url] if ctx.session_check_url else []
            probes.append(ctx.target_url)
            probes += [
                e["url"]
                for e in ctx.endpoints
                if not e.get("excluded")
                and e["method"] == "GET"
                and "{" not in e["path_template"]
                and {"api", "profile"} & set(e.get("tags", []))
            ]
            target = {
                "accounts": ctx.accounts[:MAX_ACCOUNTS],
                "probes": list(dict.fromkeys(probes))[:MAX_PROBES],
            }
            specs.append(TaskSpec("custom:jwt", target))
        return specs

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        if ctx.engine == "custom:jwt":
            return self._jwt(ctx)
        if ctx.engine == "custom:lockout":
            return self._lockout(ctx)
        raise ValueError(f"unknown engine {ctx.engine}")

    # -- JWT --------------------------------------------------------------------------------------

    def _jwt(self, ctx: TaskContext) -> dict[str, Any]:
        for account in ctx.target["accounts"]:
            headers = ctx.session_headers(account)
            slots = [s for s in auth_checks.find_tokens(headers) if auth_checks.decode(s.token)]
            if not slots:
                continue
            reported: list[str] = []
            with ctx.http("jwt") as client:
                for slot in slots:
                    probe = auth_checks.find_protected(
                        client, headers, slot, ctx.target["probes"], account, ctx.check_cancelled
                    )
                    if probe is None:
                        ctx.log(
                            f"Token JWT di {slot.label} ({account}): tidak ada endpoint yang "
                            "menolak request tanpa token; uji JWT perlu cek manual."
                        )
                        continue
                    results = auth_checks.jwt_checks(
                        client, headers, slot, probe, account, auth_checks.common_secrets()
                    )
                    for result in results:
                        self._report_jwt(ctx, account, slot, probe, result)
                        reported.append(f"{result.vuln_type}:{slot.label}")
            if reported:
                ctx.log(f"JWT ({account}): kandidat {', '.join(reported)}")
            return {"account": account, "candidates": reported}
        return {"skipped": "no JWT in the account sessions"}

    def _report_jwt(
        self,
        ctx: TaskContext,
        account: str,
        slot: auth_checks.TokenSlot,
        probe: auth_checks.Probe,
        result: auth_checks.JwtResult,
    ) -> None:
        if slot.location == "header":
            headers = {slot.name: slot.prefix + result.token}
        else:
            headers = {"Cookie": f"{slot.name}={result.token}"}
        params = {
            "location": slot.location,
            "name": slot.name,
            "protected_path": probe.target.path,
            **result.params,
        }
        ctx.report_candidate(
            Candidate(
                vuln_type=result.vuln_type,
                method="GET",
                url=probe.target.url,
                parameter=slot.name,
                poc={
                    "method": "GET",
                    "path": probe.target.path,
                    "query": {},
                    "headers": headers,
                    "body": None,
                    "body_encoding": "none",
                    # The token is forged from this account's token; the PoC header carries it.
                    "account": account,
                    "validator": result.vuln_type,
                    "validator_params": params,
                },
                evidence=tuple(result.evidence),
                note=result.note,
            )
        )

    # -- login attempts ---------------------------------------------------------------------------

    def _lockout(self, ctx: TaskContext) -> dict[str, Any]:
        form = auth_checks.login_form(dict(ctx.target))
        if form is None:
            return {"skipped": "not a login form"}
        with ctx.http("lockout") as client:
            burst = auth_checks.login_burst(client, form, ctx.check_cancelled)
        path = urlsplit(form.url).path or "/"
        if burst.limited is None:
            ctx.log(f"{form.method} {path}: {burst.note} Uji lockout perlu cek manual.")
            return {"inconclusive": burst.note}
        if burst.limited:
            ctx.log(f"{form.method} {path}: {burst.note}")
            return {"limited": True, "attempts": burst.attempts}
        body = {form.user_field: burst.username, form.password_field: "<salah>"}
        ctx.report_candidate(
            Candidate(
                vuln_type="weak_lockout",
                method=form.method,
                url=form.url,
                parameter=None,
                poc={
                    "method": form.method,
                    "path": path,
                    "query": {},
                    "headers": {},
                    "body": body,
                    "body_encoding": form.location,
                    "account": None,
                    "validator": "weak_lockout",
                    "validator_params": {
                        "user_field": form.user_field,
                        "password_field": form.password_field,
                        "other_fields": list(form.other_fields),
                        "csrf_field": form.csrf_field,
                        "attempts": burst.attempts,
                    },
                },
                evidence=tuple(burst.evidence),
                note=burst.note + ".",
            )
        )
        ctx.log(f"{form.method} {path}: kandidat weak_lockout ({burst.attempts} percobaan)")
        return {"limited": False, "attempts": burst.attempts}
