"""Identity Management (WSTG-IDNT) (IPD F8b).

Testing stage: one `custom:enumeration` task per login endpoint (a POST with a password field):
does the login answer registered usernames differently from unknown ones
(`identity_checks.find_enumeration`)? The usernames that exist come from the accounts' optional
username (`ctx.account_username`, decrypted at run time), else a short list of common names.

Registration and role provisioning tests would create accounts on the target; they stay on the
manual checklist.
"""

from __future__ import annotations

from typing import Any, ClassVar
from urllib.parse import urlsplit

from rajdoll.core.enums import ScanStage
from rajdoll.modules import auth_checks, identity_checks
from rajdoll.modules.base import Candidate, PlanContext, TaskContext, TaskSpec

MAX_LOGINS = 5
MAX_ACCOUNTS = 3


class Identity:
    name: ClassVar[str] = "identity"
    label: ClassVar[str] = "Identity Management"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage != ScanStage.TESTING:
            return []
        logins = [
            e
            for e in ctx.endpoints
            if self.name in e.get("modules", []) and auth_checks.login_form(e) is not None
        ][:MAX_LOGINS]
        return [
            TaskSpec(
                "custom:enumeration",
                {
                    "endpoint_id": e["id"],
                    "method": e["method"],
                    "url": e["url"],
                    "body_params": e.get("body_params", []),
                    "accounts": ctx.accounts[:MAX_ACCOUNTS],
                },
            )
            for e in logins
        ]

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        if ctx.engine != "custom:enumeration":
            raise ValueError(f"unknown engine {ctx.engine}")
        form = auth_checks.login_form(dict(ctx.target))
        if form is None:
            return {"skipped": "not a login form"}
        known = [ctx.account_username(label) for label in ctx.target.get("accounts", [])]
        known = [name for name in dict.fromkeys(known) if name]
        with ctx.http("enumeration") as client:
            found = identity_checks.find_enumeration(client, form, known, ctx.check_cancelled)
        path = urlsplit(form.url).path or "/"
        if found is None:
            return {"enumerable": False}
        source = "akun uji" if found.known else "username umum"
        ctx.report_candidate(
            Candidate(
                vuln_type="account_enumeration",
                method=form.method,
                url=form.url,
                parameter=form.user_field,
                poc={
                    "method": form.method,
                    "path": path,
                    "query": {},
                    "headers": {},
                    "body": None,
                    "body_encoding": form.location,
                    "account": None,
                    # The username stays in the encrypted PoC, never in a note.
                    "validator": "account_enumeration",
                    "validator_params": {
                        "username": found.username,
                        "user_field": form.user_field,
                        "password_field": form.password_field,
                        "other_fields": list(form.other_fields),
                        "csrf_field": form.csrf_field,
                    },
                },
                evidence=tuple(found.evidence),
                note=f"Login menjawab username terdaftar ({source}) berbeda dari yang tidak.",
            )
        )
        ctx.log(f"{form.method} {path}: kandidat account_enumeration ({source})")
        return {"enumerable": True}
