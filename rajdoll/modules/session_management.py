"""Session Management (WSTG-SESS): attributes of the session cookies (IPD F8a).

Testing stage: one `custom:cookies` task. The target root and the GET endpoints tagged `auth`
(login pages, where many applications start a session) are fetched without a session, and the
root once with each account's session; every `Set-Cookie` of a session-like cookie (a cookie
of the pasted sessions, or a name such as `PHPSESSID`, `sid`, `token`) is checked for
`HttpOnly`, `Secure` (on HTTPS), and `SameSite`. One candidate per cookie name.

Session fixation, logout invalidation, and session timeout need a fresh login (credentials,
auto-login in F9) or would end the pasted session, so they stay on the manual checklist.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import urlsplit

from rajdoll.core.enums import ScanStage
from rajdoll.modules import authz_checks, httpkit
from rajdoll.modules.authz_checks import Fetched, Target
from rajdoll.modules.base import Candidate, PlanContext, TaskContext, TaskSpec

MAX_PAGES = 10
MAX_ACCOUNTS = 3
_SESSION_NAME = re.compile(
    r"sess|sid|auth|token|jwt|login|remember|jsessionid|aspxauth|connect\.sid", re.I
)
_NOT_SESSION = re.compile(r"csrf|xsrf", re.I)  # meant to be read by scripts


@dataclass(frozen=True)
class CookieIssue:
    name: str
    missing: tuple[str, ...]
    header: str  # the Set-Cookie value, with the cookie's value masked


def _attributes(set_cookie: str) -> tuple[str, str, dict[str, str]]:
    first, *rest = set_cookie.split(";")
    name, _, value = first.partition("=")
    attributes: dict[str, str] = {}
    for part in rest:
        key, _, attr = part.strip().partition("=")
        if key:
            attributes[key.strip().lower()] = attr.strip().lower()
    return name.strip(), value.strip(), attributes


def _removed(value: str, attributes: dict[str, str]) -> bool:
    """A Set-Cookie that deletes the cookie (empty value, Max-Age=0, or a past Expires)."""
    if not value:
        return True
    max_age = attributes.get("max-age")
    if max_age is not None and (max_age == "0" or max_age.startswith("-")):
        return True
    return bool(re.search(r"\b(19\d\d|200\d|201\d)\b", attributes.get("expires", "")))


def missing_flags(set_cookie: str, https: bool) -> tuple[str, ...]:
    """The security attributes a session cookie's Set-Cookie lacks."""
    _name, _value, attributes = _attributes(set_cookie)
    missing = []
    if "httponly" not in attributes:
        missing.append("HttpOnly")
    if https and "secure" not in attributes:
        missing.append("Secure")
    same_site = attributes.get("samesite")
    if same_site is None:
        missing.append("SameSite")
    elif same_site == "none" and "secure" not in attributes and "Secure" not in missing:
        missing.append("Secure (wajib untuk SameSite=None)")
    return tuple(missing)


def session_like(name: str, known: set[str]) -> bool:
    return name in known or (bool(_SESSION_NAME.search(name)) and not _NOT_SESSION.search(name))


def cookie_issues(fetched: Fetched, url: str, known: set[str]) -> list[CookieIssue]:
    """Session cookies a response sets without HttpOnly, Secure (HTTPS), or SameSite."""
    https = urlsplit(url).scheme == "https"
    issues = []
    for header in fetched.set_cookies:
        name, value, attributes = _attributes(header)
        if not name or _removed(value, attributes) or not session_like(name, known):
            continue
        missing = missing_flags(header, https)
        if missing:
            issues.append(CookieIssue(name, missing, httpkit.mask_set_cookie(header)))
    return issues


def cookie_names(headers: dict[str, str]) -> set[str]:
    names = set()
    for name, value in headers.items():
        if name.lower() == "cookie":
            names |= {p.split("=", 1)[0].strip() for p in value.split(";") if "=" in p}
    return names


class SessionManagement:
    name: ClassVar[str] = "session"
    label: ClassVar[str] = "Session Management"

    def plan(self, ctx: PlanContext) -> list[TaskSpec]:
        if ctx.stage != ScanStage.TESTING:
            return []
        pages = [ctx.target_url] + [
            e["url"]
            for e in ctx.endpoints
            if self.name in e.get("modules", [])
            and e["method"] == "GET"
            and "{" not in e["path_template"]
        ]
        target = {
            "pages": list(dict.fromkeys(pages))[:MAX_PAGES],
            "accounts": ctx.accounts[:MAX_ACCOUNTS],
        }
        return [TaskSpec("custom:cookies", target)]

    def run(self, ctx: TaskContext) -> dict[str, Any]:
        if ctx.engine != "custom:cookies":
            raise ValueError(f"unknown engine {ctx.engine}")
        headers = {a: ctx.session_headers(a) for a in ctx.target["accounts"]}
        known = set().union(*(cookie_names(h) for h in headers.values()))
        visits: list[tuple[str, str | None]] = [(url, None) for url in ctx.target["pages"]]
        visits += [(ctx.target_url, account) for account, sent in headers.items() if sent]
        reported: dict[str, str] = {}
        with ctx.http("cookies") as client:
            for url, account in visits:
                ctx.check_cancelled()
                sent = headers.get(account, {}) if account else {}
                mask = f"[sesi {account}]" if account else httpkit.MASK
                who = account or "tanpa sesi"
                fetched = authz_checks.send(client, Target(url), sent, mask, f"dibuka {who}")
                for issue in cookie_issues(fetched, url, known):
                    if issue.name in reported:
                        continue
                    reported[issue.name] = url
                    self._report(ctx, url, account, issue, fetched)
        if reported:
            ctx.log("Cookie sesi tanpa atribut keamanan: " + ", ".join(sorted(reported)))
        return {"candidates": [f"cookie_flags:{name}" for name in sorted(reported)]}

    def _report(
        self, ctx: TaskContext, url: str, account: str | None, issue: CookieIssue, fetched: Fetched
    ) -> None:
        path = urlsplit(url).path or "/"
        note = (
            f"Cookie sesi {issue.name} dibuat di {path} tanpa atribut {', '.join(issue.missing)}: "
            f"Set-Cookie: {issue.header}"
        )
        ctx.report_candidate(
            Candidate(
                vuln_type="cookie_flags",
                method="GET",
                url=url,
                parameter=issue.name,
                poc={
                    "method": "GET",
                    "path": path,
                    "query": {},
                    "headers": {},
                    "body": None,
                    "body_encoding": "none",
                    "account": account,
                    "validator": "cookie_flags",
                    "validator_params": {"cookie": issue.name, "missing": list(issue.missing)},
                },
                evidence=(fetched.exchange,),
                note=note,
            )
        )
