"""Account enumeration on login endpoints (WSTG-IDNT-04).

Two random usernames that cannot exist get a failed login each; when both answers are alike, the
answer for a username that exists (an account username the assessor gave, else a common one such
as `admin`) is compared with them. A different status, page, or redirect for the existing
username means the login tells registered usernames apart. The tried username is removed from the
pages before comparing, so an echoed name alone does not count.

Each username gets exactly one failed login per check, so a real account is never locked out.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from rajdoll.modules import httpkit
from rajdoll.modules.auth_checks import LoginForm, random_username
from rajdoll.modules.authz_checks import similarity
from rajdoll.modules.base import Exchange

COMMON_USERNAMES = ("admin", "administrator", "root", "test", "user", "demo", "operator")
SAME = 0.9


@dataclass
class Answer:
    status: int
    text: str
    location: str
    exchange: Exchange


def attempt(client: httpx.Client, form: LoginForm, username: str, note: str) -> Answer:
    """One failed login for `username` (random wrong password), redirects not followed."""
    body = {form.user_field: username, form.password_field: ""}
    body.update({name: httpkit.default_value(name) for name in form.other_fields})
    point = httpkit.Injection(
        form.method, form.url, form.password_field, form.location, {}, body, form.location
    )
    client.cookies.clear()
    client.follow_redirects = False
    response, exchange = point.send(client, f"Salah-{secrets.token_hex(4)}", None, note)
    text = response.text.replace(username, "")
    return Answer(response.status_code, text, response.headers.get("location", ""), exchange)


def alike(first: Answer, second: Answer) -> bool:
    return (
        first.status == second.status
        and first.location.split("?")[0] == second.location.split("?")[0]
        and similarity(first.text, second.text) >= SAME
    )


@dataclass
class Enumeration:
    username: str
    known: bool  # an account username the assessor gave (else a common one)
    evidence: list[Exchange]


def find_enumeration(
    client: httpx.Client,
    form: LoginForm,
    known: list[str],
    check_cancelled: Callable[[], None],
) -> Enumeration | None:
    """The first username whose failed login is answered differently from unknown usernames."""
    first = attempt(client, form, random_username(form.user_field), "username tidak terdaftar (1)")
    second = attempt(client, form, random_username(form.user_field), "username tidak terdaftar (2)")
    if not alike(first, second):
        return None  # the answer changes on its own; comparing it would mean nothing
    names = [(name, True) for name in known] + [
        (name, False) for name in COMMON_USERNAMES if name not in known
    ]
    for name, is_known in names:
        check_cancelled()
        answer = attempt(client, form, name, "username terdaftar")
        if not alike(answer, first):
            return Enumeration(name, is_known, [first.exchange, answer.exchange])
    return None


def still_enumerable(
    client: httpx.Client, form: LoginForm, username: str
) -> tuple[bool, list[Exchange]]:
    """The validator's round: new unknown usernames are alike, the username still differs."""
    first = attempt(client, form, random_username(form.user_field), "username tidak terdaftar (1)")
    second = attempt(client, form, random_username(form.user_field), "username tidak terdaftar (2)")
    answer = attempt(client, form, username, "username terdaftar")
    evidence = [first.exchange, second.exchange, answer.exchange]
    return alike(first, second) and not alike(answer, first), evidence


def login_form_from_poc(base: str, poc: dict[str, Any]) -> LoginForm:
    params = poc.get("validator_params") or {}
    return LoginForm(
        method=str(poc.get("method", "POST")),
        url=base.rstrip("/") + str(poc.get("path", "/")),
        user_field=str(params.get("user_field") or ""),
        password_field=str(params.get("password_field") or ""),
        location=str(poc.get("body_encoding") or "form"),
        other_fields=tuple(params.get("other_fields") or ()),
        csrf_field=params.get("csrf_field"),
    )
