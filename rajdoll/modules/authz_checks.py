"""Authorization checks with two or more target accounts (WSTG-ATHZ-03, -04; TRD 6.2, 6.3).

Every request is a GET with exactly one account's session, or none, so the checks never change
data. What each account receives is compared:

- IDOR: object references (one path placeholder such as `/akun/{id}`, or an id-like query
  parameter) are looked up in the links and JSON of each account's own pages (the target root
  and the profile pages). A reference only one account sees is that account's object. Another
  account then requests it. A round is positive when the other account gets a success response
  that carries the owner's specific values (words of the owner's object that the other
  account's own object, the control, does not have) and a request without a session does not.
- Privilege escalation: an admin function one account opens and another is refused (the
  reference) tells which account is privileged. Another admin function in the same area (the
  same path up to the admin segment) that the lower account opens with the same content as the
  privileged account, while a request without a session is refused, is a candidate.

The validators repeat the same rounds (rajdoll/validators/authorization.py).
"""

from __future__ import annotations

import html
import json
import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

import httpx

from rajdoll.modules import httpkit
from rajdoll.modules.base import Exchange
from rajdoll.services.tagging import ADMIN_PATH, ID_PARAM

MAX_TEXT = 200_000
NONEXISTENT = "999999999"
SHARE_CONFIRM = 0.8  # share of the owner's specific values the other account must receive
SHARE_ASK = 0.3  # from here up to SHARE_CONFIRM the LLM may be asked; it only steers
ANON_SHARE = 0.5  # a request without a session that gets this much is a public object
SAME_CONTENT = 0.9  # privilege escalation: the lower account sees what the higher one sees
ANON_SAME = 0.7  # privilege escalation: without a session, this similar means a public page

_WORD = re.compile(r"\w{3,}")
_RANDOM = re.compile(r"(?=\w*\d)(?=\w*[^\W\d_])\w{16,}")  # CSRF tokens, nonces, hashes
_URLISH = re.compile(r"""https?://[^\s"'<>\\]+|(?<=["'=(\s,])/[^\s"'<>\\]*""")
_PLACEHOLDER = re.compile(r"\{[^{}/]+\}")
_VALUE = re.compile(r"[A-Za-z0-9_.~-]{1,64}")


# -- comparing responses -----------------------------------------------------------------------


def words(text: str) -> set[str]:
    """Words of a response, without values that change on every response."""
    return {w for w in _WORD.findall(text[:MAX_TEXT]) if not _RANDOM.fullmatch(w)}


def specific_values(owner: str, control: str) -> list[str]:
    """Words of the owner's object that the control object does not have."""
    return sorted(words(owner) - words(control))


def share(values: list[str], text: str) -> float:
    """The share of `values` that appear in `text`."""
    if not values:
        return 0.0
    present = words(text)
    return sum(1 for value in values if value in present) / len(values)


def similarity(first: str, second: str) -> float:
    """Word-multiset similarity (Dice) of two responses, 1.0 for identical text."""
    a = Counter(_WORD.findall(first[:MAX_TEXT]))
    b = Counter(_WORD.findall(second[:MAX_TEXT]))
    total = sum(a.values()) + sum(b.values())
    if not total:
        return 1.0 if first.strip() == second.strip() else 0.0
    return 2 * sum((a & b).values()) / total


# -- sending -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    """One GET request: the URL without its query, and the query."""

    url: str
    query: dict[str, str] = field(default_factory=dict)

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    @property
    def label(self) -> str:
        return self.path + ("?" + urlencode(self.query) if self.query else "")


@dataclass(frozen=True)
class Fetched:
    status: int
    text: str
    content_type: str
    exchange: Exchange
    set_cookies: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


def send(
    client: httpx.Client, target: Target, headers: dict[str, str], mask: str, note: str
) -> Fetched:
    """One GET with exactly `headers` (cookies the client collected are dropped), redirects not
    followed (a redirect is an answer, often a refusal to the login page). Session headers
    show as `mask` in the evidence."""
    client.cookies.clear()
    response = client.get(
        target.url, params=target.query or None, headers=headers, follow_redirects=False
    )
    exchange = Exchange(
        httpkit.raw_request(response.request, mask),
        httpkit.raw_response(response),
        response.status_code,
        note,
    )
    return Fetched(
        response.status_code,
        response.text[:MAX_TEXT],
        response.headers.get("content-type", "").lower(),
        exchange,
        tuple(response.headers.get_list("set-cookie")),
    )


Fetch = Callable[[Target, str | None, str], Fetched]


def fetcher(
    client: httpx.Client,
    headers: dict[str, dict[str, str]],
    check_cancelled: Callable[[], None],
) -> Fetch:
    """`fetch(target, account, note)`: a GET with that account's session (None: no session).

    Evidence masks the session as `[sesi <account>]`, so it shows which account sent what.
    """

    def fetch(target: Target, account: str | None, note: str) -> Fetched:
        check_cancelled()
        sent = headers.get(account, {}) if account else {}
        mask = f"[sesi {account}]" if account else httpkit.MASK
        return send(client, target, sent, mask, note)

    return fetch


# -- IDOR --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Reference:
    """Where a GET endpoint takes an object reference."""

    endpoint_url: str  # the inventory URL, path template included (`https://h/akun/{id}`)
    parameter: str
    location: str  # path | query

    def target(self, value: str, query: dict[str, str] | None = None) -> Target:
        if self.location == "path":
            url = _PLACEHOLDER.sub(lambda _m: value, self.endpoint_url, count=1)
            return Target(url, dict(query or {}))
        return Target(self.endpoint_url, {**(query or {}), self.parameter: value})


def references(endpoint: dict[str, Any]) -> list[Reference]:
    """The object references of an inventory endpoint (GET only: the checks never write)."""
    if endpoint.get("method") != "GET":
        return []
    url = str(endpoint["url"])
    placeholders = _PLACEHOLDER.findall(urlsplit(url).path)
    if len(placeholders) == 1:
        return [Reference(url, placeholders[0].strip("{}"), "path")]
    if placeholders:
        return []  # several placeholders: which one is the object is a manual question
    names = endpoint.get("query_params") or []
    return [Reference(url, name, "query") for name in names if ID_PARAM.match(name)]


def _json_values(data: Any, keys: set[str], depth: int = 0) -> Iterator[str]:
    if depth > 4:
        return
    if isinstance(data, dict):
        for key, value in list(data.items())[:200]:
            if key in keys and isinstance(value, str | int) and not isinstance(value, bool):
                text = str(value)
                if _VALUE.fullmatch(text):
                    yield text
            else:
                yield from _json_values(value, keys, depth + 1)
    elif isinstance(data, list):
        for item in data[:200]:
            yield from _json_values(item, keys, depth + 1)


def find_objects(ref: Reference, page: Target, fetched: Fetched) -> dict[str, Target]:
    """References to `ref`'s endpoint on one page: value -> the request that opens the object."""
    found: dict[str, Target] = {}
    endpoint = urlsplit(ref.endpoint_url)
    pattern = None
    if ref.location == "path":
        before, after = _PLACEHOLDER.split(endpoint.path, maxsplit=1)
        pattern = re.compile(re.escape(before) + f"({_VALUE.pattern})" + re.escape(after))
    for raw in _URLISH.findall(fetched.text):
        link = urlsplit(urljoin(page.url, html.unescape(raw)))
        if link.netloc.lower() != endpoint.netloc.lower():
            continue
        if pattern is not None:
            match = pattern.fullmatch(link.path)
            if match:
                found.setdefault(match.group(1), ref.target(match.group(1)))
        elif link.path == endpoint.path:
            query = dict(parse_qsl(link.query))
            value = query.get(ref.parameter, "")
            if _VALUE.fullmatch(value):
                found.setdefault(value, Target(ref.endpoint_url, query))
    if "json" in fetched.content_type:
        try:
            data = json.loads(fetched.text)
        except ValueError:
            data = None
        for value in _json_values(data, {ref.parameter}):
            found.setdefault(value, ref.target(value))
    return found


@dataclass(frozen=True)
class Owned:
    target: Target
    page: Fetched  # the owner's own page that references the object (evidence of ownership)


def owned_objects(
    ref: Reference, pages: dict[str, list[tuple[Target, Fetched]]]
) -> dict[str, dict[str, Owned]]:
    """Per account, the objects of `ref` that only that account's own pages reference."""
    seen: dict[str, dict[str, Owned]] = {}
    for account, fetched_pages in pages.items():
        objects: dict[str, Owned] = {}
        for page, fetched in fetched_pages:
            if not fetched.ok:
                continue
            for value, target in find_objects(ref, page, fetched).items():
                objects.setdefault(value, Owned(target, fetched))
        seen[account] = objects
    owned: dict[str, dict[str, Owned]] = {}
    for account, objects in seen.items():
        others = {v for other, objs in seen.items() if other != account for v in objs}
        owned[account] = {v: o for v, o in objects.items() if v not in others}
    return owned


@dataclass
class IdorRound:
    share: float  # of the owner's specific values in the other account's response
    evidence: list[Exchange]
    note: str
    values: list[str] = field(default_factory=list)
    owner_text: str = ""
    other_text: str = ""


def idor_round(fetch: Fetch, obj: Target, control: Target, owner: str, other: str) -> IdorRound:
    """One round: the owner opens its object, the other account opens its own object (the
    control) and then the owner's, and a request without a session opens the owner's."""
    evidence: list[Exchange] = []
    own = fetch(obj, owner, f"{owner} (pemilik) membuka objeknya sendiri")
    evidence.append(own.exchange)
    if not own.ok:
        return IdorRound(0.0, evidence, f"{owner} sendiri tidak mendapat respons sukses.")
    control_seen = fetch(control, other, f"{other} membuka objek pembanding")
    evidence.append(control_seen.exchange)
    values = specific_values(own.text, control_seen.text)
    if not values:
        return IdorRound(0.0, evidence, "Isi objek tidak bergantung pada pengenalnya.")
    cross = fetch(obj, other, f"{other} membuka objek milik {owner}")
    evidence.append(cross.exchange)
    if not cross.ok:
        return IdorRound(0.0, evidence, f"{other} ditolak (HTTP {cross.status}).")
    anon = fetch(obj, None, "tanpa sesi")
    evidence.append(anon.exchange)
    if anon.ok and share(values, anon.text) >= ANON_SHARE:
        return IdorRound(
            0.0,
            evidence,
            "Objek juga terbuka tanpa login; bukan IDOR antar akun (cek akses publik).",
        )
    got = share(values, cross.text)
    note = (
        f"{other} menerima {round(got * 100)}% nilai khas objek milik {owner} "
        f"({len(values)} nilai), tanpa sesi ditolak"
    )
    return IdorRound(got, evidence, note, values, own.text, cross.text)


# -- privilege escalation ------------------------------------------------------------------------


def admin_area(path: str) -> str | None:
    """The path up to its admin segment: `/api/admin/users` -> `/api/admin`."""
    match = ADMIN_PATH.search(path)
    return path[: match.end(1)].lower() if match else None


@dataclass
class AdminView:
    """An admin function as each account (and no session) sees it."""

    target: Target
    responses: dict[str | None, Fetched]


def denials(views: list[AdminView], accounts: list[str]) -> list[tuple[AdminView, str, str]]:
    """References: (view, higher account, lower account) where the higher one opens the admin
    function and the lower one is refused."""
    found = []
    for view in views:
        for high in accounts:
            for low in accounts:
                if high != low and view.responses[high].ok and not view.responses[low].ok:
                    found.append((view, high, low))
    return found


def escalation(
    high_seen: Fetched, low_seen: Fetched, anon: Fetched, high: str, low: str
) -> tuple[bool, str]:
    """Whether the lower account opens what the higher one opens, while no session is refused."""
    if not high_seen.ok:
        return False, f"{high} sendiri tidak mendapat respons sukses."
    if not low_seen.ok:
        return False, f"{low} ditolak (HTTP {low_seen.status})."
    same = similarity(high_seen.text, low_seen.text)
    if same < SAME_CONTENT:
        return False, f"Isi untuk {low} berbeda dari isi untuk {high} (kemiripan {same:.0%})."
    if anon.ok and similarity(high_seen.text, anon.text) >= ANON_SAME:
        return False, "Fungsi ini juga terbuka tanpa login; bukan eskalasi hak antar akun."
    return True, (
        f"{low} membuka fungsi admin ini dengan isi yang sama dengan {high} "
        f"(kemiripan {same:.0%}), tanpa sesi ditolak"
    )


@dataclass
class EscalationRound:
    confirmed: bool
    evidence: list[Exchange]
    note: str


def escalation_round(
    fetch: Fetch, target: Target, reference: Target, high: str, low: str
) -> EscalationRound:
    """One validation round: the reference still refuses the lower account and admits the
    higher one, and the target admits both with the same content."""
    ref_high = fetch(reference, high, f"{high} membuka fungsi admin pembanding")
    ref_low = fetch(reference, low, f"{low} membuka fungsi admin pembanding")
    evidence = [ref_high.exchange, ref_low.exchange]
    if not ref_high.ok or ref_low.ok:
        note = f"Fungsi pembanding {reference.label} tidak lagi membedakan {high} dan {low}."
        return EscalationRound(False, evidence, note)
    high_seen = fetch(target, high, f"{high} (hak lebih tinggi) membuka fungsi admin")
    low_seen = fetch(target, low, f"{low} (hak lebih rendah) membuka fungsi admin")
    anon = fetch(target, None, "tanpa sesi")
    evidence += [high_seen.exchange, low_seen.exchange, anon.exchange]
    confirmed, note = escalation(high_seen, low_seen, anon, high, low)
    if confirmed:
        note += f"; {reference.label} menolak {low}"
    return EscalationRound(confirmed, evidence, note)
