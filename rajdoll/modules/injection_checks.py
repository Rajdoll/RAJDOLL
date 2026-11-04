"""Detection probes for SQLi, XSS, command injection, SSTI, and SSRF (WSTG-INPV).

Each probe sends a few requests for one injection point and returns a `Hit` when the response
shows the behaviour the vulnerability causes. Probes prefer evidence that reflection alone cannot
fake: an arithmetic result computed by the target (SSTI, command injection), an SQL error that
appears only with an unbalanced quote, or the target's own page fetched by the server (SSRF).
Validators re-run the same ideas with fresh values (rajdoll/validators/injection.py).
"""

from __future__ import annotations

import html
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote_plus

import httpx

from rajdoll.modules.base import Exchange
from rajdoll.modules.httpkit import Injection

SQL_ERRORS = re.compile(
    r"SQL syntax|mysql_fetch|Warning: mysql|MariaDB server|valid MySQL result"
    r"|PostgreSQL.*ERROR|pg_query\(|PSQLException|syntax error at or near"
    r"|unterminated quoted string at or near"  # PostgreSQL; a shell says the same without it
    r"|ORA-\d{5}|Oracle error|Microsoft OLE DB|ODBC SQL Server Driver|SQLServer JDBC Driver"
    r"|Unclosed quotation mark|Incorrect syntax near|SQLite3::|sqlite3\.OperationalError"
    r"|SQLITE_ERROR|unrecognized token: \"|SQLSTATE\[|quoted string not properly terminated",
    re.I,
)
SSTI_SYNTAXES = ("{{%d*%d}}", "${%d*%d}", "<%%= %d*%d %%>", "#{%d*%d}")
CMDI_SEPARATORS = (";", "|", "&&", "$(%s)", "`%s`")
REDIRECT_NAMES = re.compile(
    r"^(url|uri|link|href|src|source|redirect|redirect_uri|redirect_url|return|returnurl|"
    r"return_url|next|callback|dest|destination|continue|target|goto|feed|host|site|path|ambil)$",
    re.I,
)
INVALID_HOST_URL = "http://rajdoll-invalid.invalid/"


@dataclass
class Hit:
    vuln_type: str
    payload: str
    note: str
    evidence: list[Exchange] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)


Sender = Callable[[str, str | None], tuple[httpx.Response, Exchange]]


def numbers() -> tuple[int, int]:
    """Two factors whose product cannot appear by chance in a page."""
    return 100 + secrets.randbelow(800), 1000 + secrets.randbelow(8000)


def nonce() -> str:
    return "rjdl" + secrets.token_hex(3)


def sqli_error(send: Sender, base: str, baseline: str) -> Hit | None:
    response, exchange = send(base + "'", "kutip tunggal tidak seimbang")
    match = SQL_ERRORS.search(response.text)
    if not match or SQL_ERRORS.search(baseline):
        return None
    balanced, second = send(base + "''", "kutip ganda (seimbang)")
    if SQL_ERRORS.search(balanced.text):
        return None
    return Hit(
        "sqli",
        base + "'",
        "Pesan error SQL muncul dengan kutip tunggal dan hilang dengan kutip ganda: "
        + match.group(0),
        [exchange, second],
        {"technique": "error"},
    )


def sqli_boolean(send: Sender, base: str) -> Hit | None:
    for true_part, false_part in (
        ("' OR '1'='1' -- x", "' AND '1'='2' -- x"),
        (" OR 1=1 -- x", " AND 1=2 -- x"),
    ):
        true_value, false_value = base + true_part, base + false_part
        true_resp, true_ex = send(true_value, "kondisi benar")
        false_resp, false_ex = send(false_value, "kondisi salah")
        if true_resp.status_code != 200 or false_resp.status_code != 200:
            continue
        # A page that only echoes the value differs too: compare without the reflected values.
        true_text = _without(true_resp.text, true_value)
        if _differs(true_text, _without(false_resp.text, false_value)):
            again, again_ex = send(true_value, "kondisi benar, ulangan")
            if not _differs(_without(again.text, true_value), true_text):
                return Hit(
                    "sqli",
                    base + true_part,
                    "Respons kondisi benar dan salah berbeda secara konsisten (boolean-based).",
                    [true_ex, false_ex, again_ex],
                    {"technique": "boolean", "true": true_part, "false": false_part},
                )
    return None


def ssti(send: Sender, base: str, baseline: str) -> Hit | None:
    for syntax in SSTI_SYNTAXES:
        a, b = numbers()
        marker = nonce()
        response, exchange = send(base + marker + syntax % (a, b), "ekspresi template")
        if f"{marker}{a * b}" in response.text and f"{marker}{a * b}" not in baseline:
            return Hit(
                "ssti",
                base + marker + syntax % (a, b),
                f"Ekspresi {syntax % (a, b)} dievaluasi menjadi {a * b} oleh server.",
                [exchange],
                {"syntax": syntax},
            )
    return None


def cmdi(send: Sender, base: str) -> Hit | None:
    for separator in CMDI_SEPARATORS:
        a, b = numbers()
        marker = nonce()
        command = f"echo {marker}$(({a}*{b}))"
        payload = base + (separator % command if "%s" in separator else f"{separator}{command}")
        response, exchange = send(payload, "perintah echo dengan aritmetika shell")
        if f"{marker}{a * b}" in response.text:
            return Hit(
                "cmdi",
                payload,
                f"Shell menjalankan echo dan menghitung {a}*{b} = {a * b}.",
                [exchange],
                {"separator": separator},
            )
    return None


def xss(send: Sender, base: str, content_type: str | None) -> Hit | None:
    marker = nonce()
    probe = f"{base}{marker}<x\"'>"
    response, exchange = send(probe, "pantulan karakter HTML")
    is_html = "html" in (response.headers.get("content-type") or content_type or "html").lower()
    if is_html and f"{marker}<x" in response.text:
        return Hit(
            "xss_reflected",
            probe,
            "Karakter < dipantulkan tanpa encoding ke halaman HTML.",
            [exchange],
            {"marker": marker},
        )
    return None


def ssrf(send: Sender, injection: Injection, target_url: str, page_marker: str) -> Hit | None:
    if not page_marker or not REDIRECT_NAMES.match(injection.parameter):
        return None
    invalid, invalid_ex = send(INVALID_HOST_URL, "URL ke host yang tidak ada")
    response, exchange = send(target_url, "URL ke halaman target")
    if page_marker in response.text and page_marker not in invalid.text:
        return Hit(
            "ssrf",
            target_url,
            "Server mengambil URL yang diberikan dan mengembalikan isinya.",
            [invalid_ex, exchange],
            {"marker": page_marker},
        )
    return None


def _differs(a: str, b: str) -> bool:
    if a == b:
        return False
    longest = max(len(a), len(b), 1)
    return abs(len(a) - len(b)) / longest > 0.02 or _strip_numbers(a) != _strip_numbers(b)


def _without(text: str, value: str) -> str:
    """The page with every reflection of `value` (raw, HTML-escaped, URL-encoded) removed."""
    for form in {value, html.escape(value), html.escape(value, quote=False), quote_plus(value)}:
        text = text.replace(form, "")
    return text


def _strip_numbers(text: str) -> str:
    return re.sub(r"\d+", "", text)


def page_marker(html: str) -> str:
    """Text that identifies the target's own page (its <title>)."""
    match = re.search(r"<title[^>]*>([^<]{3,120})</title>", html, re.I)
    return match.group(1).strip() if match else ""
