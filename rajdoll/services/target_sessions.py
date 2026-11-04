"""Parse and validate pasted target-application sessions (PRD F-04; AFD 6).

Accepted input, pasted from Burp or browser DevTools:

* header lines, one per line: `Cookie: a=1; b=2` and `Authorization: Bearer ...`
* a bare cookie string: `a=1; b=2`
* a whole raw HTTP request (request line, headers, optional body): only the headers that
  carry identity are kept

The result is `{"cookies": {name: value}, "headers": {name: value}}`.
"""

import re
from dataclasses import dataclass, field

_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_REQUEST_LINE = re.compile(r"^[A-Z]{3,10} \S+ HTTP/\d(\.\d)?$")
_COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$")
MAX_VALUE_LENGTH = 8192

# Request headers that describe the connection or browser, not who is logged in.
_DROPPED_HEADERS = {
    "host",
    "content-length",
    "content-type",
    "connection",
    "keep-alive",
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
    "origin",
    "referer",
    "upgrade-insecure-requests",
    "priority",
    "cache-control",
    "pragma",
    "te",
    "dnt",
    "if-none-match",
    "if-modified-since",
    "transfer-encoding",
}


class SessionParseError(ValueError):
    """The pasted session cannot be used. The message is safe to show the user."""


@dataclass
class TargetSession:
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, dict[str, str]]:
        return {"cookies": dict(self.cookies), "headers": dict(self.headers)}

    def summary(self) -> dict[str, list[str]]:
        """Names only, for display; values never leave the encrypted column."""
        return {"cookie_names": sorted(self.cookies), "header_names": sorted(self.headers)}


def _check_value(value: str, what: str) -> str:
    if any(ord(ch) < 0x20 and ch != "\t" for ch in value) or "\x7f" in value:
        raise SessionParseError(f"{what} berisi karakter kontrol (misalnya baris baru).")
    if len(value) > MAX_VALUE_LENGTH:
        raise SessionParseError(f"{what} terlalu panjang (maksimal {MAX_VALUE_LENGTH} karakter).")
    return value


def _parse_cookie_string(text: str, cookies: dict[str, str]) -> None:
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition("=")
        name = name.strip()
        if not sep or not _COOKIE_NAME.match(name):
            raise SessionParseError(f"Bagian cookie tidak valid: {part[:60]}")
        cookies[name] = _check_value(value.strip(), f"Nilai cookie {name}")


def parse_session_text(text: str) -> TargetSession:
    session = TargetSession()
    lines = [line.rstrip("\r") for line in text.strip().splitlines()]
    if not lines or not any(line.strip() for line in lines):
        raise SessionParseError("Tempel cookie atau header sesi terlebih dahulu.")

    if _REQUEST_LINE.match(lines[0].strip()):
        lines = lines[1:]
        if "" in lines:  # stop at the blank line before a request body
            lines = lines[: lines.index("")]

    content = [line for line in lines if line.strip()]
    if len(content) == 1 and ":" not in content[0].split("=", 1)[0]:
        _parse_cookie_string(content[0], session.cookies)
    else:
        for line in content:
            name, sep, value = line.partition(":")
            name = name.strip()
            if not sep or not _HEADER_NAME.match(name):
                raise SessionParseError(f"Baris bukan header yang valid: {line[:60]}")
            value = value.strip()
            if name.lower() == "cookie":
                _parse_cookie_string(value, session.cookies)
            elif name.lower() not in _DROPPED_HEADERS:
                session.headers[name] = _check_value(value, f"Nilai header {name}")

    if not session.cookies and not session.headers:
        raise SessionParseError(
            "Tidak ada cookie atau header sesi yang dikenali. "
            "Tempel header Cookie/Authorization atau string cookie."
        )
    return session


def session_from_parts(cookies: object, headers: object) -> TargetSession:
    """Validate an already structured session (JSON API)."""
    session = TargetSession()
    for source, target, label, pattern in (
        (cookies, session.cookies, "cookie", _COOKIE_NAME),
        (headers, session.headers, "header", _HEADER_NAME),
    ):
        if source is None:
            continue
        if not isinstance(source, dict):
            raise SessionParseError(f"Daftar {label} harus berupa objek nama → nilai.")
        for name, value in source.items():
            if not isinstance(name, str) or not pattern.match(name):
                raise SessionParseError(f"Nama {label} tidak valid: {name!r}")
            if not isinstance(value, str):
                raise SessionParseError(f"Nilai {label} {name} harus teks.")
            target[name] = _check_value(value, f"Nilai {label} {name}")
    if not session.cookies and not session.headers:
        raise SessionParseError("Minimal satu cookie atau header harus diisi.")
    return session
