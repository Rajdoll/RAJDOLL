"""Parse a raw HTTP request pasted from Burp (AFD A5: "tempel request mentah dari Burp")."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from rajdoll.services.errors import ValidationFailed

MAX_RAW = 1_000_000
_REQUEST_LINE = re.compile(r"^([A-Z]{3,10})\s+(\S+)\s+HTTP/\d(?:\.\d)?$")
_HEADER = re.compile(r"^([!#$%&'*+.^_`|~0-9A-Za-z-]+):\s*(.*)$")
# `name="x"` of a part, not the `filename="..."` next to it.
_MULTIPART_NAME = re.compile(r'(?:^|[;\s])name="([^"]{1,128})"')


@dataclass
class RawRequest:
    method: str
    url: str
    content_type: str | None
    body_params: list[dict[str, str]] = field(default_factory=list)


def _error(message: str) -> ValidationFailed:
    return ValidationFailed.one("raw_request", message)


def parse(raw: str, default_scheme: str = "https") -> RawRequest:
    """Method, absolute URL, and body parameter names of a pasted request."""
    if len(raw) > MAX_RAW:
        raise _error("Request terlalu besar (maksimal 1 MB).")
    text = raw.replace("\r\n", "\n").lstrip("\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    match = _REQUEST_LINE.match(lines[0].strip())
    if not match:
        raise _error("Baris pertama harus berupa request line, misalnya 'GET /path HTTP/1.1'.")
    method, target = match.groups()
    headers: dict[str, str] = {}
    for line in lines[1:]:
        header = _HEADER.match(line.strip())
        if header:
            headers[header.group(1).lower()] = header.group(2).strip()
    if target.startswith(("http://", "https://")):
        url = target
    else:
        host = headers.get("host")
        if not host or not target.startswith("/"):
            raise _error("Header Host tidak ada; tidak bisa menentukan URL endpoint.")
        url = f"{default_scheme}://{host}{target}"
    if not urlsplit(url).hostname:
        raise _error("URL endpoint tidak valid.")

    content_type = headers.get("content-type")
    params: list[dict[str, str]] = []
    body = body.strip()
    ctype = (content_type or "").lower()
    if body and "json" in ctype:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            params = [{"name": str(k), "location": "json"} for k in data]
    elif body and "multipart" in ctype:
        names = dict.fromkeys(_MULTIPART_NAME.findall(body))
        params = [{"name": n, "location": "multipart"} for n in names]
    elif body and ("urlencoded" in ctype or not ctype):
        names = dict.fromkeys(k for k, _ in parse_qsl(body, keep_blank_values=True))
        params = [{"name": n, "location": "form"} for n in names]
    return RawRequest(method=method, url=url, content_type=content_type, body_params=params)
