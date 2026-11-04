"""Sending test requests and keeping them as evidence (BSD 6.2, 6.3).

`Injection` describes one parameter of one endpoint; `Injection.send(client, value)` sends the
endpoint's request with that parameter set to `value` and returns the response with an
`Exchange` (raw request and response). Session headers are masked in evidence: findings and
reports show `[sesi akun]` instead of cookies or tokens.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx

from rajdoll.modules.base import Exchange

MASKED_HEADERS = {"cookie", "authorization", "proxy-authorization", "x-api-key"}
MASK = "[sesi akun]"
_PLACEHOLDER = re.compile(r"\{[^{}/]+\}")
MAX_RESPONSE = 1_048_576


def concrete_url(url: str) -> str:
    """A path template (`/akun/{id}`) as a requestable URL (`/akun/1`)."""
    return _PLACEHOLDER.sub("1", url)


def default_value(name: str) -> str:
    lowered = name.lower()
    if lowered.endswith("id") or lowered in ("id", "page", "limit", "qty", "jumlah", "harga"):
        return "1"
    if lowered in ("url", "uri", "link", "next", "redirect", "return", "callback", "dest"):
        return "/"
    if "mail" in lowered:
        return "rajdoll@contoh.test"
    return "rajdoll"


def raw_request(request: httpx.Request, mask: str = MASK) -> str:
    """The request as raw HTTP/1.1 text; session headers show `mask` (for example
    `[sesi Akun B]` when the account matters, as in authorization tests)."""
    target = request.url.raw_path.decode("ascii", errors="replace")
    lines = [f"{request.method} {target} HTTP/1.1", f"Host: {request.url.netloc.decode()}"]
    for name, value in request.headers.items():
        if name.lower() in ("host", "content-length", "accept-encoding", "connection"):
            continue
        lines.append(f"{name}: {mask if name.lower() in MASKED_HEADERS else value}")
    try:
        content = request.content
    except httpx.RequestNotRead:  # multipart bodies are streamed
        content = request.read()
    body = content.decode("utf-8", errors="replace") if content else ""
    return "\r\n".join(lines) + "\r\n\r\n" + body


def mask_set_cookie(value: str) -> str:
    """A Set-Cookie value with the cookie's value masked and its attributes kept."""
    name, _, rest = value.partition("=")
    _value, sep, attributes = rest.partition(";")
    return f"{name}={MASK}{sep}{attributes}"


def raw_response(response: httpx.Response) -> str:
    lines = [f"HTTP/1.1 {response.status_code} {response.reason_phrase}"]
    for name, value in response.headers.multi_items():
        if name.lower() == "set-cookie":
            value = mask_set_cookie(value)
        lines.append(f"{name}: {value}")
    return "\r\n".join(lines) + "\r\n\r\n" + response.text[:MAX_RESPONSE]


_HEADER_LINE = re.compile(r"^([A-Za-z0-9-]+):[ \t]*(.*)$")


def mask_raw(text: str) -> str:
    """Session headers in a raw request or response from a tool, masked like `raw_request`."""
    lines = text.split("\n")
    for index, line in enumerate(lines):
        if not line.strip("\r"):
            break  # end of the header block
        match = _HEADER_LINE.match(line.rstrip("\r"))
        if not match:
            continue
        name = match.group(1).lower()
        end = "\r" if line.endswith("\r") else ""
        if name in MASKED_HEADERS:
            lines[index] = f"{match.group(1)}: {MASK}{end}"
        elif name == "set-cookie":
            lines[index] = f"{match.group(1)}: {mask_set_cookie(match.group(2))}{end}"
    return "\n".join(lines)


@dataclass(frozen=True)
class Injection:
    """One parameter of one endpoint, with the endpoint's other parameters at default values."""

    method: str
    url: str  # concrete URL without the query string
    parameter: str
    location: str  # query | form | json | multipart
    query: dict[str, str] = field(default_factory=dict)
    body: dict[str, str] = field(default_factory=dict)
    body_location: str | None = None  # form | json | multipart

    def request_parts(self, value: str) -> tuple[dict[str, str], dict[str, str]]:
        query, body = dict(self.query), dict(self.body)
        if self.location == "query":
            query[self.parameter] = value
        else:
            body[self.parameter] = value
        return query, body

    def send(
        self,
        client: httpx.Client,
        value: str,
        headers: dict[str, str] | None = None,
        note: str | None = None,
    ) -> tuple[httpx.Response, Exchange]:
        query, body = self.request_parts(value)
        kwargs: dict[str, Any] = {"params": query or None, "headers": headers or {}}
        if self.method != "GET" and body:
            if self.body_location == "json":
                kwargs["json"] = body
            elif self.body_location == "multipart":
                kwargs["files"] = {k: (None, v) for k, v in body.items()}
            else:
                kwargs["data"] = body
        response = client.request(self.method, self.url, **kwargs)
        exchange = Exchange(
            raw_request(response.request), raw_response(response), response.status_code, note
        )
        return response, exchange

    @property
    def tool_location(self) -> str | None:
        """Where the tools' request spec carries the parameter (None for multipart)."""
        if self.location == "query":
            return "query"
        return "body" if self.body_location in ("form", "json") else None

    def request_spec(self, value: str | None = None) -> dict[str, Any]:
        """The request as the injection tools take it (tools/runner/adapters/request.py)."""
        query, body = self.request_parts(value) if value is not None else (self.query, self.body)
        spec: dict[str, Any] = {"method": self.method, "url": self.url, "query": dict(query)}
        if self.method != "GET" and body and self.body_location in ("form", "json"):
            spec["body"] = dict(body)
            spec["body_encoding"] = self.body_location
        return spec

    def poc(self, value: str, validator: str, **params: Any) -> dict[str, Any]:
        """BSD 6.2 PoC spec: path relative to the target, no session (taken at run time)."""
        query, body = self.request_parts(value)
        parts = urlsplit(self.url)
        encoding = "none"
        payload: Any = None
        if self.method != "GET" and body:
            encoding = {"json": "json", "multipart": "multipart"}.get(
                self.body_location or "", "form"
            )
            payload = body
        return {
            "method": self.method,
            "path": parts.path or "/",
            "query": query,
            "headers": {},
            "body": payload,
            "body_encoding": encoding,
            "account": None,
            "validator": validator,
            "validator_params": {"parameter": self.parameter, "location": self.location, **params},
        }


def injections(endpoint: dict[str, Any], values: dict[str, str] | None = None) -> list[Injection]:
    """Every parameter of an inventory endpoint as an injection point. `values` replaces the
    built-in normal values (for example realistic values from the LLM's `build_input`)."""
    chosen = values or {}

    def normal(name: str) -> str:
        return chosen.get(name) or default_value(name)

    method = endpoint["method"]
    url = concrete_url(endpoint["url"])
    query = {name: normal(name) for name in endpoint.get("query_params") or []}
    body_params = [p for p in endpoint.get("body_params") or [] if p.get("name")]
    body = {p["name"]: normal(p["name"]) for p in body_params}
    locations = {p.get("location") for p in body_params}
    body_location = (
        "json"
        if "json" in locations
        else ("multipart" if "multipart" in locations else ("form" if body_params else None))
    )
    points = [Injection(method, url, name, "query", query, body, body_location) for name in query]
    points += [
        Injection(method, url, p["name"], body_location or "form", query, body, body_location)
        for p in body_params
        if p.get("location") != "multipart" or "file" not in p["name"].lower()
    ]
    return points


def from_poc(base_url: str, poc: dict[str, Any]) -> Injection:
    """Rebuild the injection point of a finding from its PoC spec."""
    params = poc.get("validator_params") or {}
    location = params.get("location", "query")
    body = poc.get("body") or {}
    body_location = {"json": "json", "multipart": "multipart", "form": "form"}.get(
        poc.get("body_encoding", "none")
    )
    return Injection(
        method=poc.get("method", "GET"),
        url=base_url.rstrip("/") + poc.get("path", "/"),
        parameter=params.get("parameter", ""),
        location=location,
        query={k: str(v) for k, v in (poc.get("query") or {}).items()},
        body={k: str(v) for k, v in body.items()} if isinstance(body, dict) else {},
        body_location=body_location,
    )


def curl(base_url: str, poc: dict[str, Any]) -> str:
    """The PoC as a curl command (for the finding detail and the report)."""
    url = base_url.rstrip("/") + poc.get("path", "/")
    if poc.get("query"):
        url += "?" + urlencode(poc["query"])
    parts = ["curl", "-i", "-X", poc.get("method", "GET"), _quote(url)]
    for name, value in (poc.get("headers") or {}).items():
        parts += ["-H", _quote(f"{name}: {value}")]
    body = poc.get("body")
    if body is not None:
        if poc.get("body_encoding") == "json":
            parts += [
                "-H",
                _quote("Content-Type: application/json"),
                "--data",
                _quote(json.dumps(body)),
            ]
        elif poc.get("body_encoding") == "multipart":
            for name, value in body.items():
                parts += ["-F", _quote(f"{name}={value}")]
        else:
            parts += ["--data", _quote(urlencode(body))]
    return " ".join(parts)


MULTIPART_BOUNDARY = "----rajdoll-poc"


def raw_from_poc(base_url: str, poc: dict[str, Any]) -> str:
    """The PoC as a raw HTTP/1.1 request, ready to paste into Burp Repeater."""
    parts = urlsplit(base_url)
    target = (parts.path.rstrip("/") + poc.get("path", "/")) or "/"
    if poc.get("query"):
        target += "?" + urlencode(poc["query"])
    lines = [f"{poc.get('method', 'GET')} {target} HTTP/1.1", f"Host: {parts.netloc}"]
    lines += [f"{name}: {value}" for name, value in (poc.get("headers") or {}).items()]
    body = poc.get("body")
    content = ""
    if body is not None:
        encoding = poc.get("body_encoding")
        if encoding == "json":
            content, kind = json.dumps(body), "application/json"
        elif encoding == "multipart":
            chunks = [
                f'--{MULTIPART_BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"'
                f"\r\n\r\n{value}\r\n"
                for name, value in body.items()
            ]
            content = "".join(chunks) + f"--{MULTIPART_BOUNDARY}--\r\n"
            kind = f"multipart/form-data; boundary={MULTIPART_BOUNDARY}"
        else:
            content, kind = urlencode(body), "application/x-www-form-urlencoded"
        lines += [f"Content-Type: {kind}", f"Content-Length: {len(content.encode())}"]
    return "\r\n".join(lines) + "\r\n\r\n" + content


def _quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
