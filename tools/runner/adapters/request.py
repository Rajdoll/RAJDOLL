"""One HTTP request with named parameters, shared by the injection tools (sqlmap, commix, dalfox).

The worker sends the endpoint's request as structured fields (never as a command line); the
adapters rebuild the URL and body from them and mark the parameter under test.
"""

import json
from typing import Literal
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tools.runner.adapters.base import http_url

MAX_FIELD = 4096
_FORBIDDEN = {chr(c) for c in range(0x20)} | {"\x7f"}


def _clean(values: dict[str, str]) -> dict[str, str]:
    if len(values) > 50:
        raise ValueError("too many parameters")
    for name, value in values.items():
        if not name or len(name) > 256 or len(value) > MAX_FIELD:
            raise ValueError("parameter name or value too long")
        if set(name) & _FORBIDDEN or set(value) & _FORBIDDEN:
            raise ValueError("control characters are not allowed")
    return values


class RequestSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    url: str  # without query string
    query: dict[str, str] = {}
    body: dict[str, str] | None = None
    body_encoding: Literal["form", "json"] = "form"

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        value = http_url(value)
        parts = urlsplit(value)
        if parts.query or parts.fragment or "*" in value:
            raise ValueError("url must not contain a query string, fragment, or '*'")
        return value

    @field_validator("query", "body")
    @classmethod
    def _fields(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        return None if value is None else _clean(value)


def _encode(values: dict[str, str], marked: str | None, marker: str) -> str:
    return "&".join(
        f"{quote(name, safe='')}={quote(value, safe='')}" + (marker if name == marked else "")
        for name, value in values.items()
    )


class MarkedRequest(BaseModel):
    """The request as a tool receives it, with the tested parameter followed by `marker`."""

    url: str
    data: str | None
    # The marked string (url or data) around the injected value: payload = prefix + value + suffix.
    prefix: str
    suffix: str
    place: Literal["url", "data"]


def build(spec: RequestSpec) -> tuple[str, str | None]:
    """The request's URL (with query string) and body text."""
    query = _encode(spec.query, None, "")
    url = spec.url + (f"?{query}" if query else "")
    if spec.body is None:
        return url, None
    if spec.body_encoding == "json":
        return url, json.dumps(spec.body, ensure_ascii=False)
    return url, _encode(spec.body, None, "")


def _shown(value: str, json_body: bool) -> str:
    """How a value appears in the encoded URL or body."""
    return json.dumps(value, ensure_ascii=False)[1:-1] if json_body else quote(value, safe="")


def mark(
    spec: RequestSpec, parameter: str, location: Literal["query", "body"], marker: str
) -> MarkedRequest:
    """Build URL and body with `marker` right after the tested parameter's value."""
    query = _encode(spec.query, parameter if location == "query" else None, marker)
    url = spec.url + (f"?{query}" if query else "")
    data = None
    json_body = spec.body_encoding == "json"
    if spec.body is not None:
        if json_body:
            body = {k: v + marker if location == "body" and k == parameter else v
                    for k, v in spec.body.items()}  # fmt: skip
            data = json.dumps(body, ensure_ascii=False)
        else:
            data = _encode(spec.body, parameter if location == "body" else None, marker)
    if location == "query":
        marked, place, value = url, "url", _shown(spec.query[parameter], False)
    else:
        body_fields = spec.body or {}
        marked, place, value = data or "", "data", _shown(body_fields[parameter], json_body)
    index = marked.index(marker)
    return MarkedRequest(
        url=url,
        data=data,
        prefix=marked[: index - len(value)],
        suffix=marked[index + len(marker) :],
        place=place,
    )


def injected_value(marked: dict[str, str], payload: str) -> str | None:
    """The tested parameter's value inside a tool's payload (the marked string, injected)."""
    prefix, suffix = marked["prefix"], marked["suffix"]
    if (
        payload.startswith(prefix)
        and payload.endswith(suffix)
        and len(payload) >= len(prefix) + len(suffix)
    ):
        return payload[len(prefix) : len(payload) - len(suffix)]
    return None


def check_parameter(spec: RequestSpec, parameter: str, location: str) -> None:
    fields = spec.query if location == "query" else (spec.body or {})
    if parameter not in fields:
        raise ValueError(f"parameter {parameter!r} is not in the request {location}")
    for value in [*spec.query.values(), *(spec.body or {}).values()]:
        if "*" in value:
            raise ValueError("values must not contain '*' (the injection marker)")


class InjectionParams(BaseModel):
    """Common fields of the injection tools: the request and the parameter to test."""

    model_config = ConfigDict(extra="forbid")

    request: RequestSpec
    parameter: str = Field(min_length=1, max_length=256)
    location: Literal["query", "body"] = "query"

    @model_validator(mode="after")
    def _parameter(self) -> "InjectionParams":
        check_parameter(self.request, self.parameter, self.location)
        return self
