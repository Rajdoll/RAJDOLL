"""Endpoints that exist only in JavaScript (IPD F5; ported from the legacy JS bundle analyzer and
source-map parser, extended to follow string concatenation and fetch/XHR calls).

Pure functions over source text: no network, so they are easy to test and safe on hostile input
(every regex is linear and inputs are size-capped by the caller).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

MAX_SOURCE = 5_000_000
_STATIC = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|css|map|mp4|webm|mp3|html?)(\?|$)", re.I
)
_QUOTED = r"""(?:"([^"\\\n]{1,300})"|'([^'\\\n]{1,300})'|`([^`\\\n]{1,300})`)"""
_Q = r"""(?:"[^"\\\n]{1,300}"|'[^'\\\n]{1,300}'|`[^`\\\n]{1,300}`)"""
_INTERPOLATION = re.compile(r"\$\{[^{}]{1,80}\}")
_TERM = r"(?:[A-Za-z_$][\w$.]*|" + _Q + ")"
_LITERAL = re.compile(_QUOTED)
_ASSIGN = re.compile(
    r"""\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*""" + _QUOTED + r"\s*[;,\n]"
)
# A whole concatenation chain such as  api + "/pesanan/" + id
_CHAIN = re.compile(_TERM + r"(?:\s*\+\s*" + _TERM + r")+")
_FETCH = re.compile(r"""\bfetch\s*\(\s*(""" + _TERM + r"(?:\s*\+\s*" + _TERM + r")*)\s*(,\s*\{)?")
_AXIOS = re.compile(
    r"""\b(?:axios|\$|http|api)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*("""
    + _TERM
    + r"(?:\s*\+\s*"
    + _TERM
    + r")*)",
    re.I,
)
_XHR = re.compile(
    r"""\.open\s*\(\s*["'](GET|POST|PUT|PATCH|DELETE)["']\s*,\s*("""
    + _TERM
    + r"(?:\s*\+\s*"
    + _TERM
    + r")*)",
    re.I,
)
_METHOD = re.compile(r"""method\s*:\s*["'](\w+)["']""", re.I)
_JSON_BODY = re.compile(r"""JSON\.stringify\s*\(\s*\{([^{}]{0,400})\}""")
_KEY = re.compile(r"""(?:^|,)\s*["']?([A-Za-z_][\w-]{0,63})["']?\s*:""")
_SOURCE_MAP = re.compile(r"""//[#@]\s*sourceMappingURL=([^\s'"]+)""")
_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
_INLINE_SCRIPT = re.compile(r"""<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>""", re.I | re.S)
MAX_OPTIONS = 2000


def _options(source: str, brace: int) -> str:
    """The text of a `{...}` object starting at `brace`, with nested braces (size-capped)."""
    depth = 0
    for index in range(brace, min(len(source), brace + MAX_OPTIONS)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : index]
    return ""


@dataclass
class JsEndpoint:
    method: str
    path: str  # absolute URL or a path starting with "/"
    body_params: list[str] = field(default_factory=list)


def _text(match: re.Match[str], start: int = 1) -> str:
    value = next(g for g in match.groups()[start - 1 : start + 2] if g is not None)
    # Template literal: `/users/${id}` -> /users/{id}
    return _INTERPOLATION.sub("{id}", value) if "${" in value else value


def _looks_like_path(value: str) -> bool:
    if value.startswith(("http://", "https://")):
        return bool(urlsplit(value).hostname) and " " not in value
    if not value.startswith("/") or value.startswith("//") or len(value) < 2:
        return False
    if any(ch in value for ch in " <>{}\\|^") and not re.search(r"\{\w+\}", value):
        return False
    if _STATIC.search(value):
        return False
    # At least one segment with a letter: drops "/" alone, regex fragments, and dates.
    return any(re.search(r"[A-Za-z]{2,}", seg) for seg in value.split("/") if seg)


def _variables(source: str) -> dict[str, str]:
    return {m.group(1): _text(m, 2) for m in _ASSIGN.finditer(source)}


def _resolve(expr: str, variables: dict[str, str]) -> tuple[str | None, set[str]]:
    """A concatenation chain as a path: known variables are substituted, a variable after a
    literal ending in "/" becomes {id}, and an unknown leading variable (an origin) is dropped.
    Also returns the literals the chain used."""
    out = ""
    literals: set[str] = set()
    for index, part in enumerate(p.strip() for p in expr.split("+")):
        literal = _LITERAL.fullmatch(part)
        if literal:
            value = _text(literal)
            literals.add(value)
            out += value
        elif re.fullmatch(r"[A-Za-z_$][\w$.]*", part):
            if part in variables:
                literals.add(variables[part])
                out += variables[part]
            elif out.endswith("/"):
                out += "{id}"
            elif index > 0 and out:
                break  # a query string or suffix built at runtime
        else:
            return None, literals
    out = out.split("?")[0].split("#")[0]
    return (out or None), literals


def extract(source: str) -> list[JsEndpoint]:
    source = source[:MAX_SOURCE]
    variables = _variables(source)
    found: dict[tuple[str, str], JsEndpoint] = {}
    consumed: set[str] = set(variables.values())

    def add(method: str, path: str | None, body: list[str] | None = None) -> None:
        if not path or not _looks_like_path(path):
            return
        key = (method.upper(), path)
        entry = found.setdefault(key, JsEndpoint(method.upper(), path))
        for name in body or []:
            if name not in entry.body_params:
                entry.body_params.append(name)

    for match in _FETCH.finditer(source):
        path, used = _resolve(match.group(1), variables)
        consumed |= used
        method, keys = "GET", []
        if match.group(2):
            options = _options(source, match.end() - 1)
            found_method = _METHOD.search(options)
            method = found_method.group(1) if found_method else "GET"
            body = _JSON_BODY.search(options)
            keys = [k.group(1) for k in _KEY.finditer(body.group(1))] if body else []
        add(method, path, keys)
    for pattern in (_AXIOS, _XHR):
        for match in pattern.finditer(source):
            path, used = _resolve(match.group(2), variables)
            consumed |= used
            add(match.group(1), path)
    for match in _CHAIN.finditer(source):
        path, used = _resolve(match.group(0), variables)
        consumed |= used
        if not any((m, path) in found for m in ("POST", "PUT", "PATCH", "DELETE")):
            add("GET", path)
    # Any other path-looking literal that was not part of a call or a chain.
    for match in _LITERAL.finditer(source):
        value = _text(match)
        if value in consumed:
            continue
        value = value.split("?")[0]
        if value.count("/") >= 2 or "api" in value.lower():
            add("GET", value)
    return list(found.values())


def source_map_url(source: str, script_url: str) -> str | None:
    match = _SOURCE_MAP.search(source[-2000:])
    if not match or match.group(1).startswith("data:"):
        return None
    return urljoin(script_url, match.group(1))


def extract_from_source_map(source_map: dict) -> list[JsEndpoint]:
    endpoints: list[JsEndpoint] = []
    for content in source_map.get("sourcesContent") or []:
        if isinstance(content, str):
            endpoints.extend(extract(content))
    return endpoints


def scripts_in_html(html: str, page_url: str) -> tuple[list[str], list[str]]:
    """External script URLs and inline script bodies of an HTML page."""
    html = html[:MAX_SOURCE]
    external = [urljoin(page_url, src) for src in _SCRIPT_SRC.findall(html)]
    inline = [body for body in _INLINE_SCRIPT.findall(html) if body.strip()]
    return external, inline
