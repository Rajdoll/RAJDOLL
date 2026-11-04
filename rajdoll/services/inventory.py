"""Endpoint inventory: normalization and de-duplication per engagement (BSD 4.4; IPD F5).

Every recon source (crawl, browser, fuzzing, JavaScript, OpenAPI, Burp paste) reports what it saw
as `EndpointSeen`. Here the URL becomes (method, scheme, host, path template) with parameter
names, and the row is inserted or merged, so one endpoint seen by five tools is one row.
Hosts outside the scope are not stored; they are counted for the checkpoint instead.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from rajdoll.core import scope as scope_rules
from rajdoll.core.models import Endpoint
from rajdoll.modules.base import EndpointSeen

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
# Static files are not test targets. JavaScript stays: the JS analysis and Client-Side use it.
SKIPPED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".map", ".mp4", ".webm", ".mp3", ".pdf",
}  # fmt: skip
_DEFAULT_PORTS = {"http": 80, "https": 443}
_NUMBER = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")
_EXPRESS = re.compile(r"^:([A-Za-z_][A-Za-z0-9_]*)$")
_TEMPLATE = re.compile(r"^\{[^{}/]{1,64}\}$")
MAX_PATH = 2000


@dataclass(frozen=True)
class Normalized:
    method: str
    scheme: str
    host: str
    path_template: str
    query_params: tuple[str, ...]


def _segment(segment: str) -> str:
    decoded = unquote(segment)
    if _NUMBER.match(decoded):
        return "{id}"
    if _UUID.match(decoded):
        return "{uuid}"
    if _HEX.match(decoded):
        return "{hash}"
    express = _EXPRESS.match(decoded)
    if express:
        return "{" + express.group(1) + "}"
    if _TEMPLATE.match(decoded):
        return decoded
    return segment


def normalize(method: str, url: str) -> Normalized | None:
    """None for URLs that are not stored (not http(s), static files, unknown methods)."""
    method = (method or "GET").upper()
    if method not in METHODS:
        return None
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()
    if scheme not in _DEFAULT_PORTS or not hostname:
        return None
    path = parts.path or "/"
    if any(path.lower().endswith(ext) for ext in SKIPPED_EXTENSIONS) or len(path) > MAX_PATH:
        return None
    segments = [_segment(s) for s in path.split("/") if s]
    template = "/" + "/".join(segments)
    host = hostname if port in (None, _DEFAULT_PORTS[scheme]) else f"{hostname}:{port}"
    params = tuple(sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True)}))
    return Normalized(method, scheme, host, template, params)


def url_of(endpoint: Endpoint | dict[str, Any]) -> str:
    get = endpoint.get if isinstance(endpoint, dict) else lambda k: getattr(endpoint, k)
    return f"{get('scheme')}://{get('host')}{get('path_template')}"


@dataclass
class RecordResult:
    added: int = 0
    updated: int = 0
    out_of_scope: Counter[str] = field(default_factory=Counter)


def _merge_body(old: list[dict[str, Any]], new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = {(p.get("name"), p.get("location")) for p in old}
    merged = list(old)
    for param in new:
        key = (param.get("name"), param.get("location"))
        if param.get("name") and key not in seen:
            seen.add(key)
            merged.append(dict(param))
    return merged


def exclusion_reason(
    path_template: str, query_params: list[str] | tuple[str, ...], patterns: list[str]
) -> str | None:
    """`pattern:<p>` when the path or a parameter name contains an exclusion pattern (TRD 3.4)."""
    haystacks = [path_template.lower(), *(name.lower() for name in query_params)]
    for pattern in patterns:
        needle = pattern.lower().strip()
        if needle and any(needle in text for text in haystacks):
            return f"pattern:{pattern}"
    return None


def record(
    session: Session,
    engagement_id: int,
    scan_id: int | None,
    seen: list[EndpointSeen],
    scope: list[str],
    exclude_patterns: list[str] | None = None,
) -> RecordResult:
    """Insert new endpoints and merge parameters into known ones.

    New endpoints matching an exclusion pattern are stored as excluded; an assessor's later
    decision on a known endpoint is never overwritten.
    """
    result = RecordResult()
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in seen:
        norm = normalize(item.method, item.url)
        if norm is None:
            continue
        hostname = norm.host.rsplit(":", 1)[0] if ":" in norm.host else norm.host
        if not scope_rules.in_scope(scope, hostname):
            result.out_of_scope[hostname] += 1
            continue
        key = (norm.method, norm.host, norm.path_template)
        entry = grouped.setdefault(
            key,
            {
                "scheme": norm.scheme,
                "query_params": set(),
                "body_params": [],
                "content_type": None,
                "source": item.source,
            },
        )
        entry["query_params"].update(norm.query_params, item.query_params)
        entry["body_params"] = _merge_body(
            entry["body_params"], [dict(p) for p in item.body_params]
        )
        entry["content_type"] = entry["content_type"] or item.content_type
    if not grouped:
        return result

    existing = {
        (e.method, e.host, e.path_template): e
        for e in session.scalars(
            select(Endpoint).where(Endpoint.engagement_id == engagement_id).with_for_update()
        )
        if (e.method, e.host, e.path_template) in grouped
    }
    for key, entry in grouped.items():
        method, host, template = key
        row = existing.get(key)
        if row is None:
            reason = exclusion_reason(
                template, sorted(entry["query_params"]), exclude_patterns or []
            )
            # ON CONFLICT: two workers may record the same endpoint at once.
            inserted = session.execute(
                insert(Endpoint)
                .values(
                    engagement_id=engagement_id,
                    method=method,
                    scheme=entry["scheme"],
                    host=host,
                    path_template=template,
                    query_params=sorted(entry["query_params"]),
                    body_params=entry["body_params"],
                    content_type=entry["content_type"],
                    source=entry["source"],
                    excluded=reason is not None,
                    exclude_reason=reason,
                    first_seen_scan_id=scan_id,
                    last_seen_scan_id=scan_id,
                )
                .on_conflict_do_nothing()
                .returning(Endpoint.id)
            ).scalar()
            if inserted is not None:
                result.added += 1
                continue
            row = session.scalars(
                select(Endpoint).where(
                    Endpoint.engagement_id == engagement_id,
                    Endpoint.method == method,
                    Endpoint.host == host,
                    Endpoint.path_template == template,
                )
            ).one()
        params = sorted(set(row.query_params) | entry["query_params"])
        body = _merge_body(list(row.body_params or []), entry["body_params"])
        changed = params != list(row.query_params) or body != list(row.body_params or [])
        row.query_params = params
        row.body_params = body
        row.content_type = row.content_type or entry["content_type"]
        if scan_id is not None and row.last_seen_scan_id != scan_id:
            row.last_seen_scan_id = scan_id
            changed = True
        if changed:
            result.updated += 1
    session.flush()
    return result


def list_for(session: Session, engagement_id: int) -> list[Endpoint]:
    return list(
        session.scalars(
            select(Endpoint)
            .where(Endpoint.engagement_id == engagement_id)
            .order_by(Endpoint.host, Endpoint.path_template, Endpoint.method)
        )
    )


def as_dict(endpoint: Endpoint) -> dict[str, Any]:
    return {
        "id": endpoint.id,
        "method": endpoint.method,
        "scheme": endpoint.scheme,
        "host": endpoint.host,
        "path_template": endpoint.path_template,
        "url": url_of(endpoint),
        "query_params": list(endpoint.query_params),
        "body_params": list(endpoint.body_params or []),
        "content_type": endpoint.content_type,
        "source": endpoint.source,
        "tags": list(endpoint.tags),
        "tag_source": endpoint.tag_source,
        "excluded": endpoint.excluded,
        "exclude_reason": endpoint.exclude_reason,
    }


def count_for(session: Session, engagement_id: int) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(Endpoint)
            .where(Endpoint.engagement_id == engagement_id)
        )
        or 0
    )


def merge_recon(current: dict[str, Any] | None, data: dict[str, Any]) -> dict[str, Any]:
    """Merge recon facts: lists without duplicates, host counts summed, other values replaced."""
    import json

    merged = dict(current or {})
    for key, value in data.items():
        if key == "out_of_scope_hosts" and isinstance(value, dict):
            counts = dict(merged.get(key) or {})
            for host, count in value.items():
                counts[host] = counts.get(host, 0) + int(count)
            merged[key] = counts
        elif isinstance(value, list):
            existing = list(merged.get(key) or [])
            seen = {json.dumps(item, sort_keys=True) for item in existing}
            for item in value:
                marker = json.dumps(item, sort_keys=True)
                if marker not in seen:
                    seen.add(marker)
                    existing.append(item)
            merged[key] = existing
        elif isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged
