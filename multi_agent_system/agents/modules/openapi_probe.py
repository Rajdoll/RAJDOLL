"""Passive OpenAPI / Swagger / GraphQL discovery."""
from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger(__name__)

OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs/swagger.json",
    "/api-docs/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger-ui/swagger.json",
)

GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")

INTROSPECTION_QUERY = (
    '{"query":"{__schema{queryType{name} mutationType{name} '
    'types{name fields{name}}}}"}'
)

_SPEC_URL_RE = re.compile(
    r"""url\s*[:=]\s*["']([^"']+\.(?:json|yaml)[^"']*)["']""",
    re.IGNORECASE,
)


def _extract_spec_url_from_html(html: str) -> str | None:
    """Parse Swagger UI HTML for the embedded spec URL.

    Swagger UI embeds the spec URL as: url: "/path/to/spec.json"
    Returns the first match, or None if not found.
    """
    m = _SPEC_URL_RE.search(html)
    return m.group(1) if m else None


def parse_openapi_spec(spec: dict) -> list[dict]:
    """Parse an OpenAPI/Swagger spec dict into endpoint records with rich metadata."""
    out: list[dict] = []
    paths = spec.get("paths") or {}
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
            if method not in ops:
                continue
            op = ops[method]
            params = op.get("parameters") or []
            param_names = [p.get("name", "") for p in params if isinstance(p, dict)]
            consumes = op.get("consumes") or spec.get("consumes") or []
            content_type = consumes[0] if consumes else "application/json"
            out.append({
                "path": path,
                "method": method.upper(),
                "discovered_by": "R1_openapi",
                "response_signature": {
                    "status": 200,
                    "content_type": content_type,
                    "sample_keys": param_names,
                },
            })
    return out


def parse_graphql_introspection(schema: dict, graphql_path: str) -> list[dict]:
    out: list[dict] = []
    types = (schema.get("data") or {}).get("__schema", {}).get("types") or []
    for t in types:
        if t.get("name") not in ("Query", "Mutation"):
            continue
        for field in t.get("fields") or []:
            out.append({
                "path": graphql_path,
                "method": "POST",
                "graphql_field": field.get("name"),
                "graphql_root": t["name"],
                "discovered_by": "R1_graphql",
            })
    return out


async def probe_openapi(base_url: str, http_client) -> list[dict]:
    """Probe for OpenAPI/Swagger specs. Follows Swagger UI HTML to embedded spec URL."""
    out: list[dict] = []
    probed: set[str] = set()

    async def _try_fetch_spec(url: str) -> list[dict]:
        if url in probed:
            return []
        probed.add(url)
        try:
            r = await http_client.get(url)
            if r.status_code != 200:
                return []
            ct = r.headers.get("content-type", "")
            if "html" in ct:
                spec_path = _extract_spec_url_from_html(r.text)
                if spec_path:
                    spec_url = (
                        spec_path if spec_path.startswith("http")
                        else f"{base_url.rstrip('/')}{spec_path}"
                    )
                    return await _try_fetch_spec(spec_url)
                return []
            try:
                spec = r.json() if callable(r.json) else r.json
            except Exception:
                return []
            if isinstance(spec, dict):
                return parse_openapi_spec(spec)
        except Exception as exc:
            log.debug("openapi probe %s failed: %s", url, exc)
        return []

    for p in OPENAPI_PATHS:
        endpoints = await _try_fetch_spec(f"{base_url.rstrip('/')}{p}")
        out.extend(endpoints)
        if out:
            break  # Found a valid spec - stop probing

    return out


async def probe_graphql_introspection(base_url: str, http_client) -> list[dict]:
    out: list[dict] = []
    for gpath in GRAPHQL_PATHS:
        try:
            r = await http_client.post(
                f"{base_url.rstrip('/')}{gpath}",
                content=INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
            )
            if r.status_code == 200:
                try:
                    body = r.json() if callable(r.json) else r.json
                except Exception:
                    continue
                if isinstance(body, dict) and "data" in body:
                    out.extend(parse_graphql_introspection(body, gpath))
        except Exception as exc:
            log.debug("graphql probe %s failed: %s", gpath, exc)
    return out
