"""Passive OpenAPI / Swagger / GraphQL discovery."""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
)

GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")

INTROSPECTION_QUERY = (
    '{"query":"{__schema{queryType{name} mutationType{name} '
    'types{name fields{name}}}}"}'
)


def parse_openapi_spec(spec: dict) -> list[dict]:
    out: list[dict] = []
    paths = spec.get("paths") or {}
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
            if method in ops:
                out.append({
                    "path": path,
                    "method": method.upper(),
                    "discovered_by": "R1_openapi",
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
    out: list[dict] = []
    for p in OPENAPI_PATHS:
        try:
            r = await http_client.get(f"{base_url.rstrip('/')}{p}")
            if r.status_code == 200:
                try:
                    spec = r.json() if callable(r.json) else r.json
                except Exception:
                    continue
                if isinstance(spec, dict):
                    out.extend(parse_openapi_spec(spec))
        except Exception as exc:
            log.debug("openapi probe %s failed: %s", p, exc)
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
