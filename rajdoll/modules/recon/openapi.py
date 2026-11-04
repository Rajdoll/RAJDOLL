"""OpenAPI/Swagger and GraphQL discovery (ported from the legacy openapi_probe, with request body
and parameter locations kept for the inventory)."""

from __future__ import annotations

import re
from typing import Any

import yaml

SPEC_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api-docs/swagger.json",
    "/api-docs/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger-ui/index.html",
    "/swagger/index.html",
)
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")
INTROSPECTION = {"query": "{__schema{queryType{name} mutationType{name}}}"}
METHODS = ("get", "post", "put", "patch", "delete", "options", "head")
MAX_SPEC = 5_000_000
_SPEC_URL = re.compile(r"""url\s*[:=]\s*["']([^"']+\.(?:json|ya?ml)[^"']*)["']""", re.I)


def spec_url_in_html(html: str) -> str | None:
    """Swagger UI pages embed the spec URL as `url: "/path/spec.json"`."""
    match = _SPEC_URL.search(html[:MAX_SPEC])
    return match.group(1) if match else None


def load_spec(text: str) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(text[:MAX_SPEC])  # JSON is valid YAML
    except yaml.YAMLError:
        return None
    if (
        isinstance(data, dict)
        and isinstance(data.get("paths"), dict)
        and ("openapi" in data or "swagger" in data)
    ):
        return data
    return None


def _schema_properties(schema: Any, spec: dict[str, Any], depth: int = 0) -> list[str]:
    if not isinstance(schema, dict) or depth > 3:
        return []
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        node: Any = spec
        for part in ref[2:].split("/"):
            node = node.get(part) if isinstance(node, dict) else None
        return _schema_properties(node, spec, depth + 1)
    props = schema.get("properties")
    return [str(name) for name in props] if isinstance(props, dict) else []


def endpoints_from_spec(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """[{method, path, query_params, body_params, content_type}] from OpenAPI 2 or 3."""
    base = ""
    if spec.get("swagger") and isinstance(spec.get("basePath"), str):
        base = spec["basePath"].rstrip("/")
    out = []
    for path, operations in spec["paths"].items():
        if not isinstance(operations, dict) or not isinstance(path, str):
            continue
        shared = operations.get("parameters") or []
        for method in METHODS:
            operation = operations.get(method)
            if not isinstance(operation, dict):
                continue
            params = [
                p for p in [*shared, *(operation.get("parameters") or [])] if isinstance(p, dict)
            ]
            query = sorted({str(p.get("name")) for p in params if p.get("in") == "query"})
            body: list[dict[str, str]] = [
                {"name": str(p.get("name")), "location": "form"}
                for p in params
                if p.get("in") == "formData"
            ]
            content_type = None
            content = (operation.get("requestBody") or {}).get("content") or {}
            if isinstance(content, dict) and content:
                content_type = next(iter(content))
                location = (
                    "multipart"
                    if "multipart" in content_type
                    else ("form" if "urlencoded" in content_type else "json")
                )
                schema = (content[content_type] or {}).get("schema")
                body += [
                    {"name": n, "location": location} for n in _schema_properties(schema, spec)
                ]
            for p in params:
                if p.get("in") == "body":
                    content_type = content_type or "application/json"
                    body += [
                        {"name": n, "location": "json"}
                        for n in _schema_properties(p.get("schema"), spec)
                    ]
            out.append(
                {
                    "method": method.upper(),
                    "path": base + path,
                    "query_params": query,
                    "body_params": body,
                    "content_type": content_type,
                }
            )
    return out


def graphql_answered(body: Any) -> bool:
    return isinstance(body, dict) and isinstance(body.get("data"), dict)
