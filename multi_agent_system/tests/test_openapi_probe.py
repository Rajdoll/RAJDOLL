"""Tests for OpenAPI/Swagger/GraphQL probes."""
from unittest.mock import AsyncMock

import pytest

from multi_agent_system.agents.modules.openapi_probe import (
    parse_openapi_spec,
    parse_graphql_introspection,
    probe_openapi,
    probe_graphql_introspection,
)


def test_parse_openapi_v3_spec_extracts_endpoints():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {"get": {}, "post": {}},
            "/users/{id}": {"get": {}, "delete": {}},
        },
    }
    eps = parse_openapi_spec(spec)
    paths = {(e["path"], e["method"]) for e in eps}
    assert ("/users", "GET") in paths
    assert ("/users", "POST") in paths
    assert ("/users/{id}", "GET") in paths
    assert ("/users/{id}", "DELETE") in paths


def test_parse_swagger_v2_spec_extracts_endpoints():
    spec = {"swagger": "2.0", "paths": {"/login": {"post": {}}}}
    eps = parse_openapi_spec(spec)
    assert eps == [{"path": "/login", "method": "POST", "discovered_by": "R1_openapi"}]


def test_parse_graphql_introspection_emits_synthetic_endpoints():
    schema = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {"name": "Query", "fields": [{"name": "user"}, {"name": "orders"}]},
                    {"name": "Mutation", "fields": [{"name": "createOrder"}]},
                ],
            }
        }
    }
    eps = parse_graphql_introspection(schema, graphql_path="/graphql")
    methods = {e["method"] for e in eps}
    paths = {e["path"] for e in eps}
    assert "POST" in methods
    assert "/graphql" in paths
    fields = {e.get("graphql_field") for e in eps}
    assert "user" in fields
    assert "createOrder" in fields


@pytest.mark.asyncio
async def test_probe_openapi_tries_known_paths():
    httpx_mock = AsyncMock()
    httpx_mock.get = AsyncMock(side_effect=[
        AsyncMock(status_code=404),
        AsyncMock(status_code=200, json=lambda: {"openapi": "3.0", "paths": {"/x": {"get": {}}}}),
        AsyncMock(status_code=404),
        AsyncMock(status_code=404),
        AsyncMock(status_code=404),
    ])
    eps = await probe_openapi("https://example.com", httpx_mock)
    assert any(e["path"] == "/x" for e in eps)


@pytest.mark.asyncio
async def test_probe_graphql_returns_empty_on_disabled():
    httpx_mock = AsyncMock()
    httpx_mock.post = AsyncMock(return_value=AsyncMock(status_code=400, json=lambda: {"errors": []}))
    eps = await probe_graphql_introspection("https://example.com", httpx_mock)
    assert eps == []
