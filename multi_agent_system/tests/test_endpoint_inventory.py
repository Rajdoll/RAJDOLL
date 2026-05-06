"""Tests for endpoint inventory schema and helpers."""
from multi_agent_system.core.endpoint_inventory import (
    TAXONOMY,
    AGENT_TAG_MAP,
    build_inventory,
    read_tag,
    resolve_placeholders,
    SCHEMA_VERSION,
)


def test_taxonomy_has_14_tags():
    assert len(TAXONOMY) == 14
    assert "idor_candidate" in TAXONOMY
    assert "state_changing_money" in TAXONOMY
    assert "auth_token_endpoint" in TAXONOMY


def test_agent_tag_map_covers_consumers():
    assert AGENT_TAG_MAP["AuthorizationAgent"] == ["idor_candidate", "admin_panel"]
    assert AGENT_TAG_MAP["BusinessLogicAgent"] == [
        "state_changing_money",
        "state_changing_resource",
    ]
    assert AGENT_TAG_MAP["FileUploadAgent"] == ["file_upload"]


def test_build_inventory_creates_by_tag_index():
    endpoints = [
        {
            "id": "ep_001",
            "path": "/api/Users/{id}",
            "method": "GET",
            "auth_required": True,
            "discovered_by": "R2_auth_crawl",
            "response_signature": {"status": 200, "content_type": "application/json", "sample_keys": ["id", "email"]},
            "tags": ["idor_candidate", "user_profile"],
            "tag_confidence": {"idor_candidate": 0.91, "user_profile": 0.95},
        },
        {
            "id": "ep_002",
            "path": "/login",
            "method": "POST",
            "auth_required": False,
            "discovered_by": "R1_passive",
            "response_signature": {"status": 200, "content_type": "application/json", "sample_keys": ["token"]},
            "tags": ["user_login", "auth_token_endpoint"],
            "tag_confidence": {"user_login": 0.99, "auth_token_endpoint": 0.93},
        },
    ]
    inv = build_inventory(endpoints, stats={"by_phase": {"R1": 1, "R2": 1}})
    assert inv["version"] == SCHEMA_VERSION
    assert inv["stats"]["total_endpoints"] == 2
    assert inv["by_tag"]["idor_candidate"] == ["ep_001"]
    assert inv["by_tag"]["user_login"] == ["ep_002"]
    assert "discovered_at" in inv


def test_read_tag_returns_endpoint_records():
    endpoints = [
        {"id": "ep_001", "path": "/a", "method": "GET", "tags": ["idor_candidate"]},
        {"id": "ep_002", "path": "/b", "method": "GET", "tags": ["api_generic"]},
    ]
    inv = build_inventory(endpoints)
    eps = read_tag(inv, "idor_candidate")
    assert len(eps) == 1
    assert eps[0]["id"] == "ep_001"
    assert read_tag(inv, "admin_panel") == []  # missing tag returns empty list


def test_resolve_placeholders_substitutes_real_ids():
    eps = [{"path": "/api/Users/{id}", "method": "GET"}]
    captured = {"/api/Users/": ["1", "42"]}  # captured during R2 crawl
    out = resolve_placeholders(eps, captured)
    assert out[0]["path"] == "/api/Users/1"  # picks first captured value
