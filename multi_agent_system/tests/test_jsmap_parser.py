"""Tests for JS source map URL extraction."""
from multi_agent_system.agents.modules.jsmap_parser import extract_urls_from_sourcemap


def test_extract_from_sourcemap_pulls_api_paths():
    sm = {
        "version": 3,
        "sources": ["src/api/users.ts", "src/api/orders.ts"],
        "sourcesContent": [
            "const url = '/api/users/' + id;\nfetch('/api/users/me');",
            "axios.get('/api/orders')\naxios.post('/api/orders/checkout')",
        ],
    }
    urls = extract_urls_from_sourcemap(sm)
    assert "/api/users/me" in urls
    assert "/api/orders" in urls
    assert "/api/orders/checkout" in urls


def test_extract_from_sourcemap_handles_missing_content():
    sm = {"version": 3, "sources": ["a.ts"]}
    assert extract_urls_from_sourcemap(sm) == []
