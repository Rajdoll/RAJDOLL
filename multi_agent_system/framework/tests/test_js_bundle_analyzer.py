from pathlib import Path

import httpx
import pytest

from multi_agent_system.framework.js_bundle_analyzer import JSBundleAnalyzer


def test_analyzer_constructs():
    analyzer = JSBundleAnalyzer()
    assert analyzer.cache_path.parent.exists() or analyzer.cache_path.parent.name == "data"


def test_extract_routes_angular():
    fixture = Path(__file__).parent / "fixtures" / "sample_angular_bundle.js"
    js = fixture.read_text()
    analyzer = JSBundleAnalyzer()
    routes = analyzer._extract_routes(js, source_file="main.js")
    paths = {r["path"] for r in routes}
    assert "/login" in paths or "login" in paths
    assert "/admin" in paths or "admin" in paths
    assert "/profile" in paths or "profile" in paths


def test_extract_routes_react():
    fixture = Path(__file__).parent / "fixtures" / "sample_react_bundle.js"
    js = fixture.read_text()
    analyzer = JSBundleAnalyzer()
    routes = analyzer._extract_routes(js, source_file="bundle.js")
    paths = {r["path"] for r in routes}
    assert "/dashboard" in paths
    assert "/settings" in paths


def test_extract_routes_empty_on_garbage():
    analyzer = JSBundleAnalyzer()
    routes = analyzer._extract_routes("alert(1);", source_file="x.js")
    assert routes == []


def test_extract_dependencies_from_es_imports():
    js = """
    import lodash from 'lodash';
    import { useState } from 'react';
    import * as moment from 'moment';
    """
    analyzer = JSBundleAnalyzer()
    deps = analyzer._extract_dependencies(js)
    names = {d["name"] for d in deps}
    assert "lodash" in names
    assert "react" in names
    assert "moment" in names


def test_extract_dependencies_from_webpack_chunks():
    js = """
    /***/ "./node_modules/jquery/dist/jquery.min.js":
    /*!*****************************************!*\\
      !*** ./node_modules/jquery/dist/jquery.min.js ***!
      \\*****************************************/
    /***/ "./node_modules/axios/lib/axios.js":
    """
    analyzer = JSBundleAnalyzer()
    deps = analyzer._extract_dependencies(js)
    names = {d["name"] for d in deps}
    assert "jquery" in names
    assert "axios" in names


def test_extract_dependencies_empty_on_no_match():
    analyzer = JSBundleAnalyzer()
    assert analyzer._extract_dependencies("var x = 1;") == []


from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_osv_query_returns_advisories():
    analyzer = JSBundleAnalyzer()
    mock_response = httpx.Response(
        200,
        json={"vulns": [{"id": "GHSA-xxx", "summary": "RCE", "severity": [{"score": "9.0"}]}]},
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: mock_response)) as client:
        advisories = await analyzer._osv_query(client, "lodash", "4.17.15")
    assert len(advisories) == 1
    assert advisories[0]["id"] == "GHSA-xxx"


@pytest.mark.asyncio
async def test_osv_query_uses_cache(tmp_path):
    analyzer = JSBundleAnalyzer(cache_path=tmp_path / "osv.db")
    # Pre-populate cache
    import json
    import sqlite3
    with sqlite3.connect(analyzer.cache_path) as conn:
        conn.execute(
            "INSERT INTO osv_cache (package, version, advisories_json) VALUES (?, ?, ?)",
            ("lodash", "4.17.15", json.dumps([{"id": "CACHED-1"}])),
        )

    # If httpx raises, we still get cached result
    async def boom(req):
        raise httpx.RequestError("network down")
    async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as client:
        advisories = await analyzer._osv_query(client, "lodash", "4.17.15")
    assert advisories[0]["id"] == "CACHED-1"


@pytest.mark.asyncio
async def test_osv_query_returns_empty_on_network_failure_uncached(tmp_path):
    analyzer = JSBundleAnalyzer(cache_path=tmp_path / "osv.db")
    async def boom(req):
        raise httpx.RequestError("down")
    async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as client:
        advisories = await analyzer._osv_query(client, "unknown-pkg", "1.0.0")
    assert advisories == []
