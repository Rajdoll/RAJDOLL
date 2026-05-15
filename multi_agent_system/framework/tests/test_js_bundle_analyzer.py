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
