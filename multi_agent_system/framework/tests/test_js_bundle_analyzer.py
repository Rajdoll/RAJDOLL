from pathlib import Path

import httpx
import pytest

from multi_agent_system.framework.js_bundle_analyzer import JSBundleAnalyzer


def test_analyzer_constructs():
    analyzer = JSBundleAnalyzer()
    assert analyzer is not None


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


@pytest.mark.asyncio
async def test_analyze_end_to_end():
    analyzer = JSBundleAnalyzer()
    homepage_html = """
    <html><body>
      <script src="/static/js/main.bundle.js"></script>
    </body></html>
    """
    main_js = "RouterModule.forRoot([{path:'admin',component:X}]);"

    responses = {
        "http://target.test/": httpx.Response(200, text=homepage_html),
        "http://target.test/static/js/main.bundle.js": httpx.Response(200, text=main_js),
    }
    def handler(req):
        return responses.get(str(req.url), httpx.Response(404))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await analyzer.analyze("http://target.test/", client)

    paths = {r["path"] for r in result["routes"]}
    assert "/admin" in paths


@pytest.mark.asyncio
async def test_analyze_returns_empty_for_non_spa():
    analyzer = JSBundleAnalyzer()
    def handler(req):
        return httpx.Response(200, text="<html><body>no scripts here</body></html>")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await analyzer.analyze("http://target.test/", client)
    assert result["routes"] == []
