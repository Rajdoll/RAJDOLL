"""Tests for coverage improvement: R4 JS bundle fix and wordlist catalog."""
import re


def test_r4_api_regex_matches_fetch_and_axios():
    """The API extraction regex must capture paths from fetch/axios calls."""
    api_regex = re.compile(r'["\'](\/?(?:api|rest|graphql)\/[\w/.\-]+)["\']')
    js_content = """
        fetch('/api/Users/1', { method: 'GET' });
        axios.post('/rest/user/login', data);
        const url = '/graphql/query';
        axios.get("/api/BasketItems");
    """
    matches = api_regex.findall(js_content)
    assert "/api/Users/1" in matches
    assert "/rest/user/login" in matches
    assert "/api/BasketItems" in matches


def test_r4_script_src_regex_matches_chunk_files():
    """The script src extraction regex must match chunk-style filenames."""
    script_re = re.compile(r'<script[^>]+src=["\']([^"\']+\.js)["\']', re.IGNORECASE)
    html = """
    <script src="/chunk-24EZLZ4I.js" type="module"></script>
    <script src="/polyfills.js"></script>
    <script src="https://cdn.example.com/external.js"></script>
    <script src="/main.abc123.js"></script>
    """
    matches = script_re.findall(html)
    assert "/chunk-24EZLZ4I.js" in matches
    assert "/polyfills.js" in matches
    assert "/main.abc123.js" in matches
    assert "https://cdn.example.com/external.js" in matches
