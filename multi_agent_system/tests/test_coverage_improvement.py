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


import asyncio
import json
from unittest.mock import AsyncMock, patch


def test_wordlist_catalog_structure():
    from multi_agent_system.core.wordlist_catalog import WORDLIST_CATALOG
    assert "always" in WORDLIST_CATALOG
    assert "tech_specific" in WORDLIST_CATALOG
    assert "deep" in WORDLIST_CATALOG
    assert isinstance(WORDLIST_CATALOG["always"], list)
    assert isinstance(WORDLIST_CATALOG["tech_specific"], dict)
    assert len(WORDLIST_CATALOG["always"]) >= 1


def test_generate_strategic_plan_parses_valid_response():
    from multi_agent_system.utils.simple_llm_client import SimpleLLMClient

    client = SimpleLLMClient.__new__(SimpleLLMClient)
    client.provider = "openai"
    client.model = "gpt-4o-mini"
    client._strip_thinking_tags = lambda x: x

    llm_response = json.dumps({
        "focus_instructions": {
            "AuthenticationAgent": "Test JWT forgery on /rest/user/login",
            "InputValidationAgent": "Test SQLi on /rest/products/search?q=",
        },
        "inject_tools": {
            "AuthorizationAgent": [{"tool": "test_idor", "arguments": {"endpoint": "/api/Users/1"}}],
        },
        "wordlists": ["/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"],
        "reasoning": "Login endpoint found; SQLi and auth bypass are high priority."
    })

    async def _run():
        with patch.object(client, "chat_completion", new=AsyncMock(return_value=llm_response)):
            return await client.generate_strategic_plan(
                recon_summary="Found /rest/user/login and /api/Users endpoints.",
                endpoint_inventory={"by_tag": {"user_login": ["ep_001"], "api_generic": ["ep_002"]}},
                tech_stack={"frontend": "React", "backend": "Node.js"},
                remaining_agents=["AuthenticationAgent", "InputValidationAgent", "AuthorizationAgent"],
                wordlist_catalog={"always": [], "tech_specific": {}, "deep": []},
            )

    result = asyncio.run(_run())
    assert result is not None
    assert "AuthenticationAgent" in result.focus_instructions
    assert "AuthorizationAgent" in result.inject_tools
    assert len(result.inject_tools["AuthorizationAgent"]) == 1
    assert hasattr(result, "wordlists")
    assert isinstance(result.wordlists, list)
