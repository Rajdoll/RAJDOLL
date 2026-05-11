import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_tag_endpoints_with_subtests_returns_dict():
    from multi_agent_system.utils.simple_llm_client import SimpleLLMClient
    client = SimpleLLMClient.__new__(SimpleLLMClient)
    client._strip_thinking_tags = lambda x: x

    mock_response = json.dumps({
        "http://t/api/products": ["WSTG-INPV-05"],
        "http://t/rest/user/login": ["WSTG-ATHN-01", "WSTG-INPV-05"],
    })
    client.chat_completion = AsyncMock(return_value=mock_response)

    result = await client.tag_endpoints_with_subtests(
        endpoints=[
            {"url": "http://t/api/products", "method": "GET", "params": ["q"]},
            {"url": "http://t/rest/user/login", "method": "POST", "params": ["email", "password"]},
        ],
        catalog_summary=[
            {"id": "WSTG-INPV-05", "title": "SQL Injection"},
            {"id": "WSTG-ATHN-01", "title": "Testing for Credentials"},
        ],
        tech_stack={"backend": "Node.js"},
    )
    assert result["http://t/api/products"] == ["WSTG-INPV-05"]
    assert "WSTG-ATHN-01" in result["http://t/rest/user/login"]


@pytest.mark.asyncio
async def test_tag_endpoints_returns_empty_on_llm_failure():
    from multi_agent_system.utils.simple_llm_client import SimpleLLMClient
    client = SimpleLLMClient.__new__(SimpleLLMClient)
    client._strip_thinking_tags = lambda x: x
    client.chat_completion = AsyncMock(side_effect=RuntimeError("LLM down"))

    result = await client.tag_endpoints_with_subtests(
        endpoints=[{"url": "http://t/", "method": "GET", "params": []}],
        catalog_summary=[{"id": "WSTG-INFO-01", "title": "X"}],
        tech_stack={},
    )
    assert result == {}


@pytest.mark.asyncio
async def test_tag_endpoints_filters_invalid_ids():
    from multi_agent_system.utils.simple_llm_client import SimpleLLMClient
    client = SimpleLLMClient.__new__(SimpleLLMClient)
    client._strip_thinking_tags = lambda x: x
    mock_response = json.dumps({
        "http://t/": ["WSTG-INPV-05", "WSTG-FAKE-99", "not-a-wstg-id"],
    })
    client.chat_completion = AsyncMock(return_value=mock_response)
    result = await client.tag_endpoints_with_subtests(
        endpoints=[{"url": "http://t/", "method": "GET", "params": []}],
        catalog_summary=[{"id": "WSTG-INPV-05", "title": "SQL Injection"}],
        tech_stack={},
        known_ids={"WSTG-INPV-05"},
    )
    # FAKE-99 and non-WSTG IDs filtered out
    assert result["http://t/"] == ["WSTG-INPV-05"]
