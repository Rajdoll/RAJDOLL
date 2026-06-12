"""Unit tests for tolerant LLM test-plan parsing. No Docker required."""
from multi_agent_system.agents.input_validation_agent import _safe_parse_test_plan


def test_parses_plain_json():
    assert _safe_parse_test_plan('{"priority_urls": [1, 2]}') == {"priority_urls": [1, 2]}


def test_parses_fenced_json():
    text = "Here is the plan:\n```json\n{\"a\": 1}\n```\nthanks"
    assert _safe_parse_test_plan(text) == {"a": 1}


def test_repairs_trailing_comma():
    assert _safe_parse_test_plan('{"a": [1, 2,], "b": 3,}') == {"a": [1, 2], "b": 3}


def test_extracts_object_from_surrounding_prose():
    assert _safe_parse_test_plan('blah {"x": "y"} trailing') == {"x": "y"}


def test_returns_none_on_unparseable():
    assert _safe_parse_test_plan("not json at all") is None
    assert _safe_parse_test_plan("") is None
