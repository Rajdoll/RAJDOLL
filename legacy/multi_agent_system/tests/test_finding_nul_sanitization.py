"""Unit tests for NUL-byte sanitization in findings. No Docker required."""
from multi_agent_system.agents.base_agent import _strip_nul_bytes


def test_strips_nul_from_string():
	assert _strip_nul_bytes("malicious.php\x00.jpg") == "malicious.php.jpg"


def test_strips_nul_in_nested_dict():
	evidence = {"url": "http://x/up\x00load", "nested": {"k": "a\x00b"}}
	assert _strip_nul_bytes(evidence) == {"url": "http://x/upload", "nested": {"k": "ab"}}


def test_strips_nul_in_list():
	assert _strip_nul_bytes(["a\x00", "b", 3]) == ["a", "b", 3]


def test_passes_through_non_strings():
	assert _strip_nul_bytes(None) is None
	assert _strip_nul_bytes(42) == 42
	assert _strip_nul_bytes(True) is True


def test_no_nul_is_unchanged():
	assert _strip_nul_bytes("clean title") == "clean title"
