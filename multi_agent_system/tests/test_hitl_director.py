"""Unit tests for HITL Director directive parser. No Docker required."""
import pytest
from multi_agent_system.utils.directive_parser import (
    parse_directive_commands,
    validate_skip_tools,
    format_for_llm,
    get_skip_tools,
)


def test_parse_focus():
    cmds = parse_directive_commands("FOCUS: /api/admin")
    assert cmds == [{"cmd": "FOCUS", "value": "/api/admin"}]


def test_parse_multiple_commands():
    text = "FOCUS: /api/admin\nSKIP: run_sqlmap\nDEPTH: shallow"
    cmds = parse_directive_commands(text)
    assert len(cmds) == 3
    assert cmds[0] == {"cmd": "FOCUS", "value": "/api/admin"}
    assert cmds[1] == {"cmd": "SKIP", "value": "run_sqlmap"}
    assert cmds[2] == {"cmd": "DEPTH", "value": "shallow"}


def test_parse_case_insensitive_cmd():
    cmds = parse_directive_commands("focus: /api/admin")
    assert cmds[0]["cmd"] == "FOCUS"


def test_parse_note_allows_spaces_in_value():
    cmds = parse_directive_commands("NOTE: Admin panel found at /administration")
    assert cmds[0]["value"] == "Admin panel found at /administration"


def test_parse_invalid_command_raises():
    with pytest.raises(ValueError, match="Unknown command"):
        parse_directive_commands("HACK: /api/admin")


def test_parse_missing_colon_raises():
    with pytest.raises(ValueError, match="missing colon"):
        parse_directive_commands("FOCUS /api/admin")


def test_parse_invalid_depth_raises():
    with pytest.raises(ValueError, match="Invalid DEPTH value"):
        parse_directive_commands("DEPTH: extreme")


def test_parse_empty_value_raises():
    with pytest.raises(ValueError, match="Empty value"):
        parse_directive_commands("FOCUS: ")


def test_parse_blank_lines_ignored():
    cmds = parse_directive_commands("\nFOCUS: /api/admin\n\nSKIP: run_sqlmap\n")
    assert len(cmds) == 2


def test_validate_skip_tools_valid():
    cmds = [{"cmd": "SKIP", "value": "run_sqlmap"}, {"cmd": "FOCUS", "value": "/api"}]
    errors = validate_skip_tools(cmds, available_tools=["run_sqlmap", "test_xss_dalfox"])
    assert errors == []


def test_validate_skip_tools_unknown():
    cmds = [{"cmd": "SKIP", "value": "nonexistent_tool"}]
    errors = validate_skip_tools(cmds, available_tools=["run_sqlmap"])
    assert len(errors) == 1
    assert "nonexistent_tool" in errors[0]


def test_format_for_llm_empty():
    assert format_for_llm([]) == ""


def test_format_for_llm_full():
    cmds = [
        {"cmd": "FOCUS", "value": "/api/admin"},
        {"cmd": "SKIP", "value": "run_sqlmap"},
        {"cmd": "DEPTH", "value": "shallow"},
        {"cmd": "NOTE", "value": "Admin at /administration"},
    ]
    result = format_for_llm(cmds)
    assert "[DIRECTOR INSTRUCTIONS]" in result
    assert "Focus testing on: /api/admin" in result
    assert "Skip tool: run_sqlmap" in result
    assert "Scan intensity: shallow" in result
    assert "Note: Admin at /administration" in result


def test_get_skip_tools():
    cmds = [
        {"cmd": "SKIP", "value": "run_sqlmap"},
        {"cmd": "FOCUS", "value": "/api/admin"},
        {"cmd": "SKIP", "value": "run_nikto"},
    ]
    result = get_skip_tools(cmds)
    assert result == {"run_sqlmap", "run_nikto"}


def test_get_skip_tools_empty():
    cmds = [{"cmd": "FOCUS", "value": "/api/admin"}]
    assert get_skip_tools(cmds) == set()


def test_parse_max_commands_enforced():
    text = "\n".join([f"NOTE: line {i}" for i in range(6)])
    with pytest.raises(ValueError, match="Too many commands"):
        parse_directive_commands(text)


def test_parse_line_too_long():
    long_line = "FOCUS: " + "x" * 200
    with pytest.raises(ValueError, match="exceeds"):
        parse_directive_commands(long_line)


def test_parse_depth_normalized_to_lowercase():
    cmds = parse_directive_commands("DEPTH: Shallow")
    assert cmds[0]["value"] == "shallow"


def test_parse_line_exactly_at_limit_is_allowed():
    from multi_agent_system.utils.directive_parser import MAX_LINE_LENGTH
    line = "FOCUS: " + "x" * (MAX_LINE_LENGTH - len("FOCUS: "))
    assert len(line) == MAX_LINE_LENGTH
    cmds = parse_directive_commands(line)
    assert cmds[0]["cmd"] == "FOCUS"


def test_format_for_llm_include_exclude():
    cmds = [
        {"cmd": "INCLUDE", "value": "http://example.com/admin"},
        {"cmd": "EXCLUDE", "value": "/api/products"},
    ]
    result = format_for_llm(cmds)
    assert "Include target URL: http://example.com/admin" in result
    assert "Exclude URL pattern: /api/products" in result


def test_validate_skip_tools_empty_inputs():
    errors = validate_skip_tools([], available_tools=[])
    assert errors == []
