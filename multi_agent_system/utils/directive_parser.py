"""
Directive command parser for HITL Director Mode.

Parses, validates, and formats structured directive commands entered by the
human Director at PRE-AGENT checkpoints.

Command grammar (one per line):
  FOCUS: <path_or_keyword>      — Narrow agent to specific endpoint
  SKIP: <tool_name>             — Exclude a planned tool
  INCLUDE: <url>                — Add a URL to agent scope
  EXCLUDE: <pattern>            — Exclude URL pattern from scope
  DEPTH: shallow|normal|deep    — Set scan intensity
  NOTE: <free text>             — Inject context note into LLM prompt
"""
from __future__ import annotations

VALID_COMMANDS: frozenset[str] = frozenset({
    "FOCUS", "SKIP", "INCLUDE", "EXCLUDE", "DEPTH", "NOTE"
})
VALID_DEPTH_VALUES: frozenset[str] = frozenset({"shallow", "normal", "deep"})
MAX_COMMANDS = 5
MAX_LINE_LENGTH = 200


def parse_directive_commands(text: str) -> list[dict]:
    """Parse structured directive text into a list of command dicts.

    Args:
        text: Multi-line string of directive commands.

    Returns:
        List of dicts: [{"cmd": "FOCUS", "value": "/api/admin"}, ...]

    Raises:
        ValueError: If any line is invalid.
    """
    commands: list[dict] = []
    for raw_line in text.strip().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if len(line) > MAX_LINE_LENGTH:
            raise ValueError(f"Line exceeds {MAX_LINE_LENGTH} characters: {line[:50]!r}...")
        if ":" not in line:
            raise ValueError(f"Invalid directive line (missing colon): {line!r}")
        cmd_part, _, value = line.partition(":")
        cmd = cmd_part.strip().upper()
        value = value.strip()
        if cmd not in VALID_COMMANDS:
            raise ValueError(
                f"Unknown command {cmd!r}. Valid commands: {sorted(VALID_COMMANDS)}"
            )
        if not value:
            raise ValueError(f"Empty value for command {cmd!r}")
        if cmd == "DEPTH" and value.lower() not in VALID_DEPTH_VALUES:
            raise ValueError(
                f"Invalid DEPTH value {value!r}. Must be one of: {sorted(VALID_DEPTH_VALUES)}"
            )
        commands.append({"cmd": cmd, "value": value})

    if len(commands) > MAX_COMMANDS:
        raise ValueError(f"Too many commands ({len(commands)}). Maximum is {MAX_COMMANDS}.")

    return commands


def validate_skip_tools(commands: list[dict], available_tools: list[str]) -> list[str]:
    """Return list of validation error messages for SKIP commands."""
    errors: list[str] = []
    for c in commands:
        if c["cmd"] == "SKIP" and c["value"] not in available_tools:
            errors.append(
                f"SKIP tool {c['value']!r} is not in the planned tool list: {available_tools}"
            )
    return errors


def format_for_llm(commands: list[dict]) -> str:
    """Format parsed commands as a [DIRECTOR INSTRUCTIONS] block for LLM injection."""
    if not commands:
        return ""
    lines = ["[DIRECTOR INSTRUCTIONS]"]
    _FORMATTERS = {
        "FOCUS":   lambda v: f"- Focus testing on: {v}",
        "SKIP":    lambda v: f"- Skip tool: {v}",
        "INCLUDE": lambda v: f"- Include target URL: {v}",
        "EXCLUDE": lambda v: f"- Exclude URL pattern: {v}",
        "DEPTH":   lambda v: f"- Scan intensity: {v}",
        "NOTE":    lambda v: f"- Note: {v}",
    }
    for c in commands:
        formatter = _FORMATTERS.get(c["cmd"])
        if formatter:
            lines.append(formatter(c["value"]))
    return "\n".join(lines)


def get_skip_tools(commands: list[dict]) -> set[str]:
    """Extract tool names that should be skipped from parsed commands."""
    return {c["value"] for c in commands if c["cmd"] == "SKIP"}
