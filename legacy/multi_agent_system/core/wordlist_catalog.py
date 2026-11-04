"""Wordlist catalog for tech-aware ffuf scanning (R3).

'always' wordlists always run at top-level.
'tech_specific' entries are selected by the strategic planner based on detected tech_stack.
'deep' wordlists are only used when explicitly requested by the strategic planner.
"""
from __future__ import annotations
from pathlib import Path

_BASE = Path("/usr/share/seclists/Discovery/Web-Content")

WORDLIST_CATALOG: dict[str, list[str] | dict[str, str]] = {
    "always": [
        str(_BASE / "api" / "api-endpoints.txt"),
        str(_BASE / "quickhits.txt"),
    ],
    "tech_specific": {
        "php":       str(_BASE / "PHP.fuzz.txt"),
        "wordpress": str(_BASE / "CMS" / "wp-plugins.fuzz.txt"),
        "spring":    str(_BASE / "Spring-boot.txt"),
        "graphql":   str(_BASE / "graphql.txt"),
    },
    "deep": [
        str(_BASE / "raft-medium-directories.txt"),
        str(_BASE / "common.txt"),
    ],
}


def available_catalog() -> dict:
    """Return catalog with only paths that exist on disk."""
    return {
        "always": [p for p in WORDLIST_CATALOG["always"] if Path(p).exists()],
        "tech_specific": {
            k: v for k, v in WORDLIST_CATALOG["tech_specific"].items()
            if Path(v).exists()
        },
        "deep": [p for p in WORDLIST_CATALOG["deep"] if Path(p).exists()],
    }
