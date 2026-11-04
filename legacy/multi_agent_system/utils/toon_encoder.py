"""Utilities for encoding structured data into TOON (Token-Oriented Object Notation).

The goal is to compress repetitive JSON-friendly structures before sending them to
LLM prompts. We only support the subset we need: flat tables composed of
homogeneous dict records.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Sequence


def _coerce_row(value: Any) -> dict[str, Any]:
    """Normalize supported row shapes into a dict."""
    if isinstance(value, dict):
        return value
    if isinstance(value, (list, tuple)):
        return {f"col{idx}": item for idx, item in enumerate(value)}
    return {"value": value}


def _sanitize_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\n", " ").replace("\r", " ")
    return text.strip()


def encode_toon_table(
    name: str,
    rows: Sequence[Any],
    *,
    fields: Sequence[str] | None = None,
    max_rows: int = 50,
    max_fields: int = 8,
) -> str:
    """Encode a homogeneous list into TOON notation.

    Args:
        name: Identifier for the table (no spaces recommended).
        rows: Sequence of dicts (preferred), tuples, or primitives.
        fields: Explicit column order. If omitted we infer from the first rows.
        max_rows: Hard cap to avoid runaway prompts.
        max_fields: When inferring columns, limit how many keys we keep.
    Returns:
        Multiline string representing the TOON table. Empty string if no rows.
    """

    if not rows:
        return ""

    normalized: List[dict[str, Any]] = []
    for item in rows[:max_rows]:
        normalized.append(_coerce_row(item))

    column_order: List[str] = []
    if fields:
        column_order = [str(f) for f in fields]
    else:
        for row in normalized:
            for key in row.keys():
                if key not in column_order:
                    column_order.append(key)
                if len(column_order) >= max_fields:
                    break
            if len(column_order) >= max_fields:
                break
    if not column_order:
        column_order = ["value"]

    header = f"{name}[{len(normalized)}]{{{','.join(column_order)}}}:"
    lines = [header]
    for row in normalized:
        cells = [_sanitize_cell(row.get(col, "")) for col in column_order]
        lines.append(" ".join(cells))
    return "\n".join(lines)


def encode_mapping(name: str, mapping: dict[str, Any], *, max_items: int = 20) -> str:
    """Encode a simple dict as TOON table with key/value columns."""
    if not mapping:
        return ""
    items = list(mapping.items())[:max_items]
    rows = [{"key": k, "value": v} for k, v in items]
    return encode_toon_table(name, rows, fields=["key", "value"])


def join_toon_sections(sections: Iterable[str]) -> str:
    filtered = [section.strip() for section in sections if section and section.strip()]
    return "\n\n".join(filtered) if filtered else "(no tabular recon data)"
