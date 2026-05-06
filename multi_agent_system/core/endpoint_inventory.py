"""Endpoint inventory schema, taxonomy, and helpers.

Recon writes endpoint_inventory once (atomic). Agents read by tag.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = 2

TAXONOMY: tuple[str, ...] = (
    "idor_candidate",
    "admin_panel",
    "state_changing_money",
    "state_changing_resource",
    "user_registration",
    "user_login",
    "user_profile",
    "password_recovery",
    "file_upload",
    "error_prone_param",
    "client_render_sink",
    "auth_token_endpoint",
    "api_generic",
    "hidden_path",
)

AGENT_TAG_MAP: dict[str, list[str]] = {
    "AuthorizationAgent": ["idor_candidate", "admin_panel"],
    "BusinessLogicAgent": ["state_changing_money", "state_changing_resource"],
    "IdentityManagementAgent": ["user_registration", "user_profile", "password_recovery"],
    "ConfigDeployAgent": ["admin_panel", "hidden_path"],
    "ClientSideAgent": ["client_render_sink", "error_prone_param"],
    "WeakCryptoAgent": ["auth_token_endpoint", "user_login"],
    "ErrorHandlingAgent": ["error_prone_param"],
    "FileUploadAgent": ["file_upload"],
    "ApiTestingAgent": ["api_generic"],
    "ReactAgent": ["api_generic", "client_render_sink"],
    "AuthenticationAgent": ["user_login", "password_recovery", "auth_token_endpoint"],
    "SessionManagementAgent": ["auth_token_endpoint", "user_login"],
    "InputValidationAgent": ["error_prone_param", "api_generic"],
}


def build_inventory(
    endpoints: list[dict[str, Any]],
    stats: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the full endpoint_inventory payload with by_tag index."""
    by_tag: dict[str, list[str]] = {tag: [] for tag in TAXONOMY}
    for ep in endpoints:
        for tag in ep.get("tags", []):
            if tag in by_tag:
                by_tag[tag].append(ep["id"])

    full_stats = {"total_endpoints": len(endpoints), **(stats or {})}
    return {
        "version": SCHEMA_VERSION,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
        "stats": full_stats,
        "endpoints": endpoints,
        "by_tag": by_tag,
    }


def read_tag(inventory: dict[str, Any], tag: str) -> list[dict[str, Any]]:
    """Return full endpoint records for a tag. Empty list if no matches."""
    if not inventory:
        return []
    ids = set(inventory.get("by_tag", {}).get(tag, []))
    if not ids:
        return []
    return [ep for ep in inventory.get("endpoints", []) if ep.get("id") in ids]


_PLACEHOLDER_RE = re.compile(r"\{[^}]+\}|:\w+")


def resolve_placeholders(
    endpoints: list[dict[str, Any]],
    captured_ids: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Replace {id}/:id in path with first captured real value for that prefix."""
    out: list[dict[str, Any]] = []
    for ep in endpoints:
        path = ep.get("path", "")
        match = _PLACEHOLDER_RE.search(path)
        if not match:
            out.append(ep)
            continue
        prefix = path[: match.start()]
        candidates = captured_ids.get(prefix, [])
        new_ep = dict(ep)
        if candidates:
            new_ep["path"] = path[: match.start()] + candidates[0] + path[match.end():]
        out.append(new_ep)
    return out
