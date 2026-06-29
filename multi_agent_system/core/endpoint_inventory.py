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
        ep_id = ep.get("id")
        if not ep_id:
            continue
        for tag in ep.get("tags", []):
            if tag in by_tag:
                by_tag[tag].append(ep_id)

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

_NUMERIC_ID_RE = re.compile(r"/\{[^}]+\}|/:[a-zA-Z]+|/\d+(/|$)")
_REGISTRATION_HINT_RE = re.compile(
    r"(?:^|/)(users?|register|signup|account|registration)(?:/|$)",
    re.IGNORECASE,
)
_LOGIN_HINT_RE = re.compile(r"(?:^|/)(login|signin|authenticate)(?:/|$)", re.IGNORECASE)
_PASSWORD_RECOVERY_HINT_RE = re.compile(
    r"(?:^|/)(reset[-_]?password|forgot[-_]?password|password[-_]?recovery)(?:/|$)",
    re.IGNORECASE,
)
_ADMIN_HINT_RE = re.compile(r"(?:^|/)(admin|administrator|console|dashboard)(?:/|$)", re.IGNORECASE)
_FILE_UPLOAD_HINT_RE = re.compile(r"(?:^|/)(upload|file|attachment|image)(?:/|$)", re.IGNORECASE)


def augment_tags_heuristic(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for ep in endpoints:
        path = ep.get("path") or ep.get("url") or ""
        method = (ep.get("method") or "GET").upper()
        params = ep.get("params") or []
        content_type = (ep.get("content_type") or "").lower()
        current = set(ep.get("tags") or [])

        if params or "?" in path:
            current.add("error_prone_param")

        if _NUMERIC_ID_RE.search(path):
            current.add("idor_candidate")

        if _FILE_UPLOAD_HINT_RE.search(path):
            current.add("file_upload")

        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            current.add("state_changing_resource")
            if _REGISTRATION_HINT_RE.search(path):
                current.add("user_registration")
            if _LOGIN_HINT_RE.search(path):
                current.add("user_login")
            if _PASSWORD_RECOVERY_HINT_RE.search(path):
                current.add("password_recovery")
            if "multipart" in content_type:
                current.add("file_upload")

        if path.startswith("/api/") or "/api/" in path or "/rest/" in path:
            current.add("api_generic")

        if _ADMIN_HINT_RE.search(path):
            current.add("admin_panel")

        ep["tags"] = sorted(current)
    return endpoints


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
