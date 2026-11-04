"""Rule-based test plan and checkpoint edits (TRD 3.4, 6.2; PRD F-14, F-46; AFD A5; BSD 10.4).

Which modules test which endpoint follows from the endpoint's tags (TRD 6.2). The plan is computed
from the inventory each time it is shown, so every checkpoint edit (excluding an endpoint, changing
tags, switching a module off, adding endpoints) changes it at once; the testing stage plans its
tasks from the same rules when the checkpoint is continued.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from rajdoll.core.crypto import KeyStore
from rajdoll.core.enums import EndpointSource, EventType, ScanStatus, TagSource
from rajdoll.core.models import Endpoint, Scan
from rajdoll.modules.base import EndpointSeen
from rajdoll.modules.registry import MODULE_LABELS
from rajdoll.services import engagements, inventory, raw_request, scans, tagging
from rajdoll.services.errors import Conflict, ValidationFailed
from rajdoll.services.events import emit

Rule = Callable[[set[str], dict[str, Any]], bool]


def _is_page(endpoint: dict[str, Any]) -> bool:
    path = endpoint.get("path_template", "").lower()
    return endpoint.get("method") == "GET" and not path.endswith((".js", ".json", ".xml", ".txt"))


# TRD 6.2: what each module tests. Configuration and Weak Cryptography also run once per host.
MODULE_RULES: dict[str, Rule] = {
    "input_validation": lambda t, e: bool({"has_params", "state_change"} & t),
    "authorization": lambda t, e: bool({"idor_candidate", "admin", "profile"} & t),
    "authentication": lambda t, e: bool({"auth", "password_reset", "registration"} & t),
    "session": lambda t, e: "auth" in t,
    "identity": lambda t, e: bool({"registration", "profile"} & t),
    "business_logic": lambda t, e: "price" in t,
    "file_upload": lambda t, e: "upload" in t,
    "error_handling": lambda t, e: "has_params" in t,
    "client_side": lambda t, e: "redirect_param" in t or (_is_page(e) and "api" not in t),
    "configuration": lambda t, e: bool({"admin", "hidden"} & t),
    "cryptography": lambda t, e: "auth" in t,
}
HOST_MODULES = ("configuration", "cryptography")

# Rough request counts for the checkpoint estimate (PRD F-14), per endpoint unless noted.
_PER_PARAM = {"input_validation": 120, "error_handling": 6}
_PER_ENDPOINT = {
    "authorization": 6,
    "authentication": 40,
    "session": 10,
    "identity": 20,
    "business_logic": 15,
    "file_upload": 30,
    "client_side": 8,
    "configuration": 5,
    "cryptography": 3,
}
_PER_HOST = {"configuration": 400, "cryptography": 150}

SKIP_LABELS = {
    "not_available": "belum tersedia di versi ini",
    "needs_two_accounts": "butuh dua akun",
    "disabled": "dimatikan di checkpoint",
}


def modules_for(endpoint: dict[str, Any], active: list[str]) -> list[str]:
    """Modules that test this endpoint, in profile order; none for an excluded endpoint."""
    if endpoint.get("excluded"):
        return []
    tags = set(endpoint.get("tags") or [])
    return [m for m in active if m in MODULE_RULES and MODULE_RULES[m](tags, endpoint)]


def _param_count(endpoint: dict[str, Any]) -> int:
    return len(endpoint.get("query_params") or []) + len(endpoint.get("body_params") or [])


def estimate(endpoints: list[dict[str, Any]], active: list[str]) -> int:
    """Approximate requests of the testing stage for the current plan."""
    total = 0
    hosts = {e["host"] for e in endpoints if not e.get("excluded")}
    for endpoint in endpoints:
        for module in modules_for(endpoint, active):
            if module in _PER_PARAM:
                total += _PER_PARAM[module] * max(1, _param_count(endpoint))
            else:
                total += _PER_ENDPOINT.get(module, 0)
    for module, per_host in _PER_HOST.items():
        if module in active:
            total += per_host * len(hosts)
    return total


def plan_endpoints(session: Session, scan: Scan) -> list[dict[str, Any]]:
    """The inventory as dicts, with the modules that will test each endpoint."""
    rows = [inventory.as_dict(e) for e in inventory.list_for(session, scan.engagement_id)]
    for row in rows:
        row["modules"] = modules_for(row, list(scan.modules))
    return rows


def module_rows(
    scan: Scan, available: set[str], account_count: int, endpoints: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Every module of the full profile with its state for this scan (BSD 10.4 `modules`)."""
    rows = []
    for name in MODULE_LABELS:
        enabled = name in scan.modules
        reason = None
        if name not in available:
            reason = "not_available"
        elif name == "authorization" and account_count < 2:
            reason = "needs_two_accounts"
        elif not enabled:
            reason = "disabled"
        rows.append(
            {
                "name": name,
                "label": MODULE_LABELS[name],
                "enabled": enabled,
                "skipped_reason": reason,
                "endpoints": sum(1 for e in endpoints if name in e.get("modules", [])),
            }
        )
    return rows


def checkpoint(
    session: Session, scan: Scan, available: set[str], recon: dict[str, Any]
) -> dict[str, Any]:
    """`GET /scans/{id}/checkpoint` (BSD 10.4)."""
    endpoints = plan_endpoints(session, scan)
    accounts = len(engagements.accounts(session, scan.engagement_id))
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "deadline": scan.checkpoint_deadline,
        "resolution": scan.checkpoint_resolution,
        "recon_summary": {**recon, "estimated_requests": estimate(endpoints, list(scan.modules))},
        "modules": module_rows(scan, available, accounts, endpoints),
        "endpoints": endpoints,
        "editable": scan.status == ScanStatus.AWAITING_CHECKPOINT,
    }


# ------------------------------------------------------------------------------- edits


def _as_list(value: Any, field: str) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise ValidationFailed.one(field, f"{field} harus berupa daftar.")


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "ya", "on", "yes")


def _tags(value: Any) -> list[str]:
    raw = value if isinstance(value, list) else str(value or "").split(",")
    names = [str(t).strip() for t in raw if str(t).strip()]
    try:
        return tagging.validate(names)
    except ValueError as exc:
        raise ValidationFailed.one("tags", f"Tanda tidak dikenal: {exc}") from None


def _set_modules(scan: Scan, value: Any) -> str | None:
    chosen = {str(m) for m in _as_list(value, "modules")}
    unknown = sorted(chosen - set(MODULE_LABELS))
    if unknown:
        raise ValidationFailed.one("modules", f"Modul tidak dikenal: {', '.join(unknown)}")
    if not chosen:
        raise ValidationFailed.one("modules", "Pilih minimal satu modul.")
    ordered = [m for m in MODULE_LABELS if m in chosen]
    if ordered == list(scan.modules):
        return None
    scan.modules = ordered
    return f"modul diatur menjadi {len(ordered)}"


def _edit_endpoints(session: Session, scan: Scan, value: Any) -> str | None:
    edits = _as_list(value, "endpoints")
    if not edits:
        return None
    ids = [int(item["id"]) for item in edits if isinstance(item, dict) and "id" in item]
    rows = {
        e.id: e
        for e in session.scalars(
            select(Endpoint).where(
                Endpoint.engagement_id == scan.engagement_id, Endpoint.id.in_(ids)
            )
        )
    }
    changed = 0
    for item in edits:
        endpoint = rows.get(int(item.get("id", 0))) if isinstance(item, dict) else None
        if endpoint is None:
            raise ValidationFailed.one("endpoints", "Endpoint tidak ditemukan di penugasan ini.")
        if "excluded" in item:
            excluded = _bool(item["excluded"])
            if excluded != endpoint.excluded:
                endpoint.excluded = excluded
                endpoint.exclude_reason = "user" if excluded else None
                changed += 1
        if "tags" in item:
            tags = _tags(item["tags"])
            if tags != list(endpoint.tags) or endpoint.tag_source != TagSource.USER:
                endpoint.tags = tags
                endpoint.tag_source = TagSource.USER
                changed += 1
    return f"{changed} endpoint diubah" if changed else None


def _add_endpoints(
    session: Session, keystore: KeyStore, scan: Scan, value: Any, scope: list[str]
) -> str | None:
    items = _as_list(value, "add_endpoints")
    if not items:
        return None
    engagement = engagements.get(session, scan.engagement_id)
    default_scheme = "http" if engagement.target_url.startswith("http://") else "https"
    added = 0
    for item in items:
        if not isinstance(item, dict):
            raise ValidationFailed.one("add_endpoints", "Format endpoint tidak valid.")
        raw = item.get("raw_request")
        if raw:
            parsed = raw_request.parse(str(raw), default_scheme)
            seen = EndpointSeen(
                parsed.method,
                parsed.url,
                EndpointSource.BURP_PASTE,
                body_params=tuple(parsed.body_params),
                content_type=parsed.content_type,
            )
        else:
            method = str(item.get("method") or "GET").upper()
            url = str(item.get("url") or "").strip()
            if method not in inventory.METHODS:
                raise ValidationFailed.one("method", f"Metode tidak didukung: {method}")
            seen = EndpointSeen(method, url, EndpointSource.MANUAL)
        norm = inventory.normalize(seen.method, seen.url)
        if norm is None:
            raise ValidationFailed.one(
                "url", "URL harus http(s) dan bukan file statis (gambar, CSS, font)."
            )
        result = inventory.record(session, scan.engagement_id, scan.id, [seen], scope)
        if result.out_of_scope:
            host = next(iter(result.out_of_scope))
            raise ValidationFailed.one(
                "url", f"Host {host} di luar scope. Tambahkan ke scope dulu."
            )
        added += result.added
        if raw:
            endpoint = session.scalars(
                select(Endpoint).where(
                    Endpoint.engagement_id == scan.engagement_id,
                    Endpoint.method == norm.method,
                    Endpoint.host == norm.host,
                    Endpoint.path_template == norm.path_template,
                )
            ).one()
            endpoint.sample_request_enc = engagements.cipher(keystore, engagement).encrypt_text(
                "endpoint", "sample_request_enc", str(raw)
            )
    return f"{len(items)} endpoint ditambahkan ({added} baru)"


def _add_scope(session: Session, scan: Scan, value: Any) -> str | None:
    patterns = [str(p) for p in _as_list(value, "add_scope") if str(p).strip()]
    if not patterns:
        return None
    engagement = engagements.get(session, scan.engagement_id)
    existing = set(engagements.scope_patterns(session, scan.engagement_id))
    for pattern in patterns:
        if pattern.strip().lower() not in existing:
            engagements.add_scope(session, engagement, pattern)
    return f"scope ditambah: {', '.join(patterns)}"


def edit(session: Session, keystore: KeyStore, scan: Scan, data: dict[str, Any]) -> list[str]:
    """`PATCH /scans/{id}/checkpoint`: apply edits and stop the countdown (AFD A5)."""
    if scan.status != ScanStatus.AWAITING_CHECKPOINT:
        raise Conflict("Rencana hanya bisa disunting saat scan menunggu checkpoint.")
    if scan.checkpoint_deadline is not None:
        scans.checkpoint_hold(session, scan)
    done: list[str | None] = []
    # Scope first, so endpoints on a newly added host can be added in the same request.
    done.append(_add_scope(session, scan, data.get("add_scope")))
    scope = engagements.scope_patterns(session, scan.engagement_id)
    if "modules" in data:
        done.append(_set_modules(scan, data["modules"]))
    done.append(_edit_endpoints(session, scan, data.get("endpoints")))
    done.append(_add_endpoints(session, keystore, scan, data.get("add_endpoints"), scope))
    changes = [d for d in done if d]
    if changes:
        emit(session, scan.id, EventType.NOTICE, "Rencana disunting: " + "; ".join(changes) + ".")
    session.flush()
    return changes
