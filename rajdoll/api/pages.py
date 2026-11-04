"""Shared context for the engagement pages: tabs and the scan banner (AFD 1, 4)."""

from typing import Any

from sqlalchemy.orm import Session

from rajdoll.core.models import Engagement
from rajdoll.services import monitor

# Tabs from AFD section 1. A tab without an href is shown but not yet available.
TABS = [
    ("summary", "Ringkasan", "", None),
    ("scope", "Scope & Akun", "/scope", None),
    ("scan", "Scan", "/scans", None),
    ("findings", "Temuan", "/findings", None),
    ("retest", "Retest", None, "F10"),
    ("report", "Laporan", "/reports", None),
    ("settings", "Pengaturan", "/settings", None),
]


def tabs(engagement: Engagement, current: str) -> list[dict[str, Any]]:
    return [
        {
            "key": key,
            "label": label,
            "href": f"/engagements/{engagement.id}{suffix}" if suffix is not None else None,
            "phase": phase,
            "current": key == current,
        }
        for key, label, suffix, phase in TABS
    ]


def engagement_context(
    db: Session, engagement: Engagement, tab: str, *, banner: bool = True
) -> dict[str, Any]:
    """Header context for an engagement page, with the banner for its active scan (AFD 4)."""
    scan = monitor.banner_scan(db, engagement.id) if banner else None
    return {
        "engagement": engagement,
        "tabs": tabs(engagement, tab),
        "active_nav": "engagements",
        "banner_scan": scan,
        "banner_minutes": monitor.minutes_left(scan.checkpoint_deadline) if scan else None,
    }
