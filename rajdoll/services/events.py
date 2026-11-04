"""Scan events: the log, notifications, and SSE source (BSD 5.3)."""

from typing import Any

from sqlalchemy.orm import Session

from rajdoll.core.enums import EventLevel, EventType
from rajdoll.core.models import ScanEvent


def emit(
    session: Session,
    scan_id: int,
    event_type: EventType,
    message: str,
    *,
    level: EventLevel = EventLevel.INFO,
    data: dict[str, Any] | None = None,
) -> ScanEvent:
    """Add an event to the current transaction; the NOTIFY trigger fires on commit."""
    event = ScanEvent(scan_id=scan_id, type=event_type, level=level, message=message, data=data)
    session.add(event)
    return event
