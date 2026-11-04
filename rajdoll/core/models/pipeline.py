"""Pipeline tables: scan, task, scan_event (BSD section 5)."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    LargeBinary,
    SmallInteger,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from rajdoll.core.enums import (
    CheckpointResolution,
    EventLevel,
    EventType,
    PausedReason,
    ScanKind,
    ScanProfile,
    ScanStage,
    ScanStatus,
    TaskStatus,
)
from rajdoll.core.models.base import Base, check_in, id_pk, ts_created


class Scan(Base):
    __tablename__ = "scan"
    __table_args__ = (
        UniqueConstraint("engagement_id", "kind", "number"),
        check_in("kind", ScanKind),
        check_in("profile", ScanProfile),
        check_in("status", ScanStatus),
        check_in("stage", ScanStage),
        check_in("paused_reason", PausedReason),
        check_in("checkpoint_resolution", CheckpointResolution),
        CheckConstraint(
            "(kind = 'scan' AND profile IS NOT NULL) OR (kind = 'retest' AND profile IS NULL)",
            name="profile_matches_kind",
        ),
        CheckConstraint(
            "(status = 'paused') = (paused_reason IS NOT NULL)",
            name="paused_reason_iff_paused",
        ),
    )

    id: Mapped[int] = id_pk()
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id", ondelete="CASCADE"))
    kind: Mapped[str]
    number: Mapped[int]
    profile: Mapped[str | None]
    modules: Mapped[list[str]] = mapped_column(server_default=text("'{}'::text[]"))
    status: Mapped[str] = mapped_column(server_default=ScanStatus.QUEUED.value)
    stage: Mapped[str | None]
    paused_reason: Mapped[str | None]
    checkpoint_deadline: Mapped[datetime | None]
    checkpoint_resolution: Mapped[str | None]
    base_url: Mapped[str | None]
    settings_snapshot: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    llm_snapshot: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    recon_summary: Mapped[dict[str, Any] | None]
    stats: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    error: Mapped[str | None]
    created_at: Mapped[datetime] = ts_created()
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class Task(Base):
    __tablename__ = "task"
    __table_args__ = (
        check_in("stage", ScanStage),
        check_in("status", TaskStatus),
        Index("ix_task_scan_id_status", "scan_id", "status"),
        Index(
            "ix_task_pending_created_at",
            "created_at",
            postgresql_where=text("status = 'pending'"),
        ),
    )

    id: Mapped[int] = id_pk()
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"))
    stage: Mapped[str]
    module: Mapped[str]
    engine: Mapped[str]
    target: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    params: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    status: Mapped[str] = mapped_column(server_default=TaskStatus.PENDING.value)
    attempt: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    locked_by: Mapped[str | None]
    locked_at: Mapped[datetime | None]
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    result_summary: Mapped[dict[str, Any] | None]
    raw_output_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    error: Mapped[str | None]
    created_at: Mapped[datetime] = ts_created()


class ScanEvent(Base):
    __tablename__ = "scan_event"
    __table_args__ = (
        check_in("level", EventLevel),
        check_in("type", EventType),
        Index("ix_scan_event_scan_id_id", "scan_id", "id"),
    )

    id: Mapped[int] = id_pk()
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = ts_created()
    level: Mapped[str]
    type: Mapped[str]
    message: Mapped[str]
    data: Mapped[dict[str, Any] | None]
