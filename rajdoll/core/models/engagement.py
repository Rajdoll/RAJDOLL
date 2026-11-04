"""Engagement tables: engagement, scope, target accounts, endpoint inventory (BSD section 4)."""

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, LargeBinary, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from rajdoll.core.enums import (
    AuthMethod,
    EndpointSource,
    EngagementStatus,
    SessionStatus,
    TagSource,
)
from rajdoll.core.models.base import Base, check_in, id_pk, ts_created, ts_updated


class Engagement(Base):
    __tablename__ = "engagement"
    __table_args__ = (
        check_in("status", EngagementStatus),
        CheckConstraint(
            "start_date IS NULL OR end_date IS NULL OR end_date >= start_date",
            name="date_order",
        ),
    )

    id: Mapped[int] = id_pk()
    name: Mapped[str]
    organization: Mapped[str | None]
    target_url: Mapped[str]
    notes: Mapped[str | None]
    start_date: Mapped[date | None]
    end_date: Mapped[date | None]
    status: Mapped[str] = mapped_column(server_default=EngagementStatus.DRAFT.value)
    key_id: Mapped[uuid.UUID] = mapped_column(unique=True)
    settings: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    session_check_url: Mapped[str | None]
    session_check_marker: Mapped[str | None]
    created_at: Mapped[datetime] = ts_created()
    updated_at: Mapped[datetime] = ts_updated()


class ScopeRule(Base):
    __tablename__ = "scope_rule"
    __table_args__ = (UniqueConstraint("engagement_id", "pattern"),)

    id: Mapped[int] = id_pk()
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id", ondelete="CASCADE"))
    pattern: Mapped[str]
    created_at: Mapped[datetime] = ts_created()


class TargetAccount(Base):
    __tablename__ = "target_account"
    __table_args__ = (
        UniqueConstraint("engagement_id", "label"),
        check_in("auth_method", AuthMethod),
        check_in("session_status", SessionStatus),
    )

    id: Mapped[int] = id_pk()
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id", ondelete="CASCADE"))
    label: Mapped[str]
    auth_method: Mapped[str]
    session_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    credentials_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    session_status: Mapped[str] = mapped_column(server_default=SessionStatus.UNKNOWN.value)
    session_checked_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = ts_created()
    updated_at: Mapped[datetime] = ts_updated()


class Endpoint(Base):
    __tablename__ = "endpoint"
    __table_args__ = (
        UniqueConstraint("engagement_id", "method", "host", "path_template"),
        check_in("source", EndpointSource),
        check_in("tag_source", TagSource),
    )

    id: Mapped[int] = id_pk()
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id", ondelete="CASCADE"))
    method: Mapped[str]
    host: Mapped[str]
    path_template: Mapped[str]
    query_params: Mapped[list[str]] = mapped_column(server_default=text("'{}'::text[]"))
    body_params: Mapped[list[Any]] = mapped_column(server_default=text("'[]'::jsonb"))
    content_type: Mapped[str | None]
    source: Mapped[str]
    sample_request_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    tags: Mapped[list[str]] = mapped_column(server_default=text("'{}'::text[]"))
    tag_source: Mapped[str] = mapped_column(server_default=TagSource.RULE.value)
    excluded: Mapped[bool] = mapped_column(server_default=text("false"))
    exclude_reason: Mapped[str | None]
    first_seen_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan.id", ondelete="SET NULL")
    )
    last_seen_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = ts_created()
    updated_at: Mapped[datetime] = ts_updated()
