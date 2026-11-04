"""Audit and output tables: llm_call, request_log, report_export (BSD section 6.6-6.8)."""

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Index, LargeBinary, text
from sqlalchemy.orm import Mapped, mapped_column

from rajdoll.core.enums import (
    LlmCallStatus,
    LlmTaskKind,
    ReportKind,
    RequestKind,
    RequestOutcome,
)
from rajdoll.core.models.base import Base, check_in, id_pk, ts_created


class LlmCall(Base):
    __tablename__ = "llm_call"
    __table_args__ = (
        check_in("task_kind", LlmTaskKind),
        check_in("status", LlmCallStatus),
        Index("ix_llm_call_engagement_id_created_at", "engagement_id", "created_at"),
        Index("ix_llm_call_finding_id", "finding_id"),
    )

    id: Mapped[int] = id_pk()
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id", ondelete="CASCADE"))
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan.id", ondelete="SET NULL"))
    task_kind: Mapped[str]
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("finding.id", ondelete="SET NULL"))
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoint.id", ondelete="SET NULL"))
    model: Mapped[str]
    is_local: Mapped[bool]
    prompt_enc: Mapped[bytes] = mapped_column(LargeBinary)
    output_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    status: Mapped[str]
    tokens_in: Mapped[int | None]
    tokens_out: Mapped[int | None]
    duration_ms: Mapped[int | None]
    created_at: Mapped[datetime] = ts_created()


class RequestLog(Base):
    __tablename__ = "request_log"
    __table_args__ = (
        check_in("kind", RequestKind),
        check_in("outcome", RequestOutcome),
        Index("ix_request_log_scan_id_ts", "scan_id", "ts"),
        Index("ix_request_log_engagement_id_outcome", "engagement_id", "outcome"),
    )

    id: Mapped[int] = id_pk()
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id", ondelete="CASCADE"))
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan.id", ondelete="SET NULL"))
    task_id: Mapped[int | None] = mapped_column(BigInteger)
    ts: Mapped[datetime] = ts_created()
    kind: Mapped[str]
    tool: Mapped[str]
    method: Mapped[str | None]
    url: Mapped[str]
    host: Mapped[str]
    status: Mapped[int | None]
    response_bytes: Mapped[int | None]
    duration_ms: Mapped[int | None]
    outcome: Mapped[str]


class ReportExport(Base):
    __tablename__ = "report_export"
    __table_args__ = (
        check_in("kind", ReportKind),
        CheckConstraint(
            "kind <> 'retest' OR retest_scan_id IS NOT NULL",
            name="retest_report_needs_scan",
        ),
    )

    id: Mapped[int] = id_pk()
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id", ondelete="CASCADE"))
    kind: Mapped[str]
    retest_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"))
    finding_count: Mapped[int]
    warnings: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    content_enc: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = ts_created()
