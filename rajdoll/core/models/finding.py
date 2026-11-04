"""Finding tables: finding, evidence, retest_result, finding_template (BSD section 6.1-6.5)."""

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    LargeBinary,
    Numeric,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from rajdoll.core.enums import (
    Decision,
    EvidenceKind,
    RetestOutcome,
    RetestResult,
    Severity,
    Validation,
)
from rajdoll.core.models.base import Base, check_in, id_pk, ts_created, ts_updated


class FindingTemplate(Base):
    __tablename__ = "finding_template"
    __table_args__ = (check_in("default_severity", Severity),)

    id: Mapped[int] = id_pk()
    vuln_type: Mapped[str] = mapped_column(unique=True)
    title: Mapped[str]
    wstg_id: Mapped[str | None]
    cwe_id: Mapped[str | None]
    description: Mapped[str]
    impact: Mapped[str]
    recommendation: Mapped[str]
    references: Mapped[list[Any]] = mapped_column(server_default=text("'[]'::jsonb"))
    cvss31_vector: Mapped[str | None]
    cvss40_vector: Mapped[str | None]
    default_severity: Mapped[str]
    is_builtin: Mapped[bool] = mapped_column(server_default=text("false"))
    created_at: Mapped[datetime] = ts_created()
    updated_at: Mapped[datetime] = ts_updated()


class Finding(Base):
    __tablename__ = "finding"
    __table_args__ = (
        UniqueConstraint("engagement_id", "fingerprint"),
        check_in("severity", Severity),
        check_in("validation", Validation),
        check_in("decision", Decision),
        check_in("retest_result", RetestResult),
        CheckConstraint(
            "decision <> 'rejected' OR length(btrim(coalesce(decision_reason, ''))) > 0",
            name="rejection_needs_reason",
        ),
        CheckConstraint(
            "retest_result = 'not_tested' OR decision = 'accepted'",
            name="retest_only_when_accepted",
        ),
        CheckConstraint("cvss31_score BETWEEN 0 AND 10", name="cvss31_score_range"),
        CheckConstraint("cvss40_score BETWEEN 0 AND 10", name="cvss40_score_range"),
        Index(
            "ix_finding_engagement_id_decision_severity", "engagement_id", "decision", "severity"
        ),
        Index("ix_finding_engagement_id_validation", "engagement_id", "validation"),
    )

    id: Mapped[int] = id_pk()
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagement.id", ondelete="CASCADE"))
    fingerprint: Mapped[str]
    title: Mapped[str]
    vuln_type: Mapped[str]
    module: Mapped[str]
    wstg_id: Mapped[str | None]
    cwe_id: Mapped[str | None]
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoint.id", ondelete="SET NULL"))
    parameter: Mapped[str | None]
    severity: Mapped[str]
    cvss31_vector: Mapped[str | None]
    cvss31_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    cvss40_vector: Mapped[str | None]
    cvss40_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    validation: Mapped[str]
    decision: Mapped[str] = mapped_column(server_default=Decision.PENDING.value)
    decision_reason: Mapped[str | None]
    decided_at: Mapped[datetime | None]
    retest_result: Mapped[str] = mapped_column(server_default=RetestResult.NOT_TESTED.value)
    description: Mapped[str] = mapped_column(server_default=text("''"))
    impact: Mapped[str] = mapped_column(server_default=text("''"))
    recommendation: Mapped[str] = mapped_column(server_default=text("''"))
    references: Mapped[list[Any]] = mapped_column(server_default=text("'[]'::jsonb"))
    template_id: Mapped[int | None] = mapped_column(
        ForeignKey("finding_template.id", ondelete="SET NULL")
    )
    poc_spec_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    llm_notes_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    merged_into_id: Mapped[int | None] = mapped_column(
        ForeignKey("finding.id", ondelete="SET NULL")
    )
    first_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan.id", ondelete="SET NULL"))
    last_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = ts_created()
    updated_at: Mapped[datetime] = ts_updated()


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        check_in("kind", EvidenceKind),
        Index("ix_evidence_finding_id_sequence", "finding_id", "sequence"),
    )

    id: Mapped[int] = id_pk()
    finding_id: Mapped[int] = mapped_column(ForeignKey("finding.id", ondelete="CASCADE"))
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scan.id", ondelete="SET NULL"))
    kind: Mapped[str]
    sequence: Mapped[int]
    request_enc: Mapped[bytes] = mapped_column(LargeBinary)
    response_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    response_status: Mapped[int | None]
    truncated: Mapped[bool] = mapped_column(server_default=text("false"))
    note: Mapped[str | None]
    created_at: Mapped[datetime] = ts_created()


class RetestResultRow(Base):
    __tablename__ = "retest_result"
    __table_args__ = (
        UniqueConstraint("scan_id", "finding_id"),
        check_in("auto_result", RetestOutcome),
        check_in("result", RetestOutcome),
    )

    id: Mapped[int] = id_pk()
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"))
    finding_id: Mapped[int] = mapped_column(ForeignKey("finding.id", ondelete="CASCADE"))
    auto_result: Mapped[str | None]
    result: Mapped[str]
    corrected: Mapped[bool] = mapped_column(server_default=text("false"))
    note: Mapped[str | None]
    created_at: Mapped[datetime] = ts_created()
    updated_at: Mapped[datetime] = ts_updated()
