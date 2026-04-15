from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship, Mapped

from ..core.db import Base


class JobStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class AgentStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    skipped = "skipped"


class FindingSeverity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ConfidenceLevel(str, enum.Enum):
    """Confidence levels for vulnerability findings."""
    speculative = "speculative"  # 0.0 - 0.3
    low = "low"                  # 0.3 - 0.5
    medium = "medium"            # 0.5 - 0.7
    high = "high"                # 0.7 - 0.9
    confirmed = "confirmed"      # 0.9 - 1.0


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[int] = Column(Integer, primary_key=True)
    target: Mapped[str] = Column(String(512), nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    started_at: Mapped[Optional[datetime]] = Column(DateTime, nullable=True)
    status: Mapped[JobStatus] = Column(Enum(JobStatus), default=JobStatus.queued, nullable=False)
    plan: Mapped[Optional[dict]] = Column(JSON, nullable=True)
    summary: Mapped[Optional[str]] = Column(Text, nullable=True)

    agents: Mapped[list[JobAgent]] = relationship("JobAgent", back_populates="job", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="job", cascade="all, delete-orphan")


class JobAgent(Base):
    __tablename__ = "job_agents"
    __table_args__ = (UniqueConstraint("job_id", "agent_name", name="uq_job_agent"),)

    id: Mapped[int] = Column(Integer, primary_key=True)
    job_id: Mapped[int] = Column(Integer, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    agent_name: Mapped[str] = Column(String(128), nullable=False)
    status: Mapped[AgentStatus] = Column(Enum(AgentStatus), default=AgentStatus.pending, nullable=False)
    started_at: Mapped[Optional[datetime]] = Column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = Column(DateTime, nullable=True)
    attempts: Mapped[int] = Column(Integer, default=0, nullable=False)
    error: Mapped[Optional[str]] = Column(Text, nullable=True)
    context: Mapped[Optional[dict]] = Column(JSON, nullable=True)

    job: Mapped[Job] = relationship("Job", back_populates="agents")
    events: Mapped[list[AgentEvent]] = relationship("AgentEvent", back_populates="job_agent", cascade="all, delete-orphan")


class AgentEvent(Base):
    __tablename__ = "agent_events"

    id: Mapped[int] = Column(Integer, primary_key=True)
    job_agent_id: Mapped[int] = Column(Integer, ForeignKey("job_agents.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, default=datetime.utcnow, nullable=False)
    level: Mapped[str] = Column(String(16), default="info", nullable=False)
    message: Mapped[str] = Column(Text, nullable=False)
    data: Mapped[Optional[dict]] = Column(JSON, nullable=True)

    job_agent: Mapped[JobAgent] = relationship("JobAgent", back_populates="events")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("job_id", "agent_name", "category", "title", name="uq_finding"),)

    id: Mapped[int] = Column(Integer, primary_key=True)
    job_id: Mapped[int] = Column(Integer, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    agent_name: Mapped[str] = Column(String(128), nullable=False)
    category: Mapped[str] = Column(String(128), nullable=False)
    title: Mapped[str] = Column(String(512), nullable=False)
    severity: Mapped[FindingSeverity] = Column(Enum(FindingSeverity), default=FindingSeverity.info, nullable=False)
    evidence: Mapped[Optional[dict]] = Column(JSON, nullable=True)
    details: Mapped[Optional[str]] = Column(Text, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=datetime.utcnow, nullable=False)
    # Confidence scoring
    confidence_score: Mapped[Optional[float]] = Column(Float, nullable=True)
    confidence_level: Mapped[Optional[ConfidenceLevel]] = Column(Enum(ConfidenceLevel), nullable=True)
    attack_chain_id: Mapped[Optional[str]] = Column(String(64), nullable=True)
    # Enrichment columns (populated by EnrichmentService at write time)
    explanation: Mapped[Optional[str]] = Column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = Column(Text, nullable=True)
    cwe_id: Mapped[Optional[str]] = Column(String(20), nullable=True)
    wstg_id: Mapped[Optional[str]] = Column(String(30), nullable=True)
    cvss_score_v4: Mapped[Optional[float]] = Column(Float, nullable=True)
    references: Mapped[Optional[list]] = Column("references", JSON, nullable=True)
    enrichment_source: Mapped[Optional[str]] = Column(String(20), nullable=True)
    # Manual precision validation
    is_true_positive: Mapped[Optional[bool]] = Column(Boolean, nullable=True, default=None)
    validation_notes: Mapped[Optional[str]] = Column(Text, nullable=True, default=None)

    job: Mapped[Job] = relationship("Job", back_populates="findings")


class SharedContext(Base):
    """
    Key/value context items shared across agents within a job.
    Examples: discovered_urls, credentials, cookies, tech_stack, live_subdomains.
    """

    __tablename__ = "shared_context"
    __table_args__ = (UniqueConstraint("job_id", "key", name="uq_job_context_key"),)

    id: Mapped[int] = Column(Integer, primary_key=True)
    job_id: Mapped[int] = Column(Integer, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    key: Mapped[str] = Column(String(128), nullable=False)
    value: Mapped[dict] = Column(JSON, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class ScanCost(Base):
    """
    Track LLM API usage and costs for each scan.
    Enables cost monitoring and budget management for research.
    """

    __tablename__ = "scan_costs"

    id: Mapped[int] = Column(Integer, primary_key=True)
    job_id: Mapped[int] = Column(Integer, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    component: Mapped[str] = Column(String(50), nullable=False)  # 'orchestrator', 'agent_planning', 'url_analysis'
    agent_name: Mapped[Optional[str]] = Column(String(128), nullable=True)  # Which agent made the call
    prompt_tokens: Mapped[int] = Column(Integer, default=0, nullable=False)
    completion_tokens: Mapped[int] = Column(Integer, default=0, nullable=False)
    estimated_cost_usd: Mapped[float] = Column(Float, default=0.0, nullable=False)
    created_at: Mapped[datetime] = Column(DateTime, default=datetime.utcnow, nullable=False)


class AttackChain(Base):
    """
    Track detected vulnerability chains that amplify attack impact.
    Example: SQL Injection → Admin Access → Data Exfiltration
    """

    __tablename__ = "attack_chains"

    id: Mapped[int] = Column(Integer, primary_key=True)
    job_id: Mapped[int] = Column(Integer, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    chain_id: Mapped[str] = Column(String(64), nullable=False)  # UUID for grouping
    name: Mapped[str] = Column(String(256), nullable=False)  # "SQL Injection to Admin Access"
    category: Mapped[str] = Column(String(64), nullable=False)  # AUTHENTICATION_BYPASS, DATA_EXFILTRATION, etc.
    impact_multiplier: Mapped[float] = Column(Float, default=1.0, nullable=False)  # Chain increases impact
    steps: Mapped[dict] = Column(JSON, nullable=False)  # List of vulnerability steps in order
    confidence: Mapped[float] = Column(Float, default=0.0, nullable=False)  # Combined chain confidence
    created_at: Mapped[datetime] = Column(DateTime, default=datetime.utcnow, nullable=False)


class KnowledgeGraphSnapshot(Base):
    """
    Store knowledge graph state for job analysis and debugging.
    Enables graph-based analysis of vulnerability relationships.
    """

    __tablename__ = "knowledge_graph_snapshots"

    id: Mapped[int] = Column(Integer, primary_key=True)
    job_id: Mapped[int] = Column(Integer, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    entities: Mapped[dict] = Column(JSON, nullable=False)  # Serialized entities
    relationships: Mapped[dict] = Column(JSON, nullable=False)  # Serialized relationships
    agent_name: Mapped[Optional[str]] = Column(String(128), nullable=True)  # Agent that created snapshot
    snapshot_type: Mapped[str] = Column(String(32), nullable=False)  # 'incremental', 'final', 'checkpoint'
    created_at: Mapped[datetime] = Column(DateTime, default=datetime.utcnow, nullable=False)
