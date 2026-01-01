"""
HITL (Human-In-The-Loop) Database Schema

Add approval workflow to RAJDOLL scanning process
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime
import enum

from ..core.db import Base

class ApprovalStatus(str, enum.Enum):
    """Approval status for HITL checkpoints"""
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    modified = "modified"
    skipped = "skipped"

class PlanApproval(Base):
    """
    Stores strategic plan for user approval before execution
    
    HITL Checkpoint: After Phase 1 (Recon) and Phase 2 (Planning)
    User can review and approve/modify the execution plan
    """
    __tablename__ = "plan_approvals"
    
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False, unique=True)
    
    # Plan details
    original_plan = Column(JSONB, nullable=False)  # LLM-generated plan
    modified_plan = Column(JSONB, nullable=True)   # User-modified plan (if any)
    
    # Approval workflow
    status = Column(SQLEnum(ApprovalStatus), default=ApprovalStatus.pending)
    requested_at = Column(DateTime, default=datetime.utcnow)
    responded_at = Column(DateTime, nullable=True)
    
    # User feedback
    user_notes = Column(Text, nullable=True)
    
    # Metadata
    recon_summary = Column(JSONB, nullable=True)  # Summary from ReconAgent
    risk_level = Column(String(20), nullable=True)  # low, medium, high
    estimated_duration = Column(Integer, nullable=True)  # minutes
    
    # Conversational HITL Enhancement
    conversation_history = Column(JSONB, nullable=True, default=list)  # [{role, message, timestamp, data}]
    user_instructions = Column(Text, nullable=True)  # Latest user instruction in natural language
    ai_interpretation = Column(JSONB, nullable=True)  # How AI understood the instruction

class FindingApproval(Base):
    """
    Stores individual findings for user verification
    
    HITL Checkpoint: After each critical/high severity finding
    User can confirm, reject, or request retest
    """
    __tablename__ = "finding_approvals"
    
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    
    # Approval workflow
    status = Column(SQLEnum(ApprovalStatus), default=ApprovalStatus.pending)
    requested_at = Column(DateTime, default=datetime.utcnow)
    responded_at = Column(DateTime, nullable=True)
    
    # User feedback
    is_false_positive = Column(Boolean, default=False)
    user_notes = Column(Text, nullable=True)
    retest_requested = Column(Boolean, default=False)
    
    # Retest tracking
    retest_count = Column(Integer, default=0)
    last_retest_at = Column(DateTime, nullable=True)
    
    # Conversational HITL Enhancement
    conversation_history = Column(JSONB, nullable=True, default=list)  # User asks questions about finding
    user_questions = Column(JSONB, nullable=True, default=list)  # Array of user questions

class RiskApproval(Base):
    """
    Stores high-risk test approvals
    
    HITL Checkpoint: Before executing potentially dangerous tests
    User must explicitly approve (e.g., DoS tests, brute force)
    """
    __tablename__ = "risk_approvals"
    
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False)
    
    # Test details
    agent_name = Column(String(100), nullable=False)
    test_name = Column(String(200), nullable=False)
    risk_type = Column(String(50), nullable=False)  # dos, data_modification, account_lockout
    risk_description = Column(Text, nullable=False)
    
    # Approval workflow
    status = Column(SQLEnum(ApprovalStatus), default=ApprovalStatus.pending)
    requested_at = Column(DateTime, default=datetime.utcnow)
    responded_at = Column(DateTime, nullable=True)
    
    # User decision
    skip_this_test = Column(Boolean, default=False)
    skip_all_similar = Column(Boolean, default=False)
    user_notes = Column(Text, nullable=True)
    
    # Conversational HITL Enhancement
    conversation_history = Column(JSONB, nullable=True, default=list)  # User discusses alternatives
    alternative_suggested = Column(JSONB, nullable=True)  # Safer alternatives AI suggested


class ToolPolicyMode(str, enum.Enum):
    """Defines how a policy should influence approvals."""

    auto = "auto"          # auto-approve matching requests
    block = "block"        # block matching requests automatically
    batch = "batch"        # group matching requests under one approval


class ToolApprovalPolicy(Base):
    """Reusable policy definitions for automating tool approvals."""

    __tablename__ = "tool_approval_policies"

    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=True)  # null -> global
    agent_name = Column(String(128), nullable=True)
    tool_name = Column(String(128), nullable=False)
    server = Column(String(128), nullable=True)
    match_arguments = Column(JSONB, nullable=True)  # optional partial args to match against
    mode = Column(SQLEnum(ToolPolicyMode), default=ToolPolicyMode.auto)
    risk_tolerance = Column(String(32), default="low")
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(128), nullable=True)
    notes = Column(Text, nullable=True)
    last_used_at = Column(DateTime, nullable=True)


class ToolApproval(Base):
    """Stores per-tool execution approvals before MCP invocation."""

    __tablename__ = "tool_approvals"

    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False)
    agent_name = Column(String(128), nullable=False)
    tool_name = Column(String(128), nullable=False)
    server = Column(String(128), nullable=False)
    arguments = Column(JSONB, nullable=True)
    reason = Column(Text, nullable=True)
    status = Column(SQLEnum(ApprovalStatus), default=ApprovalStatus.pending)
    requested_at = Column(DateTime, default=datetime.utcnow)
    responded_at = Column(DateTime, nullable=True)
    user_notes = Column(Text, nullable=True)
    approved_arguments = Column(JSONB, nullable=True)
    auto_decision = Column(Boolean, default=False)
    batch_key = Column(String(255), nullable=True)
    policy_id = Column(Integer, ForeignKey("tool_approval_policies.id"), nullable=True)

# Migration SQL (run this in PostgreSQL)
"""
-- Add HITL tables

CREATE TYPE approval_status AS ENUM ('pending', 'approved', 'rejected', 'modified', 'skipped');

CREATE TABLE plan_approvals (
    id SERIAL PRIMARY KEY,
    job_id INTEGER REFERENCES jobs(id) NOT NULL UNIQUE,
    original_plan JSONB NOT NULL,
    modified_plan JSONB,
    status approval_status DEFAULT 'pending',
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    responded_at TIMESTAMP,
    user_notes TEXT,
    recon_summary JSONB,
    risk_level VARCHAR(20),
    estimated_duration INTEGER,
    conversation_history JSONB DEFAULT '[]',
    user_instructions TEXT,
    ai_interpretation JSONB
);

CREATE TABLE finding_approvals (
    id SERIAL PRIMARY KEY,
    job_id INTEGER REFERENCES jobs(id) NOT NULL,
    finding_id INTEGER REFERENCES findings(id) NOT NULL,
    status approval_status DEFAULT 'pending',
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    responded_at TIMESTAMP,
    is_false_positive BOOLEAN DEFAULT FALSE,
    user_notes TEXT,
    retest_requested BOOLEAN DEFAULT FALSE,
    retest_count INTEGER DEFAULT 0,
    last_retest_at TIMESTAMP,
    conversation_history JSONB DEFAULT '[]',
    user_questions JSONB DEFAULT '[]'
);

CREATE TABLE risk_approvals (
    id SERIAL PRIMARY KEY,
    job_id INTEGER REFERENCES jobs(id) NOT NULL,
    agent_name VARCHAR(100) NOT NULL,
    test_name VARCHAR(200) NOT NULL,
    risk_type VARCHAR(50) NOT NULL,
    risk_description TEXT NOT NULL,
    status approval_status DEFAULT 'pending',
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    responded_at TIMESTAMP,
    skip_this_test BOOLEAN DEFAULT FALSE,
    skip_all_similar BOOLEAN DEFAULT FALSE,
    user_notes TEXT,
    conversation_history JSONB DEFAULT '[]',
    alternative_suggested JSONB
);

CREATE TABLE tool_approval_policies (
    id SERIAL PRIMARY KEY,
    job_id INTEGER REFERENCES jobs(id),
    agent_name VARCHAR(128),
    tool_name VARCHAR(128) NOT NULL,
    server VARCHAR(128),
    match_arguments JSONB,
    mode VARCHAR(16) NOT NULL DEFAULT 'auto',
    risk_tolerance VARCHAR(32) DEFAULT 'low',
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(128),
    notes TEXT,
    last_used_at TIMESTAMP
);

CREATE TABLE tool_approvals (
    id SERIAL PRIMARY KEY,
    job_id INTEGER REFERENCES jobs(id) NOT NULL,
    agent_name VARCHAR(128) NOT NULL,
    tool_name VARCHAR(128) NOT NULL,
    server VARCHAR(128) NOT NULL,
    arguments JSONB,
    reason TEXT,
    status approval_status DEFAULT 'pending',
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    responded_at TIMESTAMP,
    user_notes TEXT,
    approved_arguments JSONB,
    auto_decision BOOLEAN DEFAULT FALSE,
    batch_key VARCHAR(255),
    policy_id INTEGER REFERENCES tool_approval_policies(id)
);

CREATE INDEX idx_plan_approvals_job ON plan_approvals(job_id);
CREATE INDEX idx_finding_approvals_job ON finding_approvals(job_id);
CREATE INDEX idx_finding_approvals_status ON finding_approvals(status);
CREATE INDEX idx_risk_approvals_job ON risk_approvals(job_id);
CREATE INDEX idx_risk_approvals_status ON risk_approvals(status);
"""
