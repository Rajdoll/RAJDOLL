"""
HITL (Human-In-The-Loop) API Routes

Endpoints for plan approval, finding verification, and risk management
"""
import json

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import or_

from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Job, Finding
from multi_agent_system.models.hitl_models import (
    PlanApproval,
    FindingApproval,
    RiskApproval,
    ToolApproval,
    ToolApprovalPolicy,
    ToolPolicyMode,
    ApprovalStatus,
    AgentCheckpoint,
    CheckpointAction,
)

router = APIRouter()

# ============================================================================
# Request/Response Models
# ============================================================================

class PlanApprovalRequest(BaseModel):
    """User's response to plan approval request"""
    status: str  # approved, rejected, modified
    modified_plan: Optional[Dict[str, Any]] = None
    user_notes: Optional[str] = None

class FindingApprovalRequest(BaseModel):
    """User's response to finding verification"""
    status: str  # approved, rejected
    is_false_positive: bool = False
    retest_requested: bool = False
    user_notes: Optional[str] = None

class RiskApprovalRequest(BaseModel):
    """User's response to risk approval"""
    status: str  # approved, rejected
    skip_this_test: bool = False
    skip_all_similar: bool = False
    user_notes: Optional[str] = None


class ToolApprovalDecision(BaseModel):
    """User response for per-tool execution."""
    status: str  # approved, rejected
    approved_arguments: Optional[Dict[str, Any]] = None
    user_notes: Optional[str] = None


class ToolPolicyRequest(BaseModel):
    """Define auto-approval or batching policies for tool executions."""

    job_id: Optional[int] = None
    agent_name: Optional[str] = None
    tool_name: str
    server: Optional[str] = None
    match_arguments: Optional[Dict[str, Any]] = None
    mode: ToolPolicyMode = ToolPolicyMode.auto
    risk_tolerance: Optional[str] = "low"
    expires_at: Optional[datetime] = None
    notes: Optional[str] = None


class AgentCheckpointResponse(BaseModel):
    """User's response at an agent-level checkpoint"""
    action: str  # proceed, skip_next, reorder, auto, abort
    user_notes: Optional[str] = None
    next_agent_override: Optional[str] = None  # For reorder action
    skip_agents: Optional[List[str]] = None     # Agents to skip


class PreAgentDirectiveRequest(BaseModel):
    """Director's response to a PRE-AGENT checkpoint."""
    action: str                              # proceed, skip_current, abort
    directive_text: Optional[str] = None    # Raw multi-line directive commands (validated server-side)
    user_notes: Optional[str] = None


class HighRiskToolArgRequest(BaseModel):
    """Director's response to a HIGH_RISK tool argument review."""
    action: str                                      # approve, edit, skip
    approved_arguments: Optional[Dict[str, Any]] = None
    user_notes: Optional[str] = None

# ============================================================================
# Plan Approval Endpoints
# ============================================================================

@router.get("/api/hitl/plan/{job_id}")
async def get_plan_approval(job_id: int):
    """
    Get pending plan approval request for a job
    
    Returns plan details and reconnaissance summary for user review
    """
    with get_db() as db:
        approval = db.query(PlanApproval).filter(
            PlanApproval.job_id == job_id
        ).first()
        
        if not approval:
            raise HTTPException(
                status_code=404,
                detail=f"No plan approval found for job {job_id}"
            )
        
        return {
            "status": "success",
            "approval_id": approval.id,
            "job_id": approval.job_id,
            "status": approval.status.value,
            "original_plan": approval.original_plan,
            "modified_plan": approval.modified_plan,
            "recon_summary": approval.recon_summary,
            "risk_level": approval.risk_level,
            "estimated_duration": approval.estimated_duration,
            "requested_at": approval.requested_at.isoformat() if approval.requested_at else None,
            "responded_at": approval.responded_at.isoformat() if approval.responded_at else None,
            "user_notes": approval.user_notes
        }

@router.post("/api/hitl/plan/{job_id}/approve")
async def approve_plan(job_id: int, request: PlanApprovalRequest):
    """
    User approves, rejects, or modifies execution plan
    
    Body:
        {
            "status": "approved" | "rejected" | "modified",
            "modified_plan": {...},  // if status=modified
            "user_notes": "Skip brute force tests"
        }
    """
    with get_db() as db:
        approval = db.query(PlanApproval).filter(
            PlanApproval.job_id == job_id
        ).first()
        
        if not approval:
            raise HTTPException(
                status_code=404,
                detail=f"No plan approval found for job {job_id}"
            )
        
        # Update approval status
        approval.status = ApprovalStatus(request.status)
        approval.responded_at = datetime.utcnow()
        approval.user_notes = request.user_notes
        
        if request.modified_plan:
            approval.modified_plan = request.modified_plan
        
        db.commit()
        
        # Resume job execution
        job = db.query(Job).get(job_id)
        if job and request.status in ['approved', 'modified']:
            job.status = "running"
            db.commit()
        
        return {
            "status": "success",
            "message": f"Plan {request.status}",
            "job_id": job_id
        }

# ============================================================================
# Finding Approval Endpoints
# ============================================================================

@router.get("/api/hitl/findings/{job_id}")
async def get_pending_findings(job_id: int):
    """
    Get all pending finding approvals for a job
    
    Returns list of findings awaiting user verification
    """
    with get_db() as db:
        approvals = db.query(FindingApproval).filter(
            FindingApproval.job_id == job_id,
            FindingApproval.status == ApprovalStatus.pending
        ).all()
        
        result = []
        for approval in approvals:
            # Get finding details
            finding = db.query(Finding).get(approval.finding_id)
            
            result.append({
                "approval_id": approval.id,
                "finding_id": approval.finding_id,
                "finding": {
                    "title": finding.title if finding else "Unknown",
                    "category": finding.category if finding else None,
                    "severity": finding.severity if finding else None,
                    "evidence": finding.evidence if finding else None,
                    "details": finding.details if finding else None
                },
                "requested_at": approval.requested_at.isoformat() if approval.requested_at else None
            })
        
        return {
            "status": "success",
            "job_id": job_id,
            "pending_count": len(result),
            "findings": result
        }

@router.post("/api/hitl/findings/{approval_id}/verify")
async def verify_finding(approval_id: int, request: FindingApprovalRequest):
    """
    User verifies or rejects a finding
    
    Body:
        {
            "status": "approved" | "rejected",
            "is_false_positive": false,
            "retest_requested": false,
            "user_notes": "Confirmed on manual test"
        }
    """
    with get_db() as db:
        approval = db.query(FindingApproval).get(approval_id)
        
        if not approval:
            raise HTTPException(
                status_code=404,
                detail=f"Finding approval {approval_id} not found"
            )
        
        approval.status = ApprovalStatus(request.status)
        approval.responded_at = datetime.utcnow()
        approval.is_false_positive = request.is_false_positive
        approval.retest_requested = request.retest_requested
        approval.user_notes = request.user_notes
        
        db.commit()
        
        return {
            "status": "success",
            "message": "Finding verification recorded",
            "approval_id": approval_id
        }

# ============================================================================
# Risk Approval Endpoints
# ============================================================================

@router.get("/api/hitl/risks/{job_id}")
async def get_pending_risks(job_id: int):
    """
    Get all pending risk approvals for a job
    
    Returns list of risky tests awaiting user approval
    """
    with get_db() as db:
        approvals = db.query(RiskApproval).filter(
            RiskApproval.job_id == job_id,
            RiskApproval.status == ApprovalStatus.pending
        ).all()
        
        result = []
        for approval in approvals:
            result.append({
                "approval_id": approval.id,
                "agent_name": approval.agent_name,
                "test_name": approval.test_name,
                "risk_type": approval.risk_type,
                "risk_description": approval.risk_description,
                "requested_at": approval.requested_at.isoformat() if approval.requested_at else None
            })
        
        return {
            "status": "success",
            "job_id": job_id,
            "pending_count": len(result),
            "risks": result
        }

@router.post("/api/hitl/risks/{approval_id}/decide")
async def decide_risk(approval_id: int, request: RiskApprovalRequest):
    """
    User approves or rejects a risky test
    
    Body:
        {
            "status": "approved" | "rejected",
            "skip_this_test": false,
            "skip_all_similar": false,
            "user_notes": "Proceed with caution"
        }
    """
    with get_db() as db:
        approval = db.query(RiskApproval).get(approval_id)
        
        if not approval:
            raise HTTPException(
                status_code=404,
                detail=f"Risk approval {approval_id} not found"
            )
        
        approval.status = ApprovalStatus(request.status)
        approval.responded_at = datetime.utcnow()
        approval.skip_this_test = request.skip_this_test
        approval.skip_all_similar = request.skip_all_similar
        approval.user_notes = request.user_notes
        
        db.commit()
        
        return {
            "status": "success",
            "message": "Risk decision recorded",
            "approval_id": approval_id
        }

# ============================================================================
# Tool Approval Endpoints
# ============================================================================

@router.get("/api/hitl/tools/{job_id}")
async def get_pending_tools(job_id: int):
    """Return pending tool approvals for a job."""
    with get_db() as db:
        approvals = db.query(ToolApproval).filter(
            ToolApproval.job_id == job_id,
            ToolApproval.status == ApprovalStatus.pending
        ).order_by(ToolApproval.requested_at.asc()).all()

        result = []
        for approval in approvals:
            result.append({
                "approval_id": approval.id,
                "agent_name": approval.agent_name,
                "tool_name": approval.tool_name,
                "server": approval.server,
                "arguments": approval.arguments,
                "reason": approval.reason,
                "requested_at": approval.requested_at.isoformat() if approval.requested_at else None,
                "batch_key": approval.batch_key,
                "policy_id": approval.policy_id
            })

        return {
            "status": "success",
            "job_id": job_id,
            "pending_count": len(result),
            "tools": result
        }


@router.post("/api/hitl/tools/{approval_id}/decide")
async def decide_tool(approval_id: int, request: ToolApprovalDecision):
    """Approve or reject an individual tool execution."""
    with get_db() as db:
        approval = db.query(ToolApproval).get(approval_id)
        if not approval:
            raise HTTPException(status_code=404, detail=f"Tool approval {approval_id} not found")

        approval.status = ApprovalStatus(request.status)
        approval.responded_at = datetime.utcnow()
        approval.user_notes = request.user_notes
        if request.approved_arguments is not None:
            approval.approved_arguments = request.approved_arguments
        db.commit()

        return {
            "status": "success",
            "message": f"Tool execution {request.status}",
            "approval_id": approval_id
        }


@router.post("/api/hitl/tools/{job_id}/approve-all")
async def approve_all_tools(job_id: int):
    """Approve every pending tool request for a job in one action."""
    with get_db() as db:
        approvals = db.query(ToolApproval).filter(
            ToolApproval.job_id == job_id,
            ToolApproval.status == ApprovalStatus.pending
        ).all()

        for approval in approvals:
            approval.status = ApprovalStatus.approved
            approval.responded_at = datetime.utcnow()
            approval.approved_arguments = approval.arguments

        db.commit()

        return {
            "status": "success",
            "message": f"Approved {len(approvals)} tool executions",
            "job_id": job_id
        }


# ============================================================================
# Tool Policy Endpoints
# ============================================================================

@router.get("/api/hitl/tool-policies")
async def list_tool_policies(job_id: Optional[int] = None):
    """Return configured auto-approval policies."""
    with get_db() as db:
        query = db.query(ToolApprovalPolicy)
        if job_id is not None:
            query = query.filter(
                or_(
                    ToolApprovalPolicy.job_id == job_id,
                    ToolApprovalPolicy.job_id == None
                )
            )

        policies = query.order_by(ToolApprovalPolicy.created_at.desc()).all()
        data = []
        for policy in policies:
            data.append({
                "policy_id": policy.id,
                "job_id": policy.job_id,
                "agent_name": policy.agent_name,
                "tool_name": policy.tool_name,
                "server": policy.server,
                "mode": policy.mode.value,
                "risk_tolerance": policy.risk_tolerance,
                "match_arguments": policy.match_arguments,
                "expires_at": policy.expires_at.isoformat() if policy.expires_at else None,
                "notes": policy.notes,
                "last_used_at": policy.last_used_at.isoformat() if policy.last_used_at else None,
            })

        return {
            "status": "success",
            "policies": data
        }


@router.post("/api/hitl/tool-policies")
async def create_tool_policy(request: ToolPolicyRequest):
    """Create a new policy that influences tool approvals."""
    with get_db() as db:
        policy = ToolApprovalPolicy(
            job_id=request.job_id,
            agent_name=request.agent_name,
            tool_name=request.tool_name,
            server=request.server,
            match_arguments=request.match_arguments,
            mode=request.mode,
            risk_tolerance=request.risk_tolerance,
            expires_at=request.expires_at,
            notes=request.notes,
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)

        return {
            "status": "success",
            "policy_id": policy.id
        }


@router.delete("/api/hitl/tool-policies/{policy_id}")
async def delete_tool_policy(policy_id: int):
    """Remove an existing tool approval policy."""
    with get_db() as db:
        policy = db.query(ToolApprovalPolicy).get(policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")

        db.delete(policy)
        db.commit()

        return {
            "status": "success",
            "message": f"Policy {policy_id} deleted"
        }

# ============================================================================
# Bulk Operations
# ============================================================================

@router.post("/api/hitl/plan/{job_id}/skip")
async def skip_plan_approval(job_id: int):
    """
    Skip plan approval and proceed with original plan
    
    Useful for automated/scheduled scans
    """
    with get_db() as db:
        approval = db.query(PlanApproval).filter(
            PlanApproval.job_id == job_id
        ).first()
        
        if not approval:
            raise HTTPException(
                status_code=404,
                detail=f"No plan approval found for job {job_id}"
            )
        
        approval.status = ApprovalStatus.skipped
        approval.responded_at = datetime.utcnow()
        approval.user_notes = "User skipped approval"
        db.commit()
        
        # Resume job
        job = db.query(Job).get(job_id)
        if job:
            job.status = "running"
            db.commit()
        
        return {
            "status": "success",
            "message": "Plan approval skipped, proceeding with original plan"
        }

@router.post("/api/hitl/findings/{job_id}/approve-all")
async def approve_all_findings(job_id: int):
    """
    Approve all pending findings for a job
    
    Useful when user trusts the scanner results
    """
    with get_db() as db:
        approvals = db.query(FindingApproval).filter(
            FindingApproval.job_id == job_id,
            FindingApproval.status == ApprovalStatus.pending
        ).all()
        
        for approval in approvals:
            approval.status = ApprovalStatus.approved
            approval.responded_at = datetime.utcnow()
        
        db.commit()
        
        return {
            "status": "success",
            "message": f"Approved {len(approvals)} findings"
        }

@router.post("/api/hitl/risks/{job_id}/approve-all")
async def approve_all_risks(job_id: int):
    """
    Approve all pending risky tests for a job
    
    Use with caution!
    """
    with get_db() as db:
        approvals = db.query(RiskApproval).filter(
            RiskApproval.job_id == job_id,
            RiskApproval.status == ApprovalStatus.pending
        ).all()
        
        for approval in approvals:
            approval.status = ApprovalStatus.approved
            approval.responded_at = datetime.utcnow()
        
        db.commit()
        
        return {
            "status": "success",
            "message": f"Approved {len(approvals)} risky tests"
        }

# ============================================================================
# Statistics
# ============================================================================

@router.get("/api/hitl/stats/{job_id}")
async def get_hitl_stats(job_id: int):
    """
    Get HITL statistics for a job
    
    Returns counts of pending/approved/rejected items
    """
    with get_db() as db:
        plan_approval = db.query(PlanApproval).filter(
            PlanApproval.job_id == job_id
        ).first()
        
        finding_approvals = db.query(FindingApproval).filter(
            FindingApproval.job_id == job_id
        ).all()
        
        risk_approvals = db.query(RiskApproval).filter(
            RiskApproval.job_id == job_id
        ).all()
        
        return {
            "status": "success",
            "job_id": job_id,
            "plan": {
                "status": plan_approval.status.value if plan_approval else None,
                "risk_level": plan_approval.risk_level if plan_approval else None
            },
            "findings": {
                "total": len(finding_approvals),
                "pending": sum(1 for f in finding_approvals if f.status == ApprovalStatus.pending),
                "approved": sum(1 for f in finding_approvals if f.status == ApprovalStatus.approved),
                "false_positives": sum(1 for f in finding_approvals if f.is_false_positive)
            },
            "risks": {
                "total": len(risk_approvals),
                "pending": sum(1 for r in risk_approvals if r.status == ApprovalStatus.pending),
                "approved": sum(1 for r in risk_approvals if r.status == ApprovalStatus.approved),
                "skipped": sum(1 for r in risk_approvals if r.skip_this_test)
            }
        }


# ============================================================================
# Agent-Level Checkpoint Endpoints (HITL v2)
# ============================================================================

@router.get("/api/hitl/agent-checkpoint/{job_id}")
async def get_pending_agent_checkpoint(job_id: int):
    """
    Get the current pending agent checkpoint for a job.

    Returns the checkpoint data including agent summary, findings,
    recommendations, and available actions.
    """
    with get_db() as db:
        checkpoint = (
            db.query(AgentCheckpoint)
            .filter(
                AgentCheckpoint.job_id == job_id,
                AgentCheckpoint.action == CheckpointAction.pending,
            )
            .order_by(AgentCheckpoint.requested_at.desc())
            .first()
        )

        if not checkpoint:
            return {"status": "no_pending", "message": "No pending checkpoint"}

        return {
            "status": "pending",
            "checkpoint": {
                "id": checkpoint.id,
                "job_id": checkpoint.job_id,
                "completed_agent": checkpoint.completed_agent,
                "agent_sequence_index": checkpoint.agent_sequence_index,
                "findings_count": checkpoint.findings_count,
                "findings_by_severity": checkpoint.findings_by_severity or {},
                "agent_summary": checkpoint.agent_summary,
                "cumulative_summary": checkpoint.cumulative_summary,
                "key_findings": checkpoint.key_findings or [],
                "next_agent": checkpoint.next_agent,
                "remaining_agents": checkpoint.remaining_agents or [],
                "recommendations": checkpoint.recommendations or [],
                "requested_at": checkpoint.requested_at.isoformat() if checkpoint.requested_at else None,
            }
        }


@router.get("/api/hitl/agent-checkpoints/{job_id}")
async def list_agent_checkpoints(job_id: int):
    """List all agent checkpoints for a job (history)."""
    with get_db() as db:
        checkpoints = (
            db.query(AgentCheckpoint)
            .filter(AgentCheckpoint.job_id == job_id)
            .order_by(AgentCheckpoint.agent_sequence_index)
            .all()
        )

        return {
            "status": "success",
            "job_id": job_id,
            "total": len(checkpoints),
            "checkpoints": [
                {
                    "id": cp.id,
                    "completed_agent": cp.completed_agent,
                    "index": cp.agent_sequence_index,
                    "findings_count": cp.findings_count,
                    "findings_by_severity": cp.findings_by_severity or {},
                    "action": cp.action.value if cp.action else "pending",
                    "user_notes": cp.user_notes,
                    "wait_duration_seconds": cp.wait_duration_seconds,
                    "requested_at": cp.requested_at.isoformat() if cp.requested_at else None,
                    "responded_at": cp.responded_at.isoformat() if cp.responded_at else None,
                }
                for cp in checkpoints
            ],
        }


@router.post("/api/hitl/agent-checkpoint/{checkpoint_id}/respond")
async def respond_to_agent_checkpoint(checkpoint_id: int, body: AgentCheckpointResponse):
    """
    Respond to an agent-level checkpoint.

    Actions:
    - proceed: Continue to the next agent (default order)
    - skip_next: Skip the next planned agent
    - reorder: Change which agent runs next (provide next_agent_override)
    - auto: Disable checkpoints for remaining agents (run fully automated)
    - abort: Stop the scan entirely
    """
    valid_actions = {"proceed", "skip_next", "reorder", "auto", "abort"}
    if body.action not in valid_actions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action '{body.action}'. Must be one of: {valid_actions}"
        )

    with get_db() as db:
        checkpoint = db.query(AgentCheckpoint).get(checkpoint_id)

        if not checkpoint:
            raise HTTPException(status_code=404, detail="Checkpoint not found")

        if checkpoint.action != CheckpointAction.pending:
            raise HTTPException(
                status_code=400,
                detail=f"Checkpoint already responded to (action: {checkpoint.action.value})"
            )

        # Validate reorder action
        if body.action == "reorder":
            if not body.next_agent_override:
                raise HTTPException(
                    status_code=400,
                    detail="next_agent_override required for reorder action"
                )
            remaining = checkpoint.remaining_agents or []
            if body.next_agent_override not in remaining:
                raise HTTPException(
                    status_code=400,
                    detail=f"'{body.next_agent_override}' not in remaining agents: {remaining}"
                )

        # Update checkpoint
        checkpoint.action = CheckpointAction(body.action)
        checkpoint.user_notes = body.user_notes
        checkpoint.next_agent_override = body.next_agent_override
        checkpoint.skip_agents = body.skip_agents
        checkpoint.responded_at = datetime.utcnow()

        # Calculate wait duration
        if checkpoint.requested_at:
            wait = (checkpoint.responded_at - checkpoint.requested_at).total_seconds()
            checkpoint.wait_duration_seconds = int(wait)

        db.commit()

        return {
            "status": "success",
            "checkpoint_id": checkpoint_id,
            "action": body.action,
            "message": f"Checkpoint responded: {body.action}",
        }


# ============================================================================
# Director Mode Endpoints (HITL v3)
# ============================================================================

@router.post("/api/hitl/pre-agent-checkpoint/{checkpoint_id}/respond")
async def respond_to_pre_agent_checkpoint(checkpoint_id: int, body: PreAgentDirectiveRequest):
    """
    Director responds to a PRE-AGENT checkpoint.

    Actions:
    - proceed: Run the agent (optional directive applied)
    - skip_current: Skip this agent
    - abort: Stop the scan
    """
    valid_actions = {"proceed", "skip_current", "abort"}
    if body.action not in valid_actions:
        raise HTTPException(400, f"Invalid action '{body.action}'. Must be one of: {valid_actions}")

    directive_commands: list = []
    if body.directive_text and body.directive_text.strip():
        try:
            from multi_agent_system.utils.directive_parser import parse_directive_commands
            directive_commands = parse_directive_commands(body.directive_text)
        except ValueError as e:
            raise HTTPException(400, f"Invalid directive: {e}")

    with get_db() as db:
        checkpoint = db.query(AgentCheckpoint).get(checkpoint_id)
        if not checkpoint:
            raise HTTPException(404, "Checkpoint not found")
        if getattr(checkpoint, "checkpoint_type", "post_agent") != "pre_agent":
            raise HTTPException(400, "This endpoint is for pre_agent checkpoints only")
        if checkpoint.action != CheckpointAction.pending:
            raise HTTPException(400, f"Checkpoint already responded to (action: {checkpoint.action.value})")

        checkpoint.action = CheckpointAction(body.action)
        checkpoint.user_notes = body.user_notes
        checkpoint.directive = json.dumps(directive_commands) if directive_commands else None
        checkpoint.responded_at = datetime.utcnow()
        if checkpoint.requested_at:
            wait = (checkpoint.responded_at - checkpoint.requested_at).total_seconds()
            checkpoint.wait_duration_seconds = int(wait)
        db.commit()

    return {
        "status": "success",
        "checkpoint_id": checkpoint_id,
        "action": body.action,
        "directive_commands": directive_commands,
    }


@router.post("/api/hitl/tool-approval/{approval_id}/director-review")
async def respond_to_high_risk_tool(approval_id: int, body: HighRiskToolArgRequest):
    """
    Director responds to a HIGH_RISK tool argument review.

    Actions:
    - approve: Run with original LLM-generated arguments
    - edit: Run with approved_arguments (must be provided)
    - skip: Skip this tool entirely
    """
    valid_actions = {"approve", "edit", "skip"}
    if body.action not in valid_actions:
        raise HTTPException(400, f"Invalid action. Must be one of: {valid_actions}")

    if body.action == "edit" and body.approved_arguments is None:
        raise HTTPException(400, "approved_arguments required when action == 'edit'")

    with get_db() as db:
        approval = db.query(ToolApproval).get(approval_id)
        if not approval:
            raise HTTPException(404, "Tool approval not found")
        if not getattr(approval, "is_high_risk_review", False):
            raise HTTPException(400, "This endpoint is for HIGH_RISK Director reviews only")
        if approval.status != ApprovalStatus.pending:
            raise HTTPException(400, f"Approval already resolved (status: {approval.status.value})")

        if body.action == "approve":
            approval.status = ApprovalStatus.approved
            approval.approved_arguments = approval.arguments
        elif body.action == "edit":
            approval.status = ApprovalStatus.modified
            approval.approved_arguments = body.approved_arguments
        elif body.action == "skip":
            approval.status = ApprovalStatus.rejected
        approval.user_notes = body.user_notes
        approval.responded_at = datetime.utcnow()
        db.commit()

    return {
        "status": "success",
        "approval_id": approval_id,
        "action": body.action,
    }
