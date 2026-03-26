"""
HITL (Human-In-The-Loop) API Routes

Endpoints for plan approval, finding verification, and risk management
"""
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
    ApprovalStatus
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
