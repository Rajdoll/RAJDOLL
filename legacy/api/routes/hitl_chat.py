"""
HITL Chat API Routes

Conversational approval endpoints for Human-In-The-Loop workflow
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional

from multi_agent_system.core.db import get_db
from multi_agent_system.models.hitl_models import PlanApproval, FindingApproval, RiskApproval
from multi_agent_system.utils.hitl_manager import HITLManager

router = APIRouter(prefix="/api/hitl", tags=["HITL Chat"])


# Request Models
class ChatMessage(BaseModel):
    message: str


# ============================================================
# PLAN APPROVAL CHAT
# ============================================================

@router.post("/plan/{job_id}/chat")
async def chat_plan_approval(job_id: int, request: ChatMessage):
    """
    Chat with AI about plan approval
    
    User can:
    - Ask questions about the plan
    - Give instructions to modify the plan
    - Request explanations
    - Approve with natural language
    
    Example messages:
    - "Skip brute force tests"
    - "Focus SQLi on authentication endpoints only"
    - "Why are you testing business logic?"
    - "Approve and proceed"
    """
    try:
        # Get approval record
        with get_db() as db:
            approval = db.query(PlanApproval).filter(
                PlanApproval.job_id == job_id
            ).first()
            
            if not approval:
                raise HTTPException(
                    status_code=404, 
                    detail=f"No plan approval found for job {job_id}"
                )
            
            # Process chat message
            hitl_manager = HITLManager(job_id)
            result = await hitl_manager.chat_plan_approval(
                approval_id=approval.id,
                user_message=request.message
            )
            
            if "error" in result:
                raise HTTPException(status_code=500, detail=result["error"])
            
            return {
                "status": "success",
                "job_id": job_id,
                "approval_id": approval.id,
                "ai_response": result.get("response"),
                "understanding": result.get("understanding"),
                "changes": result.get("changes"),
                "modified_plan": result.get("modified_plan"),
                "impact": result.get("impact"),
                "requires_confirmation": result.get("requires_confirmation", True),
                "auto_applied": not result.get("requires_confirmation", True)
            }
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# FINDING VERIFICATION CHAT
# ============================================================

@router.post("/findings/{approval_id}/chat")
async def chat_finding_verification(approval_id: int, request: ChatMessage):
    """
    Chat with AI about a specific finding
    
    User can:
    - Ask for evidence details
    - Request explanation of the vulnerability
    - Ask about impact and exploitability
    - Confirm the finding
    
    Example messages:
    - "Show me the exact request and response"
    - "Is this really exploitable?"
    - "What's the impact of this SQLi?"
    - "Confirm this as valid"
    """
    try:
        # Get approval record
        with get_db() as db:
            approval = db.query(FindingApproval).get(approval_id)
            
            if not approval:
                raise HTTPException(
                    status_code=404,
                    detail=f"Finding approval {approval_id} not found"
                )
            
            # Process chat message
            hitl_manager = HITLManager(approval.job_id)
            result = await hitl_manager.chat_finding_verification(
                approval_id=approval_id,
                user_message=request.message
            )
            
            if "error" in result:
                raise HTTPException(status_code=500, detail=result["error"])
            
            return {
                "status": "success",
                "approval_id": approval_id,
                "job_id": approval.job_id,
                "finding_id": approval.finding_id,
                "ai_response": result.get("ai_response"),
                "evidence": result.get("evidence"),
                "is_confirmation": result.get("is_confirmation", False),
                "auto_approved": result.get("is_confirmation", False)
            }
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# RISK APPROVAL CHAT
# ============================================================

@router.post("/risks/{approval_id}/chat")
async def chat_risk_approval(approval_id: int, request: ChatMessage):
    """
    Chat with AI about a risky test
    
    User can:
    - Ask about the risk level
    - Request safer alternatives
    - Ask about impact
    - Approve or reject
    
    Example messages:
    - "Is there a safer way to test this?"
    - "What's the worst that could happen?"
    - "Can you explain the risk?"
    - "Yes, proceed with the test"
    - "Skip this test"
    """
    try:
        # Get approval record
        with get_db() as db:
            approval = db.query(RiskApproval).get(approval_id)
            
            if not approval:
                raise HTTPException(
                    status_code=404,
                    detail=f"Risk approval {approval_id} not found"
                )
            
            # Process chat message
            hitl_manager = HITLManager(approval.job_id)
            result = await hitl_manager.chat_risk_approval(
                approval_id=approval_id,
                user_message=request.message
            )
            
            if "error" in result:
                raise HTTPException(status_code=500, detail=result["error"])
            
            return {
                "status": "success",
                "approval_id": approval_id,
                "job_id": approval.job_id,
                "ai_response": result.get("response"),
                "alternatives": result.get("alternatives"),
                "is_approval": result.get("is_approval", False),
                "is_rejection": result.get("is_rejection", False),
                "auto_decided": result.get("is_approval") or result.get("is_rejection")
            }
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# CONVERSATION HISTORY
# ============================================================

@router.get("/plan/{job_id}/conversation")
async def get_plan_conversation(job_id: int):
    """Get full conversation history for plan approval"""
    try:
        with get_db() as db:
            approval = db.query(PlanApproval).filter(
                PlanApproval.job_id == job_id
            ).first()
            
            if not approval:
                raise HTTPException(status_code=404, detail="Approval not found")
            
            return {
                "status": "success",
                "job_id": job_id,
                "conversation_history": approval.conversation_history or [],
                "user_instructions": approval.user_instructions,
                "ai_interpretation": approval.ai_interpretation
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/findings/{approval_id}/conversation")
async def get_finding_conversation(approval_id: int):
    """Get full conversation history for finding verification"""
    try:
        with get_db() as db:
            approval = db.query(FindingApproval).get(approval_id)
            
            if not approval:
                raise HTTPException(status_code=404, detail="Approval not found")
            
            return {
                "status": "success",
                "approval_id": approval_id,
                "conversation_history": approval.conversation_history or [],
                "user_questions": approval.user_questions or []
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/risks/{approval_id}/conversation")
async def get_risk_conversation(approval_id: int):
    """Get full conversation history for risk approval"""
    try:
        with get_db() as db:
            approval = db.query(RiskApproval).get(approval_id)
            
            if not approval:
                raise HTTPException(status_code=404, detail="Approval not found")
            
            return {
                "status": "success",
                "approval_id": approval_id,
                "conversation_history": approval.conversation_history or [],
                "alternatives_suggested": approval.alternative_suggested
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
