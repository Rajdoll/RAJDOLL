from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import json

from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Job, JobAgent, Finding, AgentEvent


router = APIRouter()


@router.get("/scans")
def list_scans(limit: int = Query(20, ge=1, le=200)):
    with get_db() as db:
        jobs = (
            db.query(Job)
            .order_by(Job.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "job_id": j.id,
                "target": j.target,
                "status": j.status.value if hasattr(j.status, 'value') else str(j.status),
                "created_at": j.created_at,
            }
            for j in jobs
        ]


@router.get("/scans/{job_id}/findings")
def get_findings(job_id: int):
    with get_db() as db:
        job = db.query(Job).get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        findings = (
            db.query(Finding)
            .filter(Finding.job_id == job_id)
            .order_by(Finding.created_at.asc())
            .all()
        )
        return [
            {
                "id": f.id,
                "agent_name": f.agent_name,
                "category": f.category,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "evidence": f.evidence,
                "details": f.details,
                "created_at": f.created_at,
                "is_true_positive": f.is_true_positive,
                "validation_notes": f.validation_notes,
            }
            for f in findings
        ]


@router.get("/scans/{job_id}/plan")
def get_plan(job_id: int):
    """Expose LLM planning artifacts and computed execution plan for UI."""
    with get_db() as db:
        job = db.query(Job).get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        # Orchestrator persists LLM artifacts in Job.plan
        plan_meta = job.plan if isinstance(job.plan, dict) else {}
        meta = plan_meta or {}

        llm_plan = meta.get("llm_test_plan") or {}
        if isinstance(llm_plan, str):
            try:
                llm_plan = json.loads(llm_plan)
            except Exception:
                llm_plan = {}
        # Build a simple map of agent->tools if present
        tools_map = {}
        try:
            cats = llm_plan.get("owasp_categories", [])
            for item in cats:
                agent = item.get("agent")
                tlist = []
                for t in item.get("mcp_tools", []) or []:
                    if isinstance(t, dict) and t.get("tool"):
                        tlist.append(t.get("tool"))
                if agent:
                    tools_map[agent] = tlist
        except Exception:
            pass
        return {
            "llm_test_plan": llm_plan,
            "llm_execution_plan": meta.get("llm_execution_plan"),
            "selected_tools": tools_map or None,
            "target": job.target,
        }


@router.get("/scans/{job_id}/events")
def get_events(job_id: int, agent: Optional[str] = None, limit: int = Query(200, ge=1, le=1000)):
    with get_db() as db:
        job = db.query(Job).get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        q = (
            db.query(AgentEvent)
            .join(JobAgent, AgentEvent.job_agent_id == JobAgent.id)
            .filter(JobAgent.job_id == job_id)
        )
        if agent:
            q = q.filter(JobAgent.agent_name == agent)
        events = q.order_by(AgentEvent.created_at.asc()).limit(limit).all()

        return [
            {
                "created_at": e.created_at,
                "agent_name": db.query(JobAgent).get(e.job_agent_id).agent_name,  # minimal extra lookup
                "level": e.level,
                "message": e.message,
                "data": e.data,
            }
            for e in events
        ]


# Legacy compatibility: support old path `/api/results/findings?job_id=...`
@router.get("/results/findings")
def legacy_get_findings(job_id: int = Query(..., description="Job ID to fetch findings for")):
    return get_findings(job_id)
