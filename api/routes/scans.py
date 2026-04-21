from __future__ import annotations

import hashlib
from datetime import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Job, JobStatus, JobAgent, AgentStatus, ScanCost
from ..schemas.schemas import CreateScanRequest, ScanStatusResponse, JobAgentState
from multi_agent_system.orchestrator import Orchestrator, DEFAULT_PLAN
from multi_agent_system.tasks.celery_app import celery_app

# 🆕 Security safeguards integration
from multi_agent_system.core.security_guards import (
	security_guard,
	audit_logger,
	UnauthorizedTargetError,
	SecurityPolicyViolation,
	InvalidAuthTokenError
)
import multi_agent_system.core.config as _config
from multi_agent_system.core.config import SCAN_PROFILE_DEFAULTS
from typing import Optional


def _resolve_hitl_mode(request_hitl: Optional[str]) -> str:
	"""Resolve HITL mode: per-scan explicit > SCAN_PROFILE > fallback."""
	if request_hitl:
		return request_hitl
	profile = _config.settings.scan_profile
	return SCAN_PROFILE_DEFAULTS.get(profile, {}).get("hitl_mode", "off")


def _resolve_adaptive_mode(request_adaptive: Optional[str]) -> str:
	"""Resolve adaptive mode: per-scan explicit > SCAN_PROFILE > fallback."""
	if request_adaptive:
		return request_adaptive
	profile = _config.settings.scan_profile
	return SCAN_PROFILE_DEFAULTS.get(profile, {}).get("adaptive_mode", "aggressive")


router = APIRouter()


@router.post("/scans", response_model=ScanStatusResponse)
async def create_scan(req: CreateScanRequest):
	# Auto-add whitelist_domain(s) — supports single string or list
	# Safe-Change Rule #6: append BEFORE validate_target
	for domain in req.get_whitelist_list():
		d = domain.lower().strip()
		if d and d not in security_guard.whitelist_domains:
			security_guard.whitelist_domains.append(d)

	# 🔒 SECURITY VALIDATION: Validate target before creating scan
	try:
		await security_guard.validate_target(
			url=str(req.target),
			auth_token=req.authorization_token
		)
	except UnauthorizedTargetError as e:
		audit_logger.log_unauthorized_attempt(
			target=str(req.target),
			reason=str(e),
			source_ip="API_REQUEST"
		)
		raise HTTPException(status_code=403, detail=f"Unauthorized target: {str(e)}")
	except SecurityPolicyViolation as e:
		audit_logger.log_unauthorized_attempt(
			target=str(req.target),
			reason=f"Security policy violation: {str(e)}",
			source_ip="API_REQUEST"
		)
		raise HTTPException(status_code=403, detail=f"Security policy violation: {str(e)}")
	except InvalidAuthTokenError as e:
		audit_logger.log_unauthorized_attempt(
			target=str(req.target),
			reason=f"Invalid authorization token: {str(e)}",
			source_ip="API_REQUEST"
		)
		raise HTTPException(status_code=401, detail=f"Invalid authorization token: {str(e)}")

	with get_db() as db:
		job = Job(target=str(req.target), status=JobStatus.queued)
		db.add(job)
		db.commit()
		db.refresh(job)

	# Persist scan credentials to SharedContext so orchestrator can use them
	if req.credentials:
		from multi_agent_system.utils.shared_context_manager import SharedContextManager
		ctx = SharedContextManager(job_id=job.id)
		ctx.write("scan_credentials", {
			"username": req.credentials.username,
			"password": req.credentials.password,
			"auth_type": req.credentials.auth_type,
		})

	# 📝 AUDIT LOG: Record scan initiation
	token_hash = hashlib.sha256(req.authorization_token.encode()).hexdigest() if req.authorization_token else None
	audit_logger.log_scan_started(
		job_id=job.id,
		target=str(req.target),
		user=req.user_email or "anonymous",
		auth_token_hash=token_hash
	)

	# Build plan metadata, capturing the requested coverage mode
	plan_sequence = list(DEFAULT_PLAN)
	plan_payload = {
		"sequence": plan_sequence,
		"options": {
			"full_wstg_coverage": bool(req.full_wstg_coverage),
			"hitl_enabled": req.hitl_enabled,
			"enable_tool_hitl": req.enable_tool_hitl,
			"hitl_mode": req.hitl_mode,
			"auto_approve_agents": req.auto_approve_agents,
			"skip_agents": req.skip_agents or [],
		}
	}

	# Persist plan on job for orchestrator
	with get_db() as db:
		j = db.query(Job).get(job.id)
		if j:
			j.plan = plan_payload
			db.commit()

	# Pre-create job_agents for the plan so clients can see pending agents immediately
	with get_db() as db:
		for step in plan_sequence:
			if isinstance(step, str):
				db.add(JobAgent(job_id=job.id, agent_name=step, status=AgentStatus.pending))
			elif isinstance(step, dict) and "parallel" in step:
				for name in step["parallel"]:
					db.add(JobAgent(job_id=job.id, agent_name=name, status=AgentStatus.pending))
		db.commit()

	# Enqueue background job via Celery app (ensures correct broker/config)
	celery_app.send_task("multi_agent_system.tasks.tasks.run_job_task", args=[job.id])

	return get_status(job.id)


@router.get("/scans", response_model=list[ScanStatusResponse])
def list_scans(limit: int = 20):
	"""Return recent scans ordered by newest first (used by frontend auto-restore)."""
	with get_db() as db:
		jobs = db.query(Job).order_by(Job.id.desc()).limit(limit).all()
		result = []
		for job in jobs:
			agents = db.query(JobAgent).filter(JobAgent.job_id == job.id).all()
			agent_states = [
				JobAgentState(
					agent_name=a.agent_name,
					status=a.status.value if hasattr(a.status, 'value') else str(a.status),
					started_at=a.started_at,
					finished_at=a.finished_at,
					error=a.error,
				)
				for a in agents
			]
			result.append(ScanStatusResponse(
				job_id=job.id,
				status=job.status.value if hasattr(job.status, 'value') else str(job.status),
				agents=agent_states,
				summary=job.summary,
			))
		return result


@router.get("/scans/{job_id}", response_model=ScanStatusResponse)
def get_status(job_id: int):
	with get_db() as db:
		job = db.query(Job).get(job_id)
		if not job:
			raise HTTPException(status_code=404, detail="Job not found")
		agents = db.query(JobAgent).filter(JobAgent.job_id == job_id).all()

		# Auto-heal: if all agents are in terminal states but job is still 'running',
		# compute and persist the correct final status (handles worker crash / LLM hang).
		job_status_str = job.status.value if hasattr(job.status, 'value') else str(job.status)
		if job_status_str == "running" and agents:
			_terminal = {AgentStatus.completed, AgentStatus.failed, AgentStatus.skipped}
			if all(a.status in _terminal for a in agents):
				report_agent = next(
					(a for a in agents if a.agent_name == "ReportGenerationAgent"), None
				)
				report_ok = bool(report_agent and report_agent.status == AgentStatus.completed)
				any_failed = any(a.status == AgentStatus.failed for a in agents)
				job.status = JobStatus.completed if (report_ok or not any_failed) else JobStatus.failed
				job.updated_at = datetime.utcnow()
				db.commit()
				job_status_str = job.status.value

		agent_states = [
			JobAgentState(
				agent_name=a.agent_name,
				status=a.status.value if hasattr(a.status, 'value') else str(a.status),
				started_at=a.started_at,
				finished_at=a.finished_at,
				error=a.error,
			)
			for a in agents
		]
		return ScanStatusResponse(job_id=job.id, status=job_status_str, agents=agent_states, summary=job.summary)


@router.post("/scans/{job_id}/cancel")
def cancel_scan(job_id: int):
	"""Cancel a running scan"""
	with get_db() as db:
		job = db.query(Job).get(job_id)
		if not job:
			raise HTTPException(status_code=404, detail="Job not found")
		
		# Allow cancelling queued, running, or paused jobs
		if job.status not in [JobStatus.queued, JobStatus.running, JobStatus.paused]:
			raise HTTPException(
				status_code=400,
				detail=f"Cannot cancel job with status: {job.status}"
			)

		# Clear any pending pause flag so orchestrator cannot act on it later
		from multi_agent_system.utils import pause_manager
		pause_manager.clear_pause_flag(job_id)

		# Update job status to cancelled
		job.status = JobStatus.cancelled
		job.updated_at = datetime.utcnow()
		
		# Mark all pending/running agents as skipped
		agents = db.query(JobAgent).filter(
			JobAgent.job_id == job_id,
			JobAgent.status.in_([AgentStatus.pending, AgentStatus.running])
		).all()
		
		for agent in agents:
			agent.status = AgentStatus.skipped
			if not agent.finished_at:
				agent.finished_at = datetime.utcnow()
		
		db.commit()
		
		# Try to revoke Celery task if it's still queued
		try:
			from multi_agent_system.tasks.celery_app import celery_app
			# Revoke all tasks for this job
			celery_app.control.revoke(
				f"multi_agent_system.tasks.tasks.run_job_task-{job_id}",
				terminate=True,
				signal='SIGKILL'
			)
		except Exception as e:
			print(f"[API] Warning: Could not revoke Celery task: {e}")
		
	return {"message": "Scan cancelled successfully", "job_id": job_id}


@router.post("/scans/{job_id}/pause", status_code=202)
def pause_scan(job_id: int):
	"""Request pause. Queued jobs flip to paused immediately; running jobs get a Redis flag."""
	from multi_agent_system.utils import pause_manager
	with get_db() as db:
		job = db.query(Job).get(job_id)
		if not job:
			raise HTTPException(status_code=404, detail="Job not found")

		if job.status == JobStatus.queued:
			job.status = JobStatus.paused
			job.paused_state = {
				"step_idx": 0,
				"paused_at": datetime.utcnow().isoformat() + "Z",
				"paused_by": "api",
			}
			job.updated_at = datetime.utcnow()
			db.commit()
			return {"message": "Queued job paused immediately", "job_id": job_id, "status": "paused"}

		if job.status == JobStatus.running:
			pause_manager.set_pause_requested(job_id)
			return {
				"message": "Pause requested; will take effect at next agent boundary (up to 45 min)",
				"job_id": job_id,
				"status": "running",
				"eta_hint": "pause_at_next_agent",
			}

		raise HTTPException(status_code=409, detail=f"Cannot pause job with status: {job.status.value}")


@router.post("/scans/{job_id}/resume", status_code=202)
def resume_scan(job_id: int):
	"""Resume a paused scan by dispatching a new Celery task at the saved step index."""
	from multi_agent_system.tasks.tasks import run_job_task
	with get_db() as db:
		job = db.query(Job).get(job_id)
		if not job:
			raise HTTPException(status_code=404, detail="Job not found")

		if job.status != JobStatus.paused:
			raise HTTPException(status_code=409, detail=f"Cannot resume job with status: {job.status.value}")

		if not job.paused_state or "step_idx" not in job.paused_state:
			raise HTTPException(status_code=500, detail="paused_state missing or corrupt")

		step_idx = int(job.paused_state["step_idx"])
		job.status = JobStatus.running
		job.paused_state = None
		job.updated_at = datetime.utcnow()
		db.commit()

	run_job_task.delay(job_id=job_id, resume_from_step_idx=step_idx)

	return {
		"message": f"Scan resumed from step {step_idx}",
		"job_id": job_id,
		"status": "running",
		"resume_from_step_idx": step_idx,
	}


# ============================================================================
# HITL Live Execution Monitor — status & intervention
# ============================================================================

@router.get("/scans/{job_id}/execution-status")
def get_execution_status(job_id: int):
	"""Return real-time execution status (current URL, test type, ReAct iteration)."""
	from multi_agent_system.models.models import SharedContext
	with get_db() as db:
		job = db.query(Job).get(job_id)
		if not job:
			raise HTTPException(status_code=404, detail="Job not found")
		record = db.query(SharedContext).filter(
			SharedContext.job_id == job_id,
			SharedContext.key == "execution_status"
		).one_or_none()
		return record.value if record and record.value else {}


class InterventionRequest(BaseModel):
	action: str   # cancel_test, skip_url, skip_test, skip_agent, change_technique
	technique: str | None = None
	reason: str | None = None


@router.post("/scans/{job_id}/intervene")
def intervene(job_id: int, req: InterventionRequest):
	"""Send a HITL intervention signal to a running agent."""
	valid_actions = {"cancel_test", "skip_url", "skip_test", "skip_agent", "change_technique"}
	if req.action not in valid_actions:
		raise HTTPException(status_code=400, detail=f"Invalid action. Must be one of: {valid_actions}")

	from multi_agent_system.models.models import SharedContext
	signal = {"action": req.action, "reason": req.reason or "User intervention from dashboard"}
	if req.technique:
		signal["technique"] = req.technique

	with get_db() as db:
		job = db.query(Job).get(job_id)
		if not job:
			raise HTTPException(status_code=404, detail="Job not found")
		record = db.query(SharedContext).filter(
			SharedContext.job_id == job_id,
			SharedContext.key == "hitl_intervention"
		).one_or_none()
		if record:
			record.value = signal
		else:
			db.add(SharedContext(job_id=job_id, key="hitl_intervention", value=signal))
		db.commit()

	return {"status": "success", "message": f"Intervention '{req.action}' sent", "job_id": job_id}


@router.get("/scans/{job_id}/costs")
def get_scan_costs(job_id: int):
	"""
	Get LLM API usage and cost breakdown for a scan.

	Returns:
		- total_prompt_tokens: Total prompt tokens used
		- total_completion_tokens: Total completion tokens used
		- total_tokens: Combined token usage
		- estimated_cost_usd: Total estimated cost in USD
		- breakdown: Per-component cost breakdown
	"""
	with get_db() as db:
		# Verify job exists
		job = db.query(Job).get(job_id)
		if not job:
			raise HTTPException(status_code=404, detail="Job not found")

		# Query cost records for this job
		costs = db.query(ScanCost).filter_by(job_id=job_id).all()

		if not costs:
			return {
				"scan_id": job_id,
				"total_prompt_tokens": 0,
				"total_completion_tokens": 0,
				"total_tokens": 0,
				"estimated_cost_usd": 0.0,
				"breakdown": [],
				"message": "No cost data available (using local LLM or scan not started)"
			}

		# Calculate totals
		total_prompt = sum(c.prompt_tokens for c in costs)
		total_completion = sum(c.completion_tokens for c in costs)
		total_tokens = total_prompt + total_completion
		total_cost = sum(c.estimated_cost_usd for c in costs)

		# Build breakdown by component
		breakdown = []
		for cost in costs:
			breakdown.append({
				"component": cost.component,
				"agent_name": cost.agent_name,
				"prompt_tokens": cost.prompt_tokens,
				"completion_tokens": cost.completion_tokens,
				"total_tokens": cost.prompt_tokens + cost.completion_tokens,
				"cost_usd": float(cost.estimated_cost_usd),
				"timestamp": cost.created_at.isoformat()
			})

		return {
			"scan_id": job_id,
			"total_prompt_tokens": total_prompt,
			"total_completion_tokens": total_completion,
			"total_tokens": total_tokens,
			"estimated_cost_usd": float(total_cost),
			"cost_per_finding": float(total_cost / len(job.findings)) if job.findings else 0.0,
			"breakdown": breakdown
		}


