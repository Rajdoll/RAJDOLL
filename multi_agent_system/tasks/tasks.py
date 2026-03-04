from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Dict, Any, List

from celery import shared_task

from ..core.config import settings
from ..core.db import get_db
from ..models.models import Job, JobAgent, AgentStatus, JobStatus
from ..orchestrator import Orchestrator


def _format_exception_message(exc: BaseException) -> str:
    """Return a non-empty, human-usable error string for persistence."""
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    msg = str(exc).strip()
    return msg if msg else type(exc).__name__


def _now():
    return datetime.utcnow()


@shared_task(bind=True, soft_time_limit=settings.agent_timeout, time_limit=settings.agent_timeout + 60, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 1})
def run_agent_task(self, job_id: int, agent_name: str) -> str:
    """Execute a single agent within time limits and update DB state."""
    with get_db() as db:
        ja = db.query(JobAgent).filter(JobAgent.job_id == job_id, JobAgent.agent_name == agent_name).one()
        ja.status = AgentStatus.running
        ja.started_at = _now()
        ja.attempts += 1
        db.commit()

    try:
        # Import here to avoid circulars
        from ..agents.base_agent import AgentRegistry
        agent_cls = AgentRegistry.get(agent_name)
        agent = agent_cls(job_id=job_id)
        # Run in an event loop
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(agent.run())  # type: ignore[name-defined]
        status = AgentStatus.completed
        error = None
    except Exception as e:  # pragma: no cover
        status = AgentStatus.failed
        error = _format_exception_message(e)
    finally:
        with get_db() as db:
            ja = db.query(JobAgent).filter(JobAgent.job_id == job_id, JobAgent.agent_name == agent_name).one()
            ja.status = status
            ja.finished_at = _now()
            if status == AgentStatus.failed:
                current = (error or "").strip()
                ja.error = current if current else "Agent failed (no error details)"
            else:
                ja.error = error
            db.commit()
    return status.value


@shared_task(bind=True, soft_time_limit=settings.job_total_timeout, time_limit=settings.job_total_timeout + 60, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 0})
def run_job_task(self, job_id: int) -> str:
    """Top-level orchestration task; creates plan, executes agents sequentially/parallel, aggregates."""
    orch = Orchestrator(job_id=job_id)
    try:
        orch.run()
    except Exception:  # pragma: no cover
        # We'll still compute final status from persisted agent states below.
        pass

    with get_db() as db:
        job = db.query(Job).get(job_id)
        if not job:
            return JobStatus.failed.value

        # Respect explicit cancellation.
        if job.status == JobStatus.cancelled:
            job.updated_at = _now()
            db.commit()
            return job.status.value

        statuses = db.query(JobAgent.status).filter(JobAgent.job_id == job_id).all()
        flat_statuses = [s[0] for s in statuses]

        any_failed = any(s == AgentStatus.failed for s in flat_statuses)
        any_incomplete = any(s in (AgentStatus.pending, AgentStatus.running) for s in flat_statuses)

        if any_failed or any_incomplete:
            final = JobStatus.failed
        else:
            final = JobStatus.completed

        job.status = final
        job.updated_at = _now()
        db.commit()
        return final.value
