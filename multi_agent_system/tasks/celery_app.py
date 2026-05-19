from __future__ import annotations

from celery import Celery
from ..core.config import settings


celery_app = Celery(
    "rajdoll",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_soft_time_limit=settings.celery_soft_time_limit,
    task_time_limit=settings.celery_hard_time_limit,
    worker_max_tasks_per_child=100,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_transport_options={
        "visibility_timeout": settings.celery_visibility_timeout,
    },
)

# Import tasks so they're registered when the app module is imported
try:  # pragma: no cover
    from . import tasks  # noqa: F401
except Exception:
    pass

# Also enable autodiscovery for good measure
celery_app.autodiscover_tasks(['multi_agent_system.tasks'])


@celery_app.task(bind=True)
def healthcheck(self):  # pragma: no cover
    return "ok"


from celery.signals import worker_ready

@worker_ready.connect
def recover_stuck_jobs(sender, **kwargs):
    """On worker startup: find jobs stuck in waiting_checkpoint, auto-approve pending
    checkpoints, and re-queue them so they resume from the next agent."""
    import time
    time.sleep(3)  # Wait for DB connections to settle

    try:
        from ..core.db import get_db
        from ..models.models import Job, JobStatus
        from ..models.hitl_models import AgentCheckpoint, CheckpointAction
        from datetime import datetime

        with get_db() as db:
            stuck_jobs = db.query(Job).filter(
                Job.status == JobStatus.waiting_checkpoint
            ).all()

            if not stuck_jobs:
                return

            print(f"[Recovery] Found {len(stuck_jobs)} stuck job(s) in waiting_checkpoint")

            for job in stuck_jobs:
                pending_cp = (
                    db.query(AgentCheckpoint)
                    .filter(
                        AgentCheckpoint.job_id == job.id,
                        AgentCheckpoint.action == CheckpointAction.pending,
                    )
                    .order_by(AgentCheckpoint.id.desc())
                    .first()
                )

                if not pending_cp:
                    job.status = JobStatus.running
                    print(f"[Recovery] Job {job.id}: no pending checkpoint, restored to running")
                    db.commit()
                    continue

                pending_cp.action = CheckpointAction.proceed
                pending_cp.responded_at = datetime.utcnow()
                pending_cp.user_notes = "Auto-approved by worker recovery on restart"
                pending_cp.wait_duration_seconds = int(
                    (datetime.utcnow() - pending_cp.requested_at).total_seconds()
                ) if pending_cp.requested_at else 0

                seq_idx = pending_cp.agent_sequence_index or 0
                if pending_cp.checkpoint_type == "pre_agent":
                    resume_from = seq_idx
                else:
                    resume_from = seq_idx + 1

                job.status = JobStatus.queued
                db.commit()

                celery_app.send_task(
                    "multi_agent_system.tasks.tasks.run_job_task",
                    args=[job.id, resume_from],
                )
                print(
                    f"[Recovery] Job {job.id}: approved checkpoint {pending_cp.id}, "
                    f"re-queued with resume_from_step_idx={resume_from}"
                )

    except Exception as e:
        print(f"[Recovery] ERROR during stuck job recovery: {e}")
