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
        from ..models.models import Job, JobAgent, JobStatus, AgentStatus
        from ..models.hitl_models import AgentCheckpoint, CheckpointAction
        from datetime import datetime

        with get_db() as db:
            now = datetime.utcnow()

            # ── Zombie reaper: jobs stuck in 'running' whose worker died ──────────
            # With task_acks_late a recently-dead task may still be redelivered and
            # resume, so only reap clearly-stale ones (well past a normal scan and the
            # 2h agent timeout). The 14-16 day zombies are caught; active/resuming
            # scans are left untouched.
            reaped = 0
            for job in db.query(Job).filter(Job.status == JobStatus.running).all():
                age_hours = (now - job.updated_at).total_seconds() / 3600 if job.updated_at else 99
                if age_hours <= 3:
                    continue
                job.status = JobStatus.failed
                job.updated_at = now
                for ja in db.query(JobAgent).filter(
                    JobAgent.job_id == job.id,
                    JobAgent.status.in_([AgentStatus.running, AgentStatus.pending]),
                ).all():
                    ja.status = AgentStatus.failed
                    if not ja.finished_at:
                        ja.finished_at = now
                    ja.error = "Orphaned: worker died (startup reconcile)"
                reaped += 1
            if reaped:
                db.commit()
                print(f"[Recovery] Reaped {reaped} zombie 'running' job(s) as failed")

            # ── waiting_checkpoint recovery (existing) ───────────────────────────
            stuck_jobs = db.query(Job).filter(
                Job.status == JobStatus.waiting_checkpoint
            ).all()

            if not stuck_jobs:
                return

            print(f"[Recovery] Found {len(stuck_jobs)} stuck job(s) in waiting_checkpoint")

            for job in stuck_jobs:
                age_hours = (now - job.updated_at).total_seconds() / 3600 if job.updated_at else 99

                # Jobs older than 1 hour: the Celery task is definitely dead — cancel them
                if age_hours > 1:
                    job.status = JobStatus.cancelled
                    db.commit()
                    print(f"[Recovery] Job {job.id}: cancelled (stale, {age_hours:.1f}h old)")
                    continue

                # Recent jobs: Celery task may still be alive and polling — just approve
                # the checkpoint so it picks it up automatically. No re-queue needed.
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
                    db.commit()
                    print(f"[Recovery] Job {job.id}: no pending checkpoint, restored to running")
                    continue

                pending_cp.action = CheckpointAction.proceed
                pending_cp.responded_at = now
                pending_cp.user_notes = "Auto-approved by worker recovery on restart"
                pending_cp.wait_duration_seconds = int(
                    (now - pending_cp.requested_at).total_seconds()
                ) if pending_cp.requested_at else 0
                db.commit()
                print(f"[Recovery] Job {job.id}: approved checkpoint {pending_cp.id} (task may still be alive)")

    except Exception as e:
        print(f"[Recovery] ERROR during stuck job recovery: {e}")
