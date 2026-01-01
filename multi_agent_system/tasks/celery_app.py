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
