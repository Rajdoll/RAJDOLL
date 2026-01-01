from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from ..core.db import get_db
from ..models.models import SharedContext

LogHook = Callable[[str, str, Optional[Dict[str, Any]]], None]


class SharedContextManager:
    """Utility for reading/writing shared context with optional logging."""

    def __init__(self, job_id: int, log_hook: Optional[LogHook] = None) -> None:
        self.job_id = job_id
        self._log_hook = log_hook

    def load_all(self) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {}
        with get_db() as db:
            rows = db.query(SharedContext).filter(SharedContext.job_id == self.job_id).all()
            for row in rows:
                try:
                    ctx[row.key] = row.value
                except Exception:
                    continue
        self._log("debug", "shared_context.load_all", {"keys": list(ctx.keys())})
        return ctx

    def read(self, key: str) -> Any:
        with get_db() as db:
            record = db.query(SharedContext).filter(SharedContext.job_id == self.job_id, SharedContext.key == key).one_or_none()
            value = record.value if record else None
        self._log("debug", "shared_context.read", {"key": key, "hit": bool(value)})
        return value

    def write(self, key: str, value: Any) -> None:
        with get_db() as db:
            record = db.query(SharedContext).filter(SharedContext.job_id == self.job_id, SharedContext.key == key).one_or_none()
            if record:
                record.value = value
            else:
                db.add(SharedContext(job_id=self.job_id, key=key, value=value))
            db.commit()
        size = len(value) if hasattr(value, "__len__") else None
        self._log("debug", "shared_context.write", {"key": key, "size": size})

    def bulk_write(self, values: Dict[str, Any]) -> None:
        for key, value in values.items():
            self.write(key, value)

    def _log(self, level: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        if self._log_hook:
            try:
                self._log_hook(level, message, data)
            except Exception:
                pass
