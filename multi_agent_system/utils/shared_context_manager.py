from __future__ import annotations

from datetime import datetime, timedelta
import uuid
from typing import Any, Callable, Dict, Optional

from ..core.db import get_db
from ..models.models import SharedContext
from .secret_store import decrypt_json, encrypt_json

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

    def delete(self, key: str) -> None:
        with get_db() as db:
            record = db.query(SharedContext).filter(
                SharedContext.job_id == self.job_id,
                SharedContext.key == key,
            ).one_or_none()
            if record:
                db.delete(record)
                db.commit()
        self._log("debug", "shared_context.delete", {"key": key})

    def delete_prefix(self, prefix: str) -> int:
        deleted = 0
        with get_db() as db:
            rows = db.query(SharedContext).filter(
                SharedContext.job_id == self.job_id,
                SharedContext.key.like(f"{prefix}%"),
            ).all()
            for row in rows:
                db.delete(row)
                deleted += 1
            if deleted:
                db.commit()
        self._log("debug", "shared_context.delete_prefix", {"prefix": prefix, "deleted": deleted})
        return deleted

    def write_secret(self, kind: str, value: Any) -> str:
        secret_ref = f"{kind}-{uuid.uuid4().hex}"
        self.write(
            f"secret::{secret_ref}",
            {
                "kind": kind,
                "ciphertext": encrypt_json(value),
                "created_at": datetime.utcnow().isoformat(),
                "version": 1,
            },
        )
        return secret_ref

    def read_secret(self, secret_ref: str) -> Any:
        if not secret_ref:
            return None
        payload = self.read(f"secret::{secret_ref}")
        if not isinstance(payload, dict):
            return None
        ciphertext = payload.get("ciphertext")
        if not ciphertext:
            return None
        return decrypt_json(ciphertext)

    def acquire_execution_lease(self, execution_id: str, lease_timeout_seconds: int) -> bool:
        now = datetime.utcnow()
        stale_before = now - timedelta(seconds=max(lease_timeout_seconds, 1))

        with get_db() as db:
            record = (
                db.query(SharedContext)
                .filter(SharedContext.job_id == self.job_id, SharedContext.key == "execution_control")
                .one_or_none()
            )
            current = record.value if record else {}
            active_status = current.get("status")
            active_execution_id = current.get("execution_id")
            heartbeat_raw = current.get("heartbeat_at") or current.get("started_at")
            heartbeat_at = None
            if heartbeat_raw:
                try:
                    heartbeat_at = datetime.fromisoformat(heartbeat_raw)
                except Exception:
                    heartbeat_at = None

            if (
                active_status == "running"
                and active_execution_id
                and active_execution_id != execution_id
                and heartbeat_at
                and heartbeat_at > stale_before
            ):
                self._log(
                    "warning",
                    "shared_context.execution_lease_denied",
                    {"execution_id": execution_id, "active_execution_id": active_execution_id},
                )
                return False

            if active_status == "running" and active_execution_id == execution_id:
                self._log(
                    "warning",
                    "shared_context.execution_lease_duplicate",
                    {"execution_id": execution_id},
                )
                return False

            new_value = {
                "execution_id": execution_id,
                "status": "running",
                "started_at": current.get("started_at") if active_execution_id == execution_id else now.isoformat(),
                "heartbeat_at": now.isoformat(),
            }
            if record:
                record.value = new_value
            else:
                db.add(SharedContext(job_id=self.job_id, key="execution_control", value=new_value))
            db.commit()
        self._log("debug", "shared_context.execution_lease_acquired", {"execution_id": execution_id})
        return True

    def touch_execution_lease(self, execution_id: str) -> None:
        with get_db() as db:
            record = (
                db.query(SharedContext)
                .filter(SharedContext.job_id == self.job_id, SharedContext.key == "execution_control")
                .one_or_none()
            )
            if not record or not isinstance(record.value, dict):
                return
            if record.value.get("execution_id") != execution_id:
                return
            updated = dict(record.value)
            updated["heartbeat_at"] = datetime.utcnow().isoformat()
            record.value = updated
            db.commit()
        self._log("debug", "shared_context.execution_lease_touch", {"execution_id": execution_id})

    def release_execution_lease(self, execution_id: str, final_status: str) -> None:
        with get_db() as db:
            record = (
                db.query(SharedContext)
                .filter(SharedContext.job_id == self.job_id, SharedContext.key == "execution_control")
                .one_or_none()
            )
            if not record or not isinstance(record.value, dict):
                return
            if record.value.get("execution_id") != execution_id:
                return
            updated = dict(record.value)
            updated["status"] = final_status
            updated["released_at"] = datetime.utcnow().isoformat()
            record.value = updated
            db.commit()
        self._log(
            "debug",
            "shared_context.execution_lease_released",
            {"execution_id": execution_id, "final_status": final_status},
        )

    def bulk_write(self, values: Dict[str, Any]) -> None:
        for key, value in values.items():
            self.write(key, value)

    def _log(self, level: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        if self._log_hook:
            try:
                self._log_hook(level, message, data)
            except Exception:
                pass
