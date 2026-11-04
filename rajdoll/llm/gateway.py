"""Every LLM call goes through here (TRD 5.4; PRD F-37).

- One call at a time: a process lock plus a PostgreSQL advisory lock (one GPU serves one call).
- A per-scan budget; past it, calls are recorded as `skipped_budget` and the caller falls back.
- Output must validate against the task's pydantic model; a failure gets one repair prompt, a
  second failure is `schema_error` and the caller falls back.
- A server that cannot be reached is skipped for a while (no row per skip), so a missing LM
  Studio never slows a scan down: every caller has a rule-based fallback (TRD P2).
- Every call is recorded in `llm_call` with the prompt and output encrypted per engagement.

The gateway only returns validated data. What a caller does with it is bounded by its schema;
the LLM never confirms a finding and never changes the pipeline (TRD P1, P3).
"""

from __future__ import annotations

import base64
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from rajdoll.core.crypto import KeyStore
from rajdoll.core.enums import LlmCallStatus
from rajdoll.core.models import Engagement, LlmCall, Scan
from rajdoll.llm.client import (
    Completion,
    LlmClient,
    LlmConfig,
    LlmError,
    LlmTimeout,
    LlmUnavailable,
    extract_json,
)
from rajdoll.llm.context import CHARS_PER_TOKEN, MAX_INPUT_TOKENS, MAX_OUTPUT_TOKENS, clip
from rajdoll.services import engagements
from rajdoll.services import settings as app_settings

T = TypeVar("T", bound=BaseModel)
ADVISORY_LOCK_KEY = 0x524A444C4C4D  # "RJDLLM"
DISABLED = "disabled"
UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class LlmTask[T: BaseModel]:
    kind: str  # LlmTaskKind
    output: type[T]
    max_tokens: int = MAX_OUTPUT_TOKENS


@dataclass
class LlmOutcome[T: BaseModel]:
    value: T | None
    status: str  # an LlmCallStatus, or "disabled" / "unavailable" (no call made)
    call_id: int | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.value is not None


def api_key(keystore: KeyStore, settings: app_settings.AppSettings) -> str | None:
    if not settings.llm.api_key_enc:
        return None
    blob = base64.b64decode(settings.llm.api_key_enc)
    return keystore.decrypt_app_secret(blob, "llm.api_key")


def encrypt_api_key(keystore: KeyStore, value: str) -> str:
    return base64.b64encode(keystore.encrypt_app_secret(value, "llm.api_key")).decode()


class LlmGateway:
    UNAVAILABLE_FOR_S = 300.0
    _process_lock = threading.Lock()

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        keystore: KeyStore,
        client_factory: Callable[[LlmConfig], LlmClient] = LlmClient,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.session_factory = session_factory
        self.keystore = keystore
        self.client_factory = client_factory
        self.clock = clock
        self._down_until: dict[str, float] = {}

    # -- configuration ------------------------------------------------------------------

    def _config(self, session: Session, scan: Scan | None) -> tuple[dict[str, Any], LlmConfig]:
        settings = app_settings.load(session)
        current = {
            "enabled": settings.llm.enabled,
            "base_url": str(settings.llm.base_url),
            "model": settings.llm.model,
            "is_local": None,
            "thinking": settings.llm.thinking,
            "timeout_s": settings.llm.timeout_s,
            "budget": settings.llm_budget_per_scan,
        }
        # A scan keeps the LLM it started with (PRD NF-06: the assessor saw where data goes).
        snapshot = {**current, **(scan.llm_snapshot if scan is not None else {})}
        if snapshot["is_local"] is None:
            from rajdoll.services.scans import is_local_llm

            snapshot["is_local"] = is_local_llm(snapshot["base_url"])
        same_server = snapshot["base_url"] == current["base_url"]
        key = api_key(self.keystore, settings) if same_server else None
        config = LlmConfig(
            base_url=snapshot["base_url"],
            model=snapshot["model"],
            api_key=key,
            thinking=bool(snapshot["thinking"]),
        )
        return snapshot, config

    # -- recording ------------------------------------------------------------------------

    def _record(
        self,
        session: Session,
        engagement: Engagement,
        scan_id: int | None,
        task: LlmTask[Any],
        snapshot: dict[str, Any],
        messages: list[dict[str, str]],
        output: dict[str, Any] | None,
        status: str,
        finding_id: int | None,
        endpoint_id: int | None,
        tokens_in: int | None = None,
        tokens_out: int | None = None,
        duration_ms: int | None = None,
    ) -> int:
        cipher = engagements.cipher(self.keystore, engagement)
        row = LlmCall(
            engagement_id=engagement.id,
            scan_id=scan_id,
            task_kind=task.kind,
            finding_id=finding_id,
            endpoint_id=endpoint_id,
            model=snapshot["model"],
            is_local=bool(snapshot["is_local"]),
            prompt_enc=cipher.encrypt_json("llm_call", "prompt_enc", messages),
            output_enc=(
                None if output is None else cipher.encrypt_json("llm_call", "output_enc", output)
            ),
            status=status,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            duration_ms=duration_ms,
        )
        session.add(row)
        session.flush()
        return row.id

    @staticmethod
    def _used(session: Session, scan_id: int) -> int:
        return (
            session.scalar(
                select(func.count())
                .select_from(LlmCall)
                .where(LlmCall.scan_id == scan_id, LlmCall.status != LlmCallStatus.SKIPPED_BUDGET)
            )
            or 0
        )

    # -- the call -------------------------------------------------------------------------

    def call(
        self,
        task: LlmTask[T],
        messages: list[dict[str, str]],
        *,
        engagement_id: int,
        scan_id: int | None = None,
        finding_id: int | None = None,
        endpoint_id: int | None = None,
    ) -> LlmOutcome[T]:
        messages = _bounded(messages)
        with self.session_factory() as session:
            scan = session.get(Scan, scan_id) if scan_id else None
            snapshot, config = self._config(session, scan)
        if not snapshot["enabled"]:
            return LlmOutcome(None, DISABLED)
        if self._down_until.get(config.base_url, 0) > self.clock():
            return LlmOutcome(None, UNAVAILABLE)

        with self._process_lock, self.session_factory() as session:
            session.execute(select(func.pg_advisory_lock(ADVISORY_LOCK_KEY)))
            try:
                return self._locked_call(
                    session, task, messages, snapshot, config,
                    engagement_id, scan_id, finding_id, endpoint_id,
                )  # fmt: skip
            finally:
                session.rollback()  # anything not committed by _locked_call
                session.execute(select(func.pg_advisory_unlock(ADVISORY_LOCK_KEY)))
                session.commit()

    def _locked_call(
        self,
        session: Session,
        task: LlmTask[T],
        messages: list[dict[str, str]],
        snapshot: dict[str, Any],
        config: LlmConfig,
        engagement_id: int,
        scan_id: int | None,
        finding_id: int | None,
        endpoint_id: int | None,
    ) -> LlmOutcome[T]:
        engagement = session.get(Engagement, engagement_id)
        if engagement is None:
            return LlmOutcome(None, DISABLED)

        def record(output: dict[str, Any] | None, status: str, **usage: Any) -> int:
            call_id = self._record(
                session, engagement, scan_id, task, snapshot, transcript, output, status,
                finding_id, endpoint_id, **usage,
            )  # fmt: skip
            session.commit()
            return call_id

        transcript = list(messages)
        if scan_id is not None and self._used(session, scan_id) >= int(snapshot["budget"]):
            return LlmOutcome(None, LlmCallStatus.SKIPPED_BUDGET, record(None, "skipped_budget"))

        client = self.client_factory(config)
        schema = task.output.model_json_schema()
        timeout = float(snapshot["timeout_s"])
        answers: list[str] = []
        usage = {"tokens_in": 0, "tokens_out": 0, "duration_ms": 0}
        for attempt in (1, 2):
            try:
                completion = client.complete(
                    transcript, schema, task.kind, task.max_tokens, timeout
                )
            except LlmTimeout:
                output = {"answers": answers, "error": "timeout"}
                return LlmOutcome(None, LlmCallStatus.TIMEOUT, record(output, "timeout", **usage))
            except LlmUnavailable as exc:
                self._down_until[config.base_url] = self.clock() + self.UNAVAILABLE_FOR_S
                output = {"answers": answers, "error": str(exc)[:500]}
                return LlmOutcome(None, LlmCallStatus.ERROR, record(output, "error", **usage))
            except LlmError as exc:
                output = {"answers": answers, "error": str(exc)[:500]}
                return LlmOutcome(None, LlmCallStatus.ERROR, record(output, "error", **usage))
            _add_usage(usage, completion)
            answers.append(completion.text)
            try:
                value = task.output.model_validate(extract_json(completion.text))
            except (ValueError, ValidationError) as exc:
                if attempt == 2:
                    output = {"answers": answers, "error": _short(exc)}
                    status = LlmCallStatus.SCHEMA_ERROR
                    return LlmOutcome(None, status, record(output, status, **usage))
                transcript += [
                    {"role": "assistant", "content": completion.text},
                    {"role": "user", "content": _repair_prompt(exc)},
                ]
                continue
            status = LlmCallStatus.OK if attempt == 1 else LlmCallStatus.SCHEMA_RETRY_OK
            output = {"answers": answers, "parsed": value.model_dump(mode="json")}
            return LlmOutcome(value, status, record(output, status, **usage))
        raise AssertionError("unreachable")  # pragma: no cover


def _add_usage(usage: dict[str, int], completion: Completion) -> None:
    usage["tokens_in"] += completion.tokens_in or 0
    usage["tokens_out"] += completion.tokens_out or 0
    usage["duration_ms"] += completion.duration_ms


def _short(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'root'}: {e['msg']}" for e in exc.errors()
        )[:500]
    return f"bukan JSON yang valid ({type(exc).__name__})"


def _repair_prompt(exc: Exception) -> str:
    return (
        f"Jawaban sebelumnya tidak sesuai skema: {_short(exc)}. "
        "Balas ulang hanya dengan satu objek JSON yang sesuai skema, tanpa teks lain."
    )


def _bounded(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    """Clip the last user message so the prompt stays within the input budget (TRD 5.3)."""
    limit = MAX_INPUT_TOKENS * CHARS_PER_TOKEN
    total = sum(len(m["content"]) for m in messages)
    if total <= limit or not messages:
        return messages
    *rest, last = messages
    room = max(500, limit - sum(len(m["content"]) for m in rest))
    return [*rest, {**last, "content": clip(last["content"], room)}]
