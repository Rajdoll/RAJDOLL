"""Application settings and password change (BSD 10.2; AFD section 1)."""

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from rajdoll.api.deps import current_session, get_db, get_keystore, require_csrf
from rajdoll.api.forms import read_fields
from rajdoll.api.render import error_response, is_htmx, respond, wants_json
from rajdoll.core.crypto import KeyStore
from rajdoll.llm import status as llm_status
from rajdoll.llm.client import (
    LlmClient,
    LlmConfig,
    LlmError,
    LlmTimeout,
    LlmUnavailable,
    extract_json,
)
from rajdoll.llm.gateway import api_key, encrypt_api_key
from rajdoll.services import auth
from rajdoll.services import settings as settings_service
from rajdoll.services.auth import ActiveSession, AuthError
from rajdoll.services.settings import AppSettings, SettingsError

router = APIRouter()

_CHECKBOXES = ("checkpoint_enabled", "oob_enabled")


def _changes_from_form(form: dict[str, str]) -> dict[str, Any]:
    """Map the flat HTML form onto the nested setting keys of BSD 3.3."""
    defaults: dict[str, Any] = {
        "rate_limit_rps": form.get("rate_limit_rps"),
        "concurrency": form.get("concurrency"),
        "checkpoint_timeout_min": form.get("checkpoint_timeout_min"),
    }
    if form.get("evidence_max_kb"):
        try:
            defaults["evidence_max_bytes"] = int(float(form["evidence_max_kb"]) * 1024)
        except ValueError:
            defaults["evidence_max_bytes"] = form["evidence_max_kb"]
    for name in _CHECKBOXES:
        defaults[name] = name in form
    llm: dict[str, Any] = {
        "enabled": "llm_enabled" in form,
        "base_url": form.get("llm_base_url"),
        "model": form.get("llm_model"),
        "thinking": "llm_thinking" in form,
        "timeout_s": form.get("llm_timeout_s"),
    }
    if form.get("llm_api_key"):
        llm["api_key"] = form["llm_api_key"]
    elif "llm_api_key_clear" in form:
        llm["api_key"] = ""
    changes = {
        "llm": {k: v for k, v in llm.items() if v is not None},
        "llm_budget_per_scan": form.get("llm_budget_per_scan"),
        "cvss_primary": form.get("cvss_primary"),
        "defaults": defaults,
    }
    return {k: v for k, v in changes.items() if v is not None}


def _encrypt_key(changes: dict[str, Any], keystore: KeyStore) -> dict[str, Any]:
    """`llm.api_key` (plain text from the client) becomes `llm.api_key_enc`; a client can
    never set the encrypted value directly, and an empty key removes the stored one."""
    llm = changes.get("llm")
    if not isinstance(llm, dict):
        return changes
    llm = {k: v for k, v in llm.items() if k != "api_key_enc"}
    if "api_key" in llm:
        plain = str(llm.pop("api_key") or "").strip()
        llm["api_key_enc"] = encrypt_api_key(keystore, plain) if plain else None
    return {**changes, "llm": llm}


def _view(settings: AppSettings) -> dict[str, Any]:
    return settings.model_dump(mode="json", exclude={"llm": {"api_key_enc"}})


def _settings_page(
    request: Request,
    settings: AppSettings,
    *,
    errors: list[str] | None = None,
    saved: bool = False,
    status_code: int = 200,
) -> Response:
    context = {
        "settings": settings,
        "llm_indicator": llm_status.indicator(settings),
        "errors": errors or [],
        "saved": saved,
        "active_nav": "settings",
        "password_error": None,
        "password_saved": False,
    }
    template = "settings_form.html" if is_htmx(request) else "settings.html"
    return respond(request, template, context, data=_view(settings), status_code=status_code)


@router.get("/settings")
def settings_page(
    request: Request,
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(current_session),
) -> Response:
    return _settings_page(request, settings_service.load(db))


@router.patch("/settings")
async def settings_update(
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()
        changes = body if isinstance(body, dict) else {}
    else:
        form = await request.form()
        changes = _changes_from_form({k: v for k, v in form.items() if isinstance(v, str)})
    try:
        updated = settings_service.update(db, _encrypt_key(changes, keystore))
    except SettingsError as exc:
        db.rollback()
        if wants_json(request):
            return error_response(
                request,
                422,
                "invalid_settings",
                "Pengaturan tidak valid.",
                {"errors": [{"field": e.field, "message": e.message} for e in exc.field_errors]},
            )
        return _settings_page(
            request, settings_service.load(db), errors=exc.errors, status_code=422
        )
    db.commit()
    return _settings_page(request, updated, saved=True)


@router.post("/settings/llm/test")
async def llm_test(
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    """Connection test with the values in the form (or the saved ones), without saving."""
    fields = await read_fields(request)
    saved = settings_service.load(db)
    base_url = str(fields.get("llm_base_url") or fields.get("base_url") or saved.llm.base_url)
    model = str(fields.get("llm_model") or fields.get("model") or saved.llm.model)
    key = str(fields.get("llm_api_key") or fields.get("api_key") or "") or api_key(keystore, saved)
    result: dict[str, Any] = {"ok": False, "model": model, "latency_ms": None, "error": None}
    if not base_url.startswith(("http://", "https://")):
        result["error"] = "Alamat server LLM harus berupa URL http(s)."
    else:
        client = LlmClient(LlmConfig(base_url=base_url, model=model, api_key=key or None))
        try:
            completion = await asyncio.to_thread(client.ping)
            extract_json(completion.text)
            result.update(ok=True, latency_ms=completion.duration_ms)
        except LlmUnavailable as exc:
            result["error"] = f"Server LLM tidak terjangkau ({exc})."
        except LlmTimeout:
            result["error"] = "Server LLM tidak menjawab dalam 30 detik."
        except LlmError as exc:
            result["error"] = f"Server LLM menjawab dengan galat: {exc}"
        except ValueError:
            result["error"] = "Server menjawab, tetapi bukan JSON; periksa model yang dipilih."
    return respond(request, "_llm_test.html", result, data=result)


@router.post("/settings/password")
async def password_change(
    request: Request,
    db: Session = Depends(get_db),
    active: ActiveSession = Depends(require_csrf),
) -> Response:
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()
        fields = body if isinstance(body, dict) else {}
    else:
        form = await request.form()
        fields = {k: v for k, v in form.items() if isinstance(v, str)}
    try:
        auth.change_password(
            db,
            str(fields.get("current_password", "")),
            str(fields.get("new_password", "")),
            str(fields.get("new_password_confirm", "")),
            keep_token_hash=active.token_hash,
        )
    except AuthError as exc:
        db.rollback()
        return respond(
            request,
            "password_form.html",
            {"password_error": str(exc), "password_saved": False},
            data={"error": {"code": "invalid_password", "message": str(exc), "details": {}}},
            status_code=422,
        )
    db.commit()
    return respond(
        request,
        "password_form.html",
        {"password_error": None, "password_saved": True},
        data={"ok": True},
    )
