"""Application settings and password change (BSD 10.2; AFD section 1)."""

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from rajdoll.api.deps import current_session, get_db, require_csrf
from rajdoll.api.render import error_response, is_htmx, respond, wants_json
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
    return {
        "llm": {"base_url": form.get("llm_base_url"), "model": form.get("llm_model")},
        "cvss_primary": form.get("cvss_primary"),
        "defaults": defaults,
    }


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
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()
        changes = body if isinstance(body, dict) else {}
    else:
        form = await request.form()
        changes = _changes_from_form({k: v for k, v in form.items() if isinstance(v, str)})
    try:
        updated = settings_service.update(db, changes)
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
