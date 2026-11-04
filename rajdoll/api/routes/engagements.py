"""Engagements, scope, accounts, session check (AFD A1, A2, A11; BSD 10.3)."""

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from rajdoll.api import pages
from rajdoll.api.deps import current_session, get_db, get_keystore, get_prober, require_csrf
from rajdoll.api.forms import read_fields
from rajdoll.api.render import is_htmx, respond, service_error_response, wants_json
from rajdoll.core import scope as scope_rules
from rajdoll.core.crypto import KeyStore
from rajdoll.core.models import Engagement
from rajdoll.services import engagements as svc
from rajdoll.services import monitor
from rajdoll.services import settings as app_settings
from rajdoll.services.auth import ActiveSession
from rajdoll.services.errors import ServiceError, ValidationFailed
from rajdoll.services.session_check import Prober

router = APIRouter()

# --------------------------------------------------------------------------------------
# JSON shapes
# --------------------------------------------------------------------------------------


def _engagement_json(db: Session, keystore: KeyStore, engagement: Engagement) -> dict[str, Any]:
    return {
        "id": engagement.id,
        "name": engagement.name,
        "organization": engagement.organization,
        "target_url": engagement.target_url,
        "notes": engagement.notes,
        "start_date": engagement.start_date,
        "end_date": engagement.end_date,
        "status": engagement.status,
        "scope": svc.scope_patterns(db, engagement.id),
        "accounts": [
            svc.account_summary(keystore, engagement, a) for a in svc.accounts(db, engagement.id)
        ],
        "session_check": {
            "url": engagement.session_check_url,
            "marker": engagement.session_check_marker,
        },
        "settings": svc.overrides(engagement).model_dump(mode="json", exclude_none=True),
        "effective_settings": svc.effective_settings(db, engagement),
        "warnings": svc.warnings(db, engagement),
        "created_at": engagement.created_at,
        "updated_at": engagement.updated_at,
    }


# --------------------------------------------------------------------------------------
# Page contexts
# --------------------------------------------------------------------------------------


def _base_context(db: Session, engagement: Engagement, tab: str) -> dict[str, Any]:
    return pages.engagement_context(db, engagement, tab)


def _scope_context(db: Session, keystore: KeyStore, engagement: Engagement) -> dict[str, Any]:
    target_host = scope_rules.url_host(engagement.target_url)
    return {
        **_base_context(db, engagement, "scope"),
        "scope_rules": svc.scope_rule_rows(db, engagement.id),
        "target_host": target_host,
        "accounts": [
            svc.account_summary(keystore, engagement, a) for a in svc.accounts(db, engagement.id)
        ],
        "next_label": svc.next_account_label(db, engagement.id),
        "scope_errors": [],
        "account_errors": [],
        "session_check_errors": [],
        "session_check_saved": False,
        "check_results": {},
        "host_matches": scope_rules.host_matches,
    }


def _settings_context(db: Session, engagement: Engagement) -> dict[str, Any]:
    return {
        **_base_context(db, engagement, "settings"),
        "overrides": svc.overrides(engagement),
        "app_defaults": app_settings.load(db).defaults,
        "details_errors": [],
        "details_saved": False,
        "overrides_errors": [],
        "overrides_saved": False,
        "status_errors": [],
        "delete_errors": [],
    }


def _errors(exc: ServiceError) -> list[str]:
    return exc.errors if isinstance(exc, ValidationFailed) else [exc.message]


def _redirect(request: Request, url: str) -> Response:
    if is_htmx(request):
        return Response(status_code=204, headers={"HX-Redirect": url})
    return RedirectResponse(url, status_code=303)


# --------------------------------------------------------------------------------------
# List, create, detail
# --------------------------------------------------------------------------------------


@router.get("/")
@router.get("/engagements")
def list_page(
    request: Request,
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(current_session),
) -> Response:
    rows = svc.list_engagements(db)
    counts = svc.finding_counts(db, [e.id for e in rows])
    latest = monitor.latest_scans(db, [e.id for e in rows])
    items = [{"engagement": e, "counts": counts[e.id], "scan": latest.get(e.id)} for e in rows]
    data = [
        {
            "id": e.id,
            "name": e.name,
            "organization": e.organization,
            "status": e.status,
            "target_url": e.target_url,
            "findings_accepted": counts[e.id]["accepted"],
            "updated_at": e.updated_at,
        }
        for e in rows
    ]
    return respond(
        request,
        "engagements_list.html",
        {"items": items, "active_nav": "engagements"},
        data={"items": data},
    )


@router.get("/engagements/new")
def new_page(request: Request, _: ActiveSession = Depends(current_session)) -> Response:
    return respond(
        request, "engagement_new.html", {"errors": [], "values": {}, "active_nav": "engagements"}
    )


@router.post("/engagements")
async def create(
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    fields = await read_fields(request)
    try:
        engagement = svc.create(db, keystore, fields)
    except ValidationFailed as exc:
        db.rollback()
        if wants_json(request):
            return service_error_response(request, exc)
        context = {"errors": exc.errors, "values": fields, "active_nav": "engagements"}
        return respond(request, "engagement_new.html", context, status_code=422)
    db.commit()
    if wants_json(request):
        return respond(
            request, "", data=_engagement_json(db, keystore, engagement), status_code=201
        )
    return _redirect(request, f"/engagements/{engagement.id}/scope")


@router.get("/engagements/{engagement_id}")
def summary_page(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(current_session),
) -> Response:
    engagement = svc.get(db, engagement_id)
    context = {
        **_base_context(db, engagement, "summary"),
        "scope_count": len(svc.scope_patterns(db, engagement.id)),
        "accounts": [
            svc.account_summary(keystore, engagement, a) for a in svc.accounts(db, engagement.id)
        ],
        "counts": svc.finding_counts(db, [engagement.id])[engagement.id],
        "warnings": svc.warnings(db, engagement),
        "latest_scan": monitor.latest_scans(db, [engagement.id]).get(engagement.id),
    }
    return respond(
        request,
        "engagement_summary.html",
        context,
        data=_engagement_json(db, keystore, engagement),
    )


@router.get("/engagements/{engagement_id}/settings")
def settings_page(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(current_session),
) -> Response:
    engagement = svc.get(db, engagement_id)
    return respond(
        request,
        "engagement_settings.html",
        _settings_context(db, engagement),
        data={
            "settings": svc.overrides(engagement).model_dump(mode="json", exclude_none=True),
            "effective_settings": svc.effective_settings(db, engagement),
        },
    )


def _overrides_from_form(fields: dict[str, Any]) -> dict[str, Any]:
    """Flat form → overrides. Empty inputs and 'default' selects follow the app default."""
    changes: dict[str, Any] = {}
    for name in ("rate_limit_rps", "concurrency", "checkpoint_timeout_min"):
        value = str(fields.get(name, "")).strip()
        if value:
            changes[name] = value
    kb = str(fields.get("evidence_max_kb", "")).strip()
    if kb:
        try:
            changes["evidence_max_bytes"] = int(float(kb) * 1024)
        except ValueError:
            changes["evidence_max_bytes"] = kb
    for name in ("checkpoint_enabled", "oob_enabled"):
        choice = fields.get(name, "default")
        if choice in ("on", "off"):
            changes[name] = choice == "on"
    header_name = str(fields.get("identity_header_name", "")).strip()
    header_value = str(fields.get("identity_header_value", "")).strip()
    if header_name or header_value:
        changes["identity_header"] = {"name": header_name, "value": header_value}
    return changes


@router.patch("/engagements/{engagement_id}")
async def update(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    engagement = svc.get(db, engagement_id)
    fields = await read_fields(request)
    section = fields.get("section")
    if section is None:  # JSON client: infer from the keys present
        section = (
            "status" if "status" in fields else "overrides" if "settings" in fields else "details"
        )
    template = {
        "details": "_details_form.html",
        "overrides": "_overrides_form.html",
        "status": "_status_section.html",
    }.get(section)
    if template is None:
        return service_error_response(
            request, ValidationFailed.one("section", "Bagian yang diubah tidak dikenal.")
        )
    try:
        if section == "details":
            merged = {
                "name": engagement.name,
                "organization": engagement.organization,
                "target_url": engagement.target_url,
                "notes": engagement.notes,
                "start_date": engagement.start_date and engagement.start_date.isoformat(),
                "end_date": engagement.end_date and engagement.end_date.isoformat(),
            }
            merged.update({k: v for k, v in fields.items() if k in merged})
            svc.update_details(db, engagement, merged)
        elif section == "overrides":
            changes = fields["settings"] if "settings" in fields else _overrides_from_form(fields)
            svc.update_overrides(db, engagement, changes if isinstance(changes, dict) else {})
        else:
            svc.set_status(db, engagement, str(fields.get("status", "")))
    except ServiceError as exc:
        db.rollback()
        if wants_json(request):
            return service_error_response(request, exc)
        db.refresh(engagement)
        context = _settings_context(db, engagement)
        context[f"{section}_errors"] = _errors(exc)
        if section == "details":
            context["values"] = fields
        return respond(request, template, context, status_code=exc.status_code)
    db.commit()
    db.refresh(engagement)
    if wants_json(request):
        return respond(request, "", data=_engagement_json(db, keystore, engagement))
    context = _settings_context(db, engagement)
    if section in ("details", "overrides"):
        context[f"{section}_saved"] = True
    return respond(request, template, context)


@router.delete("/engagements/{engagement_id}")
async def delete(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    engagement = svc.get(db, engagement_id)
    fields = await read_fields(request)
    try:
        svc.delete(db, keystore, engagement, fields.get("confirm_name"))
    except ServiceError as exc:
        db.rollback()
        if wants_json(request):
            return service_error_response(request, exc)
        context = _settings_context(db, engagement)
        context["delete_errors"] = _errors(exc)
        return respond(request, "_delete_section.html", context, status_code=exc.status_code)
    db.commit()
    if wants_json(request):
        return Response(status_code=204)
    return _redirect(request, "/")


# --------------------------------------------------------------------------------------
# Scope & accounts tab
# --------------------------------------------------------------------------------------


@router.get("/engagements/{engagement_id}/scope")
def scope_page(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(current_session),
) -> Response:
    engagement = svc.get(db, engagement_id)
    rules = svc.scope_rule_rows(db, engagement.id)
    return respond(
        request,
        "engagement_scope.html",
        _scope_context(db, keystore, engagement),
        data={"scope": [{"id": r.id, "pattern": r.pattern} for r in rules]},
    )


@router.get("/engagements/{engagement_id}/accounts")
def accounts_page(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(current_session),
) -> Response:
    engagement = svc.get(db, engagement_id)
    context = _scope_context(db, keystore, engagement)
    return respond(
        request, "engagement_scope.html", context, data={"accounts": context["accounts"]}
    )


async def _scope_section_response(
    request: Request,
    db: Session,
    keystore: KeyStore,
    engagement: Engagement,
    template: str,
    error_key: str,
    action: Any,
    saved_key: str | None = None,
) -> Response:
    """Run a scope/account/session-check change and re-render its section."""
    try:
        action()
        db.flush()
    except ServiceError as exc:
        db.rollback()
        if wants_json(request):
            return service_error_response(request, exc)
        db.refresh(engagement)
        context = _scope_context(db, keystore, engagement)
        context[error_key] = _errors(exc)
        return respond(request, template, context, status_code=exc.status_code)
    db.commit()
    db.refresh(engagement)
    context = _scope_context(db, keystore, engagement)
    if saved_key:
        context[saved_key] = True
    return respond(request, template, context, data=_engagement_json(db, keystore, engagement))


@router.post("/engagements/{engagement_id}/scope")
async def scope_add(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    engagement = svc.get(db, engagement_id)
    fields = await read_fields(request)
    return await _scope_section_response(
        request,
        db,
        keystore,
        engagement,
        "_scope_section.html",
        "scope_errors",
        lambda: svc.add_scope(db, engagement, str(fields.get("pattern", ""))),
    )


@router.delete("/engagements/{engagement_id}/scope/{rule_id}")
async def scope_remove(
    engagement_id: int,
    rule_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    engagement = svc.get(db, engagement_id)
    return await _scope_section_response(
        request,
        db,
        keystore,
        engagement,
        "_scope_section.html",
        "scope_errors",
        lambda: svc.remove_scope(db, engagement, rule_id),
    )


@router.post("/engagements/{engagement_id}/accounts")
async def account_add(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    engagement = svc.get(db, engagement_id)
    fields = await read_fields(request)
    return await _scope_section_response(
        request,
        db,
        keystore,
        engagement,
        "_accounts_section.html",
        "account_errors",
        lambda: svc.add_account(db, keystore, engagement, fields),
    )


@router.patch("/engagements/{engagement_id}/accounts/{account_id}")
async def account_update(
    engagement_id: int,
    account_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    engagement = svc.get(db, engagement_id)
    account = svc.get_account(db, engagement, account_id)
    fields = await read_fields(request)
    return await _scope_section_response(
        request,
        db,
        keystore,
        engagement,
        "_accounts_section.html",
        "account_errors",
        lambda: svc.update_account(db, keystore, engagement, account, fields),
    )


@router.delete("/engagements/{engagement_id}/accounts/{account_id}")
async def account_remove(
    engagement_id: int,
    account_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    engagement = svc.get(db, engagement_id)
    account = svc.get_account(db, engagement, account_id)
    return await _scope_section_response(
        request,
        db,
        keystore,
        engagement,
        "_accounts_section.html",
        "account_errors",
        lambda: svc.remove_account(db, account),
    )


@router.put("/engagements/{engagement_id}/session-check")
async def session_check_update(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    engagement = svc.get(db, engagement_id)
    fields = await read_fields(request)
    return await _scope_section_response(
        request,
        db,
        keystore,
        engagement,
        "_session_check_section.html",
        "session_check_errors",
        lambda: svc.set_session_check(db, engagement, fields.get("url"), fields.get("marker")),
        saved_key="session_check_saved",
    )


@router.post("/engagements/{engagement_id}/accounts/{account_id}/check")
async def account_check(
    engagement_id: int,
    account_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    prober: Prober = Depends(get_prober),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    engagement = svc.get(db, engagement_id)
    account = svc.get_account(db, engagement, account_id)
    try:
        result = svc.check_account(db, keystore, engagement, account, prober)
    except ServiceError as exc:
        db.rollback()
        if wants_json(request):
            return service_error_response(request, exc)
        context = _scope_context(db, keystore, engagement)
        context["account_errors"] = _errors(exc)
        return respond(request, "_accounts_section.html", context, status_code=exc.status_code)
    db.commit()
    db.refresh(account)
    context = _scope_context(db, keystore, engagement)
    context["check_results"] = {account.id: result}
    data = {
        "status": account.session_status,
        "checked_at": account.session_checked_at,
        "checked": result.checked,
        "message": result.message,
        "http_status": result.status_code,
    }
    return respond(request, "_accounts_section.html", context, data=data)
