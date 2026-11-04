"""Scan tab, scan monitor, controls, events, and checkpoint (AFD A3–A5; BSD 10.4)."""

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from sqlalchemy.orm import Session

from rajdoll.api import pages
from rajdoll.api.deps import current_session, get_db, get_keystore, require_csrf
from rajdoll.api.forms import as_list, read_fields
from rajdoll.api.render import (
    is_htmx,
    render_fragment,
    render_html,
    respond,
    service_error_response,
    wants_json,
)
from rajdoll.api.sse import Frame, scan_stream
from rajdoll.core import scope as scope_rules
from rajdoll.core.crypto import KeyStore
from rajdoll.core.enums import SessionStatus
from rajdoll.core.models import Engagement, Scan
from rajdoll.modules.registry import MODULE_LABELS, available_modules
from rajdoll.services import engagements, monitor, planning, scans, tagging
from rajdoll.services import settings as app_settings
from rajdoll.services.auth import ActiveSession
from rajdoll.services.errors import ServiceError, ValidationFailed

router = APIRouter()


def _errors(exc: ServiceError) -> list[str]:
    return exc.errors if isinstance(exc, ValidationFailed) else [exc.message]


def _redirect(request: Request, url: str) -> Response:
    if is_htmx(request):
        return Response(status_code=204, headers={"HX-Redirect": url})
    return RedirectResponse(url, status_code=303)


# --------------------------------------------------------------------------------------
# Contexts
# --------------------------------------------------------------------------------------


def live_context(db: Session, scan: Scan) -> dict[str, Any]:
    """Everything the monitor's live fragments need (also used by the SSE stream)."""
    return {
        "scan": scan,
        "steps": monitor.stage_steps(scan),
        "modules": monitor.module_rows(db, scan),
        "requests": monitor.request_stats(db, scan),
        "findings": monitor.finding_stats(db, scan),
        "minutes_left": monitor.minutes_left(scan.checkpoint_deadline),
        "finished": monitor.is_finished(scan),
        "control_errors": [],
    }


def _start_warnings(db: Session, engagement: Engagement, llm_local: bool) -> list[str]:
    """Non-blocking warnings on the start form (AFD A3 step 4)."""
    result = []
    accounts = engagements.accounts(db, engagement.id)
    untested = [a.label for a in accounts if a.session_status != SessionStatus.VALID]
    if untested:
        result.append(f"Sesi {', '.join(untested)} belum diuji atau tidak valid.")
    if len(accounts) < 2:
        result.append("Kurang dari dua akun: modul Authorization (uji IDOR) akan dilewati.")
    if not llm_local:
        result.append("LLM memakai API di luar laptop: data scan dikirim ke penyedia API.")
    return result


def _scans_tab_context(db: Session, keystore: KeyStore, engagement: Engagement) -> dict[str, Any]:
    config = app_settings.load(db)
    llm_local = scans.is_local_llm(str(config.llm.base_url))
    history = scans.list_for(db, engagement.id)
    available = available_modules()
    return {
        **pages.engagement_context(db, engagement, "scan"),
        "history": [{"scan": scan, "modules": monitor.module_rows(db, scan)} for scan in history],
        "modules": [
            {"name": name, "label": label, "available": name in available}
            for name, label in MODULE_LABELS.items()
        ],
        "accounts": [
            engagements.account_summary(keystore, engagement, a)
            for a in engagements.accounts(db, engagement.id)
        ],
        "scope": engagements.scope_patterns(db, engagement.id),
        "effective": engagements.effective_settings(db, engagement),
        "llm": {
            "model": config.llm.model,
            "base_url": str(config.llm.base_url),
            "local": llm_local,
        },
        "start_warnings": _start_warnings(db, engagement, llm_local),
        "unfinished": next((s for s in history if s.status in scans.UNFINISHED), None),
        "start_errors": [],
        "values": {"profile": "full", "modules": []},
    }


def _monitor_context(db: Session, scan: Scan) -> dict[str, Any]:
    engagement = engagements.get(db, scan.engagement_id)
    log = monitor.events(db, scan.id)
    return {
        **pages.engagement_context(db, engagement, "scan", banner=False),
        **live_context(db, scan),
        "log": log,
        "last_event_id": log[0].id if log else 0,
    }


# --------------------------------------------------------------------------------------
# Scan tab and start (AFD A3)
# --------------------------------------------------------------------------------------


@router.get("/engagements/{engagement_id}/scans")
def scans_tab(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(current_session),
) -> Response:
    engagement = engagements.get(db, engagement_id)
    context = _scans_tab_context(db, keystore, engagement)
    data = {"items": [scans.summary(db, s) for s in scans.list_for(db, engagement.id)]}
    return respond(request, "engagement_scans.html", context, data=data)


@router.post("/engagements/{engagement_id}/scans")
async def scan_start(
    engagement_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    engagement = engagements.get(db, engagement_id)
    fields = await read_fields(request)
    profile = str(fields.get("profile") or "full")
    modules = as_list(fields.get("modules"))
    try:
        scan = scans.start(db, engagement, profile, modules if profile == "custom" else None)
    except ServiceError as exc:
        db.rollback()
        if wants_json(request):
            return service_error_response(request, exc)
        db.refresh(engagement)
        context = _scans_tab_context(db, keystore, engagement)
        context["start_errors"] = _errors(exc)
        context["values"] = {"profile": profile, "modules": modules}
        return respond(request, "engagement_scans.html", context, status_code=exc.status_code)
    db.commit()
    if wants_json(request):
        return respond(request, "", data=scans.summary(db, scan), status_code=202)
    return _redirect(request, f"/scans/{scan.id}")


# --------------------------------------------------------------------------------------
# Monitor and controls (AFD A4)
# --------------------------------------------------------------------------------------


@router.get("/scans/{scan_id}")
def monitor_page(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(current_session),
) -> Response:
    scan = scans.get(db, scan_id)
    return respond(
        request, "scan_monitor.html", _monitor_context(db, scan), data=monitor.scan_json(db, scan)
    )


async def _control(
    request: Request,
    db: Session,
    scan_id: int,
    action: Callable[[Scan, dict[str, Any]], None],
) -> Response:
    """Run a pause/resume/cancel/checkpoint action and answer with the status fragment."""
    scan = scans.get(db, scan_id)
    fields = await read_fields(request)
    try:
        action(scan, fields)
        db.flush()
    except ServiceError as exc:
        db.rollback()
        if wants_json(request) or not is_htmx(request):
            return service_error_response(request, exc)
        db.refresh(scan)
        context = live_context(db, scan)
        context["control_errors"] = _errors(exc)
        return render_html(request, "_scan_status.html", context, status_code=exc.status_code)
    db.commit()
    if wants_json(request):
        return respond(request, "", data=monitor.scan_json(db, scan))
    if is_htmx(request):
        return render_html(request, "_scan_status.html", live_context(db, scan))
    return RedirectResponse(f"/scans/{scan.id}", status_code=303)


def _rate(fields: dict[str, Any]) -> float | None:
    raw = fields.get("rate_limit_rps")
    if raw is None or raw == "":
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        raise ValidationFailed.one(
            "rate_limit_rps", "Rate limit harus berupa angka (request per detik)."
        ) from None


@router.post("/scans/{scan_id}/pause")
async def scan_pause(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    return await _control(request, db, scan_id, lambda scan, _f: scans.pause(db, scan))


@router.post("/scans/{scan_id}/resume")
async def scan_resume(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    return await _control(
        request, db, scan_id, lambda scan, fields: scans.resume(db, scan, _rate(fields))
    )


@router.post("/scans/{scan_id}/cancel")
async def scan_cancel(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    return await _control(request, db, scan_id, lambda scan, _f: scans.cancel(db, scan))


# --------------------------------------------------------------------------------------
# Tasks and events
# --------------------------------------------------------------------------------------


@router.get("/scans/{scan_id}/tasks")
def scan_tasks(
    scan_id: int,
    request: Request,
    status: str | None = None,
    module: str | None = None,
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(current_session),
) -> Response:
    scan = scans.get(db, scan_id)
    rows = monitor.tasks(db, scan.id, status or None, module or None)
    engagement = engagements.get(db, scan.engagement_id)
    context = {
        **pages.engagement_context(db, engagement, "scan", banner=False),
        "scan": scan,
        "tasks": rows,
        "filters": {"status": status or "", "module": module or ""},
        "module_names": [row["name"] for row in monitor.module_rows(db, scan)],
    }
    return respond(
        request,
        "scan_tasks.html",
        context,
        data={"items": [monitor.task_json(task) for task in rows]},
    )


@router.get("/scans/{scan_id}/events")
def scan_events(
    scan_id: int,
    request: Request,
    after_id: int = 0,
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(current_session),
) -> Response:
    scan = scans.get(db, scan_id)
    rows = monitor.events(db, scan.id, after_id=after_id, limit=500)
    engagement = engagements.get(db, scan.engagement_id)
    context = {
        **pages.engagement_context(db, engagement, "scan", banner=False),
        "scan": scan,
        "log": rows,
    }
    return respond(
        request,
        "scan_events.html",
        context,
        data={"items": [monitor.event_json(event) for event in reversed(rows)]},
    )


@router.get("/scans/{scan_id}/events/stream")
async def scan_event_stream(
    scan_id: int,
    request: Request,
    after_id: int = 0,
    db: Session = Depends(get_db),
    active: ActiveSession = Depends(current_session),
) -> Response:
    scan = scans.get(db, scan_id)
    db.close()  # the stream opens its own short sessions
    last_event = request.headers.get("last-event-id", "")
    if last_event.isdigit():
        after_id = int(last_event)
    session_factory = request.app.state.session_factory
    csrf_token = active.csrf_token

    def render(last_id: int) -> Frame:
        with session_factory() as session:
            current = session.get(Scan, scan.id)
            if current is None:
                return Frame({}, finished=True)
            context = {**live_context(session, current), "csrf_token": csrf_token}
            new = monitor.events(session, current.id, after_id=last_id, limit=200)
            return Frame(
                fragments={
                    "stage": render_fragment("_scan_status.html", context),
                    "task": render_fragment("_scan_modules.html", context),
                    "stats": render_fragment("_scan_stats.html", context),
                    "finding": render_fragment("_scan_findings.html", context),
                },
                log_html=render_fragment("_scan_log_lines.html", {"log": new}) if new else "",
                last_event_id=new[0].id if new else last_id,
                finished=monitor.is_finished(current),
            )

    stream = scan_stream(
        request,
        request.app.state.listen_dsn,
        scan.id,
        after_id,
        render,
        heartbeat_seconds=request.app.state.sse_heartbeat_seconds,
        max_seconds=request.app.state.sse_max_seconds,
    )
    return StreamingResponse(
        stream,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


# --------------------------------------------------------------------------------------
# Checkpoint (AFD A5; editing the plan arrives in F5)
# --------------------------------------------------------------------------------------


FILTERS = {"semua": "Semua", "ditandai": "Ditandai", "dikecualikan": "Dikecualikan"}


def _checkpoint_json(db: Session, scan: Scan) -> dict[str, Any]:
    return planning.checkpoint(db, scan, set(available_modules()), monitor.recon_summary(db, scan))


def _checkpoint_context(db: Session, scan: Scan, view: str) -> dict[str, Any]:
    data = _checkpoint_json(db, scan)
    endpoints = data["endpoints"]
    if view == "ditandai":
        endpoints = [e for e in endpoints if e["tags"]]
    elif view == "dikecualikan":
        endpoints = [e for e in endpoints if e["excluded"]]
    scope = engagements.scope_patterns(db, scan.engagement_id)
    hosts = [
        {**item, "in_scope": scope_rules.in_scope(scope, item["host"])}
        for item in data["recon_summary"]["out_of_scope_hosts"]
    ]
    return {
        "scan": scan,
        "checkpoint": data,
        "shown_endpoints": endpoints,
        "out_of_scope_hosts": hosts,
        "filter": view,
        "filters": FILTERS,
        "module_labels": MODULE_LABELS,
        "tag_labels": tagging.TAG_LABELS,
        "skip_labels": planning.SKIP_LABELS,
        "plan_errors": [],
        "plan_changes": [],
    }


def _view(value: Any) -> str:
    return value if value in FILTERS else "semua"


@router.get("/scans/{scan_id}/checkpoint")
def checkpoint_page(
    scan_id: int,
    request: Request,
    filter: str = "semua",  # noqa: A002 (query parameter name)
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(current_session),
) -> Response:
    scan = scans.get(db, scan_id)
    context = {**_monitor_context(db, scan), **_checkpoint_context(db, scan, _view(filter))}
    return respond(request, "scan_checkpoint.html", context, data=context["checkpoint"])


def _edits_from_form(fields: dict[str, Any]) -> dict[str, Any]:
    """BSD 10.4 PATCH body from the checkpoint page's small forms (`action` + fields)."""
    action = fields.get("action")
    if action is None:
        return {
            k: fields[k]
            for k in ("modules", "endpoints", "add_endpoints", "add_scope")
            if k in fields
        }
    endpoint_id = fields.get("endpoint_id")
    if action in ("exclude", "include"):
        return {"endpoints": [{"id": endpoint_id, "excluded": action == "exclude"}]}
    if action == "tags":
        return {"endpoints": [{"id": endpoint_id, "tags": fields.get("tags", "")}]}
    if action == "modules":
        return {"modules": as_list(fields.get("modules"))}
    if action == "add_endpoint":
        return {"add_endpoints": [{"method": fields.get("method"), "url": fields.get("url")}]}
    if action == "raw_request":
        return {"add_endpoints": [{"raw_request": fields.get("raw_request", "")}]}
    if action == "add_scope":
        return {"add_scope": [fields.get("pattern", "")]}
    raise ValidationFailed.one("action", "Aksi checkpoint tidak dikenal.")


@router.patch("/scans/{scan_id}/checkpoint")
async def checkpoint_edit(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    keystore: KeyStore = Depends(get_keystore),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    """Edit the plan at the checkpoint (AFD A5); editing stops the countdown."""
    scan = scans.get(db, scan_id)
    fields = await read_fields(request)
    view = _view(fields.get("filter"))
    try:
        changes = planning.edit(db, keystore, scan, _edits_from_form(fields))
        db.flush()
    except ServiceError as exc:
        db.rollback()
        if wants_json(request) or not is_htmx(request):
            return service_error_response(request, exc)
        db.refresh(scan)
        context = _checkpoint_context(db, scan, view)
        context["plan_errors"] = _errors(exc)
        return render_html(request, "_checkpoint_plan.html", context, status_code=exc.status_code)
    db.commit()
    if wants_json(request):
        return respond(request, "", data=_checkpoint_json(db, scan))
    context = _checkpoint_context(db, scan, view)
    context["plan_changes"] = changes
    return render_html(request, "_checkpoint_plan.html", context)


@router.post("/scans/{scan_id}/checkpoint/hold")
async def checkpoint_hold(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    return await _control(request, db, scan_id, lambda scan, _f: scans.checkpoint_hold(db, scan))


@router.post("/scans/{scan_id}/checkpoint/continue")
async def checkpoint_continue(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: ActiveSession = Depends(require_csrf),
) -> Response:
    return await _control(
        request, db, scan_id, lambda scan, _f: scans.checkpoint_continue(db, scan)
    )
