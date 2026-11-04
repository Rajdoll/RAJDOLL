"""Response rendering: full HTML page, HTMX fragment, or JSON from one route (BSD 10.1)."""

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, Response
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

if TYPE_CHECKING:
    from rajdoll.services.errors import ServiceError

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

templates = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(default=True, default_for_string=True),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)


ENGAGEMENT_STATUS_LABELS = {"draft": "draf", "ready": "siap", "active": "aktif", "done": "selesai"}
SESSION_STATUS_LABELS = {"unknown": "belum diuji", "valid": "valid", "invalid": "tidak valid"}
SEVERITY_LABELS = {
    "critical": ("K", "Kritis"),
    "high": ("T", "Tinggi"),
    "medium": ("S", "Sedang"),
    "low": ("R", "Rendah"),
    "info": ("I", "Info"),
}


def ago(moment: datetime | None) -> str:
    """Short Indonesian relative time, e.g. '5 menit lalu'."""
    if moment is None:
        return "—"
    seconds = int((datetime.now(UTC) - moment).total_seconds())
    if seconds < 60:
        return "baru saja"
    for unit_seconds, unit in ((86400, "hari"), (3600, "jam"), (60, "menit")):
        if seconds >= unit_seconds:
            return f"{seconds // unit_seconds} {unit} lalu"
    return "baru saja"


templates.globals.update(
    engagement_status_labels=ENGAGEMENT_STATUS_LABELS,
    session_status_labels=SESSION_STATUS_LABELS,
    severity_labels=SEVERITY_LABELS,
    ago=ago,
)


def is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


def wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "application/json" in accept and "text/html" not in accept


def render_html(
    request: Request,
    template: str,
    context: dict[str, Any] | None = None,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    htmx = is_htmx(request)
    values: dict[str, Any] = {
        "request": request,
        "htmx": htmx,
        "layout": "partial.html" if htmx else "base.html",
        "csrf_token": getattr(request.state, "csrf_token", None),
        "authenticated": getattr(request.state, "authenticated", False),
        "active_nav": None,
    }
    values.update(context or {})
    body = templates.get_template(template).render(values)
    return HTMLResponse(body, status_code=status_code, headers=headers)


def respond(
    request: Request,
    template: str,
    context: dict[str, Any] | None = None,
    *,
    data: Any = None,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    """JSON when the client asks for it and the route supplies `data`, otherwise HTML."""
    if data is not None and wants_json(request):
        return JSONResponse(jsonable_encoder(data), status_code=status_code, headers=headers)
    return render_html(request, template, context, status_code, headers)


def error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> Response:
    if wants_json(request):
        payload = {"error": {"code": code, "message": message, "details": details or {}}}
        return JSONResponse(payload, status_code=status_code)
    return render_html(
        request, "error.html", {"status_code": status_code, "message": message}, status_code
    )


def service_error_response(request: Request, exc: "ServiceError") -> Response:
    """BSD 10.1 error for a service-layer exception; field errors go into `details.errors`."""
    from rajdoll.services.errors import ValidationFailed

    details: dict[str, Any] = {}
    if isinstance(exc, ValidationFailed):
        details["errors"] = [{"field": e.field, "message": e.message} for e in exc.field_errors]
    return error_response(request, exc.status_code, exc.code, exc.message, details)
