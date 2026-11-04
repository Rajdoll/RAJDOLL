"""Response rendering: full HTML page, HTMX fragment, or JSON from one route (BSD 10.1)."""

from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

templates = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(default=True, default_for_string=True),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
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
        return JSONResponse(data, status_code=status_code, headers=headers)
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
