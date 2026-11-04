"""First-run setup, login, logout (AFD A0; BSD 10.2)."""

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from rajdoll.api.deps import get_db, require_csrf
from rajdoll.api.render import error_response, is_htmx, respond, wants_json
from rajdoll.services import auth
from rajdoll.services.auth import ActiveSession, AuthError

router = APIRouter()


async def _form_or_json(request: Request) -> dict[str, Any]:
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()
        return body if isinstance(body, dict) else {}
    form = await request.form()
    return {key: value for key, value in form.items() if isinstance(value, str)}


def _redirect(request: Request, url: str) -> Response:
    if is_htmx(request):
        return Response(status_code=204, headers={"HX-Redirect": url})
    return RedirectResponse(url, status_code=303)


def _start_session(request: Request, db: Session, password: str, status_code: int) -> Response:
    token, active = auth.login(db, password)
    db.commit()
    if wants_json(request):
        response: Response = JSONResponse(
            {"csrf_token": active.csrf_token}, status_code=status_code
        )
    else:
        response = _redirect(request, "/")
    response.set_cookie(
        auth.SESSION_COOKIE,
        token,
        max_age=int(auth.SESSION_LIFETIME.total_seconds()),
        httponly=True,
        samesite="strict",
        path="/",
    )
    return response


@router.get("/setup")
def setup_page(request: Request, db: Session = Depends(get_db)) -> Response:
    if auth.user_exists(db):
        return RedirectResponse("/login", status_code=303)
    return respond(request, "setup.html", {"error": None})


@router.post("/setup")
async def setup_submit(request: Request, db: Session = Depends(get_db)) -> Response:
    if auth.user_exists(db):
        return error_response(request, 409, "already_set_up", "Password sudah pernah dibuat.")
    fields = await _form_or_json(request)
    password = str(fields.get("password", ""))
    try:
        auth.create_user(db, password, str(fields.get("password_confirm", "")))
    except AuthError as exc:
        db.rollback()
        return respond(
            request,
            "setup.html",
            {"error": str(exc)},
            data={"error": {"code": "invalid_password", "message": str(exc), "details": {}}},
            status_code=422,
        )
    db.commit()
    return _start_session(request, db, password, status_code=201)


@router.get("/login")
def login_page(request: Request, db: Session = Depends(get_db)) -> Response:
    if not auth.user_exists(db):
        return RedirectResponse("/setup", status_code=303)
    if auth.resolve_session(db, request.cookies.get(auth.SESSION_COOKIE)) is not None:
        return RedirectResponse("/", status_code=303)
    return respond(request, "login.html", {"error": None})


@router.post("/login")
async def login_submit(request: Request, db: Session = Depends(get_db)) -> Response:
    if not auth.user_exists(db):
        return _redirect(request, "/setup")
    fields = await _form_or_json(request)
    try:
        return _start_session(request, db, str(fields.get("password", "")), status_code=200)
    except AuthError as exc:
        db.rollback()
        return respond(
            request,
            "login.html",
            {"error": str(exc)},
            data={"error": {"code": "invalid_credentials", "message": str(exc), "details": {}}},
            status_code=401,
        )


@router.post("/logout")
def logout(
    request: Request,
    db: Session = Depends(get_db),
    active: ActiveSession = Depends(require_csrf),
) -> Response:
    auth.logout(db, active.token_hash)
    db.commit()
    response = Response(status_code=204) if wants_json(request) else _redirect(request, "/login")
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    return response
