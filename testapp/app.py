"""RAJDOLL testapp: a small, deliberately vulnerable web application for integration tests.

Never expose this app. It runs only under the compose `test` profile, on the internal Docker
network, so modules and validators can be proven against known weaknesses (IPD F3 onward).
Each deliberate weakness is listed in WEAKNESSES and gains a matching test as phases add
modules.
"""

import secrets

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

WEAKNESSES = {
    "exposed-env": "GET /.env serves configuration with credentials (WSTG-CONF-04, CWE-538)",
}

USERS = {"budi": "budi123", "sari": "sari123"}
SESSIONS: dict[str, str] = {}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def server_header(request: Request, call_next):  # type: ignore[no-untyped-def]
    response: Response = await call_next(request)
    response.headers["Server"] = "rajdoll-testapp/1.0"
    return response


def _page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"
    )


@app.get("/")
def index() -> HTMLResponse:
    return _page(
        "RAJDOLL testapp",
        '<h1>RAJDOLL testapp</h1><a href="/login">Masuk</a> <a href="/profil">Profil</a>',
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/login")
def login_form() -> HTMLResponse:
    return _page(
        "Masuk",
        '<form method="post" action="/login"><input name="username"><input name="password" '
        'type="password"><button>Masuk</button></form>',
    )


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)) -> Response:
    if USERS.get(username) != password:
        return _page("Masuk", "<p>Login gagal</p>")
    token = secrets.token_hex(16)
    SESSIONS[token] = username
    response = RedirectResponse("/profil", status_code=303)
    response.set_cookie("sid", token)
    return response


@app.get("/profil")
def profile(request: Request) -> Response:
    user = SESSIONS.get(request.cookies.get("sid", ""))
    if user is None:
        return RedirectResponse("/login", status_code=302)
    return _page("Profil", f"<p>Halo, {user.title()}</p>")


@app.get("/.env")
def exposed_env() -> PlainTextResponse:
    # Weakness "exposed-env": configuration file served to anyone.
    return PlainTextResponse(
        "APP_ENV=production\nDB_HOST=db\nDB_PASSWORD=testapp-not-a-real-secret\n"
    )
