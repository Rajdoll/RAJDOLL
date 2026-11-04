"""FastAPI application entry point for the `api` service."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session, sessionmaker
from starlette.exceptions import HTTPException as StarletteHTTPException

from rajdoll import __version__
from rajdoll.api.deps import CsrfError, NotAuthenticatedError
from rajdoll.api.render import STATIC_DIR, error_response, is_htmx, wants_json
from rajdoll.api.routes import auth, pages, settings
from rajdoll.core.db import get_sessionmaker

# Pico's icons are data: URIs; htmx indicator styles are disabled via htmx-config, so no
# inline styles or scripts are needed anywhere (TRD 9).
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; "
    "object-src 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def create_app(session_factory: sessionmaker[Session] | None = None) -> FastAPI:
    app = FastAPI(
        title="RAJDOLL", version=__version__, docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.session_factory = session_factory or get_sessionmaker()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if not request.url.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(NotAuthenticatedError)
    async def not_authenticated(request: Request, _: NotAuthenticatedError) -> Response:
        if is_htmx(request):
            return Response(status_code=401, headers={"HX-Redirect": "/login"})
        if wants_json(request):
            return error_response(request, 401, "not_authenticated", "Login diperlukan.")
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(CsrfError)
    async def csrf_failed(request: Request, _: CsrfError) -> Response:
        return error_response(
            request, 403, "csrf_failed", "Token keamanan tidak valid. Muat ulang halaman."
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        message = "Halaman tidak ditemukan." if exc.status_code == 404 else str(exc.detail)
        return error_response(request, exc.status_code, f"http_{exc.status_code}", message)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> Response:
        if wants_json(request):
            return JSONResponse(
                {
                    "error": {
                        "code": "invalid_request",
                        "message": "Permintaan tidak valid.",
                        "details": {"errors": exc.errors()},
                    }
                },
                status_code=422,
            )
        return error_response(request, 422, "invalid_request", "Permintaan tidak valid.")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "api", "version": __version__}

    app.include_router(auth.router)
    app.include_router(pages.router)
    app.include_router(settings.router)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()
