"""Request dependencies: database session, authentication, CSRF."""

from collections.abc import Iterator

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from rajdoll.core.crypto import KeyStore
from rajdoll.llm import status as llm_status
from rajdoll.services import auth
from rajdoll.services import settings as settings_service
from rajdoll.services.auth import ActiveSession
from rajdoll.services.session_check import Prober


class NotAuthenticatedError(Exception):
    """Raised when a route needs a logged-in user and there is none."""


class CsrfError(Exception):
    """Raised when a state-changing request lacks a valid CSRF token."""


def get_db(request: Request) -> Iterator[Session]:
    """One session per request. Routes commit explicitly; anything uncommitted is rolled back."""
    session: Session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def get_keystore(request: Request) -> KeyStore:
    keystore: KeyStore = request.app.state.keystore
    return keystore


def get_prober(request: Request) -> Prober:
    prober: Prober = request.app.state.session_prober
    return prober


def current_session(request: Request, db: Session = Depends(get_db)) -> ActiveSession:
    active = auth.resolve_session(db, request.cookies.get(auth.SESSION_COOKIE))
    if active is None:
        raise NotAuthenticatedError
    db.commit()  # persist last_seen_at
    request.state.csrf_token = active.csrf_token
    request.state.authenticated = True
    request.state.llm_indicator = llm_status.indicator(settings_service.load(db))
    return active


async def require_csrf(
    request: Request, active: ActiveSession = Depends(current_session)
) -> ActiveSession:
    """For state-changing requests: header `X-CSRF-Token` (HTMX) or form field `csrf_token`."""
    provided = request.headers.get("X-CSRF-Token")
    content_type = request.headers.get("content-type", "")
    if provided is None and content_type.startswith(
        ("application/x-www-form-urlencoded", "multipart/form-data")
    ):
        form = await request.form()
        value = form.get("csrf_token")
        provided = value if isinstance(value, str) else None
    if not auth.csrf_matches(active.csrf_token, provided):
        raise CsrfError
    return active
