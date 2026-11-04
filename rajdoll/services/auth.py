"""Single-user authentication and UI sessions (BSD 3.1, 3.2; TRD 9).

The session token lives only in the browser cookie; the database stores its SHA-256 hash, so a
leaked database row cannot be replayed as a cookie.
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from rajdoll.core.models import AppUser, UiSession

SESSION_COOKIE = "rajdoll_session"
SESSION_LIFETIME = timedelta(hours=12)
MIN_PASSWORD_LENGTH = 12
USER_ID = 1

_hasher = PasswordHasher()  # argon2id with library defaults


class AuthError(Exception):
    """Authentication or password-policy failure, with a message safe to show the user."""


@dataclass(frozen=True)
class ActiveSession:
    token_hash: str
    csrf_token: str
    expires_at: datetime


def utcnow() -> datetime:
    return datetime.now(UTC)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _require_user(session: Session) -> AppUser:
    user = session.get(AppUser, USER_ID)
    if user is None:
        raise AuthError("Password belum dibuat.")
    return user


def validate_new_password(password: str, confirmation: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Password minimal {MIN_PASSWORD_LENGTH} karakter.")
    if password != confirmation:
        raise AuthError("Konfirmasi password tidak sama.")


def user_exists(session: Session) -> bool:
    return session.get(AppUser, USER_ID) is not None


def create_user(session: Session, password: str, confirmation: str) -> None:
    """First-run setup. Fails if the user already exists."""
    validate_new_password(password, confirmation)
    if user_exists(session):
        raise AuthError("Password sudah pernah dibuat.")
    session.add(AppUser(id=USER_ID, password_hash=_hasher.hash(password)))
    session.flush()


def verify_password(session: Session, password: str) -> bool:
    user = session.get(AppUser, USER_ID)
    if user is None:
        return False
    try:
        _hasher.verify(user.password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = _hasher.hash(password)
    return True


def change_password(
    session: Session, current: str, new: str, confirmation: str, keep_token_hash: str
) -> None:
    """Change the password and sign out every other UI session."""
    if not verify_password(session, current):
        raise AuthError("Password saat ini salah.")
    validate_new_password(new, confirmation)
    user = _require_user(session)
    user.password_hash = _hasher.hash(new)
    session.execute(delete(UiSession).where(UiSession.token_hash != keep_token_hash))


def login(session: Session, password: str) -> tuple[str, ActiveSession]:
    """Verify the password and open a UI session. Returns (cookie token, session)."""
    if not verify_password(session, password):
        raise AuthError("Password salah.")
    now = utcnow()
    session.execute(delete(UiSession).where(UiSession.expires_at <= now))
    token = secrets.token_urlsafe(32)
    row = UiSession(
        token_hash=_hash_token(token),
        csrf_token=secrets.token_urlsafe(32),
        created_at=now,
        last_seen_at=now,
        expires_at=now + SESSION_LIFETIME,
    )
    session.add(row)
    _require_user(session).last_login_at = now
    session.flush()
    return token, ActiveSession(row.token_hash, row.csrf_token, row.expires_at)


def resolve_session(session: Session, token: str | None) -> ActiveSession | None:
    """Look up a valid session for a cookie token and record activity."""
    if not token:
        return None
    row = session.scalar(select(UiSession).where(UiSession.token_hash == _hash_token(token)))
    now = utcnow()
    if row is None or row.expires_at <= now:
        return None
    row.last_seen_at = now
    return ActiveSession(row.token_hash, row.csrf_token, row.expires_at)


def logout(session: Session, token_hash: str) -> None:
    session.execute(delete(UiSession).where(UiSession.token_hash == token_hash))


def csrf_matches(expected: str, provided: str | None) -> bool:
    return bool(provided) and secrets.compare_digest(expected, provided or "")
