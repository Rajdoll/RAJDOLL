"""Application tables: user, UI sessions, settings (BSD section 3)."""

from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, SmallInteger
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from rajdoll.core.models.base import Base, ts_created, ts_updated


class AppUser(Base):
    __tablename__ = "app_user"
    __table_args__ = (CheckConstraint("id = 1", name="single_user"),)

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    password_hash: Mapped[str]
    created_at: Mapped[datetime] = ts_created()
    updated_at: Mapped[datetime] = ts_updated()
    last_login_at: Mapped[datetime | None]


class UiSession(Base):
    __tablename__ = "ui_session"

    token_hash: Mapped[str] = mapped_column(primary_key=True)
    csrf_token: Mapped[str]
    created_at: Mapped[datetime] = ts_created()
    last_seen_at: Mapped[datetime] = ts_created()
    expires_at: Mapped[datetime]


class AppSetting(Base):
    __tablename__ = "app_setting"

    key: Mapped[str] = mapped_column(primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = ts_updated()
