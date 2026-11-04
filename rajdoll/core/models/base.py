"""Declarative base, naming convention, and shared column helpers."""

from datetime import date, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Date,
    DateTime,
    Identity,
    MetaData,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {
        datetime: DateTime(timezone=True),
        date: Date,
        str: Text,
        dict[str, Any]: JSONB,
        list[Any]: JSONB,
        list[str]: ARRAY(Text),
    }


def id_pk() -> Mapped[int]:
    return mapped_column(BigInteger, Identity(always=True), primary_key=True)


def ts_created() -> Mapped[datetime]:
    return mapped_column(server_default=func.now())


def ts_updated() -> Mapped[datetime]:
    return mapped_column(server_default=func.now(), onupdate=func.now())


def check_in(column: str, values: type[StrEnum], name: str | None = None) -> CheckConstraint:
    """CHECK that `column` holds one of the enum values (NULL passes, as in SQL)."""
    allowed = ", ".join(f"'{member.value}'" for member in values)
    return CheckConstraint(f"{column} IN ({allowed})", name=name or column)
