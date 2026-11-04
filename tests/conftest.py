"""Shared fixtures.

Database tests need a PostgreSQL 16 server. Point RAJDOLL_TEST_DATABASE_URL at it, for example
`postgresql+psycopg://rajdoll_app:secret@127.0.0.1:5432/postgres` (the user must be able to
create databases and roles). Each test module gets a fresh, migrated database.

Without the variable, database tests are skipped, unless RAJDOLL_REQUIRE_DB_TESTS=1 (set in CI),
in which case they fail so a missing database can never turn the suite silently green.
"""

import os
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from rajdoll.core.bootstrap import run_migrations


def _admin_url() -> str:
    url = os.environ.get("RAJDOLL_TEST_DATABASE_URL")
    if not url:
        if os.environ.get("RAJDOLL_REQUIRE_DB_TESTS") == "1":
            pytest.fail("RAJDOLL_TEST_DATABASE_URL is required when RAJDOLL_REQUIRE_DB_TESTS=1")
        pytest.skip("RAJDOLL_TEST_DATABASE_URL not set")
    return url


def _create_database() -> tuple[str, str]:
    admin = make_url(_admin_url())
    name = f"rajdoll_test_{uuid.uuid4().hex[:12]}"
    engine = create_engine(admin, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(
            text(f"CREATE DATABASE \"{name}\" ENCODING 'UTF8' TEMPLATE template0")  # noqa: S608
        )
    engine.dispose()
    return name, admin.set(database=name).render_as_string(hide_password=False)


def _drop_database(name: str) -> None:
    engine = create_engine(make_url(_admin_url()), isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    engine.dispose()


@pytest.fixture(scope="module")
def empty_db_url() -> Iterator[str]:
    """URL of a fresh, empty database (no migrations applied)."""
    name, url = _create_database()
    try:
        yield url
    finally:
        _drop_database(name)


@pytest.fixture(scope="module")
def db_engine(empty_db_url: str) -> Iterator[Engine]:
    """Engine for a fresh database migrated to head."""
    run_migrations(empty_db_url)
    engine = create_engine(empty_db_url)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """A session whose work is rolled back after the test."""
    connection = db_engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection, join_transaction_mode="create_savepoint")()
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()
