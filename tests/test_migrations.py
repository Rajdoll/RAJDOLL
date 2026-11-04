"""Baseline migration: tables, model/migration sync, down-and-up, tools role, NOTIFY trigger."""

import psycopg
import pytest
from alembic import command
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.engine import make_url

from rajdoll.core.bootstrap import alembic_config, run_migrations
from rajdoll.core.models import Base

EXPECTED_TABLES = set(Base.metadata.tables)


def _public_tables(engine: Engine) -> set[str]:
    return set(inspect(engine).get_table_names()) - {"alembic_version"}


def test_bsd_defines_17_tables() -> None:
    assert len(EXPECTED_TABLES) == 17


def test_upgrade_creates_all_tables(db_engine: Engine) -> None:
    assert _public_tables(db_engine) == EXPECTED_TABLES


def test_models_match_migration(db_engine: Engine) -> None:
    # Raises if autogenerate would produce any operation, i.e. models and migrations differ.
    command.check(alembic_config(db_engine.url.render_as_string(hide_password=False)))


@pytest.mark.parametrize(
    ("table", "privilege", "expected"),
    [
        ("request_log", "INSERT", True),
        ("scan_event", "INSERT", True),
        ("task", "SELECT", True),
        ("scan", "SELECT", True),
        ("scope_rule", "SELECT", True),
        ("finding", "SELECT", False),
        ("evidence", "SELECT", False),
        ("target_account", "SELECT", False),
        ("llm_call", "SELECT", False),
        ("request_log", "SELECT", False),
        ("task", "UPDATE", False),
    ],
)
def test_tools_role_table_privileges(
    db_engine: Engine, table: str, privilege: str, expected: bool
) -> None:
    with db_engine.connect() as conn:
        allowed = conn.execute(
            text("SELECT has_table_privilege('rajdoll_tools', :t, :p)"),
            {"t": table, "p": privilege},
        ).scalar_one()
    assert allowed is expected


@pytest.mark.parametrize(
    ("column", "expected"), [("id", True), ("settings", True), ("name", False), ("notes", False)]
)
def test_tools_role_engagement_columns(db_engine: Engine, column: str, expected: bool) -> None:
    with db_engine.connect() as conn:
        allowed = conn.execute(
            text("SELECT has_column_privilege('rajdoll_tools', 'engagement', :c, 'SELECT')"),
            {"c": column},
        ).scalar_one()
    assert allowed is expected


def test_tools_role_can_insert_audit_rows(db_engine: Engine) -> None:
    with db_engine.connect() as conn, conn.begin() as tx:
        engagement_id = conn.execute(
            text(
                "INSERT INTO engagement (name, target_url, key_id) "
                "VALUES ('x', 'https://app.test', gen_random_uuid()) RETURNING id"
            )
        ).scalar_one()
        conn.execute(text("SET LOCAL ROLE rajdoll_tools"))
        conn.execute(
            text(
                "INSERT INTO request_log (engagement_id, kind, tool, url, host, outcome) "
                "VALUES (:e, 'http', 'nuclei', 'https://app.test/', 'app.test', 'forwarded')"
            ),
            {"e": engagement_id},
        )
        with pytest.raises(Exception, match="permission denied"):
            conn.execute(text("SELECT count(*) FROM finding"))
        tx.rollback()


def test_scan_event_insert_notifies(db_engine: Engine) -> None:
    url = make_url(db_engine.url).set(drivername="postgresql")
    with psycopg.connect(url.render_as_string(hide_password=False), autocommit=True) as listener:
        listener.execute("LISTEN scan_events")
        with db_engine.begin() as conn:
            engagement_id = conn.execute(
                text(
                    "INSERT INTO engagement (name, target_url, key_id) "
                    "VALUES ('x', 'https://app.test', gen_random_uuid()) RETURNING id"
                )
            ).scalar_one()
            scan_id = conn.execute(
                text(
                    "INSERT INTO scan (engagement_id, kind, number, profile) "
                    "VALUES (:e, 'scan', 1, 'full') RETURNING id"
                ),
                {"e": engagement_id},
            ).scalar_one()
            event_id = conn.execute(
                text(
                    "INSERT INTO scan_event (scan_id, level, type, message) "
                    "VALUES (:s, 'info', 'stage_changed', 'recon dimulai') RETURNING id"
                ),
                {"s": scan_id},
            ).scalar_one()
        notification = next(listener.notifies(timeout=5))
        assert notification.channel == "scan_events"
        assert notification.payload == f"{scan_id}:{event_id}"
        with db_engine.begin() as conn:
            conn.execute(text("DELETE FROM engagement WHERE id = :e"), {"e": engagement_id})


def test_downgrade_then_upgrade(empty_db_url: str, db_engine: Engine) -> None:
    command.downgrade(alembic_config(empty_db_url), "base")
    engine = create_engine(empty_db_url)
    try:
        assert _public_tables(engine) == set()
        with engine.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM pg_proc WHERE proname = 'scan_event_notify'")
                ).scalar_one()
                == 0
            )
        run_migrations(empty_db_url)
        assert _public_tables(engine) == EXPECTED_TABLES
    finally:
        engine.dispose()


def test_check_constraints_match_enums(db_engine: Engine) -> None:
    """Every `x IN (...)` CHECK in the database lists exactly the values of its model enum.

    Alembic autogenerate ignores CHECK bodies, so an enum change without a hand-written
    migration would otherwise go unnoticed.
    """
    import re

    from sqlalchemy import CheckConstraint

    expected: dict[str, set[str]] = {}
    for table in Base.metadata.tables.values():
        for constraint in table.constraints:
            if not isinstance(constraint, CheckConstraint):
                continue
            match = re.fullmatch(r"\w+ IN \((.*)\)", str(constraint.sqltext))
            if match:
                name = str(constraint.name)  # already converted by the naming convention
                expected[name if name.startswith("ck_") else f"ck_{table.name}_{name}"] = set(
                    re.findall(r"'([^']*)'", match.group(1))
                )
    with db_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE contype = 'c' AND connamespace = 'public'::regnamespace"
            )
        ).all()
    actual = {name: set(re.findall(r"'([^']*)'::text", definition)) for name, definition in rows}
    assert len(expected) >= 20
    for name, values in expected.items():
        assert actual.get(name) == values, name
