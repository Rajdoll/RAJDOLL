"""One-shot startup step run by the `api` container before the web server starts.

1. Apply database migrations (`alembic upgrade head`).
2. Make sure the master key exists and remove engagement key files left behind by an
   interrupted deletion (BSD 7, step 3).

The `worker` waits for `api` to be healthy, so it never runs against an unmigrated database.
"""

import logging
import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from rajdoll.core.config import get_settings
from rajdoll.core.crypto import KeyStore
from rajdoll.core.db import get_engine, get_sessionmaker
from rajdoll.core.models import Engagement

log = logging.getLogger("rajdoll.bootstrap")


def alembic_config(database_url: str | None = None) -> Config:
    ini = Path(os.environ.get("RAJDOLL_ALEMBIC_INI", "alembic.ini"))
    config = Config(str(ini))
    config.attributes["configure_logger"] = False
    if database_url is not None:
        config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def run_migrations(database_url: str | None = None) -> None:
    command.upgrade(alembic_config(database_url), "head")


def enable_tools_login(engine: Engine, password: str) -> None:
    """Let the egress proxy log in as `rajdoll_tools` (created NOLOGIN by the migration).

    The password is composed client-side as a literal because PostgreSQL does not accept
    bind parameters in ALTER ROLE.
    """
    statement = sql.SQL("ALTER ROLE rajdoll_tools WITH LOGIN PASSWORD {}").format(
        sql.Literal(password)
    )
    with engine.begin() as conn:
        conn.connection.dbapi_connection.execute(statement)  # type: ignore[union-attr]


def prepare_secrets(keystore: KeyStore, session_factory: sessionmaker[Session]) -> list[str]:
    """Create the master key if needed and delete orphaned engagement key files."""
    _ = keystore.master_key
    with session_factory() as session:
        known = session.scalars(select(Engagement.key_id)).all()
    removed = keystore.cleanup_orphans(known)
    return [str(key_id) for key_id in removed]


def main() -> None:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s %(message)s")
    log.info("applying database migrations")
    run_migrations(settings.database_url)
    if settings.tools_db_password:
        enable_tools_login(get_engine(), settings.tools_db_password)
        log.info("rajdoll_tools role can log in")
    else:
        log.warning("RAJDOLL_TOOLS_DB_PASSWORD not set; the egress proxy cannot reach the database")
    removed = prepare_secrets(KeyStore(settings.secrets_dir), get_sessionmaker())
    if removed:
        log.warning("removed %d orphaned engagement key file(s)", len(removed))
    log.info("bootstrap complete")


if __name__ == "__main__":
    main()
