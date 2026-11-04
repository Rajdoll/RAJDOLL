"""Worker process: runs the workflow engine until SIGTERM/SIGINT (TRD 3)."""

import logging
import signal

from sqlalchemy.engine import make_url

from rajdoll import __version__
from rajdoll.core.config import Settings, get_settings
from rajdoll.core.crypto import KeyStore
from rajdoll.core.db import get_sessionmaker
from rajdoll.services import engagements
from rajdoll.services.session_check import make_prober
from rajdoll.worker.engine import Engine
from rajdoll.worker.tools_client import ToolsClient

log = logging.getLogger("rajdoll.worker")


def listen_dsn(database_url: str) -> str:
    """psycopg connection string for LISTEN, from the SQLAlchemy URL."""
    return make_url(database_url).set(drivername="postgresql").render_as_string(hide_password=False)


def build_engine(settings: Settings) -> Engine:
    keystore = KeyStore(settings.secrets_dir)
    prober = make_prober(settings.proxy_url, settings.tools_token)
    return Engine(
        get_sessionmaker(),
        ToolsClient(settings.tools_url, settings.tools_token),
        lease_seconds=settings.worker_lease_seconds,
        max_parallel=settings.worker_max_parallel,
        session_check_seconds=settings.session_check_seconds,
        check_account=lambda session, engagement, account: engagements.check_account(
            session, keystore, engagement, account, prober
        ),
        listen_dsn=listen_dsn(settings.database_url),
    )


def main() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    engine = build_engine(settings)

    def _handle_signal(signum: int, _frame: object) -> None:
        log.info("received signal %d, stopping", signum)
        engine.stop()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    log.info("worker %s started as %s", __version__, engine.worker_id)
    engine.run_forever(settings.worker_poll_seconds)
    log.info("worker stopped")
