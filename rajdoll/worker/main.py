"""Worker process skeleton.

F0 only proves the process starts, logs a heartbeat, and stops cleanly on SIGTERM/SIGINT.
The workflow engine (task queue, stages, checkpoint, recovery) arrives in F4.
"""

import logging
import signal
import threading

from rajdoll import __version__
from rajdoll.core.config import get_settings

log = logging.getLogger("rajdoll.worker")


def run(stop: threading.Event, heartbeat_seconds: float, max_iterations: int | None = None) -> int:
    """Log a heartbeat until `stop` is set or `max_iterations` is reached.

    Returns the number of heartbeats logged.
    """
    beats = 0
    while not stop.is_set():
        beats += 1
        log.info("worker heartbeat %d", beats)
        if max_iterations is not None and beats >= max_iterations:
            break
        stop.wait(heartbeat_seconds)
    return beats


def main() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    stop = threading.Event()

    def _handle_signal(signum: int, _frame: object) -> None:
        log.info("received signal %d, stopping", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    log.info("worker %s started", __version__)
    run(stop, settings.worker_heartbeat_seconds)
    log.info("worker stopped")
