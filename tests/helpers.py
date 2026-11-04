"""Shared helpers for integration tests that start real processes."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MITMDUMP = Path(sys.executable).parent / "mitmdump"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_port(port: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"nothing listening on {port}")


def clean_env(**extra: str) -> dict[str, str]:
    """Parent environment without proxy settings, so test traffic never leaves the machine."""
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    env.update(extra)
    return env


def start_mitmdump(database_url: str, token: str, confdir: Path) -> tuple[subprocess.Popen, int]:
    port = free_port()
    process = subprocess.Popen(  # noqa: S603
        [
            str(MITMDUMP),
            "--quiet",
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(port),
            "--set",
            f"confdir={confdir}",
            "--set",
            "connection_strategy=lazy",
            "--set",
            "ssl_insecure=true",
            "-s",
            str(REPO / "tools" / "proxy" / "mitm_script.py"),
        ],
        env=clean_env(
            PYTHONPATH=str(REPO),
            RAJDOLL_PROXY_DATABASE_URL=database_url,
            RAJDOLL_TOOLS_TOKEN=token,
        ),
    )
    wait_for_port(port)
    return process, port
