"""Start the egress proxy and the runner API in one container and stop both together.

If either process exits, the other is terminated and the container exits with an error, so
Docker's restart policy brings the pair back up together.
"""

import os
import signal
import subprocess
import sys
import time

PROXY_PORT = os.environ.get("RAJDOLL_PROXY_PORT", "8081")
RUNNER_PORT = os.environ.get("RAJDOLL_RUNNER_PORT", "9000")
CONFDIR = os.environ.get("RAJDOLL_PROXY_CONFDIR", "/data/mitmproxy")

COMMANDS = {
    "proxy": [
        "mitmdump",
        "--quiet",
        "--listen-host",
        "0.0.0.0",  # noqa: S104 (internal Docker network only; no published port)
        "--listen-port",
        PROXY_PORT,
        "--set",
        f"confdir={CONFDIR}",
        "--set",
        "connection_strategy=lazy",  # never connect upstream before the scope check
        "--set",
        "ssl_insecure=true",  # targets are clones, often with self-signed certificates
        "--set",
        "stream_large_bodies=5m",
        "-s",
        "/app/tools/proxy/mitm_script.py",
    ],
    "runner": [
        "uvicorn",
        "tools.runner.app:app",
        "--host",
        "0.0.0.0",  # noqa: S104
        "--port",
        RUNNER_PORT,
    ],
}


def main() -> int:
    processes = {name: subprocess.Popen(cmd) for name, cmd in COMMANDS.items()}  # noqa: S603
    stopping = False

    def stop(signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True
        for proc in processes.values():
            if proc.poll() is None:
                proc.send_signal(signum)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    while True:
        for name, proc in processes.items():
            code = proc.poll()
            if code is not None:
                if not stopping:
                    print(f"{name} exited with {code}; stopping the container", file=sys.stderr)
                    stop(signal.SIGTERM, None)
                for other in processes.values():
                    try:
                        other.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        other.kill()
                return 0 if stopping and code in (0, -signal.SIGTERM) else 1
        time.sleep(0.5)


if __name__ == "__main__":
    sys.exit(main())
