"""Internal tool runner API for the `tools` service.

F3a exposes only /health, which also reports whether the egress proxy is accepting
connections. Tool execution (/run) and adapters arrive in F3b.
"""

import os
import socket

from fastapi import FastAPI
from fastapi.responses import JSONResponse

RUNNER_VERSION = "1.0.0.dev0"
PROXY_ADDRESS = ("127.0.0.1", int(os.environ.get("RAJDOLL_PROXY_PORT", "8081")))

app = FastAPI(title="RAJDOLL tools runner", version=RUNNER_VERSION, docs_url=None, redoc_url=None)


def proxy_listening(address: tuple[str, int] = PROXY_ADDRESS, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection(address, timeout=timeout):
            return True
    except OSError:
        return False


@app.get("/health")
def health() -> JSONResponse:
    proxy_ok = proxy_listening()
    body = {
        "status": "ok" if proxy_ok else "degraded",
        "service": "tools",
        "version": RUNNER_VERSION,
        "proxy": "listening" if proxy_ok else "down",
        "tools": {},
    }
    return JSONResponse(body, status_code=200 if proxy_ok else 503)
