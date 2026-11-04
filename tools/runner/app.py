"""Internal tool runner API for the `tools` service.

F0 exposes only /health. Tool execution (/run), adapters, and the egress proxy arrive in F3.
"""

from fastapi import FastAPI

RUNNER_VERSION = "1.0.0.dev0"

app = FastAPI(title="RAJDOLL tools runner", version=RUNNER_VERSION, docs_url=None, redoc_url=None)


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "service": "tools", "version": RUNNER_VERSION, "tools": {}}
