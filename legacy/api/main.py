from __future__ import annotations

from fastapi import FastAPI
from .routes.scans import router as scans_router
from .routes.reporting import router as reporting_router
from .routes.reporting_enhanced import router as reporting_enhanced_router
from .routes.results import router as results_router
from .routes.websocket import router as ws_router
from .routes.owasp_reports import router as owasp_reports_router
from .routes.logs import router as logs_router
from .routes.hitl import router as hitl_router
from .routes.hitl_chat import router as hitl_chat_router
from .routes.pdf_report import router as pdf_report_router


app = FastAPI(title="RAJDOLL Multi-Agent Web Security Scanner")

app.include_router(scans_router, prefix="/api")
app.include_router(reporting_router, prefix="/api")
app.include_router(reporting_enhanced_router, prefix="/api")
app.include_router(results_router, prefix="/api")
app.include_router(owasp_reports_router, prefix="/api")
app.include_router(pdf_report_router, prefix="/api")
app.include_router(ws_router)
app.include_router(logs_router)
app.include_router(hitl_router)
app.include_router(hitl_chat_router)


@app.on_event("startup")
def _run_migrations():
	import os
	from alembic import command
	from alembic.config import Config

	repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	alembic_cfg = Config(os.path.join(repo_root, "alembic.ini"))
	command.upgrade(alembic_cfg, "head")

