from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Any


class CreateScanRequest(BaseModel):
    target: HttpUrl
    full_wstg_coverage: bool = False
    hitl_enabled: Optional[bool] = None
    enable_tool_hitl: Optional[bool] = None
    hitl_mode: Optional[str] = None  # off | agent | tool — per-scan override
    auto_approve_agents: Optional[List[str]] = None
    authorization_token: Optional[str] = None  # Security guard: authorization token
    user_email: Optional[str] = None  # Audit logging: who initiated the scan


class JobAgentState(BaseModel):
    agent_name: str
    status: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None


class ScanStatusResponse(BaseModel):
    job_id: int
    status: str
    agents: List[JobAgentState]
    summary: Optional[str] = None
