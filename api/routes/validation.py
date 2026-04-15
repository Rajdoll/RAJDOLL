# api/routes/validation.py
from __future__ import annotations

import os
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel

from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Finding

router = APIRouter()


def _require_admin(x_admin_token: str = Header(default="")):
    expected = os.getenv("ADMIN_TOKEN", "")
    if not expected or x_admin_token != expected:
        raise HTTPException(status_code=403, detail="Valid admin token required")


class ValidateBody(BaseModel):
    is_true_positive: bool
    notes: Optional[str] = None


class BulkValidation(BaseModel):
    finding_id: int
    is_true_positive: bool
    notes: Optional[str] = None


class BulkValidateBody(BaseModel):
    validations: List[BulkValidation]


@router.post("/findings/{finding_id}/validate")
def validate_finding(
    finding_id: int,
    body: ValidateBody,
    _: None = Depends(_require_admin),
):
    with get_db() as db:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        finding.is_true_positive = body.is_true_positive
        finding.validation_notes = body.notes
        db.commit()
        return {"finding_id": finding_id, "is_true_positive": body.is_true_positive}


@router.post("/jobs/{job_id}/findings/validate-bulk")
def bulk_validate_findings(
    job_id: int,
    body: BulkValidateBody,
    _: None = Depends(_require_admin),
):
    with get_db() as db:
        updated = 0
        for v in body.validations:
            finding = db.query(Finding).filter(
                Finding.id == v.finding_id,
                Finding.job_id == job_id,
            ).first()
            if finding:
                finding.is_true_positive = v.is_true_positive
                finding.validation_notes = v.notes
                updated += 1
        db.commit()
        return {"updated": updated, "job_id": job_id}
