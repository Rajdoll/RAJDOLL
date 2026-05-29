# api/routes/validation.py
from __future__ import annotations

import os
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel

from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Finding
from multi_agent_system.utils.finding_policy import apply_manual_validation, classify_finding

router = APIRouter()


def _require_admin(x_admin_token: str = Header(default="")):
    expected = os.getenv("ADMIN_TOKEN", "")
    if not expected or x_admin_token != expected:
        raise HTTPException(status_code=403, detail="Valid admin token required")


class ValidateBody(BaseModel):
    is_true_positive: bool
    notes: Optional[str] = None
    source: str = "admin_review"


class BulkValidation(BaseModel):
    finding_id: int
    is_true_positive: bool
    notes: Optional[str] = None
    source: str = "admin_review"


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
        classification = apply_manual_validation(
            finding,
            is_true_positive=body.is_true_positive,
            notes=body.notes,
            source=body.source,
        )
        db.commit()
        return {
            "finding_id": finding_id,
            "is_true_positive": body.is_true_positive,
            "classification": classification,
        }


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
                apply_manual_validation(
                    finding,
                    is_true_positive=v.is_true_positive,
                    notes=v.notes,
                    source=v.source,
                )
                updated += 1
        db.commit()
        reviewed = db.query(Finding).filter(Finding.job_id == job_id).all()
        return {
            "updated": updated,
            "job_id": job_id,
            "summary": {
                "validated_true_positive": len([f for f in reviewed if f.is_true_positive is True]),
                "validated_false_positive": len([f for f in reviewed if f.is_true_positive is False]),
                "reportable_count": len([f for f in reviewed if classify_finding(f).get("reportability_status") == "reportable"]),
            },
        }
