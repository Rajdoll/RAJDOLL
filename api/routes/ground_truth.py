# api/routes/ground_truth.py
from __future__ import annotations

import os
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel

from multi_agent_system.core.db import get_db
from multi_agent_system.models.ground_truth import GroundTruthEntry

router = APIRouter()


def _require_admin(x_admin_token: str = Header(default="")):
    expected = os.getenv("ADMIN_TOKEN", "")
    if not expected or x_admin_token != expected:
        raise HTTPException(status_code=403, detail="Valid admin token required")


class GTEntryIn(BaseModel):
    vuln_name: str
    category: str
    severity: str
    cvss: Optional[float] = None


class GTEntryOut(BaseModel):
    id: int
    target_profile: str
    vuln_name: str
    category: str
    severity: str
    cvss: Optional[float]

    class Config:
        from_attributes = True


@router.get("/ground-truth/{target_profile}", response_model=List[GTEntryOut])
def list_ground_truth(target_profile: str):
    with get_db() as db:
        entries = db.query(GroundTruthEntry).filter(
            GroundTruthEntry.target_profile == target_profile
        ).all()
        return entries


@router.post("/ground-truth/{target_profile}", response_model=GTEntryOut, status_code=201)
def add_ground_truth_entry(
    target_profile: str,
    body: GTEntryIn,
    _: None = Depends(_require_admin),
):
    with get_db() as db:
        entry = GroundTruthEntry(
            target_profile=target_profile,
            vuln_name=body.vuln_name,
            category=body.category,
            severity=body.severity,
            cvss=body.cvss,
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry


@router.post("/ground-truth/{target_profile}/import", status_code=201)
def import_ground_truth(
    target_profile: str,
    entries: List[GTEntryIn],
    _: None = Depends(_require_admin),
):
    with get_db() as db:
        created = 0
        for e in entries:
            entry = GroundTruthEntry(
                target_profile=target_profile,
                vuln_name=e.vuln_name,
                category=e.category,
                severity=e.severity,
                cvss=e.cvss,
            )
            db.add(entry)
            created += 1
        db.commit()
        return {"imported": created, "target_profile": target_profile}


@router.delete("/ground-truth/{target_profile}/{entry_id}", status_code=204)
def delete_ground_truth_entry(
    target_profile: str,
    entry_id: int,
    _: None = Depends(_require_admin),
):
    with get_db() as db:
        entry = db.query(GroundTruthEntry).filter(
            GroundTruthEntry.id == entry_id,
            GroundTruthEntry.target_profile == target_profile,
        ).first()
        if not entry:
            raise HTTPException(status_code=404, detail="Entry not found")
        db.delete(entry)
        db.commit()
