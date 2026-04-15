# Precision Validation & Dynamic Ground Truth — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hardcoded `JUICE_SHOP_GROUND_TRUTH` dict and automated precision formula with a database-driven ground truth model and manual TP/FP validation workflow, making precision academically legitimate and target-agnostic.

**Architecture:** `GroundTruthEntry` records replace Python dicts for recall. `Finding.is_true_positive` (nullable bool) stores manual researcher labels for precision. A new validation API lets the researcher mark each finding TP/FP; a new ground truth API lets them import challenge lists per target. The frontend gets TP/FP toggle buttons on the findings list.

**Tech Stack:** SQLAlchemy ORM, FastAPI, PostgreSQL (ALTER TABLE migration), vanilla JS frontend (no framework), pytest + unittest.mock for tests (no Docker needed).

---

## File Map

| Action | File | Responsibility |
|--------|------|---------------|
| Create | `multi_agent_system/models/ground_truth.py` | `GroundTruthEntry` SQLAlchemy model |
| Modify | `multi_agent_system/models/models.py` | Add `is_true_positive`, `validation_notes` to `Finding` |
| Modify | `multi_agent_system/evaluation/metrics.py` | Remove hardcoded dicts; new precision (manual labels) + recall (DB entries) |
| Create | `api/routes/ground_truth.py` | CRUD + bulk import for ground truth entries |
| Create | `api/routes/validation.py` | POST validate + bulk validate for findings |
| Modify | `api/routes/evaluation.py` | New response schema: `precision_status`, `validated_count`, `unreviewed_count` |
| Modify | `api/routes/results.py` | Include `is_true_positive`, `validation_notes` in findings response |
| Modify | `api/main.py` | Register `ground_truth_router` and `validation_router` |
| Create | `multi_agent_system/data/juice_shop_ground_truth.json` | 57-entry seed data for Juice Shop benchmark |
| Modify | `frontend/index.html` | Add findings validation panel |
| Modify | `frontend/js/app.js` | Fetch findings + TP/FP button logic |
| Create | `multi_agent_system/tests/test_precision_validation.py` | Unit tests (no DB/Docker required) |

---

## Task 1: `GroundTruthEntry` Model

**Files:**
- Create: `multi_agent_system/models/ground_truth.py`

- [ ] **Step 1: Write the failing test**

```python
# multi_agent_system/tests/test_precision_validation.py
import pytest
from unittest.mock import MagicMock

class TestGroundTruthEntry:
    def test_model_has_required_fields(self):
        from multi_agent_system.models.ground_truth import GroundTruthEntry
        entry = GroundTruthEntry(
            target_profile="juice-shop",
            vuln_name="Login Admin",
            category="WSTG-INPV-05",
            severity="critical",
            cvss=9.8,
        )
        assert entry.target_profile == "juice-shop"
        assert entry.vuln_name == "Login Admin"
        assert entry.category == "WSTG-INPV-05"
        assert entry.severity == "critical"
        assert entry.cvss == 9.8

    def test_model_tablename(self):
        from multi_agent_system.models.ground_truth import GroundTruthEntry
        assert GroundTruthEntry.__tablename__ == "ground_truth_entries"
```

- [ ] **Step 2: Run to confirm it fails**

```bash
pytest multi_agent_system/tests/test_precision_validation.py::TestGroundTruthEntry -v
```

Expected: `ImportError: cannot import name 'GroundTruthEntry'`

- [ ] **Step 3: Create the model**

```python
# multi_agent_system/models/ground_truth.py
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped

from ..core.db import Base


class GroundTruthEntry(Base):
    __tablename__ = "ground_truth_entries"

    id: Mapped[int] = Column(Integer, primary_key=True)
    target_profile: Mapped[str] = Column(String(100), nullable=False, index=True)
    vuln_name: Mapped[str] = Column(String(200), nullable=False)
    category: Mapped[str] = Column(String(50), nullable=False)
    severity: Mapped[str] = Column(String(20), nullable=False)
    cvss: Mapped[Optional[float]] = Column(Float, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=datetime.utcnow, nullable=False)
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest multi_agent_system/tests/test_precision_validation.py::TestGroundTruthEntry -v
```

Expected: 2 PASSED

- [ ] **Step 5: Commit**

```bash
git add multi_agent_system/models/ground_truth.py multi_agent_system/tests/test_precision_validation.py
git commit -m "feat(models): add GroundTruthEntry model for dynamic ground truth"
```

---

## Task 2: Extend `Finding` Model with Validation Fields

**Files:**
- Modify: `multi_agent_system/models/models.py:104-130`

- [ ] **Step 1: Write the failing test**

Add to `multi_agent_system/tests/test_precision_validation.py`:

```python
class TestFindingValidationFields:
    def test_finding_has_is_true_positive(self):
        from multi_agent_system.models.models import Finding
        f = Finding()
        assert hasattr(f, "is_true_positive")
        assert f.is_true_positive is None  # nullable default

    def test_finding_has_validation_notes(self):
        from multi_agent_system.models.models import Finding
        f = Finding()
        assert hasattr(f, "validation_notes")
        assert f.validation_notes is None
```

- [ ] **Step 2: Run to confirm it fails**

```bash
pytest multi_agent_system/tests/test_precision_validation.py::TestFindingValidationFields -v
```

Expected: `AttributeError: 'Finding' object has no attribute 'is_true_positive'`

- [ ] **Step 3: Add columns to `Finding` in `models.py`**

In `multi_agent_system/models/models.py`, add `Boolean` to the SQLAlchemy imports:

```python
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
```

Then add the two columns to the `Finding` class, after the `enrichment_source` line (line 128):

```python
    # Manual precision validation
    is_true_positive: Mapped[Optional[bool]] = Column(Boolean, nullable=True, default=None)
    validation_notes: Mapped[Optional[str]] = Column(Text, nullable=True, default=None)
```

- [ ] **Step 4: Apply DB migration**

```bash
docker exec rajdoll-db-1 psql -U rajdoll -d rajdoll -c "
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_true_positive BOOLEAN DEFAULT NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_notes TEXT DEFAULT NULL;
"
```

Expected output: `ALTER TABLE` (twice)

- [ ] **Step 5: Run tests to confirm they pass**

```bash
pytest multi_agent_system/tests/test_precision_validation.py::TestFindingValidationFields -v
```

Expected: 2 PASSED

- [ ] **Step 6: Commit**

```bash
git add multi_agent_system/models/models.py multi_agent_system/tests/test_precision_validation.py
git commit -m "feat(models): add is_true_positive and validation_notes to Finding"
```

---

## Task 3: Rewrite `metrics.py` — Remove Hardcoded Dicts, New Precision/Recall

**Files:**
- Modify: `multi_agent_system/evaluation/metrics.py`

- [ ] **Step 1: Write the failing tests**

Add to `multi_agent_system/tests/test_precision_validation.py`:

```python
class TestPrecisionCalculation:
    def _make_finding(self, is_tp):
        f = MagicMock()
        f.is_true_positive = is_tp
        return f

    def test_precision_returns_none_when_no_labels(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        findings = [self._make_finding(None), self._make_finding(None)]
        assert m.calculate_precision(findings) is None

    def test_precision_all_tp(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        findings = [self._make_finding(True), self._make_finding(True), self._make_finding(True)]
        assert m.calculate_precision(findings) == 100.0

    def test_precision_mixed(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        # 3 TP, 1 FP
        findings = [self._make_finding(True)] * 3 + [self._make_finding(False)]
        assert m.calculate_precision(findings) == 75.0

    def test_precision_partial_review(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        # 2 reviewed (both TP), 1 unreviewed
        findings = [self._make_finding(True), self._make_finding(True), self._make_finding(None)]
        assert m.calculate_precision(findings) == 100.0  # computed only from reviewed


class TestRecallCalculation:
    def _make_finding(self, title, category):
        f = MagicMock()
        f.title = title
        f.details = ""
        f.category = category
        return f

    def _make_gt(self, vuln_name, category):
        gt = MagicMock()
        gt.id = id(gt)
        gt.vuln_name = vuln_name
        gt.category = category
        return gt

    def test_recall_returns_none_when_no_ground_truth(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        assert m.calculate_recall([], []) is None

    def test_recall_all_detected(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        findings = [self._make_finding("SQL Injection Login Bypass admin", "WSTG-INPV-05")]
        gt = [self._make_gt("Login Admin", "WSTG-INPV-05")]
        assert m.calculate_recall(findings, gt) == 100.0

    def test_recall_none_detected(self):
        from multi_agent_system.evaluation.metrics import EffectivenessMetrics
        m = EffectivenessMetrics()
        findings = [self._make_finding("XSS found", "WSTG-CLNT-01")]
        gt = [self._make_gt("Login Admin", "WSTG-INPV-05")]
        assert m.calculate_recall(findings, gt) == 0.0


class TestGroundTruthManager:
    def test_derive_profile_juice_shop(self):
        from multi_agent_system.evaluation.metrics import GroundTruthManager
        assert GroundTruthManager.derive_profile("http://juice-shop:3000") == "juice-shop"

    def test_derive_profile_webgoat(self):
        from multi_agent_system.evaluation.metrics import GroundTruthManager
        assert GroundTruthManager.derive_profile("http://webgoat:8080/WebGoat") == "webgoat"

    def test_derive_profile_external(self):
        from multi_agent_system.evaluation.metrics import GroundTruthManager
        assert GroundTruthManager.derive_profile("https://target.bssn.go.id") == "target.bssn.go.id"

    def test_no_hardcoded_dicts(self):
        import multi_agent_system.evaluation.metrics as m
        assert not hasattr(m, "JUICE_SHOP_GROUND_TRUTH"), "Hardcoded dict must be removed"
        assert not hasattr(m, "DVWA_GROUND_TRUTH"), "Hardcoded dict must be removed"
```

- [ ] **Step 2: Run to confirm they fail**

```bash
pytest multi_agent_system/tests/test_precision_validation.py::TestPrecisionCalculation multi_agent_system/tests/test_precision_validation.py::TestRecallCalculation multi_agent_system/tests/test_precision_validation.py::TestGroundTruthManager -v
```

Expected: Multiple FAILED / ImportError

- [ ] **Step 3: Rewrite `GroundTruthManager` and `EffectivenessMetrics` in `metrics.py`**

**3a — Add import at top of `metrics.py`:**

Add to existing imports:
```python
from urllib.parse import urlparse
from ..models.ground_truth import GroundTruthEntry
```

**3b — Replace the entire `GroundTruthManager` class** (delete `DVWA_GROUND_TRUTH`, `JUICE_SHOP_GROUND_TRUTH`, and the old `get_ground_truth` method) with:

```python
class GroundTruthManager:
    """Manage ground truth data — reads from DB, not hardcoded dicts."""

    @staticmethod
    def derive_profile(target_url: str) -> str:
        """Derive a stable profile key from a target URL hostname."""
        parsed = urlparse(target_url)
        hostname = parsed.hostname or target_url
        return hostname.lower()

    def get_ground_truth(self, target_url: str, db: Session) -> List[GroundTruthEntry]:
        """Load ground truth entries for target from the database."""
        profile = self.derive_profile(target_url)
        return db.query(GroundTruthEntry).filter(
            GroundTruthEntry.target_profile == profile
        ).all()
```

**3c — Replace `calculate_precision` in `EffectivenessMetrics`:**

```python
def calculate_precision(self, findings: List[Finding]) -> Optional[float]:
    """
    Precision = TP / (TP + FP) from manual researcher labels.
    Returns None when no findings have been reviewed yet.
    """
    reviewed = [f for f in findings if f.is_true_positive is not None]
    if not reviewed:
        return None
    tp = sum(1 for f in reviewed if f.is_true_positive is True)
    fp = sum(1 for f in reviewed if f.is_true_positive is False)
    if tp + fp == 0:
        return 0.0
    return round((tp / (tp + fp)) * 100, 2)
```

**3d — Replace `calculate_recall` in `EffectivenessMetrics`:**

```python
def calculate_recall(
    self,
    findings: List[Finding],
    ground_truth: List[GroundTruthEntry],
) -> Optional[float]:
    """
    Recall = detected GT entries / total GT entries.
    Returns None when no ground truth exists for this target.
    """
    if not ground_truth:
        return None
    detected = set()
    for f in findings:
        for gt in ground_truth:
            if self._matches(f, gt):
                detected.add(gt.id)
    return round((len(detected) / len(ground_truth)) * 100, 2)

def _matches(self, finding: Finding, gt: GroundTruthEntry) -> bool:
    """Category must match; at least 2 vuln_name keywords in finding text."""
    if finding.category != gt.category:
        return False
    keywords = gt.vuln_name.lower().replace("-", " ").replace("_", " ").split()
    finding_text = (finding.title + " " + (finding.details or "")).lower()
    return sum(1 for kw in keywords if kw in finding_text) >= 2
```

**3e — Remove the old `_matches_ground_truth` and `_matches_vulnerability` methods** from `EffectivenessMetrics` (they are replaced by `_matches`).

**3f — Update `MetricsResult` dataclass** — change `precision` and `recall` to `Optional[float]`:

```python
@dataclass
class MetricsResult:
    precision: Optional[float]   # None = not yet reviewed
    recall: Optional[float]      # None = no ground truth loaded
    f1_score: Optional[float]
    # ... rest unchanged
```

**3g — Update `calculate_f1_score`** to handle `None` inputs:

```python
def calculate_f1_score(self, precision: Optional[float], recall: Optional[float]) -> Optional[float]:
    if precision is None or recall is None:
        return None
    if precision + recall == 0:
        return 0.0
    return round(2 * (precision * recall) / (precision + recall), 2)
```

**3h — Update `MetricsCalculator.calculate_all_metrics`** to pass DB session and new signatures. Find the existing method and update the calls to `calculate_precision` and `calculate_recall`:

```python
def calculate_all_metrics(self, job_id: int, target: str) -> MetricsResult:
    with get_db() as db:
        findings = db.query(Finding).filter(Finding.job_id == job_id).all()
        ground_truth = self.ground_truth_manager.get_ground_truth(target, db)

        precision = self.effectiveness.calculate_precision(findings)
        recall = self.effectiveness.calculate_recall(findings, ground_truth)
        f1 = self.effectiveness.calculate_f1_score(precision, recall)
        # ... rest of method unchanged, pass the already-loaded findings/gt
```

- [ ] **Step 4: Run tests**

```bash
pytest multi_agent_system/tests/test_precision_validation.py -v
```

Expected: All precision/recall/GT tests PASS

- [ ] **Step 5: Commit**

```bash
git add multi_agent_system/evaluation/metrics.py multi_agent_system/tests/test_precision_validation.py
git commit -m "feat(metrics): replace hardcoded dicts with DB-driven ground truth and manual precision"
```

---

## Task 4: Ground Truth API Routes

**Files:**
- Create: `api/routes/ground_truth.py`

- [ ] **Step 1: Write the file**

```python
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
```

- [ ] **Step 2: Commit**

```bash
git add api/routes/ground_truth.py
git commit -m "feat(api): add ground truth CRUD and bulk import endpoints"
```

---

## Task 5: Finding Validation API Routes

**Files:**
- Create: `api/routes/validation.py`

- [ ] **Step 1: Write the file**

```python
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
```

- [ ] **Step 2: Commit**

```bash
git add api/routes/validation.py
git commit -m "feat(api): add finding TP/FP validation endpoints"
```

---

## Task 6: Update Evaluation Route — New Response Schema

**Files:**
- Modify: `api/routes/evaluation.py`

- [ ] **Step 1: Replace `MetricsResponse` and `get_metrics`**

Replace the `MetricsResponse` class with:

```python
from typing import Optional

class MetricsResponse(BaseModel):
    job_id: int
    target: str

    # Precision — manual labels
    precision: Optional[float]           # None = pending review
    precision_status: str                # "validated" | "partial" | "pending_review"
    validated_count: int
    unreviewed_count: int

    # Recall — DB ground truth
    recall: Optional[float]              # None = no ground truth loaded
    f1_score: Optional[float]

    # Unchanged metrics
    false_negative_rate: Optional[float]
    severity_accuracy: float
    cvss_correlation: float
    cvss_p_value: float
    ttff_seconds: float
    total_scan_hours: float
    tcr_percentage: float
    owasp_top10_coverage: float
    attack_surface_coverage: float
    crash_rate: float
    recovery_rate: float
    consistency_score: float
    acceptance_status: str
    recommendations: list[str]
```

Replace the `get_metrics` return statement with:

```python
    # Compute validation counts
    with get_db() as db:
        from multi_agent_system.models.models import Finding
        all_findings = db.query(Finding).filter(Finding.job_id == job_id).all()
        validated_count = sum(1 for f in all_findings if f.is_true_positive is not None)
        unreviewed_count = sum(1 for f in all_findings if f.is_true_positive is None)

    if validated_count == 0:
        precision_status = "pending_review"
    elif unreviewed_count == 0:
        precision_status = "validated"
    else:
        precision_status = "partial"

    return MetricsResponse(
        job_id=job_id,
        target=target,
        precision=metrics.precision,
        precision_status=precision_status,
        validated_count=validated_count,
        unreviewed_count=unreviewed_count,
        recall=metrics.recall,
        f1_score=metrics.f1_score,
        false_negative_rate=metrics.false_negative_rate,
        severity_accuracy=metrics.severity_accuracy,
        cvss_correlation=metrics.cvss_correlation,
        cvss_p_value=metrics.cvss_p_value,
        ttff_seconds=metrics.ttff_seconds,
        total_scan_hours=metrics.total_scan_hours,
        tcr_percentage=metrics.tcr_percentage,
        owasp_top10_coverage=metrics.owasp_top10_coverage,
        attack_surface_coverage=metrics.attack_surface_coverage,
        crash_rate=metrics.crash_rate,
        recovery_rate=metrics.recovery_rate,
        consistency_score=metrics.consistency_score,
        acceptance_status=acceptance_status,
        recommendations=recommendations,
    )
```

Also update the acceptance logic — if `metrics.precision` is `None`, skip precision from EXCELLENT/ACCEPTABLE check rather than erroring:

```python
    precision_ok = metrics.precision is None or metrics.precision >= 90.0
    recall_ok = metrics.recall is None or metrics.recall >= 80.0
    f1_ok = metrics.f1_score is None or metrics.f1_score >= 85.0

    if (f1_ok and metrics.tcr_percentage >= 85.0 and
            metrics.ttff_seconds <= 180 and metrics.crash_rate <= 1.0):
        acceptance_status = "EXCELLENT"
    elif (f1_ok and metrics.tcr_percentage >= 70.0 and
          metrics.ttff_seconds <= 300 and metrics.crash_rate <= 2.0):
        acceptance_status = "ACCEPTABLE"
    else:
        acceptance_status = "NEEDS_IMPROVEMENT"
```

- [ ] **Step 2: Commit**

```bash
git add api/routes/evaluation.py
git commit -m "feat(api): update metrics response with precision_status and validation counts"
```

---

## Task 7: Update Findings Response to Include Validation State

**Files:**
- Modify: `api/routes/results.py:46-58`

- [ ] **Step 1: Add `is_true_positive` and `validation_notes` to the findings list response**

Replace the return list comprehension in `get_findings`:

```python
        return [
            {
                "id": f.id,
                "agent_name": f.agent_name,
                "category": f.category,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "evidence": f.evidence,
                "details": f.details,
                "created_at": f.created_at,
                "is_true_positive": f.is_true_positive,
                "validation_notes": f.validation_notes,
            }
            for f in findings
        ]
```

- [ ] **Step 2: Commit**

```bash
git add api/routes/results.py
git commit -m "feat(api): include is_true_positive and validation_notes in findings response"
```

---

## Task 8: Register New Routers in `api/main.py`

**Files:**
- Modify: `api/main.py`

- [ ] **Step 1: Add imports and include routers**

Add after the existing imports:

```python
from .routes.ground_truth import router as ground_truth_router
from .routes.validation import router as validation_router
```

Add after the existing `app.include_router` calls (before the static mount):

```python
app.include_router(ground_truth_router, prefix="/api")
app.include_router(validation_router, prefix="/api")
```

Also ensure `GroundTruthEntry` table is created on startup — add to the `_create_tables` function by importing the model (SQLAlchemy picks it up via `Base.metadata`):

```python
@app.on_event("startup")
def _create_tables():
    from multi_agent_system.models import ground_truth  # noqa: register model
    Base.metadata.create_all(bind=engine)
```

- [ ] **Step 2: Commit**

```bash
git add api/main.py
git commit -m "feat(api): register ground truth and validation routers"
```

---

## Task 9: Juice Shop Seed Data JSON

**Files:**
- Create: `multi_agent_system/data/juice_shop_ground_truth.json`

- [ ] **Step 1: Create the 57-entry seed file**

```json
[
  {"vuln_name": "Score Board",               "category": "WSTG-INFO-06",  "severity": "info",     "cvss": 3.7},
  {"vuln_name": "Bonus Payload",             "category": "WSTG-INPV-01",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "DOM XSS",                   "category": "WSTG-CLNT-01",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Confidential Document",     "category": "WSTG-CONF-04",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Error Handling",            "category": "WSTG-ERRH-01",  "severity": "low",      "cvss": 3.7},
  {"vuln_name": "Exposed Metrics",           "category": "WSTG-CONF-05",  "severity": "medium",   "cvss": 5.3},
  {"vuln_name": "Outdated Allowlist",        "category": "WSTG-CLNT-04",  "severity": "medium",   "cvss": 5.4},
  {"vuln_name": "Repetitive Registration",   "category": "WSTG-IDNT-02",  "severity": "medium",   "cvss": 5.0},
  {"vuln_name": "Zero Stars",                "category": "WSTG-BUSL-01",  "severity": "medium",   "cvss": 5.0},
  {"vuln_name": "Login Admin",               "category": "WSTG-INPV-05",  "severity": "critical", "cvss": 9.8},
  {"vuln_name": "Password Strength",         "category": "WSTG-ATHN-07",  "severity": "medium",   "cvss": 5.3},
  {"vuln_name": "Security Policy",           "category": "WSTG-INFO-02",  "severity": "info",     "cvss": 3.7},
  {"vuln_name": "View Basket",               "category": "WSTG-ATHZ-04",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Admin Section",             "category": "WSTG-ATHZ-02",  "severity": "critical", "cvss": 9.1},
  {"vuln_name": "Deprecated Interface",      "category": "WSTG-CONF-05",  "severity": "medium",   "cvss": 5.3},
  {"vuln_name": "Five Star Feedback",        "category": "WSTG-BUSL-01",  "severity": "medium",   "cvss": 5.0},
  {"vuln_name": "Login MC SafeSearch",       "category": "WSTG-INPV-05",  "severity": "critical", "cvss": 9.8},
  {"vuln_name": "CAPTCHA Bypass",            "category": "WSTG-BUSL-07",  "severity": "medium",   "cvss": 5.0},
  {"vuln_name": "CSRF",                      "category": "WSTG-SESS-05",  "severity": "high",     "cvss": 8.0},
  {"vuln_name": "Database Schema",           "category": "WSTG-INPV-05",  "severity": "critical", "cvss": 9.8},
  {"vuln_name": "Forged Feedback",           "category": "WSTG-ATHZ-02",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Login Bender",              "category": "WSTG-INPV-05",  "severity": "critical", "cvss": 9.8},
  {"vuln_name": "Login Jim",                 "category": "WSTG-INPV-05",  "severity": "critical", "cvss": 9.8},
  {"vuln_name": "Manipulate Basket",         "category": "WSTG-BUSL-09",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Payback Time",              "category": "WSTG-BUSL-01",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Product Tampering",         "category": "WSTG-ATHZ-02",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Reset Jim Password",        "category": "WSTG-ATHN-09",  "severity": "high",     "cvss": 8.0},
  {"vuln_name": "Upload Size",               "category": "WSTG-BUSL-08",  "severity": "medium",   "cvss": 5.0},
  {"vuln_name": "Upload Type",               "category": "WSTG-BUSL-08",  "severity": "medium",   "cvss": 5.0},
  {"vuln_name": "XXE Data Access",           "category": "WSTG-INPV-07",  "severity": "high",     "cvss": 8.2},
  {"vuln_name": "Admin Registration",        "category": "WSTG-IDNT-02",  "severity": "critical", "cvss": 9.1},
  {"vuln_name": "Access Log",                "category": "WSTG-CONF-04",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Christmas Special",         "category": "WSTG-INPV-05",  "severity": "critical", "cvss": 9.8},
  {"vuln_name": "Easter Egg",                "category": "WSTG-CONF-04",  "severity": "medium",   "cvss": 5.3},
  {"vuln_name": "Expired Coupon",            "category": "WSTG-BUSL-01",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Forgotten Developer Backup","category": "WSTG-CONF-04",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Forgotten Sales Backup",    "category": "WSTG-CONF-04",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Misplaced Signature File",  "category": "WSTG-CONF-04",  "severity": "medium",   "cvss": 5.3},
  {"vuln_name": "NoSQL DoS",                 "category": "WSTG-INPV-05",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "NoSQL Exfiltration",        "category": "WSTG-INPV-05",  "severity": "critical", "cvss": 9.8},
  {"vuln_name": "Poison Null Byte",          "category": "WSTG-CONF-04",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Change Bender Password",    "category": "WSTG-ATHN-09",  "severity": "high",     "cvss": 8.0},
  {"vuln_name": "Cross Site Imaging",        "category": "WSTG-CLNT-07",  "severity": "medium",   "cvss": 5.3},
  {"vuln_name": "Deluxe Fraud",              "category": "WSTG-IDNT-02",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Email Leak",                "category": "WSTG-INPV-05",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Forged Review",             "category": "WSTG-ATHZ-02",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "Forged Signed JWT",         "category": "WSTG-CRYP-04",  "severity": "critical", "cvss": 9.8},
  {"vuln_name": "Multiple Likes",            "category": "WSTG-BUSL-07",  "severity": "medium",   "cvss": 5.0},
  {"vuln_name": "SSTi",                      "category": "WSTG-INPV-18",  "severity": "critical", "cvss": 9.8},
  {"vuln_name": "Supply Chain Attack",       "category": "WSTG-CONF-01",  "severity": "medium",   "cvss": 5.3},
  {"vuln_name": "Two Factor Authentication", "category": "WSTG-ATHN-11",  "severity": "high",     "cvss": 8.0},
  {"vuln_name": "Vulnerable Library",        "category": "WSTG-CONF-01",  "severity": "medium",   "cvss": 5.3},
  {"vuln_name": "Forged Coupon",             "category": "WSTG-BUSL-01",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "SSRF",                      "category": "WSTG-INPV-19",  "severity": "critical", "cvss": 9.0},
  {"vuln_name": "Allowlist Bypass",          "category": "WSTG-CLNT-04",  "severity": "medium",   "cvss": 5.4},
  {"vuln_name": "CSP Bypass",               "category": "WSTG-CLNT-12",  "severity": "high",     "cvss": 7.5},
  {"vuln_name": "NoSQL Manipulation",        "category": "WSTG-INPV-05",  "severity": "critical", "cvss": 9.8}
]
```

- [ ] **Step 2: Verify count**

```bash
python3 -c "import json; d=json.load(open('multi_agent_system/data/juice_shop_ground_truth.json')); print(f'{len(d)} entries')"
```

Expected: `57 entries`

- [ ] **Step 3: Commit**

```bash
git add multi_agent_system/data/juice_shop_ground_truth.json
git commit -m "data: add Juice Shop 57-entry ground truth seed file"
```

---

## Task 10: Frontend — Findings Validation UI

**Files:**
- Modify: `frontend/index.html`
- Modify: `frontend/js/app.js`

- [ ] **Step 1: Add findings validation panel to `index.html`**

Find the findings section in `index.html` (search for `monFindings` or the scan detail area). Add a new collapsible panel after the existing findings count display:

```html
<!-- Findings Validation Panel -->
<div id="findingsValidationPanel" style="display:none; margin-top:16px;">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
    <h3 style="margin:0; font-size:14px; color:var(--text-primary);">Finding Validation</h3>
    <span id="validationProgress" style="font-size:12px; color:var(--text-muted);"></span>
  </div>
  <div id="findingsList" style="max-height:400px; overflow-y:auto;"></div>
</div>
```

Add a "Validate Findings" button near the existing report download buttons:

```html
<button id="btnValidateFindings" class="btn btn-secondary" style="display:none" onclick="toggleFindingsPanel()">
  Validate Findings
</button>
```

- [ ] **Step 2: Add JS to `app.js`**

Add the following functions after the existing scan-related functions:

```javascript
// ── Findings Validation ───────────────────────────────────────────────────

let _findingsLoaded = false;

function toggleFindingsPanel() {
    const panel = document.getElementById('findingsValidationPanel');
    if (panel.style.display === 'none') {
        panel.style.display = 'block';
        if (!_findingsLoaded) loadFindings();
    } else {
        panel.style.display = 'none';
    }
}

async function loadFindings() {
    if (!currentJobId) return;
    const resp = await fetch(`${API_BASE}/scans/${currentJobId}/findings`);
    if (!resp.ok) return;
    const findings = await resp.json();
    renderFindingsList(findings);
    _findingsLoaded = true;
}

function renderFindingsList(findings) {
    const container = document.getElementById('findingsList');
    const total = findings.length;
    const reviewed = findings.filter(f => f.is_true_positive !== null).length;
    document.getElementById('validationProgress').textContent =
        `${reviewed}/${total} reviewed`;

    container.innerHTML = findings.map(f => {
        const sevColor = {critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e', info:'#6b7280'}[f.severity] || '#6b7280';
        const tpActive  = f.is_true_positive === true  ? 'background:#16a34a;color:#fff;' : '';
        const fpActive  = f.is_true_positive === false ? 'background:#dc2626;color:#fff;' : '';
        return `
        <div style="display:flex;align-items:center;gap:8px;padding:6px 4px;border-bottom:1px solid var(--border-color);" data-finding-id="${f.id}">
          <span style="font-size:10px;font-weight:700;color:${sevColor};min-width:56px;">${f.severity.toUpperCase()}</span>
          <span style="flex:1;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${f.title}">${f.title}</span>
          <button onclick="markFinding(${f.id}, true)"  style="font-size:11px;padding:2px 8px;border:1px solid #16a34a;border-radius:4px;cursor:pointer;${tpActive}">TP</button>
          <button onclick="markFinding(${f.id}, false)" style="font-size:11px;padding:2px 8px;border:1px solid #dc2626;border-radius:4px;cursor:pointer;${fpActive}">FP</button>
        </div>`;
    }).join('');
}

async function markFinding(findingId, isTP) {
    const token = localStorage.getItem('adminToken') || '';
    const resp = await fetch(`${API_BASE}/findings/${findingId}/validate`, {
        method: 'POST',
        headers: {'Content-Type':'application/json', 'X-Admin-Token': token},
        body: JSON.stringify({is_true_positive: isTP}),
    });
    if (resp.ok) {
        _findingsLoaded = false;  // force reload
        loadFindings();
    } else {
        alert('Validation failed — check admin token');
    }
}
```

- [ ] **Step 3: Show the button when a scan is selected**

Find where `currentJobId` is set and the scan detail loads. Add:

```javascript
document.getElementById('btnValidateFindings').style.display = 'inline-block';
_findingsLoaded = false;
document.getElementById('findingsValidationPanel').style.display = 'none';
```

- [ ] **Step 4: Commit**

```bash
git add frontend/index.html frontend/js/app.js
git commit -m "feat(frontend): add TP/FP finding validation panel"
```

---

## Task 11: Rebuild + Smoke Test

- [ ] **Step 1: Run all unit tests**

```bash
pytest multi_agent_system/tests/test_precision_validation.py multi_agent_system/tests/test_vdp_generalization.py -v
```

Expected: all PASS

- [ ] **Step 2: Rebuild API container**

```bash
docker-compose build --no-cache api && docker-compose up -d api
```

- [ ] **Step 3: Verify new endpoints exist**

```bash
curl -s http://localhost:8000/api/ground-truth/juice-shop | jq
```

Expected: `[]` (empty, not yet imported)

```bash
curl -s http://localhost:8000/api/jobs/9/metrics | jq '.precision_status, .validated_count, .unreviewed_count'
```

Expected: `"pending_review"`, `0`, `<total findings count>`

- [ ] **Step 4: Import Juice Shop ground truth**

```bash
curl -s -X POST http://localhost:8000/api/ground-truth/juice-shop/import \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $(grep ADMIN_TOKEN .env | cut -d= -f2)" \
  -d @multi_agent_system/data/juice_shop_ground_truth.json | jq
```

Expected: `{"imported": 57, "target_profile": "juice-shop"}`

- [ ] **Step 5: Verify recall works**

```bash
curl -s http://localhost:8000/api/jobs/9/metrics | jq '.recall'
```

Expected: a number between 90 and 100 (not null)

- [ ] **Step 6: Validate one finding as TP, verify precision updates**

```bash
FINDING_ID=$(curl -s http://localhost:8000/api/scans/9/findings | jq '.[0].id')
curl -s -X POST http://localhost:8000/api/findings/${FINDING_ID}/validate \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $(grep ADMIN_TOKEN .env | cut -d= -f2)" \
  -d '{"is_true_positive": true}' | jq

curl -s http://localhost:8000/api/jobs/9/metrics | jq '.precision, .precision_status, .validated_count'
```

Expected: `100.0`, `"partial"`, `1`

- [ ] **Step 7: Final commit**

```bash
git add .
git commit -m "test: smoke test precision validation end-to-end"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| `GroundTruthEntry` DB table | Task 1 |
| `Finding.is_true_positive` + `validation_notes` | Task 2 |
| Remove hardcoded dicts, new precision/recall | Task 3 |
| `POST /api/findings/{id}/validate` | Task 5 |
| `POST /api/jobs/{id}/findings/validate-bulk` | Task 5 |
| Ground truth CRUD + import | Task 4 |
| `GET /api/scans/{id}/metrics` new fields | Task 6 |
| Frontend TP/FP buttons | Task 10 |
| `precision: null` when unreviewed | Task 3 + Task 6 |
| Hardcoded dicts removed | Task 3 |
| No existing functionality broken | Task 11 |

**Placeholder scan:** None found.

**Type consistency:** `calculate_precision` returns `Optional[float]` throughout Tasks 3, 6. `GroundTruthEntry` is imported from `multi_agent_system.models.ground_truth` consistently in Tasks 1, 3, 4. `_matches(finding, gt)` defined in Task 3 and only called internally.
