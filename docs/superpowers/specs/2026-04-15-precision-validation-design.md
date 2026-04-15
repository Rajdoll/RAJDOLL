# Design Spec: Precision Validation & Dynamic Ground Truth

**Date:** 2026-04-15  
**Status:** Draft  
**Scope:** Evaluation metrics — replace hardcoded ground truth with database-driven model, replace automated precision with manual TP/FP validation workflow

---

## 1. Problem Statement

The current `metrics.py` implementation has two critical academic weaknesses:

1. **Hardcoded ground truth**: `JUICE_SHOP_GROUND_TRUTH` and `DVWA_GROUND_TRUTH` are Python dicts embedded in source code. Any new target requires code changes. These dicts cannot represent the full set of real vulnerabilities in a target — only named challenge entries.

2. **Automated precision is methodologically wrong**: Precision is computed by matching findings against the hardcoded dict using keyword matching. This produces raw precision of 76.7% (56/73) — below the 90% thesis threshold — because real vulnerabilities that are not named challenges are misclassified as false positives. The "adjusted precision = 100%" in the evaluation report was a post-hoc manual correction with no formal system support.

**Root cause**: Precision cannot be computed automatically without human judgment. A tool cannot know whether a finding is a real vulnerability — only a domain expert reviewing each finding can determine that.

---

## 2. Design Goals

- Precision is computed from **manual TP/FP labels** set by the researcher after each scan
- Ground truth (for recall) is stored as **database records**, not Python code
- Ground truth entries are populated manually per target profile — no hardcoding
- The system works for any target (Juice Shop, WebGoat, VDP targets) without code changes
- Recall calculation continues to work automatically against DB-stored ground truth
- Existing scan and finding data is not broken

---

## 3. Architecture

### 3.1 New DB Table: `ground_truth_entries`

```sql
CREATE TABLE ground_truth_entries (
    id          SERIAL PRIMARY KEY,
    target_profile  VARCHAR(100) NOT NULL,  -- e.g. "juice-shop", "webgoat", "bssn"
    vuln_name       VARCHAR(200) NOT NULL,  -- e.g. "Login Admin"
    category        VARCHAR(50)  NOT NULL,  -- e.g. "WSTG-INPV-05"
    severity        VARCHAR(20)  NOT NULL,  -- critical/high/medium/low
    cvss            FLOAT,
    created_at      TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_gt_target ON ground_truth_entries(target_profile);
```

No `source_doc` field — all entries are treated as manually verified by the researcher.

### 3.2 Modified `Finding` Model

Add two nullable fields to the existing `findings` table:

```sql
ALTER TABLE findings ADD COLUMN is_true_positive BOOLEAN DEFAULT NULL;
ALTER TABLE findings ADD COLUMN validation_notes  TEXT    DEFAULT NULL;
```

- `NULL` = not yet reviewed  
- `TRUE` = researcher confirmed true positive  
- `FALSE` = researcher confirmed false positive  

### 3.3 Updated `GroundTruthManager`

Remove `JUICE_SHOP_GROUND_TRUTH` and `DVWA_GROUND_TRUTH` dicts entirely. Replace with DB query:

```python
class GroundTruthManager:
    def get_ground_truth(self, target_profile: str, db: Session) -> List[GroundTruthEntry]:
        return db.query(GroundTruthEntry)\
                 .filter(GroundTruthEntry.target_profile == target_profile)\
                 .all()
```

Target profile is derived from the job's target URL:
- `juice-shop:3000` → `"juice-shop"`
- `webgoat:8080` → `"webgoat"`
- `target.bssn.go.id` → `"bssn"` (or full domain)

### 3.4 Updated Precision Calculation

```python
def calculate_precision(self, findings: List[Finding]) -> float:
    validated = [f for f in findings if f.is_true_positive is not None]
    if not validated:
        return None  # Not yet reviewed — do not report a number
    tp = sum(1 for f in validated if f.is_true_positive)
    fp = sum(1 for f in validated if not f.is_true_positive)
    return round((tp / (tp + fp)) * 100, 2) if (tp + fp) > 0 else 0.0
```

Returns `None` when no findings have been reviewed — the API and frontend show `"pending review"` instead of a number.

### 3.5 Recall Calculation (unchanged logic, new data source)

```python
def calculate_recall(self, findings: List[Finding], ground_truth: List[GroundTruthEntry]) -> float:
    detected = set()
    for f in findings:
        for gt in ground_truth:
            if self._matches(f, gt):
                detected.add(gt.id)
    return round((len(detected) / len(ground_truth)) * 100, 2) if ground_truth else None
```

`_matches()` uses the same category + keyword logic as before — only the data source changes.

---

## 4. API Endpoints

### 4.1 Validate a Finding (set TP/FP)

```
POST /api/findings/{finding_id}/validate
Body: { "is_true_positive": true, "notes": "optional text" }
Response: 200 { "finding_id": 5, "is_true_positive": true }
```

Auth: requires `ADMIN_TOKEN` header (same as other admin endpoints).

### 4.2 Bulk Validate

```
POST /api/jobs/{job_id}/findings/validate-bulk
Body: { "validations": [{"finding_id": 1, "is_true_positive": true}, ...] }
```

For marking many findings at once after a scan review session.

### 4.3 Ground Truth Management

```
GET    /api/ground-truth/{target_profile}           # list entries
POST   /api/ground-truth/{target_profile}           # add one entry
POST   /api/ground-truth/{target_profile}/import    # bulk import from JSON array
DELETE /api/ground-truth/{target_profile}/{id}      # remove entry
```

Import format (JSON array):
```json
[
  {"vuln_name": "Login Admin",  "category": "WSTG-INPV-05", "severity": "critical", "cvss": 9.8},
  {"vuln_name": "DOM XSS",      "category": "WSTG-CLNT-01", "severity": "high",     "cvss": 7.5}
]
```

### 4.4 Updated Metrics Endpoint

```
GET /api/scans/{job_id}/metrics
```

Response adds new fields:

```json
{
  "precision": 100.0,
  "precision_status": "validated",     // "validated" | "pending_review" | "partial"
  "validated_count": 91,
  "unreviewed_count": 12,
  "recall": 98.2,
  "f1_score": 99.1
}
```

---

## 5. Frontend Changes

In the findings list view, add per-finding validation controls:

```
[CRITICAL] SQL Injection at /rest/user/login     [✓ TP] [✗ FP]
[HIGH]     IDOR at /api/users/{id}               [✓ TP] [✗ FP]
[INFO]     Recon analytic summary                [✓ TP] [✗ FP]   ← researcher marks FP
```

- Buttons call `POST /api/findings/{id}/validate`
- Selected state persists (green TP / red FP)
- Metrics panel updates in real-time via WebSocket or polling

---

## 6. Migration Plan

1. Run `ALTER TABLE` SQL for `findings` — non-destructive (nullable columns)
2. Create `ground_truth_entries` table
3. Remove `JUICE_SHOP_GROUND_TRUTH` and `DVWA_GROUND_TRUTH` dicts from `metrics.py`
4. Populate Juice Shop ground truth via `POST /api/ground-truth/juice-shop/import` with a JSON file (57 entries from the automatable challenge list) — **this is a one-time data operation, not code**
5. Existing findings remain unreviewed (`is_true_positive = NULL`) until researcher validates

---

## 7. Out of Scope

- Automated TP/FP classification (this is intentionally manual)
- PDF parsing to auto-extract ground truth (PDF is researcher's reference only)
- Ground truth versioning (one profile per target is sufficient)
- Exporting ground truth (not needed for thesis)

---

## 8. Acceptance Criteria

- [ ] `POST /api/findings/{id}/validate` correctly sets `is_true_positive`
- [ ] `GET /api/scans/{job_id}/metrics` returns `precision: null` when no findings reviewed
- [ ] `GET /api/scans/{job_id}/metrics` returns correct precision after partial/full validation
- [ ] `GET /api/scans/{job_id}/metrics` returns correct recall against DB ground truth
- [ ] Ground truth import via JSON works for Juice Shop 57-entry dataset
- [ ] Hardcoded `JUICE_SHOP_GROUND_TRUTH` and `DVWA_GROUND_TRUTH` removed from codebase
- [ ] Frontend shows TP/FP buttons per finding, persists state
- [ ] No existing agent, scan, or report functionality broken
