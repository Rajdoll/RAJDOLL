# Timing Accuracy Fixes — Design Spec

**Date:** 2026-04-13  
**Branch:** feat/scope-enforcement  
**Status:** Approved

---

## Problem Summary

The RAJDOLL PDF report contains inaccurate timing data with two distinct issues:

1. **Total scan duration is wrong** — `_scan_duration()` computes `job.updated_at - job.created_at`. `created_at` is set at `POST /api/scans` time (before Celery queuing), not when scanning actually begins. There is no `job.started_at` field.

2. **~23 minutes of orchestration overhead is invisible** — Sum of all 14 agent durations = ~30 minutes, but reported total = 53m 14s. The ~23-minute gap is real work (LLM planning, per-agent summarization, auto-login) that happens between agents and is captured in the total but attributed to no specific phase.

3. **Short-duration agents are misleading without context** — `WeakCryptographyAgent < 1s` and `ErrorHandlingAgent 1s` are correct (tools ran but completed fast on an HTTP-only target), and `ReportGenerationAgent < 1s` is by design (PDF generated on-demand). The report currently shows no explanation.

---

## Scope

Three files with logic changes + one template change + one DB migration:

| File | Change |
|------|--------|
| `multi_agent_system/models/models.py` | Add `started_at` column to `Job` |
| `multi_agent_system/orchestrator.py` | Set `started_at`; capture timing for 3 overhead phases |
| `api/routes/pdf_report.py` | Fix `_scan_duration()`; load `scan_timing` from SharedContext |
| `multi_agent_system/templates/report.html.j2` | Add Scan Timeline table; add agent notes column |

---

## Fix 1 — Add `job.started_at` and fix `_scan_duration()`

### Model (`models/models.py`)

Add nullable `started_at` column to `Job`:

```python
started_at: Mapped[Optional[datetime]] = Column(DateTime, nullable=True)
```

DB migration (run once, idempotent):
```sql
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS started_at TIMESTAMP;
```

### Orchestrator (`orchestrator.py`)

At the top of `run()`, immediately after `_update_job_status(JobStatus.running)`:

```python
with get_db() as db:
    job = db.query(Job).get(self.job_id)
    if job and not job.started_at:
        job.started_at = datetime.utcnow()
        db.commit()
```

### PDF Report (`api/routes/pdf_report.py`)

Update `_scan_duration()`:

```python
def _scan_duration(job: Job) -> str:
    start = job.started_at or job.created_at   # prefer actual start
    end = job.updated_at
    if start and end:
        delta = (end - start).total_seconds()
        h, rem = divmod(int(delta), 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}h {m}m {s}s"
        return f"{m}m {s}s"
    return "N/A"
```

---

## Fix 2 — Orchestration overhead tracking

### Data structure

`SharedContext["scan_timing"]` — dict written by orchestrator, read by PDF renderer:

```json
{
  "scan_started_at": "2026-04-13T03:45:10Z",
  "phases": [
    {"name": "Auto-login",        "duration_s": 45,   "detail": "Logged in as admin@juice-sh.op"},
    {"name": "LLM Planning",      "duration_s": 187,  "detail": "14 OWASP categories planned"},
    {"name": "Summarization",     "duration_s": 823,  "detail": "13 agents × avg 63s"},
    {"name": "Agent execution",   "duration_s": 1782, "detail": "Sum of all agent durations"}
  ],
  "total_overhead_s": 1412
}
```

### Orchestrator timing capture points

Three `t_start / t_end` pairs added in `orchestrator.run()`:

| Phase | Where |
|-------|-------|
| Auto-login | Wrap the `create_authenticated_session()` block |
| LLM Planning | Wrap the `future.result(timeout=300)` call |
| Summarization (cumulative) | Accumulate in `_summarize_agent_and_accumulate()` |

After all agents complete, write `SharedContext["scan_timing"]` with all captured data.

### PDF report loading (`pdf_report.py`)

In `_render_pdf()`, after loading OSINT data:

```python
timing_ctx = db.query(SharedContext).filter(
    SharedContext.job_id == job_id,
    SharedContext.key == "scan_timing"
).one_or_none()
scan_timing = timing_ctx.value if timing_ctx and timing_ctx.value else None
```

Pass `scan_timing=scan_timing` to `template.render()`.

---

## Fix 3 — Agent table notes in report

### Template change (`report.html.j2`)

In the Agents Executed table, add a "Note" column. Populate via a Jinja2 macro:

| Condition | Note shown |
|-----------|------------|
| `duration < 1s` AND agent = `ReportGenerationAgent` | `PDF rendered on-demand` |
| `duration < 1s` OR `duration ≤ 2s` | `Fast response — target-dependent` |
| otherwise | *(empty)* |

Duration threshold check is done in `pdf_report.py` helper `_agent_note(agent)` and passed to template as part of the agents list.

---

## Non-changes

- `should_run_tool()` — not touched. The comprehensive coverage in `set_tool_plan()` already guarantees all declared tools run. Priority fast-path (`_get_tool_info`) is an optimization, not a gate.
- `ADAPTIVE_MODE` — not changed.
- Agent `execute()` logic — not changed.

---

## Testing

| Test | Method |
|------|--------|
| `job.started_at` set correctly | Check DB after scan start via `GET /api/scans/{id}` |
| `_scan_duration()` uses `started_at` | Unit test with mock Job object |
| `scan_timing` written to SharedContext | Check after scan via `SharedContext` DB query |
| PDF renders timeline table | Download PDF from completed scan |
| Agent notes appear | Inspect PDF for WeakCryptographyAgent row |

---

## Migration safety

`ADD COLUMN IF NOT EXISTS` is non-destructive. Existing rows will have `started_at = NULL`; `_scan_duration()` falls back to `created_at` for those. No data loss.
