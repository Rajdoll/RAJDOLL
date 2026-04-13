"""
PDF Report Generation Endpoint
Provides PDF download functionality for completed scans.
"""
from __future__ import annotations

import io
import json
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, JSONResponse
from typing import Dict, Any, List

from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Job, Finding, JobAgent, SharedContext

import markdown as _markdown
from markupsafe import Markup


def _md(text) -> Markup:
    """Convert markdown text to safe HTML for Jinja2 templates.

    Input must be trusted (internal LLM/KB output only — not user HTTP input).
    """
    if not text:
        return Markup("")
    return Markup(_markdown.markdown(str(text), extensions=["nl2br"]))


router = APIRouter()

_TEMPLATE_PATH = Path(__file__).parent.parent.parent / "multi_agent_system" / "templates" / "report.html.j2"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _normalize_severity(sev: str) -> str:
    s = (sev or "info").upper()
    return "INFO" if s in ("INFORMATIONAL", "INFORMATIONAL ") else s


def _format_evidence(evidence) -> str:
    if evidence is None:
        return "No evidence recorded."
    if isinstance(evidence, dict):
        # Remove internal confidence metadata from display
        display = {k: v for k, v in evidence.items() if not k.startswith("_")}
        try:
            text = json.dumps(display, indent=2, ensure_ascii=False)
        except Exception:
            text = str(display)
    else:
        try:
            text = json.dumps(evidence, indent=2, ensure_ascii=False)
        except Exception:
            text = str(evidence)
    return text[:2000] + ("\n… (truncated)" if len(text) > 2000 else "")


def _scan_duration(job: Job) -> str:
    start = job.started_at or job.created_at   # prefer actual start time
    end = job.updated_at
    if start and end:
        delta = (end - start).total_seconds()
        h, rem = divmod(int(delta), 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}h {m}m {s}s"
        return f"{m}m {s}s"
    return "N/A"


def _agent_duration(agent: JobAgent) -> str:
    if agent.started_at and agent.finished_at:
        delta = (agent.finished_at - agent.started_at).total_seconds()
        if delta < 1:
            return "< 1s"
        m, s = divmod(int(delta), 60)
        if m == 0:
            return f"{s}s"
        return f"{m}m {s}s"
    return "—"


def _render_pdf(job_id: int) -> bytes:
    """Load data from DB, render report.html.j2 via Jinja2, convert to PDF."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    try:
        from weasyprint import HTML as WeasyprintHTML
    except ImportError as e:
        raise ImportError(
            "WeasyPrint not installed. "
            "Install: pip install weasyprint && apt-get install libpango-1.0-0 libpangocairo-1.0-0"
        ) from e

    with get_db() as db:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise ValueError(f"Job {job_id} not found")

        findings_db = (
            db.query(Finding)
            .filter(Finding.job_id == job_id)
            .all()
        )
        agents_db = db.query(JobAgent).filter(JobAgent.job_id == job_id).all()

        # Load final_analysis from SharedContext
        ctx = (
            db.query(SharedContext)
            .filter(SharedContext.job_id == job_id, SharedContext.key == "final_analysis")
            .one_or_none()
        )
        final_analysis = ""
        if ctx and ctx.value:
            if isinstance(ctx.value, str):
                final_analysis = ctx.value
            elif isinstance(ctx.value, dict):
                final_analysis = ctx.value.get("text", "") or str(ctx.value)

        # Load OSINT data for out-of-scope findings
        osint_ctx = (
            db.query(SharedContext)
            .filter(SharedContext.job_id == job_id, SharedContext.key == "osint")
            .one_or_none()
        )
        osint_data = osint_ctx.value if osint_ctx and osint_ctx.value else {}

    # Build findings list (normalized)
    findings: list[dict] = []
    for f in findings_db:
        sev = _normalize_severity(f.severity.value if hasattr(f.severity, "value") else str(f.severity))
        findings.append({
            "id": f.id,
            "category": f.category or "Uncategorized",
            "title": f.title or "Untitled",
            "severity": sev,
            "agent_name": f.agent_name or "Unknown",
            "evidence": _format_evidence(f.evidence),
            "details": f.details,
            # Enrichment columns
            "explanation": f.explanation or "",
            "remediation": f.remediation or "",
            "cwe_id": f.cwe_id or "",
            "wstg_id": f.wstg_id or "",
            "cvss_score_v4": f.cvss_score_v4,
            "references": f.references or [],
            "enrichment_source": f.enrichment_source or "fallback",
        })

    # Sort by severity
    findings_sorted = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 999))

    # Add RAJDOLL reference numbers after sort
    for idx, f in enumerate(findings_sorted, 1):
        f["ref"] = f"RAJDOLL-{idx:04d}"

    # Severity counts
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings_sorted:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    # Top findings (critical + high, max 5)
    top_findings = [f for f in findings_sorted if f["severity"] in ("CRITICAL", "HIGH")][:5]

    # WSTG categories (from wstg_id — extract category prefix)
    wstg_categories: dict[str, int] = {}
    for f in findings_sorted:
        wid = f["wstg_id"]
        if wid:
            # "WSTG-INPV-05" → "WSTG-INPV"
            parts = wid.split("-")
            cat = "-".join(parts[:2]) if len(parts) >= 2 else wid
        else:
            cat = "Uncategorized"
        wstg_categories[cat] = wstg_categories.get(cat, 0) + 1

    # Enrichment stats
    enrichment_stats: dict[str, int] = {"static_kb": 0, "llm": 0, "fallback": 0}
    for f in findings_sorted:
        src = f["enrichment_source"]
        enrichment_stats[src] = enrichment_stats.get(src, 0) + 1

    # Agents list with duration
    agents_list = [
        {
            "agent_name": a.agent_name,
            "status": a.status.value if hasattr(a.status, "value") else str(a.status),
            "duration": _agent_duration(a),
        }
        for a in agents_db
    ]

    # Scope enforcement: whitelist and out-of-scope OSINT findings
    from multi_agent_system.core.security_guards import security_guard
    scope_whitelist = sorted(security_guard.whitelist_domains)

    oos_findings: dict = {"subdomains": [], "emails": [], "urls": []}
    if isinstance(osint_data, dict):
        findings_data = osint_data.get("findings", osint_data)
        oos_findings["subdomains"] = findings_data.get("subdomains_out_of_scope", [])
        oos_findings["emails"] = findings_data.get("emails_out_of_scope", [])
        for field in ("exposed_documents", "admin_panels", "directory_listings",
                      "backup_files", "pastebin_mentions"):
            for url in findings_data.get(f"{field}_out_of_scope", []):
                oos_findings["urls"].append({
                    "url": url,
                    "category": field.replace("_", " ").title()
                })
    has_oos = any(oos_findings[k] for k in oos_findings)

    # Render Jinja2 template
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_PATH.parent)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["md"] = _md
    template = env.get_template(_TEMPLATE_PATH.name)
    html_content = template.render(
        job_id=job_id,
        target=job.target,
        scan_date=job.created_at.strftime("%Y-%m-%d %H:%M UTC") if job.created_at else "N/A",
        scan_duration=_scan_duration(job),
        total_findings=len(findings_sorted),
        final_analysis=final_analysis,
        findings=findings_sorted,
        top_findings=top_findings,
        sev_counts=sev_counts,
        wstg_categories=wstg_categories,
        enrichment_stats=enrichment_stats,
        agents=agents_list,
        scope_whitelist=scope_whitelist,
        oos_findings=oos_findings if has_oos else None,
    )

    # Convert to PDF
    pdf_file = io.BytesIO()
    WeasyprintHTML(string=html_content).write_pdf(pdf_file)
    return pdf_file.getvalue()


@router.get("/scans/{job_id}/report")
async def download_json_report(job_id: int):
    """Download JSON report for a completed scan."""
    with get_db() as db:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise HTTPException(404, f"Job {job_id} not found")

        findings_db = db.query(Finding).filter(Finding.job_id == job_id).all()
        agents = db.query(JobAgent).filter(JobAgent.job_id == job_id).all()

    findings_list = []
    for f in findings_db:
        sev = _normalize_severity(f.severity.value if hasattr(f.severity, "value") else str(f.severity))
        evidence = f.evidence
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except Exception:
                pass

        findings_list.append({
            "category": f.category or "N/A",
            "title": f.title or "Untitled",
            "severity": sev,
            "evidence": evidence,
            "details": f.details,
            "explanation": f.explanation,
            "remediation": f.remediation,
            "cwe_id": f.cwe_id,
            "wstg_id": f.wstg_id,
            "cvss_score_v4": f.cvss_score_v4,
            "references": f.references,
            "enrichment_source": f.enrichment_source,
        })

    report = {
        "job_id": job_id,
        "target": job.target,
        "status": job.status.value if hasattr(job.status, "value") else str(job.status),
        "scan_duration": _scan_duration(job),
        "findings": findings_list,
        "agents_executed": len([a for a in agents if (a.status.value if hasattr(a.status, "value") else str(a.status)) == "completed"]),
        "total_agents": len(agents),
    }
    return JSONResponse(content=report)


@router.get("/scans/{job_id}/report/pdf")
async def download_pdf_report(job_id: int):
    """Generate and download a professional PDF report for a completed scan."""
    try:
        pdf_bytes = _render_pdf(job_id)
    except ValueError as e:
        raise HTTPException(404, str(e))
    except ImportError as e:
        raise HTTPException(500, str(e))
    except Exception as e:
        raise HTTPException(500, f"PDF generation failed: {e}")

    filename = f"RAJDOLL_Report_Job{job_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/pdf",
        },
    )
