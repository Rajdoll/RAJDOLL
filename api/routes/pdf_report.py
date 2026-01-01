"""
PDF Report Generation Endpoint
Provides PDF download functionality for completed scans
"""
from __future__ import annotations

import io
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, JSONResponse
from typing import Dict, Any, List

from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Job, Finding, JobAgent


router = APIRouter()


class SimplePDFGenerator:
    """Simple HTML-based PDF generator using WeasyPrint (lazy import)"""
    
    SEVERITY_COLORS = {
        "CRITICAL": "#d32f2f",
        "HIGH": "#f57c00",
        "MEDIUM": "#fbc02d",
        "LOW": "#388e3c",
        "INFO": "#1976d2"
    }
    
    @staticmethod
    def generate_html(target: str, findings: List[Dict], scan_stats: Dict) -> str:
        """Generate HTML content from scan data"""
        
        # Normalize severity to uppercase (database stores lowercase like 'info', 'critical')
        for f in findings:
            sev = f.get("severity", "info")
            # Map 'info' -> 'INFO', 'critical' -> 'CRITICAL', etc.
            f["severity"] = sev.upper() if sev.upper() != 'INFORMATIONAL' else 'INFO'
            # Also handle 'informational' -> 'INFO'
            if f["severity"] == 'INFORMATIONAL':
                f["severity"] = 'INFO'
        
        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings_sorted = sorted(
            findings,
            key=lambda x: severity_order.get(x.get("severity", "INFO"), 999)
        )
        
        # Count by severity
        sev_counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>RAJDOLL Security Report</title>
    <style>
        @page {{
            margin: 2cm;
            size: A4;
            @top-center {{
                content: "RAJDOLL Security Assessment";
                font-size: 9pt;
                color: #666;
            }}
            @bottom-center {{
                content: "Page " counter(page);
                font-size: 9pt;
                color: #999;
            }}
        }}
        
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            font-size: 10pt;
        }}
        
        .cover {{
            text-align: center;
            margin-top: 40%;
            page-break-after: always;
        }}
        
        .cover h1 {{
            font-size: 32pt;
            color: #1976d2;
            margin-bottom: 20px;
        }}
        
        h1 {{
            color: #1976d2;
            font-size: 20pt;
            border-bottom: 2px solid #1976d2;
            padding-bottom: 5px;
            margin-top: 20px;
        }}
        
        h2 {{
            color: #424242;
            font-size: 16pt;
            margin-top: 15px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin: 20px 0;
        }}
        
        .stat-box {{
            background: #f5f5f5;
            padding: 15px;
            text-align: center;
            border-radius: 5px;
        }}
        
        .stat-value {{
            font-size: 28pt;
            font-weight: bold;
        }}
        
        .stat-label {{
            font-size: 10pt;
            color: #666;
            margin-top: 5px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        
        th {{
            background: #1976d2;
            color: white;
            padding: 8px;
            text-align: left;
        }}
        
        td {{
            padding: 6px;
            border-bottom: 1px solid #ddd;
        }}
        
        .finding {{
            border: 1px solid #ddd;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
            page-break-inside: avoid;
        }}
        
        .finding-title {{
            font-weight: bold;
            font-size: 12pt;
            margin-bottom: 10px;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            font-size: 9pt;
        }}
        
        .code {{
            background: #f5f5f5;
            border-left: 3px solid #1976d2;
            padding: 10px;
            font-family: 'Courier New', monospace;
            font-size: 9pt;
            overflow-wrap: break-word;
            word-wrap: break-word;
        }}
    </style>
</head>
<body>
    <div class="cover">
        <h1>🛡️ RAJDOLL</h1>
        <p style="font-size: 16pt; color: #666;">Multi-Agent Security Assessment</p>
        <p style="margin-top: 40px;"><strong>Target:</strong> {target}</p>
        <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
        <p><strong>Total Findings:</strong> {len(findings)}</p>
    </div>
    
    <h1>Executive Summary</h1>
    <p>This report presents findings from RAJDOLL, a multi-agent vulnerability scanner based on OWASP WSTG 4.2.</p>
    <p><strong>Target:</strong> {target}</p>
    <p><strong>Scan Duration:</strong> {scan_stats.get('duration', 'N/A')}</p>
    
    <h2>Findings Overview</h2>
    <div class="stats">
        <div class="stat-box">
            <div class="stat-value" style="color: {SimplePDFGenerator.SEVERITY_COLORS['CRITICAL']}">{sev_counts.get('CRITICAL', 0)}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-box">
            <div class="stat-value" style="color: {SimplePDFGenerator.SEVERITY_COLORS['HIGH']}">{sev_counts.get('HIGH', 0)}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-box">
            <div class="stat-value" style="color: {SimplePDFGenerator.SEVERITY_COLORS['MEDIUM']}">{sev_counts.get('MEDIUM', 0)}</div>
            <div class="stat-label">Medium</div>
        </div>
    </div>
    
    <h1>Findings Summary</h1>
    <table>
        <tr>
            <th>#</th>
            <th>Category</th>
            <th>Title</th>
            <th>Severity</th>
        </tr>
"""
        
        for idx, f in enumerate(findings_sorted, 1):
            sev = f.get("severity", "INFO")
            color = SimplePDFGenerator.SEVERITY_COLORS.get(sev, "#999")
            html += f"""
        <tr>
            <td>{idx}</td>
            <td>{f.get('category', 'N/A')}</td>
            <td>{f.get('title', 'Untitled')}</td>
            <td><span style="color: {color}; font-weight: bold;">{sev}</span></td>
        </tr>
"""
        
        html += """
    </table>
    
    <h1>Detailed Findings</h1>
"""
        
        for idx, f in enumerate(findings_sorted, 1):
            sev = f.get("severity", "INFO")
            color = SimplePDFGenerator.SEVERITY_COLORS.get(sev, "#999")
            evidence = str(f.get('evidence', 'No evidence'))
            if len(evidence) > 500:
                evidence = evidence[:500] + "... (truncated)"
            
            html += f"""
    <div class="finding">
        <div>
            <span style="color: #999;">Finding #{idx}</span>
            <span class="severity-badge" style="background: {color}; float: right;">{sev}</span>
        </div>
        <div class="finding-title">{f.get('title', 'Untitled')}</div>
        <p><strong>Category:</strong> {f.get('category', 'N/A')}</p>
        <p><strong>Evidence:</strong></p>
        <div class="code">{evidence}</div>
        <p><strong>Recommendation:</strong></p>
        <p>{f.get('recommendation', 'No recommendation provided')}</p>
    </div>
"""
        
        html += f"""
    <div style="margin-top: 30px; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107;">
        <strong>⚠️ Disclaimer:</strong> This is an automated report. Verify findings manually before remediation.
    </div>
    <div style="text-align: center; margin-top: 20px; color: #999; font-size: 9pt;">
        <p>RAJDOLL Multi-Agent Security Scanner | OWASP WSTG 4.2 Compliant</p>
        <p>{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
    </div>
</body>
</html>
"""
        return html
    
    @staticmethod
    def html_to_pdf(html_content: str) -> bytes:
        """Convert HTML to PDF bytes using WeasyPrint (lazy import)"""
        try:
            from weasyprint import HTML
            pdf_file = io.BytesIO()
            HTML(string=html_content).write_pdf(pdf_file)
            return pdf_file.getvalue()
        except ImportError as e:
            raise ImportError(
                "WeasyPrint not installed or missing system dependencies. "
                "Install: apt-get install libpango-1.0-0 libpangocairo-1.0-0 "
                "libgdk-pixbuf2.0-0 libffi-dev libcairo2"
            ) from e


@router.get("/scans/{job_id}/report")
async def download_json_report(job_id: int):
    """Download JSON report"""
    with get_db() as db:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise HTTPException(404, f"Job {job_id} not found")
        
        findings_db = db.query(Finding).filter(Finding.job_id == job_id).all()
        agents = db.query(JobAgent).filter(JobAgent.job_id == job_id).all()
    
    findings_list = []
    for f in findings_db:
        evidence = f.evidence
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except:
                pass
        
        findings_list.append({
            "category": f.category or "N/A",
            "title": f.title or "Untitled",
            "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "evidence": evidence,
            "recommendation": f.details or "No recommendation"
        })
    
    scan_duration = "N/A"
    if job.updated_at and job.created_at:
        duration = (job.updated_at - job.created_at).total_seconds()
        scan_duration = f"{int(duration // 60)}m {int(duration % 60)}s"
    
    report = {
        "job_id": job_id,
        "target": job.target,
        "status": job.status.value if hasattr(job.status, 'value') else str(job.status),
        "scan_duration": scan_duration,
        "findings": findings_list,
        "agents_executed": len([a for a in agents if a.status.value == 'completed']),
        "total_agents": len(agents)
    }
    
    return JSONResponse(content=report)


@router.get("/scans/{job_id}/report/pdf")
async def download_pdf_report(job_id: int):
    """Generate and download PDF report"""
    with get_db() as db:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise HTTPException(404, f"Job {job_id} not found")
        
        findings_db = db.query(Finding).filter(Finding.job_id == job_id).all()
        agents = db.query(JobAgent).filter(JobAgent.job_id == job_id).all()
    
    findings_list = []
    for f in findings_db:
        evidence = f.evidence
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except:
                pass
        
        findings_list.append({
            "category": f.category or "N/A",
            "title": f.title or "Untitled",
            "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "evidence": evidence or "No evidence",
            "recommendation": f.details or "No recommendation"
        })
    
    scan_duration = "N/A"
    if job.updated_at and job.created_at:
        duration = (job.updated_at - job.created_at).total_seconds()
        scan_duration = f"{int(duration // 60)}m {int(duration % 60)}s"
    
    scan_stats = {
        "duration": scan_duration,
        "agents": len(agents)
    }
    
    try:
        html = SimplePDFGenerator.generate_html(job.target, findings_list, scan_stats)
        pdf_bytes = SimplePDFGenerator.html_to_pdf(html)
    except Exception as e:
        raise HTTPException(500, f"PDF generation failed: {str(e)}")
    
    filename = f"RAJDOLL_Report_Job{job_id}.pdf"
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/pdf"
        }
    )
