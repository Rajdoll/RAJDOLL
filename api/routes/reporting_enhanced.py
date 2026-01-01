from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response
from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Job, Finding, AgentEvent
import json
from datetime import datetime

router = APIRouter()

# CVSS severity mapping
CVSS_SCORES = {
    "critical": {"score": 9.5, "rating": "CRITICAL"},
    "high": {"score": 7.5, "rating": "HIGH"},
    "medium": {"score": 5.0, "rating": "MEDIUM"},
    "low": {"score": 2.5, "rating": "LOW"},
    "info": {"score": 0.0, "rating": "INFORMATIONAL"}
}

# Remediation templates
REMEDIATION_TEMPLATES = {
    "WSTG-INPV": {
        "xss": {
            "title": "Cross-Site Scripting (XSS)",
            "remediation": """
**Immediate Actions:**
1. Implement output encoding for all user-controlled data
2. Use Content Security Policy (CSP) headers
3. Enable HttpOnly and Secure flags on cookies
4. Sanitize input on both client and server side

**Long-term Solutions:**
- Adopt a templating system with auto-escaping (e.g., React, Angular)
- Implement a Web Application Firewall (WAF)
- Regular security code reviews and penetration testing

**References:**
- OWASP XSS Prevention Cheat Sheet
- CSP Implementation Guide
""",
            "code_example": """
# Python/Flask Example
from markupsafe import escape

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Escape output
    safe_query = escape(query)
    return render_template('results.html', query=safe_query)

# Add CSP Header
response.headers['Content-Security-Policy'] = "default-src 'self'"
"""
        },
        "sqli": {
            "title": "SQL Injection",
            "remediation": """
**Immediate Actions (CRITICAL):**
1. Use parameterized queries/prepared statements IMMEDIATELY
2. Never concatenate user input into SQL queries
3. Apply principle of least privilege to database accounts
4. Disable detailed error messages in production

**Long-term Solutions:**
- Implement an ORM (SQLAlchemy, Django ORM, Entity Framework)
- Use stored procedures with parameterized inputs
- Implement input validation with allowlists
- Regular database security audits
- Enable database activity monitoring

**References:**
- OWASP SQL Injection Prevention Cheat Sheet
- CWE-89: SQL Injection
""",
            "code_example": """
# VULNERABLE CODE (DO NOT USE):
query = "SELECT * FROM users WHERE id = " + user_input

# SECURE CODE (USE THIS):
# Python with SQLAlchemy
from sqlalchemy import text
stmt = text("SELECT * FROM users WHERE id = :user_id")
result = conn.execute(stmt, {"user_id": user_input})

# Python with sqlite3
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
"""
        },
        "lfi": {
            "title": "Local File Inclusion (LFI)",
            "remediation": """
**Immediate Actions:**
1. Implement strict allowlist for file paths
2. Never use user input directly in file system operations
3. Disable PHP allow_url_include if applicable
4. Chroot or jail the application

**Long-term Solutions:**
- Use indirect reference maps (IDs instead of filenames)
- Implement proper access controls
- Regular file system audits
- Security-focused code reviews

**Code Example:**
```python
# SECURE: Use allowlist
ALLOWED_FILES = {
    'home': '/var/www/pages/home.html',
    'about': '/var/www/pages/about.html'
}

file_id = request.args.get('page')
if file_id in ALLOWED_FILES:
    with open(ALLOWED_FILES[file_id], 'r') as f:
        content = f.read()
```
"""
        }
    },
    "WSTG-ATHN": {
        "default": {
            "title": "Authentication Weakness",
            "remediation": """
**Immediate Actions:**
1. Implement HTTPS for all authentication endpoints
2. Add CSRF tokens to all forms
3. Implement secure session management
4. Enable multi-factor authentication (MFA)

**Long-term Solutions:**
- Use established authentication libraries (Passport.js, OAuth 2.0)
- Implement account lockout after failed attempts
- Use bcrypt/Argon2 for password hashing
- Regular security audits of authentication flow
"""
        }
    },
    "WSTG-CLNT": {
        "default": {
            "title": "Client-Side Security Issue",
            "remediation": """
**Immediate Actions:**
1. Implement X-Frame-Options: DENY or SAMEORIGIN
2. Add Content-Security-Policy header
3. Enable X-Content-Type-Options: nosniff
4. Implement Referrer-Policy

**Example Headers:**
```
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
```
"""
        }
    }
}


def get_remediation(category: str, title: str, evidence: dict) -> dict:
    """Generate contextual remediation guidance"""
    cat_remediations = REMEDIATION_TEMPLATES.get(category, {})
    
    # Try to match specific vulnerability type
    title_lower = title.lower()
    if "xss" in title_lower:
        return cat_remediations.get("xss", cat_remediations.get("default", {}))
    elif "sql" in title_lower or "sqli" in title_lower:
        return cat_remediations.get("sqli", cat_remediations.get("default", {}))
    elif "lfi" in title_lower or "file inclusion" in title_lower:
        return cat_remediations.get("lfi", cat_remediations.get("default", {}))
    else:
        return cat_remediations.get("default", {})


def calculate_risk_score(findings: list) -> dict:
    """Calculate overall risk score and breakdown"""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_score = 0.0
    
    for f in findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total_score += CVSS_SCORES.get(sev, {"score": 0})["score"]
    
    # Weighted risk score (0-100)
    risk_score = min(100, (
        severity_counts["critical"] * 20 +
        severity_counts["high"] * 10 +
        severity_counts["medium"] * 5 +
        severity_counts["low"] * 2 +
        severity_counts["info"] * 0.5
    ))
    
    risk_level = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 30 else "LOW"
    
    return {
        "score": round(risk_score, 1),
        "level": risk_level,
        "severity_breakdown": severity_counts,
        "average_cvss": round(total_score / max(len(findings), 1), 1)
    }


@router.get("/scans/{job_id}/report/enhanced")
def get_enhanced_report(job_id: int):
    with get_db() as db:
        job = db.query(Job).get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        findings = db.query(Finding).filter(Finding.job_id == job_id).order_by(Finding.severity.desc(), Finding.created_at.desc()).all()
        events = db.query(AgentEvent).join(AgentEvent.job_agent).filter(AgentEvent.job_agent.has(job_id=job_id)).order_by(AgentEvent.created_at.asc()).all()
        
        # Group findings by category and severity
        findings_by_category = {}
        findings_by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        
        for f in findings:
            cat = f.category or "GENERAL"
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            
            if cat not in findings_by_category:
                findings_by_category[cat] = []
            findings_by_category[cat].append(f)
            
            findings_by_severity.get(sev.lower(), []).append(f)
        
        # Calculate risk
        findings_data = [{
            "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "category": f.category,
            "title": f.title
        } for f in findings]
        
        risk_assessment = calculate_risk_score(findings_data)
        
        # Build report
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("COMPREHENSIVE WEB SECURITY ASSESSMENT REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Target: {job.target}")
        report_lines.append(f"Scan ID: {job.id}")
        report_lines.append(f"Status: {job.status.value if hasattr(job.status, 'value') else str(job.status)}")
        report_lines.append(f"Started: {job.created_at}")
        report_lines.append(f"Completed: {job.updated_at}")
        report_lines.append("")
        
        # Executive Summary
        report_lines.append("=" * 80)
        report_lines.append("EXECUTIVE SUMMARY")
        report_lines.append("=" * 80)
        report_lines.append(f"Overall Risk Level: {risk_assessment['level']}")
        report_lines.append(f"Risk Score: {risk_assessment['score']}/100")
        report_lines.append(f"Average CVSS: {risk_assessment['average_cvss']}")
        report_lines.append("")
        report_lines.append("Findings Breakdown:")
        for sev, count in risk_assessment['severity_breakdown'].items():
            if count > 0:
                report_lines.append(f"  {sev.upper()}: {count}")
        report_lines.append("")
        
        # Critical & High Findings (Priority Actions)
        critical_high = findings_by_severity.get("critical", []) + findings_by_severity.get("high", [])
        if critical_high:
            report_lines.append("=" * 80)
            report_lines.append("PRIORITY ACTION ITEMS (CRITICAL & HIGH SEVERITY)")
            report_lines.append("=" * 80)
            for idx, f in enumerate(critical_high[:10], 1):
                report_lines.append(f"\n{idx}. [{f.severity.value if hasattr(f.severity, 'value') else str(f.severity)}] {f.title}")
                report_lines.append(f"   Category: {f.category}")
                report_lines.append(f"   Agent: {f.agent_name}")
                
                if f.evidence:
                    report_lines.append(f"   Evidence:")
                    report_lines.append(f"   ```json")
                    report_lines.append(f"   {json.dumps(f.evidence, indent=2)}")
                    report_lines.append(f"   ```")
                
                # Add remediation
                remediation = get_remediation(f.category, f.title, f.evidence or {})
                if remediation:
                    report_lines.append(f"\n   REMEDIATION:")
                    report_lines.append(f"   {remediation.get('remediation', 'See OWASP guidelines')}")
                    if remediation.get('code_example'):
                        report_lines.append(f"\n   CODE EXAMPLE:")
                        report_lines.append(f"   ```")
                        report_lines.append(f"   {remediation['code_example']}")
                        report_lines.append(f"   ```")
                
                report_lines.append("-" * 80)
        
        # Detailed Findings by Category
        report_lines.append("\n" + "=" * 80)
        report_lines.append("DETAILED FINDINGS BY CATEGORY")
        report_lines.append("=" * 80)
        
        for category in sorted(findings_by_category.keys()):
            cat_findings = findings_by_category[category]
            report_lines.append(f"\n## {category} ({len(cat_findings)} findings)")
            report_lines.append("-" * 80)
            
            for f in cat_findings:
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                cvss_info = CVSS_SCORES.get(sev.lower(), {"score": 0, "rating": "UNKNOWN"})
                
                report_lines.append(f"\n### {f.title}")
                report_lines.append(f"Severity: {sev.upper()} (CVSS {cvss_info['score']})")
                report_lines.append(f"Agent: {f.agent_name}")
                report_lines.append(f"Detected: {f.created_at}")
                
                if f.details:
                    report_lines.append(f"Details: {f.details}")
                
                if f.evidence:
                    report_lines.append(f"\nEvidence:")
                    report_lines.append("```json")
                    report_lines.append(json.dumps(f.evidence, indent=2))
                    report_lines.append("```")
                
                # Add remediation for MEDIUM+ findings
                if sev.lower() in ["critical", "high", "medium"]:
                    remediation = get_remediation(f.category, f.title, f.evidence or {})
                    if remediation:
                        report_lines.append(f"\n🛠️  REMEDIATION:")
                        report_lines.append(f"{remediation.get('remediation', 'See OWASP guidelines')}")
                        if remediation.get('code_example'):
                            report_lines.append(f"\n📝 CODE EXAMPLE:")
                            report_lines.append(f"```")
                            report_lines.append(f"{remediation['code_example']}")
                            report_lines.append(f"```")
                
                report_lines.append("")
        
        # Attack Surface Summary
        report_lines.append("\n" + "=" * 80)
        report_lines.append("ATTACK SURFACE SUMMARY")
        report_lines.append("=" * 80)
        
        # Extract key metrics from findings
        url_params = []
        forms_found = []
        subdomains = []
        
        for f in findings:
            if f.evidence:
                if "param_urls" in str(f.evidence):
                    url_params.extend(f.evidence.get("param_urls", [])[:5])
                if "forms" in str(f.evidence):
                    forms_found.extend(f.evidence.get("forms", [])[:3])
                if "subdomains" in str(f.evidence):
                    subdomains.extend(f.evidence.get("subdomains", [])[:5])
        
        report_lines.append(f"Parameterized URLs: {len(set(url_params))}")
        report_lines.append(f"Forms Identified: {len(forms_found)}")
        report_lines.append(f"Subdomains Found: {len(set(subdomains))}")
        report_lines.append("")
        
        # Scan Timeline
        report_lines.append("=" * 80)
        report_lines.append("SCAN TIMELINE")
        report_lines.append("=" * 80)
        key_events = [e for e in events if e.level in ['info', 'warning', 'error']][:20]
        for evt in key_events:
            agent_name = evt.job_agent.agent_name if evt.job_agent else "Unknown"
            report_lines.append(f"[{evt.created_at}] {agent_name}: {evt.message}")
        report_lines.append("")
        
        # Recommendations
        report_lines.append("=" * 80)
        report_lines.append("RECOMMENDATIONS")
        report_lines.append("=" * 80)
        
        if risk_assessment['severity_breakdown']['critical'] > 0:
            report_lines.append("⚠️  CRITICAL: Immediate action required on critical vulnerabilities")
        if risk_assessment['severity_breakdown']['high'] > 0:
            report_lines.append("⚠️  Address all HIGH severity findings within 7 days")
        if risk_assessment['severity_breakdown']['medium'] > 0:
            report_lines.append("⚡ Plan remediation for MEDIUM severity findings within 30 days")
        
        report_lines.append("\nGeneral Security Recommendations:")
        report_lines.append("1. Implement a Web Application Firewall (WAF)")
        report_lines.append("2. Enable security headers (CSP, HSTS, X-Frame-Options)")
        report_lines.append("3. Regular security testing and code reviews")
        report_lines.append("4. Implement security monitoring and logging")
        report_lines.append("5. Keep all dependencies and frameworks updated")
        report_lines.append("6. Conduct security awareness training for developers")
        report_lines.append("")
        
        report_lines.append("=" * 80)
        report_lines.append("END OF REPORT")
        report_lines.append("=" * 80)
        
        report_content = "\n".join(report_lines)
        
        return Response(content=report_content, media_type="text/plain", headers={
            "Content-Disposition": f"attachment; filename=security_report_job_{job_id}.txt"
        })
