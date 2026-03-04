"""
OWASP WSTG v4.2 Compliant Report Generator
Generates professional security assessment reports with PDF export
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import subprocess


class OWASPReportGenerator:
    """Generate OWASP WSTG v4.2 compliant security reports"""
    
    # OWASP WSTG Category Mapping
    OWASP_CATEGORIES = {
        "WSTG-INFO": "Information Gathering",
        "WSTG-CONF": "Configuration and Deployment Management Testing",
        "WSTG-IDNT": "Identity Management Testing",
        "WSTG-ATHN": "Authentication Testing",
        "WSTG-ATHZ": "Authorization Testing",
        "WSTG-SESS": "Session Management Testing",
        "WSTG-INPV": "Input Validation Testing",
        "WSTG-ERRH": "Error Handling Testing",
        "WSTG-CRYP": "Cryptography Testing",
        "WSTG-BUSL": "Business Logic Testing",
        "WSTG-CLNT": "Client-side Testing",
        "WSTG-APIT": "API Testing",
    }
    
    # CVSS v3.1 Severity Ratings
    SEVERITY_COLORS = {
        "critical": "#D32F2F",  # Red 700
        "high": "#F57C00",      # Orange 700
        "medium": "#FBC02D",    # Yellow 700
        "low": "#388E3C",       # Green 700
        "info": "#1976D2",      # Blue 700
    }
    
    def __init__(self, db_connection):
        """Initialize report generator with database connection"""
        self.db = db_connection
    
    def generate_report(self, job_id: int, output_dir: str = "reports") -> Dict[str, str]:
        """
        Generate complete OWASP WSTG compliant report
        
        Returns:
            dict: {"markdown": path, "json": path, "pdf": path}
        """
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Fetch job data
        job_data = self._fetch_job_data(job_id)
        findings = self._fetch_findings(job_id)
        agents_data = self._fetch_agents_data(job_id)
        
        # Generate report content
        report_content = self._generate_markdown_content(job_data, findings, agents_data)
        
        # Save files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"OWASP_WSTG_Report_Job{job_id}_{timestamp}"
        
        # Save Markdown
        md_path = os.path.join(output_dir, f"{base_filename}.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(report_content)
        
        # Save JSON
        json_path = os.path.join(output_dir, f"{base_filename}.json")
        json_data = self._generate_json_report(job_data, findings, agents_data)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        # Generate PDF (using Pandoc if available, fallback to HTML)
        pdf_path = self._generate_pdf(md_path, output_dir, base_filename)
        
        return {
            "markdown": md_path,
            "json": json_path,
            "pdf": pdf_path
        }
    
    def _fetch_job_data(self, job_id: int) -> Dict:
        """Fetch job metadata from database"""
        cursor = self.db.cursor()
        cursor.execute("""
            SELECT id, target, status, created_at, updated_at, plan, summary
            FROM jobs WHERE id = %s
        """, (job_id,))
        
        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Job {job_id} not found")
        
        return {
            "id": row[0],
            "target": row[1],
            "status": row[2],
            "created_at": row[3],
            "updated_at": row[4],
            "plan": row[5],
            "summary": row[6],
        }
    
    def _fetch_findings(self, job_id: int) -> List[Dict]:
        """Fetch all findings for a job"""
        cursor = self.db.cursor()
        cursor.execute("""
            SELECT id, agent_name, category, title, severity, details, evidence
            FROM findings 
            WHERE job_id = %s
            ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                category, created_at
        """, (job_id,))
        
        findings = []
        for row in cursor.fetchall():
            # Parse evidence JSON if present
            evidence_data = row[6] if row[6] else {}
            if isinstance(evidence_data, str):
                try:
                    evidence_data = json.loads(evidence_data)
                except:
                    evidence_data = {"raw": evidence_data}
            
            findings.append({
                "id": row[0],
                "agent_name": row[1],
                "category": row[2],
                "title": row[3],
                "severity": row[4],
                "details": row[5] or "No description provided",
                "evidence": evidence_data,
                "recommendation": "Review and remediate this vulnerability",
                "cvss_score": None,  # Not in current schema
                "cvss_vector": None,
                "cwe_id": None,
                "owasp_category": self._map_category_to_owasp(row[2]),
                "created_at": None,
            })
        
        return findings
    
    def _map_category_to_owasp(self, category: str) -> str:
        """Map agent category to OWASP WSTG category"""
        mapping = {
            "Information Gathering": "WSTG-INFO",
            "Configuration Testing": "WSTG-CONF",
            "Identity Management": "WSTG-IDNT",
            "Authentication": "WSTG-ATHN",
            "Authorization": "WSTG-ATHZ",
            "Session Management": "WSTG-SESS",
            "Input Validation": "WSTG-INPV",
            "Error Handling": "WSTG-ERRH",
            "Cryptography": "WSTG-CRYP",
            "Business Logic": "WSTG-BUSL",
            "Client-side": "WSTG-CLNT",
            "API Testing": "WSTG-APIT",
        }
        return mapping.get(category, "WSTG-MISC")
    
    def _fetch_agents_data(self, job_id: int) -> List[Dict]:
        """Fetch agent execution data"""
        cursor = self.db.cursor()
        cursor.execute("""
            SELECT agent_name, status, started_at, finished_at, error, context
            FROM job_agents
            WHERE job_id = %s
            ORDER BY started_at
        """, (job_id,))
        
        agents = []
        for row in cursor.fetchall():
            started = row[2]
            finished = row[3]
            duration = None
            if started and finished:
                duration = (finished - started).total_seconds()
            
            agents.append({
                "agent_name": row[0],
                "status": row[1],
                "started_at": row[2],
                "finished_at": row[3],
                "duration": duration,
                "error": row[4],
                "context": row[5],
            })
        
        return agents
    
    def _generate_markdown_content(self, job_data: Dict, findings: List[Dict], agents_data: List[Dict]) -> str:
        """Generate OWASP WSTG compliant Markdown report"""
        
        # Calculate statistics
        total_findings = len(findings)
        severity_counts = self._count_by_severity(findings)
        category_counts = self._count_by_category(findings)
        
        # Calculate execution time
        if agents_data:
            start_time = min(a["started_at"] for a in agents_data if a["started_at"])
            end_time = max(a["finished_at"] for a in agents_data if a["finished_at"])
            duration = (end_time - start_time).total_seconds() if start_time and end_time else 0
        else:
            duration = 0
        
        # Build Markdown content (OWASP WSTG Format)
        md = []
        
        # Title Page
        md.append("# Web Security Testing Report")
        md.append(f"## OWASP Web Security Testing Guide v4.2 Compliant\n")
        md.append("---\n")
        
        # Executive Summary (OWASP WSTG Section 5.1)
        md.append("## Executive Summary\n")
        md.append(f"**Target Application:** `{job_data['target']}`  ")
        md.append(f"**Assessment Date:** {job_data['created_at'].strftime('%B %d, %Y')}  ")
        md.append(f"**Report Generated:** {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}  ")
        md.append(f"**Assessment Duration:** {duration:.1f} seconds  ")
        md.append(f"**Assessment Status:** {job_data['status'].upper()}  \n")
        
        md.append("### Summary of Findings\n")
        md.append(f"Total vulnerabilities identified: **{total_findings}**\n")
        md.append("| Severity | Count | Percentage |")
        md.append("|----------|-------|------------|")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            pct = (count / total_findings * 100) if total_findings > 0 else 0
            md.append(f"| {severity.upper()} | {count} | {pct:.1f}% |")
        md.append("")
        
        # Risk Rating
        md.append("### Overall Risk Rating\n")
        if severity_counts.get("critical", 0) > 0:
            risk = "**CRITICAL** - Immediate action required"
        elif severity_counts.get("high", 0) >= 5:
            risk = "**HIGH** - Action required within 30 days"
        elif severity_counts.get("high", 0) > 0 or severity_counts.get("medium", 0) >= 10:
            risk = "**MEDIUM** - Action required within 90 days"
        else:
            risk = "**LOW** - Address during regular maintenance"
        md.append(risk + "\n")
        
        # Scope (OWASP WSTG Section 5.2)
        md.append("---\n")
        md.append("## Assessment Scope\n")
        md.append("### Target Information\n")
        md.append(f"- **Target URL:** `{job_data['target']}`")
        md.append(f"- **Assessment Type:** Automated Multi-Agent Security Testing")
        md.append(f"- **Testing Standard:** OWASP Web Security Testing Guide (WSTG) v4.2")
        md.append(f"- **Testing Coverage:** {len([c for c in category_counts.keys() if c.startswith('WSTG-')])} of 12 OWASP WSTG categories\n")
        
        md.append("### Testing Methodology\n")
        md.append("This assessment utilized an autonomous multi-agent system with 14 specialized agents:")
        md.append("1. **ReconnaissanceAgent** - Information gathering (WSTG-INFO)")
        md.append("2. **AuthenticationAgent** - Authentication testing (WSTG-ATHN)")
        md.append("3. **AuthorizationAgent** - Authorization testing (WSTG-ATHZ)")
        md.append("4. **SessionManagementAgent** - Session management (WSTG-SESS)")
        md.append("5. **InputValidationAgent** - Input validation (WSTG-INPV)")
        md.append("6. **APITestingAgent** - API security testing (WSTG-APIT)")
        md.append("7. **FileUploadAgent** - File upload testing (WSTG-BUSL)")
        md.append("8. **ClientSideAgent** - Client-side testing (WSTG-CLNT)")
        md.append("9. **ErrorHandlingAgent** - Error handling (WSTG-ERRH)")
        md.append("10. **WeakCryptographyAgent** - Cryptography testing (WSTG-CRYP)")
        md.append("11. **BusinessLogicAgent** - Business logic testing (WSTG-BUSL)")
        md.append("12. **IdentityManagementAgent** - Identity management (WSTG-IDNT)")
        md.append("13. **ConfigDeploymentAgent** - Configuration testing (WSTG-CONF)")
        md.append("14. **CVEScanAgent** - Known vulnerability scanning\n")
        
        # Findings by Category (OWASP WSTG Section 5.3)
        md.append("---\n")
        md.append("## Detailed Findings\n")
        
        # Group findings by OWASP category
        findings_by_category = {}
        for finding in findings:
            cat = finding.get("owasp_category") or finding.get("category", "UNCATEGORIZED")
            if cat not in findings_by_category:
                findings_by_category[cat] = []
            findings_by_category[cat].append(finding)
        
        # Sort categories by OWASP order
        sorted_categories = sorted(findings_by_category.keys(), 
                                    key=lambda x: list(self.OWASP_CATEGORIES.keys()).index(x) 
                                    if x in self.OWASP_CATEGORIES else 99)
        
        finding_counter = 1
        for category in sorted_categories:
            category_name = self.OWASP_CATEGORIES.get(category, category)
            category_findings = findings_by_category[category]
            
            md.append(f"### {category}: {category_name}\n")
            md.append(f"**Total Findings:** {len(category_findings)}\n")
            
            for finding in category_findings:
                md.append(f"#### Finding #{finding_counter}: {finding['title']}\n")
                
                md.append(f"**Severity:** {finding['severity'].upper()}  ")
                md.append(f"**Category:** {finding.get('owasp_category', finding['category'])}  ")
                if finding.get('cwe_id'):
                    md.append(f"**CWE:** {finding['cwe_id']}  ")
                if finding.get('cvss_score'):
                    md.append(f"**CVSS Score:** {finding['cvss_score']} ({finding.get('cvss_vector', 'N/A')})  ")
                md.append(f"**Detected by:** {finding['agent_name']}  \n")
                
                md.append("**Description:**  ")
                md.append(finding.get('details', 'No description provided.') + "\n")
                
                md.append("**Evidence:**  ")
                md.append("```")
                evidence = finding.get('evidence', 'No evidence available.')
                if isinstance(evidence, dict):
                    # Convert dict to pretty JSON string
                    evidence = json.dumps(evidence, indent=2, ensure_ascii=False)
                md.append(str(evidence))
                md.append("```\n")
                
                md.append("**Recommendation:**  ")
                md.append(finding.get('recommendation', 'No recommendation provided.') + "\n")
                
                md.append("---\n")
                finding_counter += 1
        
        # Agent Execution Summary
        md.append("## Agent Execution Summary\n")
        md.append("| Agent Name | Status | Duration | Findings |")
        md.append("|------------|--------|----------|----------|")
        
        for agent in agents_data:
            status_icon = "✅" if agent["status"] == "completed" else "❌"
            duration_str = "N/A"
            if agent["started_at"] and agent["finished_at"]:
                dur = (agent["finished_at"] - agent["started_at"]).total_seconds()
                duration_str = f"{dur:.1f}s"
            
            agent_findings = [f for f in findings if f["agent_name"] == agent["agent_name"]]
            findings_count = len(agent_findings)
            
            md.append(f"| {agent['agent_name']} | {status_icon} {agent['status']} | {duration_str} | {findings_count} |")
        
        md.append("")
        
        # Recommendations (OWASP WSTG Section 5.4)
        md.append("---\n")
        md.append("## Remediation Priorities\n")
        
        if severity_counts.get("critical", 0) > 0:
            md.append("### 🔴 CRITICAL Priority (Immediate Action)\n")
            critical = [f for f in findings if f["severity"] == "critical"]
            for i, f in enumerate(critical[:5], 1):  # Top 5
                md.append(f"{i}. **{f['title']}** ({f.get('owasp_category', f['category'])})")
                md.append(f"   - {f.get('recommendation', 'See finding details')}\n")
        
        if severity_counts.get("high", 0) > 0:
            md.append("### 🟠 HIGH Priority (Within 30 Days)\n")
            high = [f for f in findings if f["severity"] == "high"]
            for i, f in enumerate(high[:5], 1):  # Top 5
                md.append(f"{i}. **{f['title']}** ({f.get('owasp_category', f['category'])})")
                md.append(f"   - {f.get('recommendation', 'See finding details')}\n")
        
        # Conclusion
        md.append("---\n")
        md.append("## Conclusion\n")
        md.append(f"This automated security assessment identified **{total_findings} vulnerabilities** ")
        md.append(f"across **{len(findings_by_category)} OWASP WSTG categories**. ")
        
        if severity_counts.get("critical", 0) + severity_counts.get("high", 0) > 0:
            md.append(f"Immediate attention is required for **{severity_counts.get('critical', 0)} critical** ")
            md.append(f"and **{severity_counts.get('high', 0)} high severity** findings.\n")
        else:
            md.append("The application demonstrates a moderate security posture with room for improvement.\n")
        
        md.append("\n### Next Steps\n")
        md.append("1. **Validate Findings:** Manual verification of automated findings")
        md.append("2. **Prioritize Remediation:** Address critical/high severity issues first")
        md.append("3. **Implement Fixes:** Apply recommended security controls")
        md.append("4. **Re-test:** Conduct follow-up assessment after remediation")
        md.append("5. **Continuous Monitoring:** Integrate security testing into CI/CD pipeline\n")
        
        # Appendix
        md.append("---\n")
        md.append("## Appendix\n")
        md.append("### Testing Tools Used\n")
        md.append("- **Information Gathering:** Subfinder, Nmap, WhatWeb, theHarvester")
        md.append("- **Vulnerability Scanning:** SQLMap, Dalfox, ffuf")
        md.append("- **Authentication Testing:** Hydra, custom credential stuffing")
        md.append("- **Cryptography Testing:** testssl.sh, sslyze")
        md.append("- **Configuration Testing:** Nikto, dirb, feroxbuster\n")
        
        md.append("### References\n")
        md.append("- [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)")
        md.append("- [OWASP Top 10 Web Application Security Risks](https://owasp.org/www-project-top-ten/)")
        md.append("- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)")
        md.append("- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)\n")
        
        md.append("---\n")
        md.append(f"**Report Generated by:** Autonomous Multi-Agent Security Testing System  ")
        md.append(f"**Generation Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        md.append(f"**Job ID:** {job_data['id']}  \n")
        
        # Ensure all items are strings (handle any edge cases)
        md_strings = []
        for item in md:
            if isinstance(item, str):
                md_strings.append(item)
            elif item is None:
                md_strings.append("")
            else:
                # Convert any non-string to string
                md_strings.append(str(item))
        
        return "\n".join(md_strings)
    
    def _generate_json_report(self, job_data: Dict, findings: List[Dict], agents_data: List[Dict]) -> Dict:
        """Generate JSON format report for API consumption"""
        
        return {
            "metadata": {
                "job_id": job_data["id"],
                "target": job_data["target"],
                "status": job_data["status"],
                "assessment_date": job_data["created_at"].isoformat(),
                "report_generated": datetime.now().isoformat(),
                "standard": "OWASP WSTG v4.2",
            },
            "summary": {
                "total_findings": len(findings),
                "severity_distribution": self._count_by_severity(findings),
                "category_distribution": self._count_by_category(findings),
                "agents_executed": len(agents_data),
                "agents_successful": len([a for a in agents_data if a["status"] == "completed"]),
            },
            "findings": [
                {
                    "id": f["id"],
                    "title": f["title"],
                    "severity": f["severity"],
                    "category": f.get("owasp_category", f["category"]),
                    "cwe_id": f.get("cwe_id"),
                    "cvss_score": f.get("cvss_score"),
                    "cvss_vector": f.get("cvss_vector"),
                    "details": f.get("details"),
                    "evidence": f.get("evidence"),
                    "recommendation": f.get("recommendation"),
                    "detected_by": f["agent_name"],
                }
                for f in findings
            ],
            "agents": [
                {
                    "name": a["agent_name"],
                    "status": a["status"],
                    "started_at": a["started_at"].isoformat() if a["started_at"] else None,
                    "finished_at": a["finished_at"].isoformat() if a["finished_at"] else None,
                    "error": a.get("error"),
                }
                for a in agents_data
            ],
        }
    
    def _generate_pdf(self, markdown_path: str, output_dir: str, base_filename: str) -> Optional[str]:
        """
        Generate PDF from Markdown using Pandoc (if available)
        Falls back to simple HTML conversion if Pandoc not installed
        """
        pdf_path = os.path.join(output_dir, f"{base_filename}.pdf")
        
        # Try Pandoc first (best quality)
        try:
            result = subprocess.run([
                "pandoc",
                markdown_path,
                "-o", pdf_path,
                "--pdf-engine=xelatex",
                "-V", "geometry:margin=1in",
                "-V", "documentclass=article",
                "-V", "fontsize=11pt",
                "--toc",
                "--toc-depth=2",
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and os.path.exists(pdf_path):
                return pdf_path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # Pandoc not available, try fallback
        
        # Fallback: Convert to HTML then save (simple approach)
        try:
            html_path = os.path.join(output_dir, f"{base_filename}.html")
            
            with open(markdown_path, "r", encoding="utf-8") as f:
                md_content = f.read()
            
            # Simple Markdown to HTML conversion
            html_content = self._markdown_to_html(md_content)
            
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            # Note: For true PDF, user needs to install Pandoc or wkhtmltopdf
            # Return HTML path as fallback
            return html_path
        
        except Exception as e:
            print(f"PDF generation failed: {e}")
            return None
    
    def _markdown_to_html(self, markdown: str) -> str:
        """Simple Markdown to HTML conversion (basic formatting)"""
        
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>OWASP WSTG Security Report</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            max-width: 1000px; 
            margin: 40px auto; 
            padding: 20px;
            background: #f5f5f5;
        }
        .content {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #D32F2F; border-bottom: 3px solid #D32F2F; padding-bottom: 10px; }
        h2 { color: #1976D2; border-bottom: 2px solid #1976D2; padding-bottom: 8px; margin-top: 30px; }
        h3 { color: #388E3C; margin-top: 25px; }
        h4 { color: #F57C00; margin-top: 20px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #1976D2; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
        pre { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .critical { color: #D32F2F; font-weight: bold; }
        .high { color: #F57C00; font-weight: bold; }
        .medium { color: #FBC02D; font-weight: bold; }
        .low { color: #388E3C; font-weight: bold; }
        hr { border: none; border-top: 2px solid #e0e0e0; margin: 30px 0; }
    </style>
</head>
<body>
    <div class="content">
"""
        
        # Basic Markdown parsing (replace with proper parser in production)
        lines = markdown.split("\n")
        in_code_block = False
        
        for line in lines:
            # Code blocks
            if line.startswith("```"):
                if in_code_block:
                    html += "</pre>\n"
                else:
                    html += "<pre><code>"
                in_code_block = not in_code_block
                continue
            
            if in_code_block:
                html += line + "\n"
                continue
            
            # Headers
            if line.startswith("# "):
                html += f"<h1>{line[2:]}</h1>\n"
            elif line.startswith("## "):
                html += f"<h2>{line[3:]}</h2>\n"
            elif line.startswith("### "):
                html += f"<h3>{line[4:]}</h3>\n"
            elif line.startswith("#### "):
                html += f"<h4>{line[5:]}</h4>\n"
            # Horizontal rule
            elif line.strip() == "---":
                html += "<hr>\n"
            # Tables
            elif "|" in line:
                html += "<tr>" + "".join(f"<td>{cell.strip()}</td>" for cell in line.split("|")[1:-1]) + "</tr>\n"
            # Bold
            elif "**" in line:
                line = line.replace("**", "<strong>", 1).replace("**", "</strong>", 1)
                html += f"<p>{line}</p>\n"
            # Regular paragraph
            elif line.strip():
                html += f"<p>{line}</p>\n"
            else:
                html += "\n"
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    def _count_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {}
        for f in findings:
            severity = f.get("severity", "info")
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _count_by_category(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by OWASP category"""
        counts = {}
        for f in findings:
            category = f.get("owasp_category", f.get("category", "UNCATEGORIZED"))
            counts[category] = counts.get(category, 0) + 1
        return counts


# Standalone function for easy import
def generate_owasp_report(db_connection, job_id: int, output_dir: str = "reports") -> Dict[str, str]:
    """
    Generate OWASP WSTG compliant report for a job
    
    Args:
        db_connection: PostgreSQL database connection
        job_id: Job ID to generate report for
        output_dir: Output directory for reports
    
    Returns:
        dict: {"markdown": path, "json": path, "pdf": path}
    """
    generator = OWASPReportGenerator(db_connection)
    return generator.generate_report(job_id, output_dir)
