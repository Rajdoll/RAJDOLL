"""
OWASP WSTG 4.2 Compliant Report Generator
Generates professional security testing reports in Markdown and PDF formats
"""

from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import json
import os
from pathlib import Path


class OWASPReportGenerator:
    """Generate OWASP WSTG 4.2 compliant security testing reports"""
    
    # OWASP WSTG Category Mappings
    WSTG_CATEGORIES = {
        "WSTG-INFO": "Information Gathering",
        "WSTG-CONF": "Configuration and Deployment Management Testing",
        "WSTG-IDNT": "Identity Management Testing",
        "WSTG-ATHN": "Authentication Testing",
        "WSTG-ATHZ": "Authorization Testing",
        "WSTG-SESS": "Session Management Testing",
        "WSTG-INPV": "Input Validation Testing",
        "WSTG-ERRH": "Error Handling Testing",
        "WSTG-CRYP": "Weak Cryptography Testing",
        "WSTG-BUSL": "Business Logic Testing",
        "WSTG-CLNT": "Client-side Testing",
        "WSTG-APIT": "API Testing"
    }
    
    SEVERITY_COLORS = {
        "critical": "#D32F2F",
        "high": "#F57C00",
        "medium": "#FBC02D",
        "low": "#388E3C",
        "informational": "#1976D2"
    }
    
    SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
    
    def __init__(self, job_id: int, target: str, findings: List[Dict], 
                 job_metadata: Dict, agents_data: List[Dict]):
        """
        Initialize report generator
        
        Args:
            job_id: Job ID
            target: Target URL/IP
            findings: List of finding dictionaries from database
            job_metadata: Job metadata (started_at, finished_at, status)
            agents_data: List of agent execution data
        """
        self.job_id = job_id
        self.target = target
        self.findings = findings
        self.job_metadata = job_metadata
        self.agents_data = agents_data
        self.report_date = datetime.now(timezone.utc).strftime("%B %d, %Y")
        
    def generate_markdown_report(self) -> str:
        """Generate full OWASP-compliant Markdown report"""
        
        sections = [
            self._generate_cover_page(),
            self._generate_version_control(),
            self._generate_table_of_contents(),
            self._generate_team_info(),
            self._generate_scope(),
            self._generate_limitations(),
            self._generate_timeline(),
            self._generate_disclaimer(),
            self._generate_executive_summary(),
            self._generate_findings_summary(),
            self._generate_findings_details(),
            self._generate_appendices(),
            self._generate_references()
        ]
        
        return "\n\n---\n\n".join(sections)
    
    def _generate_cover_page(self) -> str:
        """Section: Cover Page"""
        return f"""# Web Vulnerability Assessment Report

**Target:** {self.target}  
**Report Date:** {self.report_date}  
**Job ID:** {self.job_id}  
**Report Version:** 1.0  

## Prepared By
**Autonomous Multi-Agent Security Testing System**  
Based on OWASP Web Security Testing Guide (WSTG) v4.2

![OWASP Logo](https://owasp.org/assets/images/logo.png)

**CONFIDENTIAL**  
This document contains sensitive security information and should be handled accordingly."""
    
    def _generate_version_control(self) -> str:
        """Section 1.1: Version Control"""
        return f"""## 1. Introduction

### 1.1 Version Control

| Version | Description | Date | Author |
|---------|-------------|------|--------|
| 1.0 | Initial Report | {self.report_date} | Autonomous Multi-Agent System |"""
    
    def _generate_table_of_contents(self) -> str:
        """Section 1.2: Table of Contents"""
        return """### 1.2 Table of Contents

1. Introduction
   - 1.1 Version Control
   - 1.2 Table of Contents
   - 1.3 The Team
   - 1.4 Scope
   - 1.5 Limitations
   - 1.6 Timeline
   - 1.7 Disclaimer

2. Executive Summary
   - 2.1 Objectives
   - 2.2 Key Findings
   - 2.3 Strategic Recommendations

3. Findings
   - 3.1 Findings Summary
   - 3.2 Findings Details (by OWASP WSTG Category)

4. Appendices
   - A. Test Methodology
   - B. Severity Rating Explanation
   - C. CVSS Scoring
   - D. Tool Output
   - E. OWASP WSTG 4.2 Checklist

5. References"""
    
    def _generate_team_info(self) -> str:
        """Section 1.3: The Team"""
        agents_list = "\n".join([
            f"- **{agent['agent_name']}**: {self._get_agent_description(agent['agent_name'])}"
            for agent in self.agents_data
        ])
        
        return f"""### 1.3 The Team

This security assessment was conducted by an **Autonomous Multi-Agent System** consisting of **{len(self.agents_data)} specialized AI agents**, each expert in specific OWASP WSTG categories:

{agents_list}

**System Architecture:**
- **Orchestrator**: LLM-based strategic planning and agent coordination
- **MCP Protocol**: Standardized integration with 70+ security tools
- **Shared Context**: Context-aware testing across agents"""
    
    def _generate_scope(self) -> str:
        """Section 1.4: Scope"""
        return f"""### 1.4 Scope

**Target Application:** {self.target}

**Testing Scope:**
- Full OWASP WSTG 4.2 coverage (11 categories, 87 test cases)
- Automated security assessment using industry-standard tools
- Black-box testing methodology
- Unauthenticated and authenticated testing (if credentials discovered)

**Testing Categories:**
{self._format_tested_categories()}

**Out of Scope:**
- Physical security testing
- Social engineering attacks
- Denial of Service (DoS) attacks
- Source code review (unless publicly exposed)"""
    
    def _generate_limitations(self) -> str:
        """Section 1.5: Limitations"""
        return """### 1.5 Limitations

**Technical Limitations:**
- Automated testing tools may produce false positives
- Some manual verification required for complex vulnerabilities
- Rate limiting may prevent comprehensive brute-force testing
- WAF/IPS may block certain test payloads

**Temporal Limitations:**
- This is a "point in time" assessment
- Application may have changed since testing
- New vulnerabilities may be discovered after report date

**Access Limitations:**
- Limited to publicly accessible interfaces
- No internal network access
- No credentials provided (unless discovered during testing)"""
    
    def _generate_timeline(self) -> str:
        """Section 1.6: Timeline"""
        started = self.job_metadata.get('started_at', 'N/A')
        finished = self.job_metadata.get('finished_at', 'N/A')
        
        if started != 'N/A' and finished != 'N/A':
            duration = (finished - started).total_seconds()
            duration_str = f"{int(duration // 60)} minutes {int(duration % 60)} seconds"
        else:
            duration_str = "N/A"
        
        return f"""### 1.6 Timeline

**Testing Start:** {started}  
**Testing End:** {finished}  
**Total Duration:** {duration_str}

**Testing Phases:**
1. **Reconnaissance** (~20% of time): Technology fingerprinting, subdomain enumeration
2. **Strategic Planning** (~5% of time): LLM-based agent ordering
3. **Active Testing** (~70% of time): {len(self.agents_data)} agents executing security tests
4. **Reporting** (~5% of time): Findings aggregation and report generation"""
    
    def _generate_disclaimer(self) -> str:
        """Section 1.7: Disclaimer"""
        return """### 1.7 Disclaimer

⚠️ **IMPORTANT LEGAL NOTICE**

This security assessment report is provided "AS IS" without warranty of any kind. The automated testing conducted represents a **point-in-time assessment** and should not be considered exhaustive.

**Key Disclaimers:**
- **No Guarantee of Completeness**: This report does not guarantee that all possible security issues have been identified
- **Temporal Validity**: The environment may have changed since testing was conducted
- **New Vulnerabilities**: New security vulnerabilities may be discovered after this report date
- **False Positives**: Automated tools may flag items that are not actually vulnerabilities (manual verification recommended)
- **No Warranty**: This report serves as a guiding document and not a warranty of security posture

**Recommendations:**
- Verify all CRITICAL and HIGH severity findings manually before remediation
- Conduct periodic re-assessments (quarterly recommended)
- Implement continuous security monitoring
- Follow up with manual penetration testing for comprehensive coverage

**Authorized Testing:** This assessment was conducted with proper authorization. Unauthorized security testing is illegal."""
    
    def _generate_executive_summary(self) -> str:
        """Section 2: Executive Summary"""
        total_findings = len(self.findings)
        severity_dist = self._calculate_severity_distribution()
        critical_high = severity_dist.get('critical', 0) + severity_dist.get('high', 0)
        
        # Risk assessment
        if critical_high >= 10:
            risk_level = "**CRITICAL**"
            risk_color = "🔴"
        elif critical_high >= 5:
            risk_level = "**HIGH**"
            risk_color = "🟠"
        elif severity_dist.get('medium', 0) >= 10:
            risk_level = "**MEDIUM**"
            risk_color = "🟡"
        else:
            risk_level = "**LOW**"
            risk_color = "🟢"
        
        return f"""## 2. Executive Summary

### 2.1 Objectives

This security assessment was conducted to:
- **Identify security vulnerabilities** in the target application
- **Assess compliance** with OWASP Web Security Testing Guide (WSTG) v4.2
- **Provide actionable recommendations** for remediation
- **Evaluate overall security posture** of the application

### 2.2 Key Findings

{risk_color} **Overall Risk Level:** {risk_level}

**Vulnerability Summary:**
- **Total Findings:** {total_findings}
- **Critical:** {severity_dist.get('critical', 0)} (Immediate action required)
- **High:** {severity_dist.get('high', 0)} (Urgent remediation needed)
- **Medium:** {severity_dist.get('medium', 0)} (Should be addressed)
- **Low:** {severity_dist.get('low', 0)} (Consider for future remediation)
- **Informational:** {severity_dist.get('informational', 0)} (Best practice recommendations)

**Most Affected Categories:**
{self._format_top_affected_categories()}

**Business Impact:**
{self._generate_business_impact(critical_high)}

### 2.3 Strategic Recommendations

**Immediate Actions (0-7 days):**
1. Address all CRITICAL severity findings (potential for immediate exploitation)
2. Implement input validation and output encoding
3. Review and fix authentication/authorization issues

**Short-term Actions (1-4 weeks):**
1. Remediate HIGH severity findings
2. Implement security headers (CSP, HSTS, X-Frame-Options)
3. Conduct code review for injection vulnerabilities

**Long-term Actions (1-3 months):**
1. Establish secure SDLC practices
2. Implement automated security testing in CI/CD pipeline
3. Conduct regular penetration testing (quarterly)
4. Security awareness training for development team"""
    
    def _generate_findings_summary(self) -> str:
        """Section 3.1: Findings Summary"""
        
        # Group findings by severity (handle both uppercase and lowercase)
        by_severity = {}
        for finding in self.findings:
            sev_raw = finding.get('severity', 'informational')
            # Normalize severity to lowercase
            if isinstance(sev_raw, str):
                sev = sev_raw.lower()
            else:
                sev = str(sev_raw).lower() if hasattr(sev_raw, 'value') else str(sev_raw).lower()
            
            # Map 'info' to 'informational' (database stores 'info', report expects 'informational')
            if sev == 'info':
                sev = 'informational'
            
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(finding)
        
        # Generate table
        table_rows = []
        ref_id = 1
        for severity in self.SEVERITY_ORDER:
            if severity in by_severity:
                for finding in by_severity[severity]:
                    table_rows.append(
                        f"| {ref_id} | {finding.get('category', 'N/A')} | "
                        f"{finding.get('title', 'Unknown')} | "
                        f"**{severity.upper()}** |"
                    )
                    ref_id += 1
        
        table = "\n".join(table_rows)
        
        return f"""## 3. Findings

### 3.1 Findings Summary

| Ref ID | OWASP Category | Finding Title | Severity |
|--------|----------------|---------------|----------|
{table}

**Severity Distribution:**
```
Critical:      {"█" * len(by_severity.get('critical', []))} ({len(by_severity.get('critical', []))})
High:          {"█" * len(by_severity.get('high', []))} ({len(by_severity.get('high', []))})
Medium:        {"█" * len(by_severity.get('medium', []))} ({len(by_severity.get('medium', []))})
Low:           {"█" * len(by_severity.get('low', []))} ({len(by_severity.get('low', []))})
Informational: {"█" * len(by_severity.get('informational', []))} ({len(by_severity.get('informational', []))})
```"""
    
    def _generate_findings_details(self) -> str:
        """Section 3.2: Findings Details (grouped by OWASP category)"""
        
        # Group findings by OWASP category
        by_category = {}
        for finding in self.findings:
            cat = finding.get('category', 'UNCATEGORIZED')
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(finding)
        
        # Sort categories by WSTG order
        sorted_categories = sorted(by_category.keys(), 
                                   key=lambda x: list(self.WSTG_CATEGORIES.keys()).index(x) 
                                   if x in self.WSTG_CATEGORIES else 999)
        
        sections = ["### 3.2 Findings Details\n"]
        ref_id = 1
        
        for category in sorted_categories:
            category_name = self.WSTG_CATEGORIES.get(category, category)
            sections.append(f"\n#### {category}: {category_name}\n")
            
            # Sort findings by severity within category (handle uppercase)
            def get_severity_key(finding):
                sev_raw = finding.get('severity', 'informational')
                if isinstance(sev_raw, str):
                    sev = sev_raw.lower()
                else:
                    sev = str(sev_raw).lower() if hasattr(sev_raw, 'value') else str(sev_raw).lower()
                
                # Map 'info' to 'informational' (database stores 'info', report expects 'informational')
                if sev == 'info':
                    sev = 'informational'
                
                return self.SEVERITY_ORDER.index(sev) if sev in self.SEVERITY_ORDER else 999
            
            cat_findings = sorted(by_category[category], key=get_severity_key)
            
            for finding in cat_findings:
                sections.append(self._format_finding_detail(ref_id, finding))
                ref_id += 1
        
        return "\n".join(sections)
    
    def _format_finding_detail(self, ref_id: int, finding: Dict) -> str:
        """Format individual finding with all OWASP-required fields"""
        
        title = finding.get('title', 'Unknown Vulnerability')
        severity = finding.get('severity', 'informational').upper()
        category = finding.get('category', 'N/A')
        evidence = finding.get('evidence', 'No evidence provided')
        recommendation = finding.get('recommendation', 'No recommendation provided')
        agent = finding.get('agent_name', 'Unknown')
        
        # Calculate CVSS (if available)
        cvss_score = self._calculate_cvss_score(severity)
        
        return f"""---

##### Finding #{ref_id}: {title}

**Reference ID:** `FINDING-{ref_id:03d}`  
**OWASP Category:** {category}  
**Severity:** <span style="color:{self.SEVERITY_COLORS.get(severity.lower(), '#000')}">**{severity}**</span>  
**CVSS Score:** {cvss_score}  
**Discovered By:** {agent}

**Description:**

{evidence}

**Impact:**

{self._generate_impact_description(severity.lower())}

**Remediation:**

{recommendation}

**References:**
- [OWASP WSTG {category}](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/)
- [CWE Database](https://cwe.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

"""
    
    def _generate_appendices(self) -> str:
        """Section 4: Appendices"""
        return f"""## 4. Appendices

### Appendix A: Test Methodology

This assessment followed the **OWASP Web Security Testing Guide (WSTG) v4.2** methodology:

**Phase 1: Information Gathering**
- Passive reconnaissance (search engines, WHOIS, DNS)
- Active reconnaissance (port scanning, service enumeration)
- Technology fingerprinting

**Phase 2: Configuration Testing**
- Network/infrastructure configuration
- Application platform configuration
- File permissions and backup files

**Phase 3: Identity & Authentication**
- User enumeration
- Authentication bypass
- Credential testing

**Phase 4: Authorization**
- Privilege escalation
- Insecure direct object references (IDOR)
- Authorization bypass

**Phase 5: Session Management**
- Cookie security
- Session fixation
- CSRF protection

**Phase 6: Input Validation**
- SQL injection
- Cross-site scripting (XSS)
- XXE, SSRF, Command injection

**Phase 7: Additional Testing**
- Error handling
- Cryptography
- Business logic
- Client-side security
- API security

### Appendix B: Severity Rating Explanation

| Severity | CVSS Range | Description | Remediation Timeline |
|----------|------------|-------------|---------------------|
| **CRITICAL** | 9.0-10.0 | Immediate exploitation possible, severe business impact | Immediate (0-24 hours) |
| **HIGH** | 7.0-8.9 | High likelihood of exploitation, significant impact | Urgent (1-7 days) |
| **MEDIUM** | 4.0-6.9 | Moderate impact, exploitation requires specific conditions | 1-4 weeks |
| **LOW** | 0.1-3.9 | Limited impact or difficult to exploit | 1-3 months |
| **INFORMATIONAL** | 0.0 | Best practice violations, minimal security impact | Optional |

### Appendix C: CVSS v3.1 Scoring

The Common Vulnerability Scoring System (CVSS) provides a standardized method for rating IT vulnerabilities.

**Scoring Components:**
- **Base Score**: Intrinsic characteristics of the vulnerability
- **Temporal Score**: Characteristics that change over time
- **Environmental Score**: Characteristics unique to a user's environment

**CVSS Calculator:** https://www.first.org/cvss/calculator/3.1

### Appendix D: Tools Used

This assessment utilized **70+ open-source security tools** integrated via Model Context Protocol (MCP):

**Reconnaissance:**
- Subfinder, Nmap, WhatWeb, theHarvester, crt.sh

**Vulnerability Scanning:**
- Nuclei (CVE templates), SQLMap, Dalfox (XSS)

**Web Testing:**
- ffuf (fuzzing), feroxbuster (directory enumeration), Nikto

**Cryptography:**
- testssl.sh, sslyze

**API Testing:**
- GraphQL introspection, REST API abuse testers

**Full Tool List:** Available in system documentation

### Appendix E: OWASP WSTG 4.2 Coverage

**Test Cases Executed:** {self._calculate_wstg_coverage()}

See full OWASP WSTG checklist: https://github.com/OWASP/wstg/tree/master/checklist"""
    
    def _generate_references(self) -> str:
        """Section 5: References"""
        return """## 5. References

### Security Standards
1. [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
2. [OWASP Top 10 Web Application Security Risks](https://owasp.org/www-project-top-ten/)
3. [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
4. [CWE/SANS Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
5. [NIST SP 800-115: Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)

### Vulnerability Databases
6. [MITRE CVE Database](https://cve.mitre.org/)
7. [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
8. [OWASP Vulnerability Database](https://owasp.org/www-community/vulnerabilities/)

### Remediation Guides
9. [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
10. [SANS Application Security](https://www.sans.org/application-security/)
11. [PortSwigger Web Security Academy](https://portswigger.net/web-security)

### Tools & Frameworks
12. [Autonomous Multi-Agent System (This Tool)](https://github.com/your-org/rajdoll)
13. [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
14. [OWASP Testing Tools](https://owasp.org/www-community/Free_for_Open_Source_Application_Security_Tools)

---

**Report Generated:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}  
**Report Version:** 1.0  
**System Version:** Multi-Agent v1.0 (14 Agents, 13 MCP Servers)

**For questions or clarifications, please contact the security team.**"""
    
    # Helper methods
    def _get_agent_description(self, agent_name: str) -> str:
        """Get agent expertise description"""
        descriptions = {
            "ReconnaissanceAgent": "OWASP WSTG-INFO specialist (Information Gathering)",
            "AuthenticationAgent": "OWASP WSTG-ATHN specialist (Authentication Testing)",
            "AuthorizationAgent": "OWASP WSTG-ATHZ specialist (Authorization Testing)",
            "SessionManagementAgent": "OWASP WSTG-SESS specialist (Session Management)",
            "InputValidationAgent": "OWASP WSTG-INPV specialist (SQL, XSS, XXE, SSRF)",
            "APITestingAgent": "OWASP WSTG-APIT specialist (GraphQL, REST, Rate Limiting)",
            "FileUploadAgent": "OWASP WSTG-BUSL specialist (Unrestricted Upload)",
            "ClientSideAgent": "OWASP WSTG-CLNT specialist (XSS, Clickjacking, DOM-based)",
            "ErrorHandlingAgent": "OWASP WSTG-ERRH specialist (Stack Traces, Info Leaks)",
            "WeakCryptographyAgent": "OWASP WSTG-CRYP specialist (TLS, Padding Oracle)",
            "BusinessLogicAgent": "OWASP WSTG-BUSL specialist (Workflow Bypass, IDOR)",
            "IdentityManagementAgent": "OWASP WSTG-IDNT specialist (Account Enumeration)",
            "ConfigDeploymentAgent": "OWASP WSTG-CONF specialist (Dir Listing, Exposed Files)",
            "CVEScanAgent": "Known Vulnerability Detection (CVE Database)"
        }
        return descriptions.get(agent_name, "Security Testing Specialist")
    
    def _calculate_severity_distribution(self) -> Dict[str, int]:
        """Calculate severity distribution (handles both uppercase and lowercase severity)"""
        dist = {sev: 0 for sev in self.SEVERITY_ORDER}
        for finding in self.findings:
            # Handle both 'CRITICAL' (database) and 'critical' (lowercase)
            sev_raw = finding.get('severity', 'informational')
            if isinstance(sev_raw, str):
                sev = sev_raw.lower()
            else:
                # Handle Enum type from SQLAlchemy
                sev = str(sev_raw).lower() if hasattr(sev_raw, 'value') else str(sev_raw).lower()
            
            # Map 'info' to 'informational' (database stores 'info', report expects 'informational')
            if sev == 'info':
                sev = 'informational'
            
            # Normalize to lowercase key
            if sev in dist:
                dist[sev] += 1
            else:
                # Fallback for unknown severity
                dist['informational'] += 1
        return dist
    
    def _format_tested_categories(self) -> str:
        """Format tested OWASP categories"""
        tested = set(f.get('category', '') for f in self.findings)
        lines = []
        for cat, name in self.WSTG_CATEGORIES.items():
            status = "✅" if cat in tested else "⬜"
            lines.append(f"{status} **{cat}**: {name}")
        return "\n".join(lines)
    
    def _format_top_affected_categories(self) -> str:
        """Format top 3 affected categories"""
        by_cat = {}
        for finding in self.findings:
            cat = finding.get('category', 'UNCATEGORIZED')
            by_cat[cat] = by_cat.get(cat, 0) + 1
        
        top_3 = sorted(by_cat.items(), key=lambda x: x[1], reverse=True)[:3]
        lines = []
        for cat, count in top_3:
            cat_name = self.WSTG_CATEGORIES.get(cat, cat)
            lines.append(f"- **{cat_name}** ({cat}): {count} findings")
        return "\n".join(lines) if lines else "- No significant concentration in specific categories"
    
    def _generate_business_impact(self, critical_high_count: int) -> str:
        """Generate business impact assessment"""
        if critical_high_count >= 10:
            return """**SEVERE**: The application has numerous critical and high severity vulnerabilities that pose an immediate risk to:
- Data confidentiality (potential data breach)
- System integrity (unauthorized access/modification)
- Business reputation (public disclosure impact)
- Regulatory compliance (GDPR, PCI-DSS, HIPAA violations possible)

**Immediate executive action required.**"""
        elif critical_high_count >= 5:
            return """**HIGH**: Multiple high-impact vulnerabilities detected that could lead to:
- Unauthorized data access
- Account takeover
- Business logic bypass
- Compliance violations

**Urgent remediation recommended within 7 days.**"""
        elif critical_high_count >= 1:
            return """**MODERATE**: Some vulnerabilities detected that may impact:
- Individual user accounts
- Specific application features
- Data integrity in limited scenarios

**Remediation recommended within 30 days.**"""
        else:
            return """**LOW**: Minimal critical vulnerabilities detected. Findings primarily consist of:
- Best practice violations
- Information disclosures
- Minor configuration issues

**Standard security hardening recommended.**"""
    
    def _generate_impact_description(self, severity: str) -> str:
        """Generate impact description based on severity"""
        impacts = {
            "critical": """A successful exploit could result in:
- Complete system compromise
- Full database access or data breach
- Remote code execution
- Administrative account takeover
- Severe business impact and reputation damage""",
            
            "high": """A successful exploit could result in:
- Unauthorized access to sensitive data
- User account compromise
- Privilege escalation
- Significant business logic bypass
- Moderate to high business impact""",
            
            "medium": """A successful exploit could result in:
- Limited unauthorized access
- Information disclosure
- Partial authentication bypass
- Minor business logic issues
- Moderate business impact""",
            
            "low": """A successful exploit could result in:
- Information leakage
- Minor configuration weaknesses
- Limited functionality bypass
- Minimal business impact""",
            
            "informational": """This finding represents:
- Security best practice violation
- Potential future vulnerability
- Defense-in-depth recommendation
- No immediate business impact"""
        }
        return impacts.get(severity, "Impact assessment not available")
    
    def _calculate_cvss_score(self, severity: str) -> str:
        """Calculate CVSS score (simplified)"""
        scores = {
            "CRITICAL": "9.0-10.0 (Critical)",
            "HIGH": "7.0-8.9 (High)",
            "MEDIUM": "4.0-6.9 (Medium)",
            "LOW": "0.1-3.9 (Low)",
            "INFORMATIONAL": "0.0 (None)"
        }
        return scores.get(severity, "N/A")
    
    def _calculate_wstg_coverage(self) -> str:
        """Calculate WSTG test coverage"""
        tested_categories = set(f.get('category', '') for f in self.findings)
        total_categories = len(self.WSTG_CATEGORIES)
        covered = len([c for c in tested_categories if c in self.WSTG_CATEGORIES])
        percentage = int((covered / total_categories) * 100)
        return f"{covered}/{total_categories} categories ({percentage}%)"
    
    def generate_pdf_report(self, output_path: str) -> str:
        """
        Generate OWASP WSTG-compliant PDF report
        
        Args:
            output_path: Path to save PDF file
            
        Returns:
            Path to generated PDF file
        """
        from .pdf_generator import generate_pdf_report
        
        # Generate Markdown content
        markdown_content = self.generate_markdown_report()
        
        # Generate PDF
        pdf_path = generate_pdf_report(markdown_content, self.job_id, 
                                      output_dir=str(Path(output_path).parent))
        
        return pdf_path


def generate_report(job_id: int, target: str, findings: List[Dict], 
                   job_metadata: Dict, agents_data: List[Dict]) -> str:
    """
    Generate OWASP WSTG-compliant Markdown report
    
    Returns:
        Markdown report string
    """
    generator = OWASPReportGenerator(job_id, target, findings, job_metadata, agents_data)
    return generator.generate_markdown_report()


def generate_full_reports(job_id: int, target: str, findings: List[Dict], 
                         job_metadata: Dict, agents_data: List[Dict],
                         output_dir: str = "reports") -> Dict[str, str]:
    """
    Generate both Markdown and PDF reports
    
    Returns:
        Dict with paths: {'markdown': '...', 'pdf': '...'}
    """
    generator = OWASPReportGenerator(job_id, target, findings, job_metadata, agents_data)
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate Markdown
    markdown_content = generator.generate_markdown_report()
    md_path = os.path.join(output_dir, f"security_report_job_{job_id}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(markdown_content)
    
    # Generate PDF
    pdf_path = os.path.join(output_dir, f"security_report_job_{job_id}.pdf")
    generator.generate_pdf_report(pdf_path)
    
    return {
        "markdown": md_path,
        "pdf": pdf_path
    }

