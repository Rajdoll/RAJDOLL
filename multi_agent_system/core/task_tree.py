"""
Task Tree module — Pentesting Task Tree (PTT) inspired by PentestGPT.

Encodes the current testing status per WSTG category as a natural language
string that can be fed to the LLM for context-aware planning.
"""
from __future__ import annotations

from typing import Dict, List, Any, Optional
from ..core.db import get_db
from ..models.models import Finding, JobAgent, AgentStatus


# Map agent names to WSTG category codes + display names
AGENT_WSTG_MAP = {
    "ReconnaissanceAgent": ("WSTG-INFO", "Information Gathering"),
    "AuthenticationAgent": ("WSTG-ATHN", "Authentication Testing"),
    "SessionManagementAgent": ("WSTG-SESS", "Session Management"),
    "InputValidationAgent": ("WSTG-INPV", "Input Validation"),
    "AuthorizationAgent": ("WSTG-ATHZ", "Authorization Testing"),
    "ConfigDeploymentAgent": ("WSTG-CONF", "Configuration & Deployment"),
    "ClientSideAgent": ("WSTG-CLNT", "Client-Side Testing"),
    "FileUploadAgent": ("WSTG-BUSL", "File Upload Testing"),
    "APITestingAgent": ("WSTG-APIT", "API Testing"),
    "ErrorHandlingAgent": ("WSTG-ERRH", "Error Handling"),
    "WeakCryptographyAgent": ("WSTG-CRYP", "Weak Cryptography"),
    "BusinessLogicAgent": ("WSTG-BUSL", "Business Logic Testing"),
    "IdentityManagementAgent": ("WSTG-IDNT", "Identity Management"),
}


def build_task_tree(job_id: int) -> str:
    """Build a natural-language task tree from DB state.

    Returns a string like:
        [DONE] WSTG-INFO (Reconnaissance) - 0 vulnerabilities
          - 47 endpoints discovered, tech: Node.js, Express, Angular
        [DONE] WSTG-ATHN (Authentication) - 3 vulnerabilities
          - CRITICAL: Default admin credentials work
          - HIGH: No account lockout
        [PENDING] WSTG-SESS (Session Management)
        ...
    """
    with get_db() as db:
        # Get agent statuses
        agents = db.query(JobAgent).filter(JobAgent.job_id == job_id).all()
        agent_status = {ja.agent_name: ja.status for ja in agents}

        # Get all findings grouped by agent
        findings = db.query(Finding).filter(Finding.job_id == job_id).all()
        agent_findings: Dict[str, List[Finding]] = {}
        for f in findings:
            agent_findings.setdefault(f.agent_name, []).append(f)

    lines = [f"PENETRATION TESTING STATUS (Job #{job_id})", "=" * 50]

    for agent_name, (wstg_code, display_name) in AGENT_WSTG_MAP.items():
        status = agent_status.get(agent_name, AgentStatus.pending)
        findings_list = agent_findings.get(agent_name, [])
        vuln_count = len([f for f in findings_list if f.severity in ("critical", "high", "medium")])

        if status == AgentStatus.completed:
            tag = "DONE"
        elif status == AgentStatus.running:
            tag = "RUNNING"
        elif status == AgentStatus.failed:
            tag = "FAILED"
        else:
            tag = "PENDING"

        header = f"[{tag}] {wstg_code} ({display_name})"
        if status == AgentStatus.completed:
            header += f" - {vuln_count} vulnerabilities"
        lines.append(header)

        # Add top findings (max 3 per agent) for completed agents
        if findings_list and status in (AgentStatus.completed, AgentStatus.failed):
            # Sort by severity: critical > high > medium > low > info
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(findings_list, key=lambda f: severity_order.get(f.severity, 5))
            for f in sorted_findings[:3]:
                sev = f.severity.upper() if f.severity else "INFO"
                title = f.title or "No title"
                lines.append(f"  - {sev}: {title}")

    return "\n".join(lines)


def build_task_tree_dict(job_id: int) -> Dict[str, Any]:
    """Build task tree as a dict (for storing in shared context)."""
    with get_db() as db:
        agents = db.query(JobAgent).filter(JobAgent.job_id == job_id).all()
        agent_status = {ja.agent_name: ja.status.value if ja.status else "pending" for ja in agents}

        findings = db.query(Finding).filter(Finding.job_id == job_id).all()
        agent_findings: Dict[str, List[Dict]] = {}
        for f in findings:
            agent_findings.setdefault(f.agent_name, []).append({
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
            })

    tree = {}
    for agent_name, (wstg_code, display_name) in AGENT_WSTG_MAP.items():
        fl = agent_findings.get(agent_name, [])
        tree[agent_name] = {
            "wstg_code": wstg_code,
            "display_name": display_name,
            "status": agent_status.get(agent_name, "pending"),
            "vuln_count": len([f for f in fl if f["severity"] in ("critical", "high", "medium")]),
            "top_findings": [f["title"] for f in fl[:3]],
        }
    return tree
