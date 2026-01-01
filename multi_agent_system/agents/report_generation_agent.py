"""
Report Generation Agent - OWASP WSTG 4.2 Compliant Report Generator
Generates comprehensive security assessment reports based on multi-agent findings
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

from ..agents.base_agent import BaseAgent, AgentRegistry
from ..core.db import get_db
from ..models.models import Finding, JobAgent, Job
# 🆕 Sensitive data redaction integration
from ..core.security_guards import data_redactor

@AgentRegistry.register("ReportGenerationAgent")
class ReportGenerationAgent(BaseAgent):
	"""
	Generate OWASP WSTG 4.2 compliant security assessment reports.
	
	Report Structure:
	1. Introduction (Version Control, Scope, Timeline, Disclaimer)
	2. Executive Summary (Business-focused findings)
	3. Findings (Technical details with remediation)
	4. Appendices (Methodology, Risk ratings, Tool outputs)
	"""
	
	agent_name = "ReportGenerationAgent"
	system_prompt = """You are an expert security report writer following OWASP WSTG 4.2 guidelines.
Your role is to synthesize technical findings into clear, actionable reports for both technical and executive audiences.
Focus on: business impact, clear remediation steps, risk prioritization, and professional presentation."""
	
	disable_llm_planning = True  # This agent doesn't need LLM planning
	
	async def execute(self, target: str = None, shared_context: Dict[str, Any] = None, job_id: int = None) -> Dict[str, Any]:
		"""Generate comprehensive OWASP WSTG 4.2 compliant report"""
		import sys
		print(f"🔥 ReportGenerationAgent.execute() CALLED - job_id={job_id or self.job_id}, target={target}", file=sys.stderr, flush=True)
		self.log("info", "Starting report generation", {"target": target})
		
		# Use self.job_id if job_id not provided
		job_id = job_id or self.job_id
		target = target or self._get_target_from_db()
		
		# Collect all findings from database
		findings = await self._collect_findings(job_id)
		self.log("info", f"Collected {len(findings)} findings from all agents")
		
		# Get job metadata
		job_metadata = await self._get_job_metadata(job_id)
		
		# Build report structure
		report = {
			"metadata": {
				"report_version": "1.0",
				"generated_at": datetime.utcnow().isoformat(),
				"generated_by": "RAJDOLL Multi-Agent Security Scanner",
				"standard": "OWASP WSTG 4.2"
			},
			"introduction": self._build_introduction(target, job_metadata),
			"executive_summary": await self._build_executive_summary(findings, shared_context),
			"findings": self._build_findings_section(findings),
			"appendices": self._build_appendices(shared_context, job_metadata)
		}
		
		# Store report in shared context
		self.shared_context_manager.save(f"final_report_{job_id}", report)
		
		self.log("info", "Report generation completed", {
			"total_findings": len(findings),
			"critical": len([f for f in findings if f.get("severity") == "CRITICAL"]),
			"high": len([f for f in findings if f.get("severity") == "HIGH"]),
			"medium": len([f for f in findings if f.get("severity") == "MEDIUM"]),
			"low": len([f for f in findings if f.get("severity") == "LOW"])
		})
		
		return {"status": "success", "report": report}
	
	async def _collect_findings(self, job_id: int) -> List[Dict[str, Any]]:
		"""Collect all findings from database for this job"""
		findings = []
		
		with get_db() as db:
			db_findings = db.query(Finding).join(JobAgent).filter(
				JobAgent.job_id == job_id
			).all()
			
			for f in db_findings:
				# 🔒 REDACT SENSITIVE DATA: Remove passwords, API keys, PII before export
				redacted_title = data_redactor.redact(f.title or "")
				redacted_description = data_redactor.redact(f.description or "")
				redacted_evidence = data_redactor.redact(f.evidence or "")
				redacted_location = data_redactor.redact(f.location or "")
				
				findings.append({
					"id": f.id,
					"title": redacted_title,
					"description": redacted_description,
					"severity": f.severity,
					"category": f.category,
					"location": redacted_location,
					"evidence": redacted_evidence,
					"remediation": f.remediation,
					"references": f.references,
					"cvss_score": f.cvss_score,
					"agent_name": db.query(JobAgent).get(f.job_agent_id).agent_name if f.job_agent_id else None
				})
		
		return findings
	
	async def _get_job_metadata(self, job_id: int) -> Dict[str, Any]:
		"""Get job metadata from database"""
		with get_db() as db:
			job = db.query(Job).get(job_id)
			if not job:
				return {}
			
			return {
				"target": job.target,
				"name": job.name,
				"created_at": job.created_at.isoformat() if job.created_at else None,
				"completed_at": job.updated_at.isoformat() if job.updated_at else None,
				"status": job.status.value if hasattr(job.status, 'value') else str(job.status)
			}
	
	def _build_introduction(self, target: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
		"""Build Introduction section (OWASP WSTG 4.2 Section 1)"""
		return {
			"version_control": {
				"version": "1.0",
				"date": metadata.get("completed_at", datetime.utcnow().isoformat()),
				"author": "RAJDOLL Multi-Agent System"
			},
			"scope": {
				"target": target,
				"scan_name": metadata.get("name", "Security Assessment"),
				"testing_approach": "Automated Multi-Agent Security Testing based on OWASP WSTG 4.2",
				"coverage": [
					"Information Gathering",
					"Configuration and Deployment Testing",
					"Identity Management",
					"Authentication Testing",
					"Authorization Testing",
					"Session Management",
					"Input Validation",
					"Error Handling",
					"Weak Cryptography",
					"Business Logic",
					"Client-side Testing",
					"API Testing"
				]
			},
			"timeline": {
				"start_time": metadata.get("created_at"),
				"end_time": metadata.get("completed_at"),
				"duration": "Automated scan execution"
			},
			"limitations": [
				"This is an automated security assessment using RAJDOLL multi-agent system",
				"Results represent a point-in-time analysis",
				"Manual verification of findings is recommended",
				"Some complex business logic vulnerabilities may require manual testing",
				"Authentication testing limited to common attack vectors"
			],
			"disclaimer": (
				"This assessment is a 'point in time' evaluation and the environment may have changed since testing. "
				"There is no guarantee that all possible security issues have been identified. "
				"This report serves as a guiding document and not a warranty that it provides a full representation "
				"of all risks threatening the system."
			)
		}
	
	async def _build_executive_summary(self, findings: List[Dict], shared_context: Dict) -> Dict[str, Any]:
		"""Build Executive Summary (OWASP WSTG 4.2 Section 2)"""
		# Count findings by severity
		severity_counts = {
			"CRITICAL": len([f for f in findings if f.get("severity") == "CRITICAL"]),
			"HIGH": len([f for f in findings if f.get("severity") == "HIGH"]),
			"MEDIUM": len([f for f in findings if f.get("severity") == "MEDIUM"]),
			"LOW": len([f for f in findings if f.get("severity") == "LOW"]),
			"INFORMATIONAL": len([f for f in findings if f.get("severity") == "INFORMATIONAL"])
		}
		
		# Overall risk assessment
		overall_risk = "CRITICAL" if severity_counts["CRITICAL"] > 0 else \
					   "HIGH" if severity_counts["HIGH"] > 0 else \
					   "MEDIUM" if severity_counts["MEDIUM"] > 0 else \
					   "LOW" if severity_counts["LOW"] > 0 else \
					   "INFORMATIONAL"
		
		# Key findings (top 5 by severity)
		key_findings = sorted(findings, key=lambda x: {
			"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4
		}.get(x.get("severity", "INFORMATIONAL"), 5))[:5]
		
		return {
			"objective": (
				"To identify security vulnerabilities in the target application using automated "
				"multi-agent testing methodology based on OWASP Web Security Testing Guide 4.2."
			),
			"overall_risk_rating": overall_risk,
			"summary_statistics": {
				"total_findings": len(findings),
				"by_severity": severity_counts
			},
			"key_findings_summary": [
				{
					"title": f.get("title"),
					"severity": f.get("severity"),
					"business_impact": self._get_business_impact(f)
				}
				for f in key_findings
			],
			"strategic_recommendations": [
				"Prioritize remediation of Critical and High severity findings",
				"Implement secure development lifecycle (SDLC) practices",
				"Conduct regular security assessments and penetration testing",
				"Provide security training for development teams",
				"Establish security code review processes",
				"Implement Web Application Firewall (WAF) as defense-in-depth"
			]
		}
	
	def _get_business_impact(self, finding: Dict) -> str:
		"""Map technical findings to business impact"""
		severity = finding.get("severity", "")
		category = finding.get("category", "")
		
		impact_map = {
			"CRITICAL": "Immediate risk of data breach, system compromise, or severe business disruption",
			"HIGH": "Significant risk of unauthorized access, data exposure, or service disruption",
			"MEDIUM": "Moderate risk that could lead to information disclosure or limited access",
			"LOW": "Minor security concern with limited potential impact",
			"INFORMATIONAL": "Security improvement opportunity with no immediate risk"
		}
		
		return impact_map.get(severity, "Requires assessment for business impact")
	
	def _build_findings_section(self, findings: List[Dict]) -> Dict[str, Any]:
		"""Build Findings section (OWASP WSTG 4.2 Section 3)"""
		# Group findings by category
		findings_by_category = {}
		for f in findings:
			category = f.get("category", "Other")
			if category not in findings_by_category:
				findings_by_category[category] = []
			findings_by_category[category].append(f)
		
		# Build findings summary table
		findings_summary = [
			{
				"id": i + 1,
				"title": f.get("title"),
				"severity": f.get("severity"),
				"category": f.get("category"),
				"location": f.get("location")
			}
			for i, f in enumerate(findings)
		]
		
		# Build detailed findings
		detailed_findings = []
		for i, f in enumerate(findings):
			detailed_findings.append({
				"reference_id": f"RAJDOLL-{i+1:04d}",
				"title": f.get("title"),
				"severity": f.get("severity"),
				"cvss_score": f.get("cvss_score"),
				"category": f.get("category"),
				"description": f.get("description"),
				"location": f.get("location"),
				"evidence": f.get("evidence"),
				"impact": self._describe_impact(f),
				"likelihood": self._assess_likelihood(f),
				"remediation": f.get("remediation"),
				"references": f.get("references", []),
				"discovered_by_agent": f.get("agent_name")
			})
		
		return {
			"summary_table": findings_summary,
			"by_category": findings_by_category,
			"detailed_findings": detailed_findings
		}
	
	def _describe_impact(self, finding: Dict) -> str:
		"""Describe the impact of a vulnerability"""
		severity = finding.get("severity", "")
		
		impact_descriptions = {
			"CRITICAL": "Complete system compromise, sensitive data exposure, or critical service disruption",
			"HIGH": "Unauthorized access to sensitive resources, significant data leakage, or service degradation",
			"MEDIUM": "Partial unauthorized access, information disclosure, or limited functionality impact",
			"LOW": "Minor information leakage or minimal impact on system security posture",
			"INFORMATIONAL": "No direct security impact, informational finding for awareness"
		}
		
		return impact_descriptions.get(severity, "Impact requires further assessment")
	
	def _assess_likelihood(self, finding: Dict) -> str:
		"""Assess exploitability likelihood"""
		severity = finding.get("severity", "")
		
		likelihood_map = {
			"CRITICAL": "High - Easily exploitable with publicly available tools",
			"HIGH": "High - Exploitable with moderate effort and common tools",
			"MEDIUM": "Medium - Requires specific conditions or advanced techniques",
			"LOW": "Low - Difficult to exploit or requires significant effort",
			"INFORMATIONAL": "N/A - Informational finding"
		}
		
		return likelihood_map.get(severity, "Requires further analysis")
	
	def _build_appendices(self, shared_context: Dict, metadata: Dict) -> Dict[str, Any]:
		"""Build Appendices section"""
		return {
			"methodology": {
				"framework": "OWASP Web Security Testing Guide v4.2",
				"approach": "Automated Multi-Agent Security Testing",
				"agents_deployed": [
					"ReconnaissanceAgent - Information Gathering",
					"AuthenticationAgent - Authentication Testing",
					"AuthorizationAgent - Authorization Testing",
					"SessionManagementAgent - Session Management Testing",
					"InputValidationAgent - Input Validation Testing",
					"BusinessLogicAgent - Business Logic Testing",
					"ClientSideAgent - Client-side Testing",
					"APITestingAgent - API Security Testing",
					"ErrorHandlingAgent - Error Handling Testing",
					"WeakCryptographyAgent - Cryptography Testing",
					"ConfigDeploymentAgent - Configuration Testing",
					"IdentityManagementAgent - Identity Management Testing",
					"FileUploadAgent - File Upload Testing"
				],
				"tools_used": [
					"Custom MCP-based security testing tools",
					"OWASP ZAP integration",
					"Nuclei vulnerability scanner",
					"SQLMap for SQL injection testing",
					"Dalfox for XSS detection",
					"Custom reconnaissance tools"
				]
			},
			"severity_ratings": {
				"CRITICAL": {
					"description": "Critical risk requiring immediate action",
					"examples": "Remote code execution, SQL injection with data access, authentication bypass"
				},
				"HIGH": {
					"description": "High risk requiring urgent remediation",
					"examples": "Privilege escalation, sensitive data exposure, session hijacking"
				},
				"MEDIUM": {
					"description": "Moderate risk requiring timely remediation",
					"examples": "Information disclosure, CSRF vulnerabilities, weak configurations"
				},
				"LOW": {
					"description": "Low risk for awareness and future improvement",
					"examples": "Verbose error messages, missing security headers, weak password policies"
				},
				"INFORMATIONAL": {
					"description": "Informational finding for security awareness",
					"examples": "Technology stack information, best practice recommendations"
				}
			},
			"shared_context_summary": {
				"tech_stack": shared_context.get("tech_stack", {}),
				"entry_points": len(shared_context.get("entry_points", [])),
				"total_tests_executed": shared_context.get("total_tests", 0)
			},
			"wstg_checklist_reference": "https://github.com/OWASP/wstg/tree/master/checklist"
		}
