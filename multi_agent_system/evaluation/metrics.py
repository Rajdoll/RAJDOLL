"""
Evaluation Metrics Module

Implements comprehensive metrics for measuring system effectiveness,
efficiency, coverage, and reliability based on academic standards.

Author: Martua Raja Doli Pangaribuan
Version: 2.0
Last Updated: December 14, 2025
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass

import numpy as np
from scipy.stats import pearsonr
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..models.models import Job, JobAgent, Finding, AgentStatus, JobStatus, FindingSeverity


@dataclass
class MetricsResult:
    """Container for evaluation metrics"""
    precision: float
    recall: float
    f1_score: float
    false_negative_rate: float
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


class GroundTruthManager:
    """Manage ground truth data for known vulnerable applications"""
    
    # DVWA Known Vulnerabilities (25 total)
    DVWA_GROUND_TRUTH = {
        "sqli_login": {"severity": "critical", "cvss": 9.8, "category": "WSTG-INPV-05"},
        "sqli_search": {"severity": "critical", "cvss": 9.8, "category": "WSTG-INPV-05"},
        "xss_reflected": {"severity": "high", "cvss": 7.5, "category": "WSTG-INPV-01"},
        "xss_stored": {"severity": "high", "cvss": 8.0, "category": "WSTG-INPV-01"},
        "xss_dom": {"severity": "high", "cvss": 7.5, "category": "WSTG-INPV-01"},
        "csrf_change_password": {"severity": "high", "cvss": 8.0, "category": "WSTG-SESS-05"},
        "file_inclusion": {"severity": "critical", "cvss": 9.0, "category": "WSTG-INPV-12"},
        "file_upload": {"severity": "critical", "cvss": 9.5, "category": "WSTG-BUSL-08"},
        "command_injection": {"severity": "critical", "cvss": 9.8, "category": "WSTG-INPV-12"},
        "weak_session_ids": {"severity": "high", "cvss": 7.0, "category": "WSTG-SESS-01"},
        "brute_force": {"severity": "high", "cvss": 7.5, "category": "WSTG-ATHN-03"},
        "insecure_captcha": {"severity": "medium", "cvss": 5.0, "category": "WSTG-ATHN-03"},
        "weak_ssl": {"severity": "medium", "cvss": 5.3, "category": "WSTG-CRYP-01"},
        "javascript_injection": {"severity": "medium", "cvss": 6.0, "category": "WSTG-CLNT-02"},
        "open_redirect": {"severity": "medium", "cvss": 5.4, "category": "WSTG-CLNT-04"},
        "info_disclosure": {"severity": "low", "cvss": 3.1, "category": "WSTG-INFO-05"},
        "missing_headers": {"severity": "low", "cvss": 3.7, "category": "WSTG-CONF-06"},
        "directory_traversal": {"severity": "high", "cvss": 7.5, "category": "WSTG-ATHZ-01"},
        "authentication_bypass": {"severity": "critical", "cvss": 9.1, "category": "WSTG-ATHN-04"},
        "privilege_escalation": {"severity": "critical", "cvss": 8.8, "category": "WSTG-AUTHZ-03"},
        "xxe_injection": {"severity": "high", "cvss": 8.2, "category": "WSTG-INPV-07"},
        "ldap_injection": {"severity": "high", "cvss": 7.7, "category": "WSTG-INPV-06"},
        "xpath_injection": {"severity": "high", "cvss": 7.5, "category": "WSTG-INPV-09"},
        "insecure_deserialization": {"severity": "critical", "cvss": 9.0, "category": "WSTG-INPV-05"},
        "server_side_include": {"severity": "high", "cvss": 7.2, "category": "WSTG-INPV-08"}
    }
    
    # OWASP Juice Shop Known Vulnerabilities (~100 total, subset shown)
    JUICE_SHOP_GROUND_TRUTH = {
        # Authentication
        "admin_section_access": {"severity": "critical", "cvss": 9.1, "category": "WSTG-ATHN-04"},
        "password_strength": {"severity": "medium", "cvss": 5.3, "category": "WSTG-ATHN-07"},
        "jwt_secret": {"severity": "critical", "cvss": 9.8, "category": "WSTG-ATHN-06"},
        
        # Injection
        "sqli_products": {"severity": "critical", "cvss": 9.8, "category": "WSTG-INPV-05"},
        "sqli_login": {"severity": "critical", "cvss": 9.8, "category": "WSTG-INPV-05"},
        "xss_search": {"severity": "high", "cvss": 7.5, "category": "WSTG-INPV-01"},
        "xss_tracker": {"severity": "high", "cvss": 7.5, "category": "WSTG-INPV-01"},
        
        # Broken Access Control
        "admin_endpoints": {"severity": "critical", "cvss": 8.8, "category": "WSTG-AUTHZ-02"},
        "basket_manipulation": {"severity": "high", "cvss": 7.5, "category": "WSTG-AUTHZ-04"},
        
        # Add more as needed...
    }
    
    def get_ground_truth(self, target: str) -> Dict[str, Dict]:
        """Get ground truth for specific target"""
        if "dvwa" in target.lower():
            return self.DVWA_GROUND_TRUTH
        elif "juice" in target.lower():
            return self.JUICE_SHOP_GROUND_TRUTH
        else:
            return {}


class EffectivenessMetrics:
    """Calculate effectiveness metrics (precision, recall, F1-score, etc.)"""
    
    def __init__(self):
        self.ground_truth_manager = GroundTruthManager()
    
    def calculate_precision(
        self, 
        findings: List[Finding], 
        ground_truth: Dict[str, Dict]
    ) -> float:
        """
        Calculate precision (positive predictive value)
        
        Precision = TP / (TP + FP)
        
        Returns:
            Precision percentage (0-100)
        """
        if not findings:
            return 0.0
        
        true_positives = 0
        false_positives = 0
        
        for finding in findings:
            signature = self._get_finding_signature(finding)
            
            if self._matches_ground_truth(signature, finding, ground_truth):
                true_positives += 1
            else:
                false_positives += 1
        
        if true_positives + false_positives == 0:
            return 0.0
        
        precision = (true_positives / (true_positives + false_positives)) * 100
        return round(precision, 2)
    
    def calculate_recall(
        self, 
        findings: List[Finding], 
        ground_truth: Dict[str, Dict]
    ) -> float:
        """
        Calculate recall (sensitivity / true positive rate)
        
        Recall = TP / (TP + FN)
        
        Returns:
            Recall percentage (0-100)
        """
        if not ground_truth:
            return 0.0
        
        detected = set()
        
        for finding in findings:
            signature = self._get_finding_signature(finding)
            
            for vuln_name, vuln_data in ground_truth.items():
                if self._matches_vulnerability(finding, vuln_name, vuln_data):
                    detected.add(vuln_name)
        
        true_positives = len(detected)
        false_negatives = len(ground_truth) - true_positives
        
        recall = (true_positives / len(ground_truth)) * 100
        return round(recall, 2)
    
    def calculate_f1_score(self, precision: float, recall: float) -> float:
        """
        Calculate F1-Score (harmonic mean of precision and recall)
        
        F1 = 2 * (Precision * Recall) / (Precision + Recall)
        
        Returns:
            F1-Score (0-100)
        """
        if precision + recall == 0:
            return 0.0
        
        f1 = 2 * (precision * recall) / (precision + recall)
        return round(f1, 2)
    
    def calculate_false_negative_rate(
        self, 
        findings: List[Finding], 
        ground_truth: Dict[str, Dict]
    ) -> float:
        """
        Calculate False Negative Rate
        
        FNR = FN / (FN + TP)
        
        Returns:
            FNR percentage (0-100)
        """
        recall = self.calculate_recall(findings, ground_truth)
        fnr = 100 - recall
        return round(fnr, 2)
    
    def calculate_severity_accuracy(
        self,
        findings: List[Finding],
        ground_truth: Dict[str, Dict]
    ) -> float:
        """
        Calculate severity classification accuracy
        
        Returns:
            Accuracy percentage (0-100)
        """
        correct = 0
        total = 0
        
        for finding in findings:
            for vuln_name, vuln_data in ground_truth.items():
                if self._matches_vulnerability(finding, vuln_name, vuln_data):
                    total += 1
                    expected_severity = vuln_data["severity"]
                    actual_severity = finding.severity.value
                    
                    if expected_severity == actual_severity:
                        correct += 1
        
        if total == 0:
            return 0.0
        
        accuracy = (correct / total) * 100
        return round(accuracy, 2)
    
    def calculate_cvss_correlation(
        self,
        findings: List[Finding],
        ground_truth: Dict[str, Dict]
    ) -> Tuple[float, float]:
        """
        Calculate Pearson correlation between system CVSS and expert CVSS
        
        Returns:
            (correlation_coefficient, p_value)
        """
        system_scores = []
        expert_scores = []
        
        for finding in findings:
            for vuln_name, vuln_data in ground_truth.items():
                if self._matches_vulnerability(finding, vuln_name, vuln_data):
                    if finding.cvss_score and vuln_data.get("cvss"):
                        system_scores.append(finding.cvss_score)
                        expert_scores.append(vuln_data["cvss"])
        
        if len(system_scores) < 2:
            return 0.0, 1.0
        
        r, p_value = pearsonr(system_scores, expert_scores)
        return round(r, 3), round(p_value, 4)
    
    def _get_finding_signature(self, finding: Finding) -> str:
        """Generate unique signature for finding"""
        return f"{finding.category}:{finding.title.lower()}:{finding.location}"
    
    def _matches_ground_truth(
        self, 
        signature: str, 
        finding: Finding, 
        ground_truth: Dict[str, Dict]
    ) -> bool:
        """Check if finding matches any ground truth vulnerability"""
        for vuln_name, vuln_data in ground_truth.items():
            if self._matches_vulnerability(finding, vuln_name, vuln_data):
                return True
        return False
    
    def _matches_vulnerability(
        self, 
        finding: Finding, 
        vuln_name: str, 
        vuln_data: Dict
    ) -> bool:
        """Check if finding matches specific vulnerability"""
        # Match by category
        if finding.category != vuln_data["category"]:
            return False
        
        # Match by keywords in title or description
        keywords = vuln_name.lower().replace("_", " ").split()
        finding_text = (finding.title + " " + finding.description).lower()
        
        # At least 2 keywords must match
        matches = sum(1 for kw in keywords if kw in finding_text)
        return matches >= 2


class EfficiencyMetrics:
    """Calculate efficiency metrics (time-based)"""
    
    def calculate_ttff(self, job_id: int) -> Optional[float]:
        """
        Calculate Time to First Finding (TTFF)
        
        Returns:
            Seconds from job start to first finding, or None if no findings
        """
        with get_db() as db:
            job = db.query(Job).get(job_id)
            if not job:
                return None
            
            first_finding = db.query(Finding)\
                .filter(Finding.job_id == job_id)\
                .order_by(Finding.created_at)\
                .first()
            
            if not first_finding:
                return None
            
            ttff = (first_finding.created_at - job.created_at).total_seconds()
            return round(ttff, 2)
    
    def calculate_total_scan_time(self, job_id: int) -> Optional[float]:
        """
        Calculate total scan duration
        
        Returns:
            Hours from start to completion, or None if not completed
        """
        with get_db() as db:
            job = db.query(Job).get(job_id)
            
            if not job or job.status != JobStatus.completed:
                return None
            
            duration_seconds = (job.updated_at - job.created_at).total_seconds()
            duration_hours = duration_seconds / 3600
            return round(duration_hours, 2)
    
    def calculate_time_per_test_case(self, job_id: int) -> Optional[float]:
        """
        Calculate average time per WSTG test case
        
        Returns:
            Minutes per test case
        """
        with get_db() as db:
            completed_agents = db.query(JobAgent).filter(
                JobAgent.job_id == job_id,
                JobAgent.status == AgentStatus.completed
            ).all()
            
            total_duration = 0
            test_case_count = 0
            
            for agent in completed_agents:
                if agent.finished_at and agent.started_at:
                    duration = (agent.finished_at - agent.started_at).total_seconds()
                    total_duration += duration
                    
                    # Approximate test cases per agent
                    test_case_count += self._get_test_case_count(agent.agent_name)
            
            if test_case_count == 0:
                return None
            
            avg_time = (total_duration / 60) / test_case_count
            return round(avg_time, 2)
    
    def _get_test_case_count(self, agent_name: str) -> int:
        """Approximate number of WSTG test cases per agent"""
        test_case_counts = {
            "ReconnaissanceAgent": 10,
            "ConfigDeploymentAgent": 8,
            "AuthenticationAgent": 10,
            "AuthorizationAgent": 8,
            "SessionManagementAgent": 9,
            "InputValidationAgent": 20,
            "ErrorHandlingAgent": 6,
            "WeakCryptographyAgent": 9,
            "BusinessLogicAgent": 11,
            "FileUploadAgent": 3,
            "APITestingAgent": 10,
            "ClientSideAgent": 13
        }
        return test_case_counts.get(agent_name, 5)


class CoverageMetrics:
    """Calculate coverage metrics (TCR, OWASP Top 10, attack surface)"""
    
    def calculate_tcr(self, job_id: int) -> float:
        """
        Calculate Task Completion Rate
        
        Returns:
            Percentage of WSTG test cases completed (0-100)
        """
        with get_db() as db:
            completed_agents = db.query(JobAgent).filter(
                JobAgent.job_id == job_id,
                JobAgent.status == AgentStatus.completed
            ).count()
            
            # Total agents (excluding reporting agent)
            total_agents = 12  # 13 minus ReportGenerationAgent
            
            tcr = (completed_agents / total_agents) * 100
            return round(tcr, 2)
    
    def calculate_owasp_top10_coverage(self, findings: List[Finding]) -> float:
        """
        Calculate OWASP Top 10 2021 coverage
        
        Returns:
            Percentage of Top 10 risks covered (0-100)
        """
        OWASP_TOP_10_MAPPING = {
            "A01": ["WSTG-AUTHZ", "WSTG-SESS"],
            "A02": ["WSTG-CRYP"],
            "A03": ["WSTG-INPV"],
            "A04": ["WSTG-BUSL"],
            "A05": ["WSTG-CONF"],
            "A06": ["WSTG-CONF-06"],
            "A07": ["WSTG-ATHN"],
            "A08": ["WSTG-BUSL"],
            "A09": ["WSTG-ERRH"],
            "A10": ["WSTG-INPV-19"]
        }
        
        covered_risks = set()
        
        for finding in findings:
            for risk, wstg_ids in OWASP_TOP_10_MAPPING.items():
                if any(wstg_id in finding.category for wstg_id in wstg_ids):
                    covered_risks.add(risk)
        
        coverage = (len(covered_risks) / 10) * 100
        return round(coverage, 2)
    
    def calculate_attack_surface_coverage(self, job_id: int) -> float:
        """
        Calculate percentage of discovered endpoints that were tested
        
        Returns:
            Coverage percentage (0-100)
        """
        with get_db() as db:
            # Get reconnaissance context
            recon_agent = db.query(JobAgent).filter(
                JobAgent.job_id == job_id,
                JobAgent.agent_name == "ReconnaissanceAgent"
            ).first()
            
            if not recon_agent or not recon_agent.context:
                return 0.0
            
            endpoints = recon_agent.context.get("endpoints", [])
            total_endpoints = len(endpoints)
            
            if total_endpoints == 0:
                return 0.0
            
            # Get tested endpoints from findings
            findings = db.query(Finding).filter(Finding.job_id == job_id).all()
            tested_endpoints = set(f.location for f in findings if f.location)
            
            coverage = (len(tested_endpoints) / total_endpoints) * 100
            return round(coverage, 2)


class ReliabilityMetrics:
    """Calculate reliability metrics (crash rate, recovery rate, consistency)"""
    
    def calculate_crash_rate(self, time_period_days: int = 30) -> float:
        """
        Calculate system crash rate over time period
        
        Returns:
            Crash rate percentage (0-100)
        """
        with get_db() as db:
            start_date = datetime.utcnow() - timedelta(days=time_period_days)
            
            total_jobs = db.query(Job).filter(
                Job.created_at >= start_date
            ).count()
            
            if total_jobs == 0:
                return 0.0
            
            failed_jobs = db.query(Job).filter(
                Job.created_at >= start_date,
                Job.status == JobStatus.failed
            ).count()
            
            crash_rate = (failed_jobs / total_jobs) * 100
            return round(crash_rate, 2)
    
    def calculate_recovery_rate(self, job_id: int) -> float:
        """
        Calculate recovery success rate for failed operations
        
        Returns:
            Recovery rate percentage (0-100)
        """
        with get_db() as db:
            agents = db.query(JobAgent).filter(
                JobAgent.job_id == job_id
            ).all()
            
            successful_recoveries = sum(
                agent.attempts - 1 for agent in agents
                if agent.status == AgentStatus.completed and agent.attempts > 1
            )
            
            total_failures = sum(
                agent.attempts - 1 for agent in agents
                if agent.attempts > 1
            )
            
            if total_failures == 0:
                return 100.0
            
            recovery_rate = (successful_recoveries / total_failures) * 100
            return round(recovery_rate, 2)
    
    def calculate_consistency(self, job_ids: List[int]) -> float:
        """
        Calculate consistency of findings across multiple scans
        
        Args:
            job_ids: List of job IDs for same target (different runs)
        
        Returns:
            Consistency percentage (0-100)
        """
        with get_db() as db:
            all_finding_sets = []
            
            for job_id in job_ids:
                findings = db.query(Finding).filter(Finding.job_id == job_id).all()
                signatures = {self._get_finding_signature(f) for f in findings}
                all_finding_sets.append(signatures)
            
            if not all_finding_sets:
                return 0.0
            
            # Intersection (found in ALL scans)
            consistent_findings = set.intersection(*all_finding_sets)
            
            # Union (all unique findings)
            all_unique_findings = set.union(*all_finding_sets)
            
            if len(all_unique_findings) == 0:
                return 0.0
            
            consistency = (len(consistent_findings) / len(all_unique_findings)) * 100
            return round(consistency, 2)
    
    def _get_finding_signature(self, finding: Finding) -> str:
        """Generate unique signature for finding"""
        return f"{finding.category}:{finding.title}:{finding.location}"


class MetricsCalculator:
    """Main class for calculating all evaluation metrics"""
    
    def __init__(self):
        self.effectiveness = EffectivenessMetrics()
        self.efficiency = EfficiencyMetrics()
        self.coverage = CoverageMetrics()
        self.reliability = ReliabilityMetrics()
        self.ground_truth_manager = GroundTruthManager()
    
    def calculate_all_metrics(self, job_id: int, target: str) -> MetricsResult:
        """
        Calculate all evaluation metrics for a job
        
        Args:
            job_id: Job ID to evaluate
            target: Target URL (for ground truth lookup)
        
        Returns:
            MetricsResult with all calculated metrics
        """
        with get_db() as db:
            findings = db.query(Finding).filter(Finding.job_id == job_id).all()
            ground_truth = self.ground_truth_manager.get_ground_truth(target)
            
            # Effectiveness metrics
            precision = self.effectiveness.calculate_precision(findings, ground_truth)
            recall = self.effectiveness.calculate_recall(findings, ground_truth)
            f1_score = self.effectiveness.calculate_f1_score(precision, recall)
            fnr = self.effectiveness.calculate_false_negative_rate(findings, ground_truth)
            severity_accuracy = self.effectiveness.calculate_severity_accuracy(findings, ground_truth)
            cvss_corr, cvss_p = self.effectiveness.calculate_cvss_correlation(findings, ground_truth)
            
            # Efficiency metrics
            ttff = self.efficiency.calculate_ttff(job_id) or 0.0
            scan_time = self.efficiency.calculate_total_scan_time(job_id) or 0.0
            
            # Coverage metrics
            tcr = self.coverage.calculate_tcr(job_id)
            owasp_top10 = self.coverage.calculate_owasp_top10_coverage(findings)
            attack_surface = self.coverage.calculate_attack_surface_coverage(job_id)
            
            # Reliability metrics
            crash_rate = self.reliability.calculate_crash_rate()
            recovery_rate = self.reliability.calculate_recovery_rate(job_id)
            
            return MetricsResult(
                precision=precision,
                recall=recall,
                f1_score=f1_score,
                false_negative_rate=fnr,
                severity_accuracy=severity_accuracy,
                cvss_correlation=cvss_corr,
                cvss_p_value=cvss_p,
                ttff_seconds=ttff,
                total_scan_hours=scan_time,
                tcr_percentage=tcr,
                owasp_top10_coverage=owasp_top10,
                attack_surface_coverage=attack_surface,
                crash_rate=crash_rate,
                recovery_rate=recovery_rate,
                consistency_score=0.0  # Requires multiple runs
            )
    
    def print_metrics_report(self, metrics: MetricsResult, job_id: int):
        """Print formatted metrics report"""
        print("\n" + "="*70)
        print(f"EVALUATION METRICS REPORT - Job #{job_id}")
        print("="*70)
        
        print("\n📊 EFFECTIVENESS METRICS:")
        print(f"  Precision:           {metrics.precision:.2f}% (Target: ≥90%)")
        print(f"  Recall:              {metrics.recall:.2f}% (Target: ≥80%)")
        print(f"  F1-Score:            {metrics.f1_score:.2f}% (Target: ≥85%)")
        print(f"  False Negative Rate: {metrics.false_negative_rate:.2f}% (Target: ≤20%)")
        print(f"  Severity Accuracy:   {metrics.severity_accuracy:.2f}% (Target: ≥80%)")
        print(f"  CVSS Correlation:    {metrics.cvss_correlation:.3f} (Target: ≥0.7)")
        
        print("\n⚡ EFFICIENCY METRICS:")
        print(f"  TTFF:                {metrics.ttff_seconds:.1f}s (Target: ≤300s)")
        print(f"  Total Scan Time:     {metrics.total_scan_hours:.2f}h (Target: ≤4h)")
        
        print("\n📋 COVERAGE METRICS:")
        print(f"  TCR:                 {metrics.tcr_percentage:.1f}% (Target: ≥70%)")
        print(f"  OWASP Top 10:        {metrics.owasp_top10_coverage:.1f}% (Target: ≥80%)")
        print(f"  Attack Surface:      {metrics.attack_surface_coverage:.1f}% (Target: ≥90%)")
        
        print("\n🛡️  RELIABILITY METRICS:")
        print(f"  Crash Rate:          {metrics.crash_rate:.2f}% (Target: ≤2%)")
        print(f"  Recovery Rate:       {metrics.recovery_rate:.1f}% (Target: ≥90%)")
        
        print("\n" + "="*70)
        
        # Overall assessment
        passing_criteria = [
            metrics.f1_score >= 85,
            metrics.ttff_seconds <= 300,
            metrics.total_scan_hours <= 4,
            metrics.tcr_percentage >= 70,
            metrics.crash_rate <= 2
        ]
        
        if all(passing_criteria):
            print("✅ SYSTEM PASSES ALL ACCEPTANCE CRITERIA")
        else:
            print("⚠️  SYSTEM NEEDS IMPROVEMENT")
            if metrics.f1_score < 85:
                print("   - F1-Score below target (improve detection accuracy)")
            if metrics.ttff_seconds > 300:
                print("   - TTFF too slow (optimize reconnaissance phase)")
            if metrics.total_scan_hours > 4:
                print("   - Total scan time exceeds target (optimize tool execution)")
            if metrics.tcr_percentage < 70:
                print("   - Test coverage insufficient (enable more test cases)")
            if metrics.crash_rate > 2:
                print("   - System reliability needs improvement (fix crashes)")
        
        print("="*70 + "\n")
