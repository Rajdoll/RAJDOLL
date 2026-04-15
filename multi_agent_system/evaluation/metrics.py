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
from urllib.parse import urlparse

import numpy as np
from scipy.stats import pearsonr
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..models.models import Job, JobAgent, Finding, AgentStatus, JobStatus, FindingSeverity
from ..models.ground_truth import GroundTruthEntry


@dataclass
class MetricsResult:
    """Container for evaluation metrics"""
    precision: Optional[float]
    recall: Optional[float]
    f1_score: Optional[float]
    false_negative_rate: Optional[float]
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
    """Manage ground truth data — reads from DB, not hardcoded dicts."""

    @staticmethod
    def derive_profile(target_url: str) -> str:
        """Derive a stable profile key from a target URL hostname."""
        parsed = urlparse(target_url)
        hostname = parsed.hostname or target_url
        return hostname.lower()

    def get_ground_truth(self, target_url: str, db: Session) -> List[GroundTruthEntry]:
        """Load ground truth entries for target from the database."""
        profile = self.derive_profile(target_url)
        return db.query(GroundTruthEntry).filter(
            GroundTruthEntry.target_profile == profile
        ).all()


class EffectivenessMetrics:
    """Calculate effectiveness metrics (precision, recall, F1-score, etc.)"""
    
    def __init__(self):
        self.ground_truth_manager = GroundTruthManager()
    
    def calculate_precision(self, findings: List[Finding]) -> Optional[float]:
        """
        Precision = TP / (TP + FP) from manual researcher labels.
        Returns None when no findings have been reviewed yet.
        """
        reviewed = [f for f in findings if f.is_true_positive is not None]
        if not reviewed:
            return None
        tp = sum(1 for f in reviewed if f.is_true_positive is True)
        fp = sum(1 for f in reviewed if f.is_true_positive is False)
        if tp + fp == 0:
            return 0.0
        return round((tp / (tp + fp)) * 100, 2)
    
    def calculate_recall(
        self,
        findings: List[Finding],
        ground_truth: List[GroundTruthEntry],
    ) -> Optional[float]:
        """
        Recall = detected GT entries / total GT entries.
        Returns None when no ground truth exists for this target.
        """
        if not ground_truth:
            return None
        detected = set()
        for f in findings:
            for gt in ground_truth:
                if self._matches(f, gt):
                    detected.add(gt.id)
        return round((len(detected) / len(ground_truth)) * 100, 2)
    
    def calculate_f1_score(self, precision: Optional[float], recall: Optional[float]) -> Optional[float]:
        """
        Calculate F1-Score (harmonic mean of precision and recall).
        Returns None when either input is None.
        """
        if precision is None or recall is None:
            return None
        if precision + recall == 0:
            return 0.0
        return round(2 * (precision * recall) / (precision + recall), 2)
    
    def calculate_false_negative_rate(
        self,
        findings: List[Finding],
        ground_truth: List[GroundTruthEntry],
    ) -> Optional[float]:
        """
        Calculate False Negative Rate = 100 - Recall.
        Returns None when no ground truth exists.
        """
        recall = self.calculate_recall(findings, ground_truth)
        if recall is None:
            return None
        return round(100 - recall, 2)
    
    def calculate_severity_accuracy(
        self,
        findings: List[Finding],
        ground_truth: List[GroundTruthEntry],
    ) -> float:
        """
        Calculate severity classification accuracy.

        Returns:
            Accuracy percentage (0-100)
        """
        correct = 0
        total = 0

        for finding in findings:
            for gt in ground_truth:
                if self._matches(finding, gt):
                    total += 1
                    expected_severity = gt.severity
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
        ground_truth: List[GroundTruthEntry],
    ) -> Tuple[float, float]:
        """
        Calculate Pearson correlation between system CVSS and expert CVSS.

        Returns:
            (correlation_coefficient, p_value)
        """
        system_scores = []
        expert_scores = []

        for finding in findings:
            for gt in ground_truth:
                if self._matches(finding, gt):
                    if finding.cvss_score_v4 and gt.cvss:
                        system_scores.append(finding.cvss_score_v4)
                        expert_scores.append(gt.cvss)

        if len(system_scores) < 2:
            return 0.0, 1.0

        r, p_value = pearsonr(system_scores, expert_scores)
        return round(r, 3), round(p_value, 4)
    
    def _get_finding_signature(self, finding: Finding) -> str:
        """Generate unique signature for finding"""
        return f"{finding.category}:{finding.title.lower()}:{finding.agent_name}"

    def _matches(self, finding: Finding, gt: GroundTruthEntry) -> bool:
        """Category must match; at least 2 vuln_name keywords in finding text."""
        if finding.category != gt.category:
            return False
        keywords = gt.vuln_name.lower().replace("-", " ").replace("_", " ").split()
        finding_text = (finding.title + " " + (finding.details or "")).lower()
        return sum(1 for kw in keywords if kw in finding_text) >= 2


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
        return f"{finding.category}:{finding.title}:{finding.agent_name}"


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
            ground_truth = self.ground_truth_manager.get_ground_truth(target, db)

            # Effectiveness metrics
            precision = self.effectiveness.calculate_precision(findings)
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
    
    @staticmethod
    def _fmt_pct(val: Optional[float], decimals: int = 2) -> str:
        if val is None:
            return "N/A (pending review)"
        return f"{val:.{decimals}f}%"

    def print_metrics_report(self, metrics: MetricsResult, job_id: int):
        """Print formatted metrics report"""
        print("\n" + "="*70)
        print(f"EVALUATION METRICS REPORT - Job #{job_id}")
        print("="*70)

        print("\n📊 EFFECTIVENESS METRICS:")
        print(f"  Precision:           {self._fmt_pct(metrics.precision)} (Target: ≥90%)")
        print(f"  Recall:              {self._fmt_pct(metrics.recall)} (Target: ≥80%)")
        print(f"  F1-Score:            {self._fmt_pct(metrics.f1_score)} (Target: ≥85%)")
        print(f"  False Negative Rate: {self._fmt_pct(metrics.false_negative_rate)} (Target: ≤20%)")
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
            metrics.f1_score is not None and metrics.f1_score >= 85,
            metrics.ttff_seconds <= 300,
            metrics.total_scan_hours <= 4,
            metrics.tcr_percentage >= 70,
            metrics.crash_rate <= 2
        ]

        if all(passing_criteria):
            print("✅ SYSTEM PASSES ALL ACCEPTANCE CRITERIA")
        else:
            print("⚠️  SYSTEM NEEDS IMPROVEMENT")
            if metrics.f1_score is None:
                print("   - F1-Score pending review (validate findings as TP/FP first)")
            elif metrics.f1_score < 85:
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
