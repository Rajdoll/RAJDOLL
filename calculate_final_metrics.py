#!/usr/bin/env python3
"""
Day 10 Final Metrics Calculation Script
========================================

Calculates research metrics for thesis Chapter 4 (Results):
- Precision: TP / (TP + FP) ≥ 90%
- Recall: TP / (TP + FN) ≥ 80%
- F1-Score: 2 * (Precision * Recall) / (Precision + Recall) ≥ 85%
- Task Completion Rate (TCR): Completed WSTG tests / Total WSTG tests ≥ 70%

Ground Truth: OWASP Juice Shop has 102 documented vulnerabilities
"""

import requests
import json
from typing import Dict, List, Any, Tuple
from datetime import datetime
from collections import defaultdict

# Configuration
API_URL = "http://localhost:8000/api"
JUICE_SHOP_TARGET = "http://juice-shop:3000"

# OWASP Juice Shop Ground Truth (102 vulnerabilities)
# Source: https://pwning.owasp-juice.shop/
JUICE_SHOP_VULNERABILITIES = {
    # Injection (WSTG-INPV)
    "SQLi": 14,  # SQL Injection vulnerabilities
    "XSS": 19,   # Cross-Site Scripting vulnerabilities
    "XXE": 1,    # XML External Entity
    "Command Injection": 1,
    "Template Injection": 1,

    # Authentication (WSTG-ATHN)
    "Weak Passwords": 8,
    "Password Reset Flaws": 3,
    "2FA Bypass": 1,
    "Admin Account Access": 4,

    # Authorization (WSTG-AUTHZ)
    "Privilege Escalation": 5,
    "IDOR": 7,  # Insecure Direct Object Reference
    "Path Traversal": 2,

    # Session Management (WSTG-SESS)
    "JWT Vulnerabilities": 4,
    "Session Fixation": 1,
    "Cookie Security": 3,

    # Cryptography (WSTG-CRYP)
    "Weak Crypto": 2,
    "Plaintext Secrets": 3,

    # Business Logic (WSTG-BUSL)
    "Race Conditions": 2,
    "Business Flaws": 6,
    "Price Manipulation": 3,

    # Client-Side (WSTG-CLNT)
    "DOM XSS": 5,
    "Client-Side Validation": 4,

    # API Testing (WSTG-APIT)
    "API Security": 3,

    # Error Handling (WSTG-ERRH)
    "Information Disclosure": 4,

    # Configuration (WSTG-CONF)
    "Misconfigurations": 2,
}

TOTAL_GROUND_TRUTH = sum(JUICE_SHOP_VULNERABILITIES.values())

# OWASP WSTG 4.2 Test Cases (for TCR calculation)
WSTG_TEST_CASES = {
    "WSTG-INFO": 10,  # Information Gathering
    "WSTG-CONF": 11,  # Configuration Testing
    "WSTG-IDNT": 5,   # Identity Management
    "WSTG-ATHN": 10,  # Authentication Testing
    "WSTG-AUTHZ": 4,  # Authorization Testing
    "WSTG-SESS": 9,   # Session Management
    "WSTG-INPV": 19,  # Input Validation
    "WSTG-ERRH": 2,   # Error Handling
    "WSTG-CRYP": 4,   # Cryptography
    "WSTG-BUSL": 9,   # Business Logic
    "WSTG-CLNT": 13,  # Client-Side Testing
    "WSTG-APIT": 1,   # API Testing
}

TOTAL_WSTG_TESTS = sum(WSTG_TEST_CASES.values())


class MetricsCalculator:
    """Calculate research metrics for Day 10 validation."""

    def __init__(self, job_id: int):
        self.job_id = job_id
        self.findings = []
        self.job_data = None

    def fetch_job_data(self) -> bool:
        """Fetch job data from API."""
        try:
            response = requests.get(f"{API_URL}/scans/{self.job_id}")
            response.raise_for_status()
            self.job_data = response.json()

            response = requests.get(f"{API_URL}/scans/{self.job_id}/findings")
            response.raise_for_status()
            self.findings = response.json()

            print(f"✅ Fetched Job {self.job_id}: {len(self.findings)} findings")
            return True
        except Exception as e:
            print(f"❌ Error fetching job data: {e}")
            return False

    def classify_findings(self) -> Tuple[List[Dict], List[Dict], List[str]]:
        """
        Classify findings as True Positive (TP) or False Positive (FP).

        Returns:
            (true_positives, false_positives, manual_review_needed)
        """
        true_positives = []
        false_positives = []
        manual_review = []

        # Auto-classification heuristics
        TP_INDICATORS = [
            "SQLi", "SQL injection", "XSS", "cross-site scripting",
            "JWT", "authentication bypass", "IDOR", "privilege escalation",
            "path traversal", "XXE", "command injection", "CSRF",
            "session fixation", "weak password", "information disclosure",
            "API exposure", "misconfiguration", "DOM XSS", "business logic"
        ]

        FP_INDICATORS = [
            "informational", "low confidence", "potential",
            "may be vulnerable", "possible", "unconfirmed"
        ]

        for finding in self.findings:
            title = finding.get("title", "").lower()
            description = finding.get("description", "").lower()
            severity = finding.get("severity", "").lower()

            # High/Critical severity are likely TP
            if severity in ["critical", "high"]:
                # Check if it matches known vulnerability patterns
                if any(indicator.lower() in title or indicator.lower() in description
                       for indicator in TP_INDICATORS):
                    true_positives.append(finding)
                else:
                    manual_review.append(f"High severity but unclear: {finding.get('title')}")

            # Info severity needs manual review
            elif severity in ["info", "informational"]:
                manual_review.append(f"Info finding: {finding.get('title')}")

            # Medium severity - check indicators
            elif severity == "medium":
                if any(indicator.lower() in title or indicator.lower() in description
                       for indicator in TP_INDICATORS):
                    true_positives.append(finding)
                elif any(indicator.lower() in title or indicator.lower() in description
                         for indicator in FP_INDICATORS):
                    false_positives.append(finding)
                else:
                    manual_review.append(f"Medium severity needs review: {finding.get('title')}")

            else:
                manual_review.append(f"Unknown severity: {finding.get('title')}")

        return true_positives, false_positives, manual_review

    def calculate_precision_recall(self, tp_count: int, fp_count: int) -> Dict[str, float]:
        """Calculate Precision, Recall, and F1-Score."""
        # Precision = TP / (TP + FP)
        precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0

        # Recall = TP / (TP + FN) where FN = Ground Truth - TP
        fn_count = TOTAL_GROUND_TRUTH - tp_count
        recall = tp_count / TOTAL_GROUND_TRUTH if TOTAL_GROUND_TRUTH > 0 else 0

        # F1-Score = 2 * (Precision * Recall) / (Precision + Recall)
        f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        return {
            "true_positives": tp_count,
            "false_positives": fp_count,
            "false_negatives": fn_count,
            "total_findings": tp_count + fp_count,
            "ground_truth": TOTAL_GROUND_TRUTH,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "precision_pct": precision * 100,
            "recall_pct": recall * 100,
            "f1_score_pct": f1_score * 100,
        }

    def calculate_tcr(self) -> Dict[str, Any]:
        """Calculate Task Completion Rate (TCR) based on OWASP WSTG coverage."""
        if not self.job_data:
            return {}

        agents_executed = [
            agent["agent_name"]
            for agent in self.job_data.get("agents", [])
            if agent.get("status") == "completed"
        ]

        # Map agents to WSTG categories
        agent_to_wstg = {
            "ReconnaissanceAgent": "WSTG-INFO",
            "ConfigDeploymentAgent": "WSTG-CONF",
            "IdentityManagementAgent": "WSTG-IDNT",
            "AuthenticationAgent": "WSTG-ATHN",
            "AuthorizationAgent": "WSTG-AUTHZ",
            "SessionManagementAgent": "WSTG-SESS",
            "InputValidationAgent": "WSTG-INPV",
            "ErrorHandlingAgent": "WSTG-ERRH",
            "WeakCryptographyAgent": "WSTG-CRYP",
            "BusinessLogicAgent": "WSTG-BUSL",
            "ClientSideAgent": "WSTG-CLNT",
            "APITestingAgent": "WSTG-APIT",
        }

        completed_tests = 0
        for agent in agents_executed:
            wstg_cat = agent_to_wstg.get(agent)
            if wstg_cat and wstg_cat in WSTG_TEST_CASES:
                completed_tests += WSTG_TEST_CASES[wstg_cat]

        tcr = completed_tests / TOTAL_WSTG_TESTS if TOTAL_WSTG_TESTS > 0 else 0

        return {
            "completed_tests": int(completed_tests),
            "total_tests": TOTAL_WSTG_TESTS,
            "tcr": tcr,
            "tcr_pct": tcr * 100,
            "agents_executed": len(agents_executed),
            "total_agents": len(self.job_data.get("agents", [])),
        }

    def calculate_scan_performance(self) -> Dict[str, Any]:
        """Calculate scan performance metrics."""
        if not self.job_data:
            return {}

        created_at = datetime.fromisoformat(self.job_data.get("created_at", ""))
        updated_at = datetime.fromisoformat(self.job_data.get("updated_at", ""))

        duration_seconds = (updated_at - created_at).total_seconds()
        duration_minutes = duration_seconds / 60

        return {
            "scan_duration_seconds": duration_seconds,
            "scan_duration_minutes": duration_minutes,
            "scan_duration_hours": duration_minutes / 60,
            "findings_per_minute": len(self.findings) / duration_minutes if duration_minutes > 0 else 0,
            "target": self.job_data.get("target"),
            "status": self.job_data.get("status"),
        }

    def generate_report(self, metrics: Dict[str, Any], output_file: str = None):
        """Generate comprehensive metrics report."""
        report = f"""
{'='*80}
DAY 10 FINAL VALIDATION METRICS REPORT
{'='*80}

Job ID: {self.job_id}
Target: {metrics['performance']['target']}
Status: {metrics['performance']['status']}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{'='*80}
1. PRECISION, RECALL, F1-SCORE (Primary Research Metrics)
{'='*80}

Ground Truth (OWASP Juice Shop): {metrics['prf']['ground_truth']} vulnerabilities

Findings Classification:
  • True Positives (TP):  {metrics['prf']['true_positives']:3d}
  • False Positives (FP): {metrics['prf']['false_positives']:3d}
  • False Negatives (FN): {metrics['prf']['false_negatives']:3d}
  • Total Findings:       {metrics['prf']['total_findings']:3d}

Research Metrics:
  • Precision: {metrics['prf']['precision_pct']:.2f}% {'✅ PASS' if metrics['prf']['precision'] >= 0.90 else '❌ FAIL'} (Target: ≥90%)
  • Recall:    {metrics['prf']['recall_pct']:.2f}% {'✅ PASS' if metrics['prf']['recall'] >= 0.80 else '❌ FAIL'} (Target: ≥80%)
  • F1-Score:  {metrics['prf']['f1_score_pct']:.2f}% {'✅ PASS' if metrics['prf']['f1_score'] >= 0.85 else '❌ FAIL'} (Target: ≥85%)

{'='*80}
2. TASK COMPLETION RATE (OWASP WSTG 4.2 Coverage)
{'='*80}

WSTG Test Coverage:
  • Completed Tests: {metrics['tcr']['completed_tests']}/{metrics['tcr']['total_tests']}
  • TCR:            {metrics['tcr']['tcr_pct']:.2f}% {'✅ PASS' if metrics['tcr']['tcr'] >= 0.70 else '❌ FAIL'} (Target: ≥70%)
  • Agents Executed: {metrics['tcr']['agents_executed']}/{metrics['tcr']['total_agents']}

{'='*80}
3. SCAN PERFORMANCE
{'='*80}

Scan Duration:
  • Total Time:     {metrics['performance']['scan_duration_minutes']:.1f} minutes ({metrics['performance']['scan_duration_hours']:.2f} hours)
  • Target Time:    ≤60 minutes {'✅ PASS' if metrics['performance']['scan_duration_minutes'] <= 60 else '❌ FAIL'}
  • Findings/min:   {metrics['performance']['findings_per_minute']:.2f}

{'='*80}
4. OVERALL THESIS SUCCESS CRITERIA
{'='*80}

"""
        # Check all success criteria
        all_pass = (
            metrics['prf']['precision'] >= 0.90 and
            metrics['prf']['recall'] >= 0.80 and
            metrics['prf']['f1_score'] >= 0.85 and
            metrics['tcr']['tcr'] >= 0.70 and
            metrics['performance']['scan_duration_minutes'] <= 60
        )

        report += f"Overall Result: {'✅ ALL CRITERIA MET - THESIS READY!' if all_pass else '❌ SOME CRITERIA NOT MET - NEEDS IMPROVEMENT'}\n\n"

        if metrics.get('manual_review'):
            report += f"""
{'='*80}
5. MANUAL REVIEW REQUIRED
{'='*80}

{len(metrics['manual_review'])} findings need manual classification:

"""
            for idx, item in enumerate(metrics['manual_review'][:20], 1):
                report += f"{idx:2d}. {item}\n"

            if len(metrics['manual_review']) > 20:
                report += f"\n... and {len(metrics['manual_review']) - 20} more\n"

        report += f"\n{'='*80}\n"

        print(report)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"\n✅ Report saved to: {output_file}")

        # Also save JSON
        json_file = output_file.replace('.txt', '.json') if output_file else f"metrics_job_{self.job_id}.json"
        with open(json_file, 'w') as f:
            json.dump(metrics, f, indent=2)
        print(f"✅ JSON metrics saved to: {json_file}\n")


def main():
    """Main execution function."""
    import sys

    # Get job ID from command line or use default
    job_id = int(sys.argv[1]) if len(sys.argv) > 1 else 2

    print(f"\n{'='*80}")
    print(f"  DAY 10 FINAL METRICS CALCULATION - Job ID {job_id}")
    print(f"{'='*80}\n")

    # Initialize calculator
    calc = MetricsCalculator(job_id)

    # Fetch data
    print("📥 Fetching job data from API...")
    if not calc.fetch_job_data():
        print("❌ Failed to fetch job data. Exiting.")
        return 1

    # Classify findings
    print("\n🔍 Classifying findings (TP vs FP)...")
    tp_findings, fp_findings, manual_review = calc.classify_findings()

    print(f"  • True Positives:  {len(tp_findings)}")
    print(f"  • False Positives: {len(fp_findings)}")
    print(f"  • Manual Review:   {len(manual_review)}")

    # Calculate metrics
    print("\n📊 Calculating research metrics...")

    prf_metrics = calc.calculate_precision_recall(len(tp_findings), len(fp_findings))
    tcr_metrics = calc.calculate_tcr()
    perf_metrics = calc.calculate_scan_performance()

    all_metrics = {
        "job_id": job_id,
        "prf": prf_metrics,
        "tcr": tcr_metrics,
        "performance": perf_metrics,
        "manual_review": manual_review,
        "classification": {
            "true_positives": [f["title"] for f in tp_findings],
            "false_positives": [f["title"] for f in fp_findings],
        }
    }

    # Generate report
    output_file = f"DAY10_METRICS_JOB{job_id}.txt"
    calc.generate_report(all_metrics, output_file)

    return 0


if __name__ == "__main__":
    exit(main())
