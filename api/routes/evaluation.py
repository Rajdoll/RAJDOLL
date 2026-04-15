"""
Evaluation Metrics API Endpoint
Provides REST API access to comprehensive evaluation metrics
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from multi_agent_system.core.db import get_db
from multi_agent_system.models.models import Job
from multi_agent_system.evaluation.metrics import MetricsCalculator, MetricsResult


router = APIRouter()


class MetricsResponse(BaseModel):
	"""Response model for metrics"""
	job_id: int
	target: str

	# Precision — manual TP/FP labels
	precision: Optional[float]            # None = pending review
	precision_status: str                 # "validated" | "partial" | "pending_review"
	validated_count: int
	unreviewed_count: int

	# Recall — DB ground truth
	recall: Optional[float]              # None = no ground truth loaded
	f1_score: Optional[float]
	false_negative_rate: Optional[float]

	# Other effectiveness
	severity_accuracy: float
	cvss_correlation: float
	cvss_p_value: float

	# Efficiency metrics
	ttff_seconds: float
	total_scan_hours: float

	# Coverage metrics
	tcr_percentage: float
	owasp_top10_coverage: float
	attack_surface_coverage: float

	# Reliability metrics
	crash_rate: float
	recovery_rate: float
	consistency_score: float

	# Overall assessment
	acceptance_status: str  # "EXCELLENT", "ACCEPTABLE", "NEEDS_IMPROVEMENT"
	recommendations: list[str]


@router.get("/jobs/{job_id}/metrics", response_model=MetricsResponse)
def get_metrics(job_id: int):
	"""
	Calculate comprehensive evaluation metrics for a completed scan
	
	Returns:
	- Effectiveness: Precision, Recall, F1-Score, Severity accuracy, CVSS correlation
	- Efficiency: TTFF, Total scan time
	- Coverage: TCR, OWASP Top 10 coverage, Attack surface coverage
	- Reliability: Crash rate, Recovery rate, Consistency
	- Overall assessment with recommendations
	"""
	# Get job from database
	with get_db() as db:
		job = db.query(Job).get(job_id)
		if not job:
			raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
		
		target = job.target
	
	# Calculate all metrics
	calculator = MetricsCalculator()
	
	try:
		metrics = calculator.calculate_all_metrics(job_id, target)
	except Exception as e:
		raise HTTPException(
			status_code=500, 
			detail=f"Failed to calculate metrics: {str(e)}"
		)
	
	# Compute validation counts
	with get_db() as db:
		from multi_agent_system.models.models import Finding
		all_findings = db.query(Finding).filter(Finding.job_id == job_id).all()
		validated_count = sum(1 for f in all_findings if f.is_true_positive is not None)
		unreviewed_count = sum(1 for f in all_findings if f.is_true_positive is None)

	if validated_count == 0:
		precision_status = "pending_review"
	elif unreviewed_count == 0:
		precision_status = "validated"
	else:
		precision_status = "partial"

	# Determine acceptance status — treat None as "not yet evaluated" (skip from gate)
	f1_ok = metrics.f1_score is None or metrics.f1_score >= 85.0
	acceptance_status = "NEEDS_IMPROVEMENT"
	recommendations = []

	# EXCELLENT criteria
	if (f1_ok and metrics.f1_score is not None and metrics.f1_score >= 90.0 and
		metrics.tcr_percentage >= 85.0 and
		metrics.ttff_seconds <= 180 and
		metrics.crash_rate <= 1.0):
		acceptance_status = "EXCELLENT"
		recommendations.append("✅ System meets EXCELLENT criteria - ready for production")

	# ACCEPTABLE criteria
	elif (f1_ok and
		  metrics.tcr_percentage >= 70.0 and
		  metrics.ttff_seconds <= 300 and
		  metrics.crash_rate <= 2.0):
		acceptance_status = "ACCEPTABLE"
		recommendations.append("✅ System meets ACCEPTABLE criteria - suitable for deployment")

		if metrics.f1_score is None:
			recommendations.append("⚠️  F1-Score pending review (validate findings as TP/FP)")
		elif metrics.f1_score < 90.0:
			recommendations.append(f"⚠️  F1-Score is {metrics.f1_score:.1f}% (target: ≥90% for EXCELLENT)")
		if metrics.tcr_percentage < 85.0:
			recommendations.append(f"⚠️  TCR is {metrics.tcr_percentage:.1f}% (target: ≥85% for EXCELLENT)")

	# NEEDS_IMPROVEMENT
	else:
		recommendations.append("❌ System does not meet minimum ACCEPTABLE criteria")

		if metrics.f1_score is None:
			recommendations.append("🔴 F1-Score pending review (validate findings as TP/FP first)")
		elif metrics.f1_score < 85.0:
			recommendations.append(f"🔴 F1-Score is {metrics.f1_score:.1f}% (minimum: ≥85%)")
		if metrics.precision is not None and metrics.precision < 90.0:
			recommendations.append(f"🔴 Precision is {metrics.precision:.1f}% (target: ≥90%)")
		if metrics.recall is not None and metrics.recall < 80.0:
			recommendations.append(f"🔴 Recall is {metrics.recall:.1f}% (target: ≥80%)")
		if metrics.tcr_percentage < 70.0:
			recommendations.append(f"🔴 TCR is {metrics.tcr_percentage:.1f}% (minimum: ≥70%)")
		if metrics.ttff_seconds > 300:
			recommendations.append(f"🔴 TTFF is {metrics.ttff_seconds:.1f}s (maximum: ≤300s)")
		if metrics.crash_rate > 2.0:
			recommendations.append(f"🔴 Crash rate is {metrics.crash_rate:.1f}% (maximum: ≤2%)")

	return MetricsResponse(
		job_id=job_id,
		target=target,
		precision=metrics.precision,
		precision_status=precision_status,
		validated_count=validated_count,
		unreviewed_count=unreviewed_count,
		recall=metrics.recall,
		f1_score=metrics.f1_score,
		false_negative_rate=metrics.false_negative_rate,
		severity_accuracy=metrics.severity_accuracy,
		cvss_correlation=metrics.cvss_correlation,
		cvss_p_value=metrics.cvss_p_value,
		ttff_seconds=metrics.ttff_seconds,
		total_scan_hours=metrics.total_scan_hours,
		tcr_percentage=metrics.tcr_percentage,
		owasp_top10_coverage=metrics.owasp_top10_coverage,
		attack_surface_coverage=metrics.attack_surface_coverage,
		crash_rate=metrics.crash_rate,
		recovery_rate=metrics.recovery_rate,
		consistency_score=metrics.consistency_score,
		acceptance_status=acceptance_status,
		recommendations=recommendations,
	)


@router.get("/jobs/{job_id}/metrics/report")
def get_metrics_report(job_id: int):
	"""
	Generate formatted metrics report (console-friendly text format)
	"""
	# Get job from database
	with get_db() as db:
		job = db.query(Job).get(job_id)
		if not job:
			raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
		
		target = job.target
	
	# Calculate all metrics
	calculator = MetricsCalculator()
	
	try:
		metrics = calculator.calculate_all_metrics(job_id, target)
	except Exception as e:
		raise HTTPException(
			status_code=500, 
			detail=f"Failed to calculate metrics: {str(e)}"
		)
	
	# Generate formatted report
	report_lines = []
	report_lines.append("=" * 80)
	report_lines.append(f"EVALUATION METRICS REPORT - Job #{job_id}")
	report_lines.append(f"Target: {target}")
	report_lines.append("=" * 80)
	report_lines.append("")
	
	# Effectiveness
	report_lines.append("📊 EFFECTIVENESS METRICS")
	report_lines.append("-" * 80)
	def _pct(v): return f"{v:>6.2f}%" if v is not None else "   N/A (pending review)"
	report_lines.append(f"  Precision:               {_pct(metrics.precision)}  (Target: ≥90%)")
	report_lines.append(f"  Recall:                  {_pct(metrics.recall)}  (Target: ≥80%)")
	report_lines.append(f"  F1-Score:                {_pct(metrics.f1_score)}  (Target: ≥85%)")
	report_lines.append(f"  False Negative Rate:     {_pct(metrics.false_negative_rate)}  (Target: ≤20%)")
	report_lines.append(f"  Severity Accuracy:       {metrics.severity_accuracy:>6.2f}%  (Target: ≥80%)")
	report_lines.append(f"  CVSS Correlation:        {metrics.cvss_correlation:>6.3f}   (Target: ≥0.7)")
	report_lines.append("")
	
	# Efficiency
	report_lines.append("⚡ EFFICIENCY METRICS")
	report_lines.append("-" * 80)
	report_lines.append(f"  Time to First Finding:   {metrics.ttff_seconds:>6.1f}s  (Target: ≤300s)")
	report_lines.append(f"  Total Scan Time:         {metrics.total_scan_hours:>6.2f}h  (Target: ≤4h)")
	report_lines.append("")
	
	# Coverage
	report_lines.append("🎯 COVERAGE METRICS")
	report_lines.append("-" * 80)
	report_lines.append(f"  Task Completion Rate:    {metrics.tcr_percentage:>6.2f}%  (Target: ≥70%)")
	report_lines.append(f"  OWASP Top 10 Coverage:   {metrics.owasp_top10_coverage:>6.2f}%  (Target: ≥80%)")
	report_lines.append(f"  Attack Surface Coverage: {metrics.attack_surface_coverage:>6.2f}%  (Target: ≥90%)")
	report_lines.append("")
	
	# Reliability
	report_lines.append("🔧 RELIABILITY METRICS")
	report_lines.append("-" * 80)
	report_lines.append(f"  Crash Rate:              {metrics.crash_rate:>6.2f}%  (Target: ≤2%)")
	report_lines.append(f"  Recovery Rate:           {metrics.recovery_rate:>6.2f}%  (Target: ≥90%)")
	report_lines.append(f"  Consistency Score:       {metrics.consistency_score:>6.2f}%  (Target: ≥95%)")
	report_lines.append("")
	
	# Overall assessment
	report_lines.append("=" * 80)
	if (metrics.f1_score is not None and metrics.f1_score >= 90.0 and metrics.tcr_percentage >= 85.0):
		report_lines.append("✅ OVERALL ASSESSMENT: EXCELLENT")
	elif (metrics.f1_score is not None and metrics.f1_score >= 85.0 and metrics.tcr_percentage >= 70.0):
		report_lines.append("✅ OVERALL ASSESSMENT: ACCEPTABLE")
	elif metrics.f1_score is None:
		report_lines.append("⏳ OVERALL ASSESSMENT: PENDING REVIEW (validate findings first)")
	else:
		report_lines.append("❌ OVERALL ASSESSMENT: NEEDS IMPROVEMENT")
	report_lines.append("=" * 80)
	
	return {"report": "\n".join(report_lines)}
