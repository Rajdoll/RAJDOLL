import json, pytest
from pathlib import Path
from unittest.mock import patch, mock_open

# tambahkan path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from update_thesis_from_benchmark import load_run_metrics, compute_aggregate

SAMPLE_METRICS = {
    "precision": 90.54, "recall": 89.47, "f1": 89.99, "tcr": 85.19,
    "tp_gt_entries": 51, "fp_findings": 4, "fn_gt_entries": 6,
    "total_findings_non_info": 55, "total_gt_entries": 57,
    "run_label": "juiceshop_benchmark_run1"
}

def make_run_dir(tmp_path, run_name, metrics, job_id=74, job_result=None):
    d = tmp_path / "runs" / run_name
    d.mkdir(parents=True)
    (d / "metrics.json").write_text(json.dumps(metrics))
    if job_result is None:
        job_result = {"job_id": job_id, "status": "completed", "target": "http://juice-shop:3000/"}
    (d / "job_result.json").write_text(json.dumps(job_result))
    return d

def test_load_run_metrics_returns_metrics_and_job_id(tmp_path):
    runs_dir = tmp_path / "runs"
    make_run_dir(tmp_path, "juiceshop_benchmark_run1", SAMPLE_METRICS, job_id=74)
    result = load_run_metrics(runs_dir, "juiceshop_benchmark_run1")
    assert result["precision"] == 90.54
    assert result["job_id"] == 74

def test_load_run_metrics_missing_file_raises(tmp_path):
    runs_dir = tmp_path / "runs"
    with pytest.raises(FileNotFoundError):
        load_run_metrics(runs_dir, "juiceshop_benchmark_run1")

def test_compute_aggregate_mean_and_std():
    metrics_list = [
        {**SAMPLE_METRICS, "precision": 90.0, "recall": 88.0, "f1": 89.0, "tcr": 84.0},
        {**SAMPLE_METRICS, "precision": 92.0, "recall": 92.0, "f1": 92.0, "tcr": 88.0},
    ]
    agg = compute_aggregate(metrics_list)
    assert agg["precision_mean"] == pytest.approx(91.0)
    assert agg["recall_mean"] == pytest.approx(90.0)
    assert agg["precision_std"] == pytest.approx(1.0, abs=0.1)
    assert agg["n_runs"] == 2
