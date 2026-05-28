#!/usr/bin/env python3
"""
Update thesis benchmark data (job74-83) menggantikan data lama (job54-67).

Usage:
  python3 multi_agent_system/evaluation/update_thesis_from_benchmark.py \
      --docx "Penelitian/Draft_70_Tugas Akhir_Latest_fixed.docx"

Jalankan dari root RAJDOLL setelah semua 10 scan benchmark selesai.
"""
import argparse
import json
import shutil
import statistics
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent
RUNS_DIR = BASE_DIR / "runs"
SUMMARY_FILE = BASE_DIR / "evaluation_juiceshop_summary.json"
RUN_LABELS = [f"juiceshop_benchmark_run{i}" for i in range(1, 11)]


def load_run_metrics(runs_dir: Path, run_label: str) -> dict:
    """Load metrics.json for one run, inject job_id from job_result.json."""
    metrics_file = runs_dir / run_label / "metrics.json"
    job_result_file = runs_dir / run_label / "job_result.json"
    if not metrics_file.exists():
        raise FileNotFoundError(f"Missing: {metrics_file}")
    m = json.loads(metrics_file.read_text())
    if job_result_file.exists():
        jr = json.loads(job_result_file.read_text())
        m["job_id"] = jr.get("job_id") or jr.get("id")
    return m


def compute_aggregate(metrics_list: list) -> dict:
    """Compute mean/std across all runs."""
    def mean_std(key):
        vals = [m[key] for m in metrics_list if m.get(key) is not None]
        if not vals:
            return None, None
        mu = round(statistics.mean(vals), 2)
        sd = round(statistics.pstdev(vals), 2) if len(vals) > 1 else 0.0
        return mu, sd

    p_mean, p_std = mean_std("precision")
    r_mean, r_std = mean_std("recall")
    f_mean, f_std = mean_std("f1")
    t_mean, t_std = mean_std("tcr")
    return {
        "n_runs": len(metrics_list),
        "precision_mean": p_mean, "precision_std": p_std,
        "recall_mean": r_mean,    "recall_std":    r_std,
        "f1_mean":     f_mean,    "f1_std":        f_std,
        "tcr_mean":    t_mean,    "tcr_std":       t_std,
    }


def update_summary_json(summary_file: Path, agg: dict, metrics_list: list, target: str = "juiceshop"):
    """Tulis ulang evaluation_juiceshop_summary.json dengan data baru."""
    per_run = []
    for m in metrics_list:
        entry = {k: v for k, v in m.items() if k != "job_id"}
        per_run.append(entry)
    data = {
        "n_runs": agg["n_runs"],
        "precision_mean": agg["precision_mean"],
        "precision_std":  agg["precision_std"],
        "recall_mean":    agg["recall_mean"],
        "recall_std":     agg["recall_std"],
        "f1_mean":        agg["f1_mean"],
        "f1_std":         agg["f1_std"],
        "tcr_mean":       agg["tcr_mean"],
        "tcr_std":        agg["tcr_std"],
        "scan_time_mean_hours": None,
        "scan_time_std_hours":  None,
        "per_run": per_run,
        "target": target,
    }
    summary_file.write_text(json.dumps(data, indent=2))
