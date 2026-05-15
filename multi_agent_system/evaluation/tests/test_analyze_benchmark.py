# multi_agent_system/evaluation/tests/test_analyze_benchmark.py
import json
from pathlib import Path

import pytest

from multi_agent_system.evaluation.analyze_benchmark import (
    load_run_metrics, aggregate_runs, paired_t_test, build_summary_table,
)


@pytest.fixture
def runs_dir(tmp_path):
    # Mock baseline runs
    for i in (1, 2, 3):
        (tmp_path / f"juiceshop_baseline_run{i}.json").write_text(json.dumps({
            "metrics": {"precision": 95.0 + i*0.2, "recall": 80.0 + i*0.5,
                         "f1_score": 87.0 + i*0.4, "tp": 46, "fp": 2, "fn": 11},
            "finding_count": 42,
            "target_pct": 95.0,
        }))
    for i in (1, 2, 3):
        (tmp_path / f"juiceshop_framework_run{i}.json").write_text(json.dumps({
            "metrics": {"precision": 96.0 + i*0.2, "recall": 91.0 + i*0.3,
                         "f1_score": 93.0 + i*0.3, "tp": 52, "fp": 2, "fn": 5},
            "finding_count": 54,
            "target_pct": 95.0,
        }))
    return tmp_path


def test_load_run_metrics(runs_dir):
    df = load_run_metrics(runs_dir)
    assert len(df) == 6
    assert {"target", "mode", "run", "precision", "recall", "f1"} <= set(df.columns)


def test_aggregate_runs(runs_dir):
    df = load_run_metrics(runs_dir)
    agg = aggregate_runs(df)
    juice_fw = agg[(agg.target == "juiceshop") & (agg.mode == "framework")].iloc[0]
    assert juice_fw["precision_mean"] > 95.0
    assert juice_fw["recall_mean"] > 90.0


def test_paired_t_test_significant(runs_dir):
    df = load_run_metrics(runs_dir)
    p_value = paired_t_test(df, target="juiceshop", metric="recall")
    assert p_value < 0.05


def test_build_summary_table(runs_dir, tmp_path):
    df = load_run_metrics(runs_dir)
    csv_path = tmp_path / "summary.csv"
    build_summary_table(df, csv_path)
    content = csv_path.read_text()
    assert "juiceshop" in content
    assert "f1_mean" in content
