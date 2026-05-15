# multi_agent_system/evaluation/analyze_benchmark.py
"""Statistical analysis of multi-target benchmark + ablation results."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pandas as pd
from scipy import stats


_FILE_PATTERN = re.compile(
    r"(?P<target>[a-z]+)_(?P<mode>baseline|framework)_run(?P<run>\d+)\.json"
)


class BenchmarkFrame(pd.DataFrame):
    """DataFrame subclass that exposes 'mode' column as a property.

    pandas.DataFrame.mode() is a built-in statistical method; without this
    override, attribute access df.mode returns the method object instead of the
    'mode' column, breaking boolean indexing.
    """

    @property
    def mode(self) -> pd.Series:
        return self["mode"].astype(object)

    @property
    def _constructor(self):
        return BenchmarkFrame


def load_run_metrics(runs_dir: Path) -> BenchmarkFrame:
    """Scan directory for benchmark run files, build a tidy BenchmarkFrame."""
    runs_dir = Path(runs_dir)
    rows: list[dict] = []
    for fp in sorted(runs_dir.glob("*.json")):
        m = _FILE_PATTERN.match(fp.name)
        if not m:
            continue
        data = json.loads(fp.read_text())
        metrics = data.get("metrics", {})
        rows.append({
            "file": fp.name,
            "target": m.group("target"),
            "mode": m.group("mode"),
            "run": int(m.group("run")),
            "precision": float(metrics.get("precision", 0)),
            "recall": float(metrics.get("recall", 0)),
            "f1": float(metrics.get("f1_score", 0)),
            "tp": int(metrics.get("tp", 0)),
            "fp": int(metrics.get("fp", 0)),
            "fn": int(metrics.get("fn", 0)),
            "finding_count": int(data.get("finding_count", 0)),
        })
    return BenchmarkFrame(rows)


def aggregate_runs(df: pd.DataFrame) -> BenchmarkFrame:
    """Mean & std per (target, mode)."""
    metric_cols = ["precision", "recall", "f1", "finding_count"]
    grouped = df.groupby(["target", "mode"])[metric_cols].agg(["mean", "std"]).reset_index()
    grouped.columns = ["_".join(c).strip("_") for c in grouped.columns.values]
    return BenchmarkFrame(grouped)


def paired_t_test(df: pd.DataFrame, *, target: str, metric: str) -> float:
    """Paired t-test between baseline and framework for one target."""
    df_b = BenchmarkFrame(df)
    baseline = df_b[(df_b.target == target) & (df_b.mode == "baseline")].sort_values("run")[metric]
    framework = df_b[(df_b.target == target) & (df_b.mode == "framework")].sort_values("run")[metric]
    n = min(len(baseline), len(framework))
    if n < 2:
        return float("nan")
    t_stat, p_value = stats.ttest_rel(framework.values[:n], baseline.values[:n])
    return float(p_value)


def build_summary_table(df: pd.DataFrame, output_csv: Path) -> None:
    """Write a tesis-ready summary CSV."""
    agg = aggregate_runs(df)
    rows = []
    for target in agg["target"].unique():
        sub = agg[agg.target == target]
        row = {"target": target}
        for mode in ("baseline", "framework"):
            mrow = sub[sub["mode"] == mode]
            if mrow.empty:
                continue
            mrow = mrow.iloc[0]
            for metric in ("precision", "recall", "f1"):
                row[f"{mode}_{metric}_mean"] = round(mrow[f"{metric}_mean"], 2)
                row[f"{mode}_{metric}_std"] = round(mrow[f"{metric}_std"] or 0, 2)
        for metric in ("precision", "recall", "f1"):
            row[f"{metric}_pvalue"] = round(paired_t_test(df, target=target, metric=metric), 4)
        rows.append(row)
    pd.DataFrame(rows).to_csv(output_csv, index=False)


def main() -> None:
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("runs_dir", type=Path)
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args()
    out = args.out or (args.runs_dir / "summary_table.csv")
    df = load_run_metrics(args.runs_dir)
    if df.empty:
        print(f"No run artefacts in {args.runs_dir}")
        return
    build_summary_table(df, out)
    print(f"Summary written to {out}")
    print(aggregate_runs(df).to_string(index=False))


if __name__ == "__main__":
    main()
