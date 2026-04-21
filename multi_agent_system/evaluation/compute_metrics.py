#!/usr/bin/env python3
"""
Standalone P/R/F1/TCR computation from scan_runner.sh output JSON files.
No RAJDOLL imports, no live DB required.

Usage (from /mnt/d/MCP/RAJDOLL/):
  python3 multi_agent_system/evaluation/compute_metrics.py \\
    --target dvwa --runs dvwa_run1 dvwa_run2 dvwa_run3

  python3 multi_agent_system/evaluation/compute_metrics.py \\
    --target juiceshop --runs juiceshop_run3 juiceshop_run4 juiceshop_run5

  python3 multi_agent_system/evaluation/compute_metrics.py \\
    --all  # runs all three targets using canonical run labels

Output:
  evaluation/runs/{run}/metrics.json           (per run)
  evaluation/evaluation_{target}_summary.json  (aggregate mean +/- std)
  Markdown table printed to stdout
"""

import argparse
import json
import math
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent

CANONICAL_RUNS = {
    "dvwa": ["dvwa_run1", "dvwa_run2", "dvwa_run3"],
    "bwapp": ["bwapp_run1", "bwapp_run2", "bwapp_run3"],
    "juiceshop": ["juiceshop_run3", "juiceshop_run4", "juiceshop_run5"],
}


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_ground_truth(target: str) -> list:
    gt_file = BASE_DIR / f"ground_truth_{target}.json"
    if not gt_file.exists():
        sys.exit(f"ERROR: {gt_file} not found")
    return json.loads(gt_file.read_text())["entries"]


def load_findings(run_label: str) -> list:
    f = BASE_DIR / "runs" / run_label / "findings.json"
    if not f.exists():
        print(f"  WARNING: no findings.json for '{run_label}'")
        return []
    return json.loads(f.read_text())


def load_job_result(run_label: str) -> dict:
    f = BASE_DIR / "runs" / run_label / "job_result.json"
    return json.loads(f.read_text()) if f.exists() else {}


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def matches(finding_category: str, gt_wstg: str) -> bool:
    """WSTG prefix matching — identical to metrics.py._matches()."""
    fc = finding_category.strip()
    gc = gt_wstg.strip()
    return fc == gc or gc.startswith(fc + "-") or fc.startswith(gc + "-")


# ---------------------------------------------------------------------------
# Scan time from agent timestamps
# ---------------------------------------------------------------------------

def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts.split("+")[0].split("Z")[0].strip(), fmt)
        except ValueError:
            continue
    return None


def compute_scan_time(job_result: dict) -> float | None:
    """Return scan duration in hours derived from agent start/finish timestamps."""
    agents = job_result.get("agents", [])
    starts = [_parse_ts(a.get("started_at")) for a in agents]
    ends = [_parse_ts(a.get("finished_at")) for a in agents]
    starts = [t for t in starts if t]
    ends = [t for t in ends if t]
    if not starts or not ends:
        return None
    delta = max(ends) - min(starts)
    return round(delta.total_seconds() / 3600, 2)


# ---------------------------------------------------------------------------
# Agent stats
# ---------------------------------------------------------------------------

def compute_agent_stats(job_result: dict) -> dict:
    agents = job_result.get("agents", [])
    total = len(agents)
    completed = sum(1 for a in agents if a.get("status") == "completed")
    failed = sum(1 for a in agents if a.get("status") == "failed")
    skipped = sum(1 for a in agents if a.get("status") == "skipped")
    return {
        "total": total,
        "completed": completed,
        "failed": failed,
        "skipped": skipped,
        "success_rate": round(completed / total * 100, 1) if total else 0.0,
    }


# ---------------------------------------------------------------------------
# Core metrics
# ---------------------------------------------------------------------------

def compute_run_metrics(findings: list, ground_truth: list, job_result: dict) -> dict:
    """Compute P/R/F1/TCR for a single scan run."""
    # --- Recall: GT-entry coverage ---
    detected_gt_ids = set()
    for gt in ground_truth:
        gt_wstg = gt.get("owasp_wstg", "")
        for f in findings:
            if matches(f.get("category", ""), gt_wstg):
                detected_gt_ids.add(gt["id"])
                break

    tp_gt = len(detected_gt_ids)
    fn_gt = len(ground_truth) - tp_gt
    recall = (tp_gt / len(ground_truth) * 100) if ground_truth else 0.0

    # --- Precision: finding-level TP/FP ---
    # On intentionally-vulnerable targets: finding matches any GT category = TP,
    # no match = FP. Info-severity findings excluded (baseline noise).
    tp_findings = fp_findings = 0
    for f in findings:
        if f.get("severity", "").lower() == "info":
            continue
        matched = any(matches(f.get("category", ""), gt.get("owasp_wstg", ""))
                      for gt in ground_truth)
        if matched:
            tp_findings += 1
        else:
            fp_findings += 1

    total_reviewed = tp_findings + fp_findings
    precision = (tp_findings / total_reviewed * 100) if total_reviewed > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # --- TCR: WSTG category coverage ---
    gt_wstg_cats = set(gt.get("owasp_wstg", "") for gt in ground_truth if gt.get("owasp_wstg"))
    detected_cats = set()
    for gt in ground_truth:
        if gt["id"] in detected_gt_ids:
            detected_cats.add(gt.get("owasp_wstg", ""))
    tcr = (len(detected_cats) / len(gt_wstg_cats) * 100) if gt_wstg_cats else 0.0

    sev_counts: dict = {}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    return {
        "tp_findings": tp_findings,
        "fp_findings": fp_findings,
        "tp_gt_entries": tp_gt,
        "fn_gt_entries": fn_gt,
        "total_findings_non_info": total_reviewed,
        "total_gt_entries": len(ground_truth),
        "detected_wstg_categories": len(detected_cats),
        "total_wstg_categories": len(gt_wstg_cats),
        "precision": round(precision, 2),
        "recall": round(recall, 2),
        "f1": round(f1, 2),
        "tcr": round(tcr, 2),
        "findings_by_severity": sev_counts,
        "scan_time_hours": compute_scan_time(job_result),
        "agent_stats": compute_agent_stats(job_result),
    }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def aggregate(per_run: list) -> dict:
    def mean_std(vals):
        vals = [v for v in vals if v is not None]
        if not vals:
            return None, None
        m = sum(vals) / len(vals)
        std = math.sqrt(sum((x - m) ** 2 for x in vals) / len(vals))
        return round(m, 2), round(std, 2)

    pm, ps = mean_std([r["precision"] for r in per_run])
    rm, rs = mean_std([r["recall"] for r in per_run])
    fm, fs = mean_std([r["f1"] for r in per_run])
    tm, ts_ = mean_std([r["tcr"] for r in per_run])
    scan_times = [r.get("scan_time_hours") for r in per_run]
    stm, sts = mean_std([t for t in scan_times if t is not None])

    return {
        "n_runs": len(per_run),
        "precision_mean": pm, "precision_std": ps,
        "recall_mean": rm, "recall_std": rs,
        "f1_mean": fm, "f1_std": fs,
        "tcr_mean": tm, "tcr_std": ts_,
        "scan_time_mean_hours": stm, "scan_time_std_hours": sts,
        "per_run": per_run,
    }


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def print_markdown_table(target: str, summary: dict) -> None:
    n = summary["n_runs"]
    header = f"\n### {target.upper()} Results (n={n} runs)\n"
    print(header)
    print("| Metric | Mean | Std | Target | Status |")
    print("|--------|------|-----|--------|--------|")

    targets = {
        "Precision": (summary["precision_mean"], summary["precision_std"], 90.0, "≥ 90%"),
        "Recall": (summary["recall_mean"], summary["recall_std"], 80.0, "≥ 80%"),
        "F1-Score": (summary["f1_mean"], summary["f1_std"], 85.0, "≥ 85%"),
        "TCR": (summary["tcr_mean"], summary["tcr_std"], 70.0, "≥ 70%"),
    }
    for metric, (mean, std, thresh, label) in targets.items():
        if mean is None:
            print(f"| {metric} | N/A | N/A | {label} | - |")
            continue
        status = "PASS" if mean >= thresh else "FAIL"
        std_str = f"{std}%" if std is not None else "N/A"
        print(f"| {metric} | {mean}% | {std_str} | {label} | {status} |")

    if summary.get("scan_time_mean_hours") is not None:
        t = summary["scan_time_mean_hours"]
        ts = summary.get("scan_time_std_hours")
        ts_str = f"{ts}h" if ts is not None else "N/A"
        status = "PASS" if t <= 4.0 else "FAIL"
        print(f"| Scan Time | {t}h | {ts_str} | ≤ 4h | {status} |")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run_target(target: str, run_labels: list[str]) -> dict | None:
    gt = load_ground_truth(target)
    print(f"\nGround truth: {len(gt)} entries for '{target}'")

    per_run = []
    for label in run_labels:
        findings = load_findings(label)
        if not findings:
            continue
        job = load_job_result(label)
        m = compute_run_metrics(findings, gt, job)
        m["run_label"] = label
        out = BASE_DIR / "runs" / label / "metrics.json"
        out.write_text(json.dumps(m, indent=2))
        scan_t = f" scan={m['scan_time_hours']}h" if m["scan_time_hours"] else ""
        agents = m["agent_stats"]
        print(f"  {label}: P={m['precision']}%  R={m['recall']}%  F1={m['f1']}%  "
              f"TCR={m['tcr']}%  ({m['tp_gt_entries']}/{m['total_gt_entries']} GT, "
              f"{m['fp_findings']} FP){scan_t}  "
              f"agents={agents['completed']}/{agents['total']}")
        per_run.append(m)

    if not per_run:
        print(f"  ERROR: No valid runs for '{target}' (missing findings.json?)")
        return None

    summary = aggregate(per_run)
    summary["target"] = target
    out_path = BASE_DIR / f"evaluation_{target}_summary.json"
    out_path.write_text(json.dumps(summary, indent=2))

    print(f"\n=== {target.upper()} SUMMARY ({summary['n_runs']} runs) ===")
    print(f"  Precision:  {summary['precision_mean']} ± {summary['precision_std']}%")
    print(f"  Recall:     {summary['recall_mean']} ± {summary['recall_std']}%")
    print(f"  F1-Score:   {summary['f1_mean']} ± {summary['f1_std']}%")
    print(f"  TCR:        {summary['tcr_mean']} ± {summary['tcr_std']}%")
    if summary.get("scan_time_mean_hours") is not None:
        print(f"  Scan Time:  {summary['scan_time_mean_hours']} ± {summary['scan_time_std_hours']}h")
    print(f"  -> {out_path}")

    print_markdown_table(target, summary)
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Compute P/R/F1/TCR from scan_runner.sh findings.json output"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target",
                       choices=["dvwa", "bwapp", "juiceshop", "ctf"],
                       help="Target name — must match ground_truth_{target}.json")
    group.add_argument("--all", action="store_true",
                       help="Compute metrics for all three canonical targets")
    parser.add_argument("--runs", nargs="+",
                        help="Run directory names under evaluation/runs/ (ignored with --all)")
    args = parser.parse_args()

    if args.all:
        for target, runs in CANONICAL_RUNS.items():
            run_target(target, runs)
    else:
        if not args.runs:
            sys.exit("ERROR: --runs is required with --target")
        run_target(args.target, args.runs)


if __name__ == "__main__":
    main()
