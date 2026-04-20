#!/usr/bin/env python3
"""
Standalone P/R/F1 computation from scan_runner.sh output JSON files.
No RAJDOLL imports, no live DB required.

Usage (from /mnt/d/MCP/RAJDOLL/):
  python3 multi_agent_system/evaluation/compute_metrics.py \\
    --target dvwa --runs dvwa_run1 dvwa_run2 dvwa_run3

  python3 multi_agent_system/evaluation/compute_metrics.py \\
    --target juiceshop --runs juiceshop_run3 juiceshop_run4 juiceshop_run5

Output:
  evaluation/runs/{run}/metrics.json       (per run)
  evaluation/evaluation_{target}_summary.json  (aggregate mean +/- std)
"""

import argparse
import json
import math
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent


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


def matches(finding_category: str, gt_wstg: str) -> bool:
    """WSTG prefix matching — identical to metrics.py._matches()."""
    fc = finding_category.strip()
    gc = gt_wstg.strip()
    return fc == gc or gc.startswith(fc + "-") or fc.startswith(gc + "-")


def compute_run_metrics(findings: list, ground_truth: list) -> dict:
    """Compute P/R/F1 for a single scan run."""
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
        "precision": round(precision, 2),
        "recall": round(recall, 2),
        "f1": round(f1, 2),
        "findings_by_severity": sev_counts,
    }


def aggregate(per_run: list) -> dict:
    def mean_std(vals):
        if not vals:
            return 0.0, 0.0
        m = sum(vals) / len(vals)
        std = math.sqrt(sum((x - m) ** 2 for x in vals) / len(vals))
        return round(m, 2), round(std, 2)

    pm, ps = mean_std([r["precision"] for r in per_run])
    rm, rs = mean_std([r["recall"] for r in per_run])
    fm, fs = mean_std([r["f1"] for r in per_run])
    return {
        "n_runs": len(per_run),
        "precision_mean": pm, "precision_std": ps,
        "recall_mean": rm, "recall_std": rs,
        "f1_mean": fm, "f1_std": fs,
        "per_run": per_run,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Compute P/R/F1 from scan_runner.sh findings.json output"
    )
    parser.add_argument("--target", required=True,
                        choices=["dvwa", "bwapp", "juiceshop", "ctf"],
                        help="Target name — must match ground_truth_{target}.json")
    parser.add_argument("--runs", required=True, nargs="+",
                        help="Run directory names under evaluation/runs/")
    args = parser.parse_args()

    gt = load_ground_truth(args.target)
    print(f"Ground truth: {len(gt)} entries for '{args.target}'")

    per_run = []
    for label in args.runs:
        findings = load_findings(label)
        if not findings:
            continue
        m = compute_run_metrics(findings, gt)
        m["run_label"] = label
        job = load_job_result(label)
        m["scan_time_hours"] = job.get("scan_time_hours")
        out = BASE_DIR / "runs" / label / "metrics.json"
        out.write_text(json.dumps(m, indent=2))
        print(f"  {label}: P={m['precision']}%  R={m['recall']}%  F1={m['f1']}%"
              f"  ({m['tp_gt_entries']}/{m['total_gt_entries']} GT detected,"
              f" {m['fp_findings']} FP findings)")
        per_run.append(m)

    if not per_run:
        sys.exit("ERROR: No valid runs found (missing findings.json?)")

    summary = aggregate(per_run)
    summary["target"] = args.target
    out_path = BASE_DIR / f"evaluation_{args.target}_summary.json"
    out_path.write_text(json.dumps(summary, indent=2))

    print(f"\n=== {args.target.upper()} SUMMARY ({summary['n_runs']} runs) ===")
    print(f"  Precision:  {summary['precision_mean']} +/- {summary['precision_std']}%")
    print(f"  Recall:     {summary['recall_mean']} +/- {summary['recall_std']}%")
    print(f"  F1-Score:   {summary['f1_mean']} +/- {summary['f1_std']}%")
    print(f"  -> {out_path}")


if __name__ == "__main__":
    main()
