#!/usr/bin/env python3
"""
Compute ΔRecall per-agent from ablation run outputs.

Usage (from /mnt/d/MCP/RAJDOLL/):
  python3 multi_agent_system/evaluation/compute_ablation.py \\
    --baseline juiceshop_run3 \\
    --agents AuthenticationAgent SessionManagementAgent InputValidationAgent \\
             AuthorizationAgent ConfigDeploymentAgent ClientSideAgent \\
             FileUploadAgent APITestingAgent ErrorHandlingAgent \\
             WeakCryptographyAgent BusinessLogicAgent IdentityManagementAgent

Output:
  multi_agent_system/evaluation/ablation_results.json
  Prints LaTeX Table V rows
"""

import argparse
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent


def load_findings(run_label: str) -> list:
    f = BASE_DIR / "runs" / run_label / "findings.json"
    if not f.exists():
        print(f"  WARNING: no findings.json for '{run_label}'")
        return []
    return json.loads(f.read_text())


def load_ground_truth(target: str) -> list:
    gt_file = BASE_DIR / f"ground_truth_{target}.json"
    if not gt_file.exists():
        sys.exit(f"ERROR: {gt_file} not found")
    return json.loads(gt_file.read_text())["entries"]


def matches(fc: str, gc: str) -> bool:
    return fc == gc or gc.startswith(fc + "-") or fc.startswith(gc + "-")


def compute_recall(findings: list, ground_truth: list) -> float:
    detected = set()
    for gt in ground_truth:
        gt_wstg = gt.get("owasp_wstg", "")
        for f in findings:
            if matches(f.get("category", ""), gt_wstg):
                detected.add(gt["id"])
                break
    return round(len(detected) / len(ground_truth) * 100, 2) if ground_truth else 0.0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True,
                        help="Baseline run label (e.g. juiceshop_run3)")
    parser.add_argument("--agents", required=True, nargs="+",
                        help="Agent names that were ablated")
    args = parser.parse_args()

    gt = load_ground_truth("juiceshop")
    baseline_findings = load_findings(args.baseline)
    if not baseline_findings:
        sys.exit(f"ERROR: no findings for baseline run '{args.baseline}'")

    baseline_recall = compute_recall(baseline_findings, gt)
    print(f"Baseline ({args.baseline}): Recall = {baseline_recall}%\n")

    results = []
    for agent in args.agents:
        label = f"ablation_skip_{agent}"
        findings = load_findings(label)
        if not findings:
            print(f"  SKIP {agent}: no findings.json")
            results.append({"agent": agent, "recall": None, "delta_recall": None})
            continue
        recall = compute_recall(findings, gt)
        delta = round(recall - baseline_recall, 2)
        print(f"  - {agent}: Recall={recall}%  ΔRecall={delta:+.2f}%")
        results.append({
            "agent": agent,
            "run_label": label,
            "recall": recall,
            "delta_recall": delta,
        })

    # Sort by ΔRecall ascending (most impactful agent = most negative delta)
    results.sort(key=lambda x: (x["delta_recall"] is None, x.get("delta_recall", 0)))

    ablation_data = {
        "baseline_run": args.baseline,
        "baseline_recall": baseline_recall,
        "target": "juiceshop",
        "agents": results,
    }
    out = BASE_DIR / "ablation_results.json"
    out.write_text(json.dumps(ablation_data, indent=2))
    print(f"\nSaved → {out}")

    # Print LaTeX Table V rows
    print("\n=== LaTeX Table V rows ===")
    print(f"Baseline (all agents) & {baseline_recall}\\% & -- \\\\")
    for r in results:
        agent_short = r["agent"].replace("Agent", "")
        if r["delta_recall"] is None:
            print(f"$-$ {agent_short} & N/A & N/A \\\\")
        else:
            print(f"$-$ {agent_short} & {r['recall']}\\% & {r['delta_recall']:+.2f}\\% \\\\")


if __name__ == "__main__":
    main()
