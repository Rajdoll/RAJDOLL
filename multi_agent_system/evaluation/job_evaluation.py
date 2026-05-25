from __future__ import annotations

import json
from pathlib import Path

from multi_agent_system.evaluation.compute_metrics import matches

EVAL_DIR = Path(__file__).resolve().parent


def load_gt_entries(target_profile: str) -> list[dict]:
    f = EVAL_DIR / f"ground_truth_{target_profile}.json"
    if not f.exists():
        raise FileNotFoundError(f"ground truth not found: {f}")
    return json.loads(f.read_text())["entries"]


def compare_findings_to_gt(findings: list[dict], gt_entries: list[dict]) -> dict:
    non_info = [f for f in findings if (f.get("severity") or "").lower() != "info"]

    rows = []
    detected_count = 0
    for gt in gt_entries:
        gt_wstg = gt.get("owasp_wstg", "")
        detected = any(matches(f.get("category", ""), gt_wstg) for f in non_info)
        if detected:
            detected_count += 1
        rows.append({
            "wstg": gt_wstg,
            "challenge": gt.get("challenge", ""),
            "vuln_category": gt.get("vuln_category", ""),
            "severity": gt.get("severity", ""),
            "detected": detected,
            "status": "TP" if detected else "FN",
        })

    tp_findings = 0
    false_positives = []
    for f in non_info:
        matched = any(matches(f.get("category", ""), gt.get("owasp_wstg", "")) for gt in gt_entries)
        if matched:
            tp_findings += 1
        else:
            false_positives.append({
                "wstg": f.get("category", ""),
                "title": f.get("title", ""),
                "agent_name": f.get("agent_name", ""),
                "severity": f.get("severity", ""),
            })

    fp = len(false_positives)
    total_gt = len(gt_entries)
    precision = round(tp_findings / (tp_findings + fp) * 100, 2) if (tp_findings + fp) else 0.0
    recall = round(detected_count / total_gt * 100, 2) if total_gt else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 2) if (precision + recall) else 0.0

    return {
        "summary": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp_findings": tp_findings,
            "fp_findings": fp,
            "total_findings_non_info": len(non_info),
            "detected_gt": detected_count,
            "total_gt": total_gt,
        },
        "ground_truth_rows": rows,
        "false_positives": false_positives,
    }
