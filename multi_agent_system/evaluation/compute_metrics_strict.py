#!/usr/bin/env python3
"""
Strict (validation-gated) P/R/F1/TCR recomputation for the Juice Shop
5-run benchmark (job173/177/178/179/180), used in the skripsi as the
figure directly comparable to Echefunna2024's Table 12 (True Positive
Rate), which is itself computed from manually-verified true positives.

Two corrections are applied on top of the base compute_metrics.py logic:

  1. forced-miss on the 21 ground-truth entries carrying a
     `detection_limitation` field (jsop-t038..jsop-t058). The generic
     WSTG-code matcher in compute_metrics.matches() over-credits these
     via coincidental prefix/alias overlap with unrelated findings;
     they are excluded from the "detected" set regardless of what the
     matcher says. Already applied in the officially reported figures.

  2. is_true_positive == True gate on every finding used as evidence,
     for both the Recall/TCR detection check and the Precision TP/FP
     count. NOT applied in the officially reported figures until this
     script — this is the new strict variant.

Usage (from multi_agent_system/evaluation/):
    python3 compute_metrics_strict.py
"""

import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from compute_metrics import matches  # noqa: E402

BASE_DIR = Path(__file__).parent

RUNS = [
    ("juiceshop_p23final_run1", 173),
    ("juiceshop_p23final_run4", 177),
    ("juiceshop_p23final_run5", 178),
    ("juiceshop_p23final_run6", 179),
    ("juiceshop_p23final_run7", 180),
]


def load_ground_truth() -> tuple[list, set, set]:
    gt = json.loads((BASE_DIR / "ground_truth_juiceshop.json").read_text())["entries"]
    forced_miss_ids = {g["id"] for g in gt if g.get("detection_limitation")}
    wstg_cats = {g["owasp_wstg"] for g in gt if g.get("owasp_wstg")}
    return gt, forced_miss_ids, wstg_cats


def recall_and_tcr(findings, gt, forced_miss_ids, wstg_cats):
    detected_ids = set()
    for g in gt:
        if g["id"] in forced_miss_ids:
            continue
        gw = g.get("owasp_wstg", "")
        for f in findings:
            if f.get("is_true_positive") is not True:
                continue
            if matches(f.get("category", ""), gw):
                detected_ids.add(g["id"])
                break
    recall = len(detected_ids) / len(gt) * 100
    detected_cats = {g.get("owasp_wstg", "") for g in gt if g["id"] in detected_ids}
    tcr = len(detected_cats) / len(wstg_cats) * 100
    return recall, len(detected_ids), tcr, len(detected_cats)


def precision(findings, gt):
    # TP requires a confirmed is_true_positive==True AND a matching GT category.
    # Confirmed false positives (is_true_positive==False) count as FP.
    # Unconfirmed findings (is_true_positive is None, still pending review) are
    # excluded from the denominator entirely -- consistent with how Recall
    # already treats unconfirmed findings as unusable evidence rather than
    # penalizing the system for items nobody has adjudicated yet.
    tp = fp = excluded = 0
    for f in findings:
        if f.get("severity", "").lower() == "info":
            continue
        itp = f.get("is_true_positive")
        if itp is None:
            excluded += 1
            continue
        matched = any(matches(f.get("category", ""), g.get("owasp_wstg", "")) for g in gt)
        if itp is True and matched:
            tp += 1
        else:
            fp += 1
    total = tp + fp
    return (tp / total * 100 if total else 0.0), tp, fp, excluded


def mean_std(vals):
    m = sum(vals) / len(vals)
    s = math.sqrt(sum((x - m) ** 2 for x in vals) / len(vals))
    return round(m, 2), round(s, 2)


def main():
    gt, forced_miss_ids, wstg_cats = load_ground_truth()
    print(f"Ground truth: {len(gt)} entries, {len(wstg_cats)} unique WSTG categories, "
          f"{len(forced_miss_ids)} forced-miss (detection_limitation)")
    print()
    print(f"{'run':28} {'job':5} {'Prec':>8} {'Recall':>8} {'F1':>8} {'TCR':>8}")

    p_vals, r_vals, f1_vals, tcr_vals = [], [], [], []
    for run_label, job_id in RUNS:
        findings = json.loads((BASE_DIR / "runs" / run_label / "findings.json").read_text())
        p, tp, fp, excluded = precision(findings, gt)
        r, n_det, tcr, n_cats = recall_and_tcr(findings, gt, forced_miss_ids, wstg_cats)
        f1 = (2 * p * r / (p + r)) if (p + r) > 0 else 0.0
        p_vals.append(p); r_vals.append(r); f1_vals.append(f1); tcr_vals.append(tcr)
        print(f"{run_label:28} {job_id:<5} {p:7.2f}% {r:7.2f}% {f1:7.2f}% {tcr:7.2f}%   "
              f"(TP={tp} FP={fp} excluded_unconfirmed={excluded} GT={n_det}/{len(gt)} cats={n_cats}/{len(wstg_cats)})")

    pm, ps = mean_std(p_vals)
    rm, rs = mean_std(r_vals)
    fm, fs = mean_std(f1_vals)
    tm, ts = mean_std(tcr_vals)
    print()
    print(f"Precision : {pm} +/- {ps}%")
    print(f"Recall/DR : {rm} +/- {rs}%")
    print(f"F1-Score  : {fm} +/- {fs}%")
    print(f"TCR       : {tm} +/- {ts}%")


if __name__ == "__main__":
    main()
