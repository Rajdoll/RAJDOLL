"""Recompute detection coverage of the EXISTING 10 benchmark runs against the
expanded ground truth — quantifies the false-negative set without any re-scan."""
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from compute_metrics import matches

EVAL_DIR = pathlib.Path(__file__).parent

def gap_against_gt(findings, ground_truth):
    detected = set()
    for gt in ground_truth:
        code = gt.get("owasp_wstg", "")
        if any(matches(f.get("category", ""), code) for f in findings):
            detected.add(gt["id"])
    missed = [gt for gt in ground_truth if gt["id"] not in detected]
    return {"detected_ids": detected, "missed_entries": missed}

def main():
    gt = json.loads((EVAL_DIR / "ground_truth_juiceshop.json").read_text())["entries"]
    union = []
    for i in range(1, 11):
        p = EVAL_DIR / f"runs/juiceshop_benchmark_run{i}/findings.json"
        if p.exists():
            union.extend(json.loads(p.read_text()))
    out = gap_against_gt(union, gt)
    missed = out["missed_entries"]
    lines = ["# v15.0.0 Detection Gap (existing scans vs expanded GT)", "",
             f"GT entries: {len(gt)} | covered by existing runs: {len(out['detected_ids'])} | "
             f"never detected (FN): {len(missed)}", "",
             "These FN entries scope the Plan 2 detection work:", "",
             "| Challenge | WSTG | id |", "|---|---|---|"]
    for e in sorted(missed, key=lambda x: x["owasp_wstg"]):
        lines.append(f"| {e['challenge']} | {e['owasp_wstg']} | {e['id']} |")
    (EVAL_DIR / "v15_gap_report.md").write_text("\n".join(lines))
    print("\n".join(lines))

if __name__ == "__main__":
    main()
