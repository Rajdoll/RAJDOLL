"""Per-class P/R/F1 over the 10 benchmark runs, mapped to the 5 reference-paper classes
(Injection / XSS / Security Misconfiguration / Vulnerable Components / Sensitive Data Exposure).
Reuses the same matches() logic as compute_metrics.py so numbers stay consistent.
Mapping is EXPLICIT below so it can be audited/adjusted."""
import json, statistics
from pathlib import Path

BASE = Path(__file__).parent
GT = json.load(open(BASE / "ground_truth_juiceshop.json"))["entries"]

GT_ALIAS_MAP = {
    "WSTG-INPV-18": ["WSTG-CLNT-13", "WSTG-CLNT-01"],
    "WSTG-INPV-01": ["WSTG-INPV-02", "WSTG-CLNT-01"],
    "WSTG-CLNT-04": ["WSTG-CLNT-12", "WSTG-CLNT-09"],
    "WSTG-CONF-05": ["WSTG-CONF-07", "WSTG-INFO-02"],
    "WSTG-BUSL-09": ["WSTG-ATHZ-02", "WSTG-BUSL-01"],
    "WSTG-BUSL-01": ["WSTG-BUSL-09", "WSTG-BUSL-05", "WSTG-BUSL-03"],
    "WSTG-ATHZ-04": ["WSTG-ATHZ-02", "WSTG-ATHZ"],
    "WSTG-CONF-04": ["WSTG-CONF-03"],
    "WSTG-ATHN-03": ["WSTG-INPV-05"],
}

def matches(fc, gc):
    fc, gc = fc.strip(), gc.strip()
    if fc == gc or gc.startswith(fc + "-") or fc.startswith(gc + "-"):
        return True
    return fc in GT_ALIAS_MAP.get(gc, [])

# GT owasp_wstg code -> reference class (only the overlapping subset; rest = out of scope)
CLASS_OF_WSTG = {
    "WSTG-INPV-05": "Injection",        # SQLi + NoSQLi
    "WSTG-INPV-18": "Injection",        # SSTI
    "WSTG-INPV-07": "Injection",        # XXE
    "WSTG-INPV-01": "XSS",              # Stored XSS
    "WSTG-CLNT-01": "XSS",              # DOM XSS
    "WSTG-CONF-05": "Security Misconfiguration",
    "WSTG-CLNT-12": "Security Misconfiguration",  # CSP
    "WSTG-CONF-01": "Vulnerable Components",
    "WSTG-INFO-02": "Sensitive Data Exposure",
    "WSTG-INFO-06": "Sensitive Data Exposure",
    "WSTG-CONF-04": "Sensitive Data Exposure",    # sensitive file exposure
    "WSTG-ERRH-01": "Sensitive Data Exposure",
    "WSTG-CRYP-04": "Sensitive Data Exposure",
}
CLASSES = ["Injection", "XSS", "Security Misconfiguration", "Vulnerable Components", "Sensitive Data Exposure"]

def class_of_finding(cat):
    """Map a finding category to a reference class by the same WSTG code (prefix)."""
    for code, cls in CLASS_OF_WSTG.items():
        if cat == code or cat.startswith(code + "-") or code.startswith(cat + "-"):
            return cls
    # SSTI client-side alias used by the scanner
    if cat in ("WSTG-CLNT-13",):
        return "Injection"
    return None

# GT entries per class
gt_by_class = {c: [g for g in GT if CLASS_OF_WSTG.get(g["owasp_wstg"]) == c] for c in CLASSES}
in_scope = sum(len(v) for v in gt_by_class.values())

runs = [f"juiceshop_benchmark_run{i}" for i in range(1, 11)]
per_class_runs = {c: {"P": [], "R": [], "F1": []} for c in CLASSES}

for r in runs:
    findings = json.load(open(BASE / "runs" / r / "findings.json"))
    findings = [f for f in findings if (f.get("severity", "") or "").lower() != "info"]
    for c in CLASSES:
        gt_c = gt_by_class[c]
        # Recall: GT entries of class c detected by any finding
        detected = sum(1 for g in gt_c if any(matches(f.get("category", ""), g["owasp_wstg"]) for f in findings))
        recall = detected / len(gt_c) * 100 if gt_c else 0.0
        # Precision: findings mapped to class c; TP if matches any GT, else FP
        fc = [f for f in findings if class_of_finding(f.get("category", "")) == c]
        tp = sum(1 for f in fc if any(matches(f.get("category", ""), g["owasp_wstg"]) for g in GT))
        fp = len(fc) - tp
        prec = tp / (tp + fp) * 100 if (tp + fp) else 0.0
        f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0.0
        per_class_runs[c]["P"].append(prec)
        per_class_runs[c]["R"].append(recall)
        per_class_runs[c]["F1"].append(f1)

def ms(xs): return f"{statistics.mean(xs):.1f}", f"{(statistics.pstdev(xs)):.1f}"

print(f"GT entries in-scope of the 5 reference classes: {in_scope}/57 "
      f"({57 - in_scope} out of scope: IDOR/BUSL/ATHN/ATHZ/SESS/CSRF/file-upload/mass-assign/etc.)\n")
print(f"{'Class':<28} {'n_GT':>4}  {'Precision':>14} {'Recall':>14} {'F1':>14}")
for c in CLASSES:
    n = len(gt_by_class[c])
    pm, ps = ms(per_class_runs[c]["P"]); rm, rs = ms(per_class_runs[c]["R"]); fm, fs = ms(per_class_runs[c]["F1"])
    print(f"{c:<28} {n:>4}  {pm+'±'+ps+'%':>14} {rm+'±'+rs+'%':>14} {fm+'±'+fs+'%':>14}")
