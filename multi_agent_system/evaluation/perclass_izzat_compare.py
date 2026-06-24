"""Per-OWASP-Top-10-category comparison: RAJDOLL vs Izzat et al. (Nuclei), same target Juice Shop.
Buckets the 80-entry ground truth + a run's findings into Izzat's 5 categories, computes P/R/F1
per category for RAJDOLL, prints side-by-side with Izzat's published numbers."""
import json, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from compute_metrics import matches

EVAL = pathlib.Path(__file__).parent
CATS = ["Injection", "XSS", "Security Misconfiguration", "Vulnerable Components", "Sensitive Data Exposure"]

# Izzat et al. (Nuclei) Table 4 — published per-category P/R/F1 (%)
IZZAT = {
    "Injection": (100.0, 66.67, 80.0),
    "XSS": (100.0, 75.0, 85.71),
    "Security Misconfiguration": (66.67, 100.0, 80.0),
    "Vulnerable Components": (50.0, 50.0, 50.0),
    "Sensitive Data Exposure": (100.0, 83.33, 90.91),
}

def gt_bucket(vc):
    s = (vc or "").lower()
    if "xss" in s: return "XSS"
    if any(k in s for k in ["sql injection", "nosql", "xxe", "template injection", "ssti"]): return "Injection"
    if s.strip() == "injection": return "Injection"
    if "vulnerable component" in s: return "Vulnerable Components"
    if any(k in s for k in ["sensitive data", "sensitive file", "information disclosure",
                            "sensitive endpoint", "cryptograph"]): return "Sensitive Data Exposure"
    if any(k in s for k in ["security misconfiguration", "csp misconfiguration", "error disclosure"]):
        return "Security Misconfiguration"
    return "Other"

def find_bucket(cat):
    c = cat.strip()
    inj = ["WSTG-INPV-05", "WSTG-INPV-06", "WSTG-INPV-07", "WSTG-INPV-12", "WSTG-INPV-18"]
    if any(c.startswith(x) for x in inj): return "Injection"
    if c.startswith("WSTG-INPV-01") or c.startswith("WSTG-CLNT-01") or c.startswith("WSTG-CLNT-13"): return "XSS"
    if c.startswith("WSTG-CONF-01"): return "Vulnerable Components"
    if any(c.startswith(x) for x in ["WSTG-CONF-04", "WSTG-INFO-02", "WSTG-CRYP-03", "WSTG-CRYP-04"]):
        return "Sensitive Data Exposure"
    if c.startswith("WSTG-ERRH") or any(c.startswith(f"WSTG-CONF-0{n}") for n in [2,3,5,6,7,8,9]):
        return "Security Misconfiguration"
    return "Other"

def main(run_label):
    gt = json.load(open(EVAL / "ground_truth_juiceshop.json"))["entries"]
    F = json.load(open(EVAL / "runs" / run_label / "findings.json"))
    noninfo = [f for f in F if f.get("severity") != "info"]
    print(f"# Per-category comparison vs Izzat — run: {run_label}\n")
    print(f"{'Category':<28} {'GT':>3} | {'RAJDOLL P/R/F1':>22} | {'Izzat P/R/F1':>22}")
    print("-"*82)
    for cat in CATS:
        gtc = [g for g in gt if gt_bucket(g.get("vuln_category", "")) == cat]
        det = [g for g in gtc if any(matches(f.get("category",""), g["owasp_wstg"]) for f in noninfo)]
        rec = 100*len(det)/len(gtc) if gtc else 0.0
        fc = [f for f in noninfo if find_bucket(f.get("category","")) == cat]
        tp = [f for f in fc if any(matches(f.get("category",""), g["owasp_wstg"]) for g in gtc)]
        prec = 100*len(tp)/len(fc) if fc else 0.0
        f1 = (2*prec*rec/(prec+rec)) if (prec+rec) else 0.0
        ip, ir, if1 = IZZAT[cat]
        print(f"{cat:<28} {len(gtc):>3} | {prec:5.1f}/{rec:5.1f}/{f1:5.1f}        | {ip:5.1f}/{ir:5.1f}/{if1:5.1f}")
    other=[g for g in gt if gt_bucket(g.get("vuln_category",""))=="Other"]
    print(f"\nGT outside Izzat's 5 categories (RAJDOLL-only coverage): {len(other)} challenges")
    from collections import Counter
    print("  ", dict(Counter(g.get('vuln_category','?') for g in other)))

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv)>1 else "juiceshop_v15_run1")
