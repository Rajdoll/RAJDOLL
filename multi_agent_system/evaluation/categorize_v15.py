"""Propose automatable/WSTG categorization for v15.0.0 challenges NOT yet in ground truth.
Output is a REVIEW artifact — the user ratifies before it is locked into ground truth.
Rule (verbatim): non-automatable = needs OSINT / chatbot interaction / cultural-linguistic
knowledge / external investigation / manual visual forensics."""
import json, pathlib, yaml

EVAL_DIR = pathlib.Path(__file__).parent

# Generic keyword rule (applied to name+description, case-insensitive).
NON_AUTOMATABLE_KW = [
    "chatbot", "dumpster dive", "the internet", "security question",
    "looking at an upload", "photo wall", "cultural", "easter egg",
    "privacy policy", "read our", "actually read",
]

# Explicit overrides for borderline cases the keyword rule cannot judge.
# (automatable, reason) — USER RATIFIES THESE in Task 3.
OVERRIDES = {
    "Meta Geo Stalking": (True, "EXIF GPS metadata on served image — covered by new EXIF tool"),
    "Visual Geo Stalking": (False, "needs visual landmark recognition, not metadata"),
    "Frontend Typosquatting": (True, "package-name edit-distance — covered by new SCA tool"),
    "Legacy Typosquatting": (True, "package-name edit-distance — covered by new SCA tool"),
    "Unsigned JWT": (True, "JWT alg=none — existing CRYP-04 detection"),
    "Local File Read": (True, "path traversal — existing BUSL-09 detection"),
    "Arbitrary File Write": (True, "zip-slip / file upload — existing BUSL-08 detection"),
    "GDPR Data Erasure": (True, "SQLi to access soft-deleted account — existing INPV-05"),
    "GDPR Data Theft": (True, "broken object-level authorization on data export"),
    "Leaked Unsafe Product": (True, "SQLi to surface removed product — existing INPV-05"),
    "Login Amy": (True, "weak/guessable credentials — ATHN-07"),
    "Login Bjoern": (False, "requires knowing real account email + unchanged password"),
    "Login Support Team": (False, "requires recovering hardcoded original credentials (OSINT-like)"),
    "Retrieve Blueprint": (True, "forced browsing to unreferenced file — CONF-04"),
    "Weird Crypto": (True, "detect insecure crypto algorithm in use — CRYP-04"),
    "Premium Paywall": (False, "multi-step crypto puzzle / source analysis"),
    "Nested Easter Egg": (False, "manual cryptanalysis / forensics"),
    "Imaginary Challenge": (False, "meta joke — non-existent challenge #999"),
    "Extra Language": (False, "anti-automation language-file puzzle"),
    "Reset Morty's Password": (False, "CAPTCHA + obfuscated security answer"),
    "Missing Encoding": (True, "encoded path to served media file — INPV/CONF"),
    "Empty User Registration": (True, "missing input validation on registration — IDNT-02"),
    "Ephemeral Accountant": (True, "SQLi login as non-existent user — INPV-05"),
    "User Credentials": (True, "UNION SQLi credential dump — INPV-05"),
    "Blocked RCE DoS": (True, "RCE via insecure deserialization — INPV"),
    "Successful RCE DoS": (True, "RCE via insecure deserialization — INPV"),
    "XXE DoS": (True, "XXE — existing INPV-07 detection"),
    "API-only XSS": (True, "persisted XSS via API — INPV-01"),
    "Client-side XSS Protection": (True, "XSS bypassing client filter — CLNT-01"),
    "Server-side XSS Protection": (True, "persisted XSS bypassing server filter — INPV-01"),
    "HTTP-Header XSS": (True, "persisted XSS via HTTP header — INPV-01"),
    "Reflected XSS": (True, "reflected XSS — CLNT-01"),
    "Video XSS": (True, "persisted XSS via subtitle file — INPV-01"),
    "Mass Dispel": (False, "UI-only: close multiple notifications"),
    "Privacy Policy": (False, "UI-only: read the privacy policy page"),
    "Privacy Policy Inspection": (False, "client-side obscurity puzzle in policy page"),
    "Blockchain Hype": (False, "external announcement OSINT"),
    "Steganography": (False, "image steganography forensics"),
    "Bjoern's Favorite Pet": (False, "security-question OSINT about a real person"),
    "Reset Bender's Password": (False, "security-question OSINT"),
    "Reset Bjoern's Password": (False, "security-question OSINT"),
    "Reset Uvogin's Password": (False, "security-question OSINT"),
    "Kill Chatbot": (False, "chatbot manipulation"),
    "Bully Chatbot": (False, "chatbot interaction"),
}

# Category -> default WSTG sub-code proposal (overridable per-challenge in review).
CATEGORY_WSTG = {
    "XSS": "WSTG-INPV-01",
    "Injection": "WSTG-INPV-05",
    "Insecure Deserialization": "WSTG-INPV-13",
    "XXE": "WSTG-INPV-07",
    "Vulnerable Components": "WSTG-CONF-01",
    "Sensitive Data Exposure": "WSTG-CONF-04",
    "Broken Authentication": "WSTG-ATHN-07",
    "Improper Input Validation": "WSTG-IDNT-02",
    "Security Misconfiguration": "WSTG-CONF-05",
    "Cryptographic Issues": "WSTG-CRYP-04",
    "Broken Anti Automation": "WSTG-BUSL-05",
    "Security through Obscurity": "WSTG-CONF-04",
    "Miscellaneous": "WSTG-BUSL-01",
}

# Per-challenge WSTG override where the category default is wrong.
WSTG_OVERRIDE = {
    "Reflected XSS": "WSTG-CLNT-01",
    "Client-side XSS Protection": "WSTG-CLNT-01",
    "Unsigned JWT": "WSTG-CRYP-04",
    "Local File Read": "WSTG-BUSL-09",
    "Arbitrary File Write": "WSTG-BUSL-08",
    "Meta Geo Stalking": "WSTG-CONF-04",
    "Empty User Registration": "WSTG-IDNT-02",
    "Login Amy": "WSTG-ATHN-07",
    "GDPR Data Erasure": "WSTG-INPV-05",
    "Leaked Unsafe Product": "WSTG-INPV-05",
    "Retrieve Blueprint": "WSTG-CONF-04",
}

def classify_challenge(name, category, description):
    if name in OVERRIDES:
        flag, reason = OVERRIDES[name]
        return flag, reason
    blob = f"{name} {description}".lower()
    for kw in NON_AUTOMATABLE_KW:
        if kw in blob:
            return False, f"keyword rule: '{kw}'"
    return True, "default: technical vulnerability"

def propose_wstg(name, category):
    if name in WSTG_OVERRIDE:
        return WSTG_OVERRIDE[name]
    return CATEGORY_WSTG.get(category, "WSTG-INPV-01")

def _load_yaml(path):
    return yaml.safe_load(pathlib.Path(path).read_text())

def build_review(challenges_yml: str) -> str:
    gt = json.loads((EVAL_DIR / "ground_truth_juiceshop.json").read_text())
    gt_names = {e["challenge"] for e in gt["entries"]}
    v15 = _load_yaml(challenges_yml)
    rows = []
    for c in sorted(v15, key=lambda x: (x.get("category", ""), x["name"])):
        if c["name"] in gt_names:
            continue
        flag, reason = classify_challenge(c["name"], c.get("category", ""), c.get("description", ""))
        wstg = propose_wstg(c["name"], c.get("category", "")) if flag else "-"
        rows.append((c["name"], c.get("category", ""), "Y" if flag else "N", wstg, reason))
    lines = ["# v15.0.0 New-Challenge Categorization — REVIEW BEFORE LOCK", "",
             f"Total new challenges: {len(rows)} | Automatable: {sum(1 for r in rows if r[2]=='Y')}", "",
             "| Challenge | Category | Auto | WSTG | Reason |", "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} |")
    return "\n".join(lines)

if __name__ == "__main__":
    import sys
    out = build_review(sys.argv[1])
    (EVAL_DIR / "v15_categorization_review.md").write_text(out)
    print(out)
