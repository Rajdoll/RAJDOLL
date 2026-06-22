"""Merge ratified automatable new v15.0.0 challenges into the ground truth."""
import json, pathlib, sys, yaml
import categorize_v15 as cat

EVAL_DIR = pathlib.Path(__file__).parent
GT = EVAL_DIR / "ground_truth_juiceshop.json"

def main(challenges_yml):
    d = json.loads(GT.read_text())
    existing = {e["challenge"] for e in d["entries"]}
    next_n = max(int(e["id"].split("-")[1][1:]) for e in d["entries"])
    v15 = yaml.safe_load(pathlib.Path(challenges_yml).read_text())
    added = 0
    for c in sorted(v15, key=lambda x: x["name"]):
        if c["name"] in existing:
            continue
        auto, _ = cat.classify_challenge(c["name"], c.get("category", ""), c.get("description", ""))
        if not auto:
            continue
        next_n += 1
        d["entries"].append({
            "id": f"jsop-t{next_n:03d}",
            "challenge": c["name"],
            "difficulty": f"{c.get('difficulty','?')}star",
            "vuln_category": c.get("category", ""),
            "owasp_wstg": cat.propose_wstg(c["name"], c.get("category", "")),
            "severity": "medium",
        })
        added += 1
    d["total_count"] = len(d["entries"])
    d["description"] = (f"OWASP Juice Shop v15.0.0 — {d['total_count']} automatable challenges "
                        f"of 102 total (non-automatable excluded per OSINT/chatbot/visual/external rule). "
                        f"Source: juice-shop v15.0.0 data/static/challenges.yml.")
    GT.write_text(json.dumps(d, indent=2, ensure_ascii=False))
    print(f"Added {added} entries; total now {d['total_count']}")

if __name__ == "__main__":
    main(sys.argv[1])
