import json
import sys


def split_by_source(findings: list) -> dict:
    out = {"deterministic": [], "llm-adjudicated": []}
    for f in findings or []:
        src = (f.get("evidence") or {}).get("source")
        if src == "llm-adjudicated":
            out["llm-adjudicated"].append(f)
        else:
            out["deterministic"].append(f)
    return out


if __name__ == "__main__":
    data = json.load(open(sys.argv[1]))
    findings = data if isinstance(data, list) else data.get("findings", [])
    s = split_by_source(findings)
    print(f"deterministic={len(s['deterministic'])} llm-adjudicated={len(s['llm-adjudicated'])}")
