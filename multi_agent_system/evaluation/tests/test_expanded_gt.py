import json, pathlib
GT = pathlib.Path(__file__).parents[1] / "ground_truth_juiceshop.json"

def test_gt_grew_and_is_well_formed():
    d = json.loads(GT.read_text())
    assert d["total_count"] == len(d["entries"])
    assert d["total_count"] > 57
    assert "v15.0.0" in d["description"]
    seen = set()
    for e in d["entries"]:
        for k in ("id", "challenge", "owasp_wstg", "severity"):
            assert e.get(k), f"missing {k} in {e}"
        assert e["owasp_wstg"].startswith("WSTG-")
        assert e["id"] not in seen, f"dup id {e['id']}"
        seen.add(e["id"])
