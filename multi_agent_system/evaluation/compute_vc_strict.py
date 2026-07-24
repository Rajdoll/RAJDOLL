#!/usr/bin/env python3
"""
Vulnerability Coverage (VC) recomputation for the Juice Shop 5-run benchmark.

[Echefunna2024]'s own definition of Vulnerability Coverage: "the number of URLs
identified by scanners" -- i.e. discovery/crawl breadth, not confirmed-vulnerable
count. This script reproduces VC on that same definition: the union of unique
endpoints discovered across the 5 benchmark runs (job173/177/178/179/180),
sourced from the `endpoint_inventory` key in the `shared_context` DB table
(populated during reconnaissance by katana/dirsearch/JS-bundle-analysis).

Requires the rajdoll-db-1 container running:
    docker start rajdoll-db-1

Usage:
    python3 compute_vc_strict.py
"""

import json
import re
import subprocess

JOB_IDS = [173, 177, 178, 179, 180]
TOTAL_JUICESHOP_ENDPOINTS = 329  # cited in [Echefunna2024]; see caveat in bukti_vc.md


def norm(path: str) -> str:
    path = re.sub(r"^https?://[^/]+", "", path)
    path = path.split("?")[0].rstrip("/")
    return path or "/"


def fetch_endpoint_inventory(job_id: int) -> list:
    out = subprocess.run(
        ["docker", "exec", "rajdoll-db-1", "psql", "-U", "rajdoll", "-d", "rajdoll",
         "-t", "-A", "-c",
         f"SELECT value FROM shared_context WHERE job_id={job_id} AND key='endpoint_inventory';"],
        capture_output=True, text=True, check=True,
    )
    data = json.loads(out.stdout.strip())
    return data["endpoints"]


def main():
    all_discovered = set()
    for job_id in JOB_IDS:
        endpoints = fetch_endpoint_inventory(job_id)
        norm_set = {norm(e.get("endpoint") or e.get("url") or "") for e in endpoints}
        norm_set.discard("")
        print(f"job{job_id}: {len(norm_set)} unique endpoints")
        all_discovered |= norm_set

    vc = len(all_discovered) / TOTAL_JUICESHOP_ENDPOINTS * 100
    print()
    print(f"Union unik lintas {len(JOB_IDS)} run: {len(all_discovered)}")
    print(f"VC = {len(all_discovered)}/{TOTAL_JUICESHOP_ENDPOINTS} = {vc:.2f}%")


if __name__ == "__main__":
    main()
