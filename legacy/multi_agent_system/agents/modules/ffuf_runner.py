"""ffuf wrapper for Recon Phase R3 (active fuzzing).

Runs ffuf via subprocess, parses JSON output, applies status filter
and rate limiting. Per-segment fuzzing helper picks top prefixes.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from collections import Counter
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

log = logging.getLogger(__name__)

DEFAULT_ALLOWED_STATUS = (200, 201, 204, 301, 302, 401, 403)


class FfufRunner:
    def __init__(
        self,
        rate_per_sec: int = 10,
        allowed_status: tuple[int, ...] = DEFAULT_ALLOWED_STATUS,
        timeout_seconds: int = 480,
    ):
        self.rate = rate_per_sec
        self.allowed_status = allowed_status
        self.timeout = timeout_seconds

    async def _run_subprocess(self, cmd: list[str]) -> str:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return ""
        return stdout.decode(errors="replace")

    async def run(self, target: str, wordlist: Path) -> list[dict]:
        if not shutil.which("ffuf"):
            log.warning("ffuf binary not found in PATH; skipping R3")
            return []
        cmd = [
            "ffuf",
            "-u", f"{target.rstrip('/')}/FUZZ",
            "-w", str(wordlist),
            "-mc", ",".join(str(s) for s in self.allowed_status),
            "-rate", str(self.rate),
            "-of", "json",
            "-o", "-",
            "-s",
        ]
        raw_output = await self._run_subprocess(cmd)
        if not raw_output:
            return []
        try:
            raw = json.loads(raw_output)
        except json.JSONDecodeError:
            return []
        return self.parse_results(raw)

    def parse_results(self, raw: dict) -> list[dict]:
        out: list[dict] = []
        for entry in raw.get("results", []):
            status = entry.get("status")
            if status not in self.allowed_status:
                continue
            url = entry.get("url", "")
            parsed = urlparse(url)
            path = parsed.path or "/"
            out.append({
                "path": path,
                "method": "GET",
                "discovered_by": "R3_ffuf",
                "status_seen": status,
            })
        return out

    @staticmethod
    def top_prefixes(endpoints: Iterable[dict], n: int = 3) -> list[str]:
        counts: Counter[str] = Counter()
        for ep in endpoints:
            path = ep.get("path", "")
            segments = [s for s in path.split("/") if s]
            if segments:
                counts[f"/{segments[0]}"] += 1
        return [p for p, _ in counts.most_common(n)]

    async def run_per_segment(
        self,
        target: str,
        wordlist: Path,
        seed_endpoints: list[dict],
        n_prefixes: int = 3,
    ) -> list[dict]:
        prefixes = self.top_prefixes(seed_endpoints, n=n_prefixes)
        out: list[dict] = []
        for prefix in prefixes:
            seg_target = f"{target.rstrip('/')}{prefix}"
            results = await self.run(seg_target, wordlist)
            for r in results:
                r["path"] = f"{prefix}{r['path']}"
            out.extend(results)
        return out
