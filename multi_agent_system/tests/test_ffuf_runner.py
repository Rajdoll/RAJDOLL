import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from multi_agent_system.agents.modules.ffuf_runner import FfufRunner


@pytest.mark.asyncio
async def test_ffuf_runner_filters_status_codes(tmp_path):
    runner = FfufRunner(rate_per_sec=10, allowed_status=(200, 401, 403))
    raw = {
        "results": [
            {"status": 200, "url": "https://x/a", "input": {"FUZZ": "a"}},
            {"status": 404, "url": "https://x/b", "input": {"FUZZ": "b"}},
            {"status": 403, "url": "https://x/c", "input": {"FUZZ": "c"}},
        ]
    }
    out = runner.parse_results(raw)
    paths = sorted([e["path"] for e in out])
    assert paths == ["/a", "/c"]
    assert all(e["discovered_by"] == "R3_ffuf" for e in out)


@pytest.mark.asyncio
async def test_ffuf_runner_invokes_with_correct_args(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("admin\napi\n")
    runner = FfufRunner(rate_per_sec=5)

    captured = {}
    async def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return json.dumps({"results": []})
    with patch.object(runner, "_run_subprocess", side_effect=fake_run):
        await runner.run(target="https://example.com", wordlist=wordlist)
    assert "-rate" in captured["cmd"]
    assert "5" in captured["cmd"]
    assert str(wordlist) in captured["cmd"]


@pytest.mark.asyncio
async def test_ffuf_runner_per_segment_fuzz_picks_top_prefixes(tmp_path):
    runner = FfufRunner(rate_per_sec=10)
    discovered = [
        {"path": "/api/x", "discovered_by": "R1"},
        {"path": "/api/y", "discovered_by": "R1"},
        {"path": "/api/z", "discovered_by": "R1"},
        {"path": "/admin/x", "discovered_by": "R1"},
        {"path": "/v2/y", "discovered_by": "R1"},
    ]
    prefixes = runner.top_prefixes(discovered, n=2)
    assert prefixes == ["/api", "/admin"] or prefixes == ["/api", "/v2"]
    assert prefixes[0] == "/api"
