import json, subprocess, pathlib, pytest


def _run():
    root = pathlib.Path(__file__).parents[3]
    script = (
        "from multi_agent_system.utils.shared_context_manager import SharedContextManager\n"
        "from multi_agent_system.agents.client_side_agent import _xss_candidate_urls\n"
        "import json\n"
        "scm = SharedContextManager(job_id=138)\n"
        "shared_context = {\n"
        "    'endpoint_inventory': scm.read('endpoint_inventory') or {},\n"
        "    'discovered_endpoints': scm.read('discovered_endpoints') or {},\n"
        "    'js_routes_analysis': scm.read('js_routes_analysis') or {},\n"
        "}\n"
        "cands = _xss_candidate_urls(shared_context, 'http://juice-shop:3000')\n"
        "print(json.dumps([c['url'] for c in cands]))\n"
    )
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", "api", "python3", "-c", script],
        cwd=str(root), capture_output=True, text=True, timeout=60,
    )
    lines = [l for l in out.stdout.splitlines() if l.strip().startswith("[")]
    return json.loads(lines[-1]) if lines else []


@pytest.mark.integration
def test_search_route_is_a_candidate_for_job138():
    urls = _run()
    assert any(u.endswith("/#/search") for u in urls), (
        f"expected /#/search among candidates (regression guard for the discovery gap "
        f"found in job #138), got: {urls}"
    )
