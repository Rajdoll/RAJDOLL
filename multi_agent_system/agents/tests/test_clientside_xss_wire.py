import pathlib
SRC = pathlib.Path(__file__).parents[1] / "client_side_agent.py"

def test_verify_xss_headless_registered_and_attributed():
    src = SRC.read_text()
    # tool offered to the LLM planner
    assert "verify_xss_headless" in src
    # findings attributed to CLNT-01 from the headless tool's result
    block = src[src.index("verify_xss_headless"):]
    assert "WSTG-CLNT-01" in block
    # candidates come from discovery context, not hardcoded routes
    assert "endpoint_inventory" in src or "discovered_endpoints" in src


def test_both_xss_blocks_use_shared_candidate_helper():
    src = SRC.read_text()
    assert src.count("_xss_candidate_urls(") >= 2, (
        "expected both the aggressive-mode block and the verify_xss_headless block "
        "to call _xss_candidate_urls()"
    )


def test_aggressive_block_uses_hash_aware_url_builder():
    src = SRC.read_text()
    block = src[src.index("Aggressive-mode"):src.index("Headless-browser XSS confirmation")]
    assert "_build_probe_url(" in block, (
        "aggressive-mode block must build probe URLs via a hash-aware builder, "
        "not raw httpx params= (which puts the query OUTSIDE a #fragment, "
        "breaking SPA hash-routed candidates)"
    )


def test_verify_xss_headless_loop_does_not_break_after_first_hit():
    src = SRC.read_text()
    block = src[src.index("Headless-browser XSS confirmation"):]
    block = block[:block.index("def _get_tool_info")]
    assert "break" not in block, (
        "verify_xss_headless loop should try all candidates, not stop after the first hit, "
        "so distinct XSS findings across multiple routes are reported"
    )
