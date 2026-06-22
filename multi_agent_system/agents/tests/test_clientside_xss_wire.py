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
