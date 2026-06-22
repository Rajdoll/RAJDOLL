import subprocess, pathlib

def test_client_mcp_has_chromium_and_playwright():
    root = pathlib.Path(__file__).parents[3]
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", "client-mcp", "sh", "-c",
         "which chromium && python3 -c 'import playwright'"],
        cwd=str(root), capture_output=True, text=True)
    assert out.returncode == 0, f"chromium/playwright missing: {out.stdout}{out.stderr}"
