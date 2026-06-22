import json, subprocess, pathlib, pytest

def _run():
    root = pathlib.Path(__file__).parents[3]
    script = (
        'cd /app/client-side-testing && python3 - <<PY\n'
        'import asyncio, importlib.util, pathlib, json\n'
        'p=pathlib.Path("/app/client-side-testing/client-side.py")\n'
        's=importlib.util.spec_from_file_location("cs",p); cs=importlib.util.module_from_spec(s); s.loader.exec_module(cs)\n'
        'async def main():\n'
        '    r=await cs.verify_xss_headless("http://juice-shop:3000/#/search", params=["q"])\n'
        '    print(json.dumps(r.get("data",{})))\n'
        'asyncio.run(main())\n'
        'PY'
    )
    out = subprocess.run(["docker","compose","exec","-T","client-mcp","sh","-c",script],
                         cwd=str(root), capture_output=True, text=True, timeout=180)
    line = [l for l in out.stdout.splitlines() if l.strip().startswith("{")]
    return json.loads(line[-1]) if line else {}

@pytest.mark.integration
def test_headless_verifier_fires_on_juiceshop_xss():
    data = _run()
    assert data.get("vulnerable") is True, f"verifier did not confirm XSS: {data}"
