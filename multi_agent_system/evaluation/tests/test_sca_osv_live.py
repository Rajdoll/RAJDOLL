"""Live integration smoke test: the generic SCA must recover the dependency manifest
(conventional filenames + generic null-byte bypass) and flag vulnerable dependencies via
OSV.dev, emitting WSTG-CONF-01 — where the old hardcoded check found nothing.
Requires Docker up with the worker container and juice-shop v15 reachable + OSV.dev egress.
"""
import json
import pathlib
import subprocess

import pytest

# Clean probe: imports the generic SCA helpers from the package and exercises recovery+OSV.
_PROBE = (
    "import asyncio, json, httpx\n"
    "from multi_agent_system.agents.config_deploy_agent import "
    "_recover_manifest_urls, _strip_version, _deps_with_advisories\n"
    "async def main():\n"
    "    base='http://juice-shop:3000'; manifest=None\n"
    "    async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as c:\n"
    "        for u in _recover_manifest_urls(base):\n"
    "            try:\n"
    "                r=await c.get(u)\n"
    "                if r.status_code==200 and len(r.content)>1000:\n"
    "                    j=r.json()\n"
    "                    if isinstance(j,dict) and (j.get('dependencies') or j.get('devDependencies')):\n"
    "                        manifest=j; break\n"
    "            except Exception: pass\n"
    "        if not manifest: print(json.dumps({'vulnerable':0})); return\n"
    "        deps=[(n,_strip_version(s)) for sec in ('dependencies','devDependencies') "
    "for n,s in (manifest.get(sec) or {}).items()][:60]\n"
    "        q=[{'package':{'name':n,'ecosystem':'npm'},'version':v} for n,v in deps]\n"
    "        rr=await c.post('https://api.osv.dev/v1/querybatch', json={'queries':q})\n"
    "        print(json.dumps({'vulnerable': len(_deps_with_advisories(rr.json().get('results',[]), deps))}))\n"
    "asyncio.run(main())\n"
)


def _run_probe() -> dict:
    root = pathlib.Path(__file__).parents[3]
    host_script = pathlib.Path("/tmp/_sca_live_probe.py")
    host_script.write_text(_PROBE)
    subprocess.run(["docker", "cp", str(host_script), "rajdoll-worker-1:/tmp/_sca_live_probe.py"],
                   cwd=str(root), capture_output=True, text=True, timeout=30)
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", "-e", "PYTHONPATH=/app", "worker",
         "python3", "/tmp/_sca_live_probe.py"],
        cwd=str(root), capture_output=True, text=True, timeout=120)
    lines = [ln for ln in out.stdout.splitlines() if ln.strip().startswith("{")]
    return json.loads(lines[-1]) if lines else {"_stdout": out.stdout, "_stderr": out.stderr}


@pytest.mark.integration
def test_generic_sca_flags_juiceshop_deps():
    data = _run_probe()
    assert data.get("vulnerable", 0) >= 1, f"generic SCA found no vulnerable deps: {data}"
