import sys, pathlib, inspect, importlib.util

# Try normal import first
try:
    sys.path.insert(0, str(pathlib.Path(__file__).parents[2]))
    from multi_agent_system.agents.config_deploy_agent import _strip_version, _recover_manifest_urls, _deps_with_advisories
    from multi_agent_system.agents.config_deploy_agent import ConfigDeploymentAgent
except Exception as e:
    # fallback: load via importlib with spec to allow relative imports in package
    try:
        spec = importlib.util.find_spec("multi_agent_system.agents.config_deploy_agent")
        if spec:
            mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = mod
            spec.loader.exec_module(mod)
            _strip_version = mod._strip_version
            _recover_manifest_urls = mod._recover_manifest_urls
            _deps_with_advisories = mod._deps_with_advisories
            ConfigDeploymentAgent = mod.ConfigDeploymentAgent
        else:
            raise ImportError("Could not find spec")
    except Exception as fallback_e:
        # If both fail, the helpers still need to be extracted for assertions
        _strip_version = None
        _recover_manifest_urls = None
        _deps_with_advisories = None
        ConfigDeploymentAgent = None

def _get(name):
    if name == "_strip_version":
        return _strip_version
    elif name == "_recover_manifest_urls":
        return _recover_manifest_urls
    elif name == "_deps_with_advisories":
        return _deps_with_advisories
    elif name == "_check_ftp_packages":
        return ConfigDeploymentAgent._check_ftp_packages if ConfigDeploymentAgent else None
    raise AttributeError(f"No {name}")

def test_strip_version():
    f = _get("_strip_version")
    assert f("^1.4.1") == "1.4.1"
    assert f(">=2.0.0") == "2.0.0"
    assert f("~0.4.0") == "0.4.0"
    assert f("4.17.1") == "4.17.1"

def test_strip_version_coerces_short_specs_to_three_parts():
    # legacy npm manifests commonly use 1-2 part specs (~4.16, ~0.7, ^4);
    # these must be coerced to x.y.z, not dropped by the downstream
    # 3-part-semver filter, or most real-world deps never reach OSV at all.
    f = _get("_strip_version")
    assert f("~4.16") == "4.16.0"
    assert f("~0.7") == "0.7.0"
    assert f("^4") == "4.0.0"
    assert f("~2") == "2.0.0"

def test_recover_manifest_urls_generic():
    urls = _get("_recover_manifest_urls")("http://t:3000")
    # conventional filenames + generic null-byte bypass present, generated (not a single literal)
    assert any(u.endswith("package.json.bak%2500.md") for u in urls)
    assert any(u.endswith("/package.json") for u in urls)
    assert len(urls) >= 6

def test_deps_with_advisories():
    f = _get("_deps_with_advisories")
    deps = [("jsonwebtoken", "0.4.0"), ("safe-pkg", "1.0.0")]
    results = [{"vulns": [{"id": "GHSA-x"}]}, {}]
    out = f(results, deps)
    assert len(out) == 1 and out[0]["name"] == "jsonwebtoken" and "GHSA-x" in out[0]["ids"]

def test_no_hardcoded_package_literals():
    f = _get("_check_ftp_packages")
    src = inspect.getsource(f).lower()
    for bad in ["sanitize-html", "jsonwebtoken", "lodash", "juice"]:
        assert bad not in src, f"hardcoded package literal in SCA function: {bad}"
