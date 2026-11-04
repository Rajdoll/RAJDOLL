"""testapp's declared recon surface stays in sync with the CI smoke test."""

import ast
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _testapp():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("testapp_app", REPO / "testapp" / "app.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _smoke_constant(name: str) -> object:
    tree = ast.parse((REPO / "tests" / "integration" / "smoke_scan.py").read_text())
    return next(
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == name
    )


def test_smoke_scan_expects_exactly_the_endpoints_testapp_registers() -> None:
    declared = [(method, path) for method, path, _how in _testapp().RECON_ENDPOINTS]
    assert _smoke_constant("EXPECTED") == declared


def test_smoke_scan_expects_exactly_the_findings_testapp_plants() -> None:
    assert _smoke_constant("EXPECTED_FINDINGS") == _testapp().EXPECTED_FINDINGS
    # One finding per weakness; "no-lockout" and "cleartext-login" are on two endpoints each.
    assert len(_testapp().EXPECTED_FINDINGS) == len(_testapp().WEAKNESSES) + 2


def test_every_declared_endpoint_is_served() -> None:
    from fastapi.testclient import TestClient

    app = _testapp().app
    routes = {(m, r.path.replace("{product_id}", "{id}").replace("{user_id}", "{id}")
               .replace("{order_id}", "{id}"))
              for r in app.routes for m in getattr(r, "methods", set())}  # fmt: skip
    for method, path, _how in _testapp().RECON_ENDPOINTS:
        assert (method, path) in routes, (method, path)
    assert TestClient(app).get("/cari?debug=1").text != TestClient(app).get("/cari").text
