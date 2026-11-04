import importlib.util
from pathlib import Path


def _load_file_upload_mcp():
    path = Path(__file__).resolve().parents[2] / "file-upload-testing" / "file_upload.py"
    spec = importlib.util.spec_from_file_location("file_upload_mcp", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_juice_shop_upload_success_status_includes_204():
    module = _load_file_upload_mcp()

    assert module.is_upload_success_status(200) is True
    assert module.is_upload_success_status(201) is True
    assert module.is_upload_success_status(204) is True
    assert module.is_upload_success_status(500) is False


def test_file_upload_mcp_contains_juice_shop_size_and_xxe_payloads():
    source = (Path(__file__).resolve().parents[2] / "file-upload-testing" / "file_upload.py").read_text(encoding="utf-8")

    assert "150 * 1024" in source
    assert "large_file.pdf" in source
    assert "juice_shop_b2b_etc_passwd" in source
    assert "application/xml" in source
