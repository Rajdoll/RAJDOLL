import importlib.util, pathlib
_p = pathlib.Path(__file__).parent / "input-validation.py"
_s = importlib.util.spec_from_file_location("input_validation_mod", _p)
iv = importlib.util.module_from_spec(_s); _s.loader.exec_module(iv)


def test_body_field_from_path_style_url_endpoint():
    # Juice Shop's SSRF sink is /profile/image/url, body {"url": ...} —
    # the field name is the last path segment.
    assert iv._ssrf_body_field_from_path("/profile/image/url") == "url"


def test_body_field_from_path_with_no_segments():
    assert iv._ssrf_body_field_from_path("/") is None
    assert iv._ssrf_body_field_from_path("") is None


def test_ssrf_evidence_pattern_match():
    ev = iv._ssrf_evidence("Apache/2.4.41 (Ubuntu)", "http://127.0.0.1/", r"(Apache|nginx|IIS|tomcat)")
    assert ev and "Pattern match" in ev[0]


def test_ssrf_evidence_cloud_metadata():
    ev = iv._ssrf_evidence("ami-id: ami-12345", "http://169.254.169.254/metadata/v1/", "")
    assert ev and "metadata" in ev[0].lower()


def test_ssrf_evidence_file_protocol():
    ev = iv._ssrf_evidence("root:x:0:0:root:/root:/bin/bash", "file:///etc/passwd", "")
    assert ev and "File system" in ev[0]


def test_ssrf_evidence_no_match():
    assert iv._ssrf_evidence("404 not found", "http://127.0.0.1/", r"(Apache|nginx)") == []
