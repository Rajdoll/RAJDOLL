import pytest

from rajdoll.core.scope import (
    ScopeError,
    host_matches,
    in_scope,
    normalize_pattern,
    url_host,
    url_in_scope,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("app.instansi.test", "app.instansi.test"),
        ("  APP.Instansi.Test. ", "app.instansi.test"),
        ("*.instansi.test", "*.instansi.test"),
        ("10.20.30.40", "10.20.30.40"),
        ("app.instansi.test:8443", "app.instansi.test"),
        ("https://app.instansi.test", "app.instansi.test"),
        ("https://app.instansi.test:8080/", "app.instansi.test"),
        ("localhost", "localhost"),
    ],
)
def test_normalize_accepts_hosts(raw: str, expected: str) -> None:
    assert normalize_pattern(raw) == expected


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "kosong"),
        ("*", "semua host"),
        ("*.test", "terlalu luas"),
        ("app.*.test", "Wildcard hanya boleh di awal"),
        ("*.*.instansi.test", "Wildcard hanya boleh di awal"),
        ("app.instansi.test/admin", "tanpa path"),
        ("https://app.instansi.test/admin", "tanpa path"),
        ("app.instansi.test:abc", "Port tidak valid"),
        ("-bad-.test", "Host tidak valid"),
        ("under_score.test", "Host tidak valid"),
    ],
)
def test_normalize_rejects_bad_patterns(raw: str, message: str) -> None:
    with pytest.raises(ScopeError, match=message):
        normalize_pattern(raw)


def test_exact_and_wildcard_matching() -> None:
    assert host_matches("app.instansi.test", "APP.instansi.test")
    assert not host_matches("app.instansi.test", "api.instansi.test")
    assert host_matches("*.instansi.test", "a.instansi.test")
    assert host_matches("*.instansi.test", "a.b.instansi.test")
    assert not host_matches("*.instansi.test", "instansi.test")
    assert not host_matches("*.instansi.test", "evilinstansi.test")
    assert not host_matches("*.instansi.test", "instansi.test.evil.example")


def test_empty_scope_allows_nothing() -> None:
    assert not in_scope([], "app.instansi.test")
    assert not in_scope(["app.instansi.test"], None)
    assert not in_scope(["app.instansi.test"], "")


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://app.instansi.test/login", True),
        ("http://app.instansi.test:8080/", True),
        ("https://other.test/", False),
        ("ftp://app.instansi.test/", False),
        ("app.instansi.test", False),
        ("https://app.instansi.test.evil.example/", False),
    ],
)
def test_url_in_scope(url: str, expected: bool) -> None:
    assert url_in_scope(["app.instansi.test"], url) is expected


def test_url_host_requires_http() -> None:
    assert url_host("HTTPS://App.Instansi.Test/x") == "app.instansi.test"
    with pytest.raises(ScopeError):
        url_host("javascript:alert(1)")
