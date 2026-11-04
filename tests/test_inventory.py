"""Endpoint normalization and the per-engagement inventory (BSD 4.4)."""

from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from rajdoll.core.crypto import KeyStore
from rajdoll.core.models import Engagement
from rajdoll.modules.base import EndpointSeen
from rajdoll.services import engagements, inventory


@pytest.mark.parametrize(
    ("method", "url", "expected"),
    [
        ("get", "https://App.Test/produk/12", ("GET", "https", "app.test", "/produk/{id}", ())),
        ("GET", "https://app.test:443/a/", ("GET", "https", "app.test", "/a", ())),
        ("GET", "http://testapp:8080/", ("GET", "http", "testapp:8080", "/", ())),
        ("GET", "http://app.test:80/x?b=1&a=2&a=3", ("GET", "http", "app.test", "/x", ("a", "b"))),
        (
            "GET",
            "https://app.test/u/0f8fad5b-d9cb-469f-a165-70867728950e/f",
            ("GET", "https", "app.test", "/u/{uuid}/f", ()),
        ),
        (
            "GET",
            "https://app.test/t/5d41402abc4b2a76b9719d911017c592",
            ("GET", "https", "app.test", "/t/{hash}", ()),
        ),
        (
            "DELETE",
            "https://app.test/api/users/:userId",
            ("DELETE", "https", "app.test", "/api/users/{userId}", ()),
        ),
        (
            "GET",
            "https://app.test/api/v1/pengguna/{id}",
            ("GET", "https", "app.test", "/api/v1/pengguna/{id}", ()),
        ),
        (
            "GET",
            "https://app.test/static/app.js",
            ("GET", "https", "app.test", "/static/app.js", ()),
        ),
        (
            "GET",
            "https://app.test//double//slash",
            ("GET", "https", "app.test", "/double/slash", ()),
        ),
    ],
)
def test_normalize(method: str, url: str, expected: tuple) -> None:
    norm = inventory.normalize(method, url)
    assert norm is not None
    assert (norm.method, norm.scheme, norm.host, norm.path_template, norm.query_params) == expected


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("GET", "https://app.test/logo.PNG"),
        ("GET", "https://app.test/style.css"),
        ("GET", "ftp://app.test/a"),
        ("GET", "javascript:void(0)"),
        ("TRACE", "https://app.test/"),
        ("GET", "https://app.test:99999/"),
    ],
)
def test_normalize_skips(method: str, url: str) -> None:
    assert inventory.normalize(method, url) is None


@pytest.fixture
def engagement(db_session: Session, tmp_path: Path) -> Engagement:
    return engagements.create(
        db_session, KeyStore(tmp_path), {"name": "x", "target_url": "http://testapp:8080/"}
    )


def test_record_deduplicates_and_merges(db_session: Session, engagement: Engagement) -> None:
    scope = engagements.scope_patterns(db_session, engagement.id)
    first = inventory.record(
        db_session,
        engagement.id,
        None,
        [
            EndpointSeen("GET", "http://testapp:8080/produk/1", "crawl"),
            EndpointSeen("GET", "http://testapp:8080/produk/2", "crawl"),
            EndpointSeen("GET", "http://testapp:8080/cari?q=a", "crawl"),
            EndpointSeen(
                "POST",
                "http://testapp:8080/kontak",
                "crawl",
                body_params=({"name": "nama", "location": "form"},),
                content_type="application/x-www-form-urlencoded",
            ),
            EndpointSeen("GET", "http://cdn.luar.test/lib.js", "js"),
            EndpointSeen("GET", "http://cdn.luar.test/other.js", "js"),
            EndpointSeen("GET", "http://testapp:8080/logo.png", "crawl"),
        ],
        scope,
    )
    assert (first.added, first.updated) == (3, 0)
    assert first.out_of_scope == {"cdn.luar.test": 2}

    second = inventory.record(
        db_session,
        engagement.id,
        None,
        [
            EndpointSeen("GET", "http://testapp:8080/cari", "fuzz", query_params=("debug",)),
            EndpointSeen(
                "POST",
                "http://testapp:8080/kontak",
                "crawl",
                body_params=(
                    {"name": "pesan", "location": "form"},
                    {"name": "nama", "location": "form"},
                ),
            ),
            EndpointSeen("GET", "http://testapp:8080/produk/7", "crawl"),
        ],
        scope,
    )
    assert (second.added, second.updated) == (0, 2)
    rows = {(e.method, e.path_template): e for e in inventory.list_for(db_session, engagement.id)}
    assert set(rows) == {("GET", "/produk/{id}"), ("GET", "/cari"), ("POST", "/kontak")}
    assert rows[("GET", "/cari")].query_params == ["debug", "q"]
    assert rows[("GET", "/cari")].source == "crawl"  # the first source is kept
    assert [p["name"] for p in rows[("POST", "/kontak")].body_params] == ["nama", "pesan"]
    assert rows[("POST", "/kontak")].content_type == "application/x-www-form-urlencoded"
    data = inventory.as_dict(rows[("GET", "/produk/{id}")])
    assert data["url"] == "http://testapp:8080/produk/{id}"
    assert data["scheme"] == "http" and data["host"] == "testapp:8080"
    assert inventory.count_for(db_session, engagement.id) == 3
