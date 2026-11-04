"""Rule-based tags, module selection, request estimate, raw requests, checkpoint edits (F5b)."""

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from rajdoll.core.crypto import KeyStore
from rajdoll.core.models import Endpoint, Engagement, Scan, ScanEvent
from rajdoll.modules.base import EndpointSeen
from rajdoll.services import engagements, inventory, planning, raw_request, scans, tagging
from rajdoll.services.errors import Conflict, ValidationFailed


def _ep(method: str, path: str, **extra: Any) -> dict[str, Any]:
    return {"method": method, "path_template": path, "host": "app.test", **extra}


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        (_ep("GET", "/api/v1/pengguna/{id}"), {"idor_candidate", "api", "profile"}),
        (_ep("GET", "/akun/{id}"), {"idor_candidate", "profile"}),
        (_ep("GET", "/admin"), {"admin"}),
        (
            _ep("POST", "/login", body_params=[{"name": "password", "location": "form"}]),
            {"auth", "state_change", "has_params"},
        ),
        (_ep("POST", "/register"), {"registration", "state_change"}),
        (_ep("POST", "/lupa-password"), {"password_reset", "state_change"}),
        (
            _ep("POST", "/upload", body_params=[{"name": "berkas", "location": "multipart"}]),
            {"upload", "state_change", "has_params", "file_param"},
        ),
        (
            _ep("POST", "/api/v1/transfer", body_params=[{"name": "jumlah", "location": "json"}]),
            {"price", "state_change", "has_params", "api"},
        ),
        (_ep("GET", "/go", query_params=["next"]), {"redirect_param", "has_params"}),
        (_ep("GET", "/view", query_params=["file"]), {"file_param", "has_params"}),
        (_ep("POST", "/graphql"), {"graphql", "state_change"}),
        (_ep("GET", "/.env", source="fuzz"), {"hidden"}),
        (_ep("GET", "/produk"), set()),
    ],
)
def test_rule_tags(endpoint: dict, expected: set[str]) -> None:
    assert set(tagging.rule_tags(endpoint)) == expected


def test_validate_tags() -> None:
    assert tagging.validate(["upload", "admin"]) == ["admin", "upload"]
    with pytest.raises(ValueError, match="bogus"):
        tagging.validate(["admin", "bogus"])


def test_modules_follow_tags() -> None:
    active = list(planning.MODULE_RULES) + ["information_gathering"]
    idor = _ep("GET", "/api/v1/pengguna/{id}", tags=["idor_candidate", "api", "profile"])
    assert planning.modules_for(idor, active) == ["authorization", "identity"]
    login = _ep("POST", "/login", tags=["auth", "state_change", "has_params"])
    assert planning.modules_for(login, active) == [
        "input_validation",
        "authentication",
        "session",
        "error_handling",
        "cryptography",
    ]
    page = _ep("GET", "/produk", tags=[])
    assert planning.modules_for(page, active) == ["client_side"]
    assert planning.modules_for({**login, "excluded": True}, active) == []
    assert planning.modules_for(login, ["authentication"]) == ["authentication"]


def test_estimate_counts_parameters_and_hosts() -> None:
    endpoints = [
        _ep("GET", "/cari", tags=["has_params"], query_params=["q", "debug"]),
        _ep("GET", "/logout", tags=[], excluded=True),
    ]
    only_input = planning.estimate(endpoints, ["input_validation"])
    assert only_input == 120 * 2
    with_host = planning.estimate(endpoints, ["input_validation", "configuration"])
    assert with_host == 240 + 400  # configuration runs once per host
    assert planning.estimate([], ["configuration"]) == 0


def test_raw_request_parsing() -> None:
    parsed = raw_request.parse(
        "POST /api/v1/keranjang?x=1 HTTP/1.1\r\nHost: app.test\r\nCookie: sid=abc\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"produk_id": 1, "jumlah": 2}',
    )
    assert (parsed.method, parsed.url) == ("POST", "https://app.test/api/v1/keranjang?x=1")
    assert [p["name"] for p in parsed.body_params] == ["produk_id", "jumlah"]
    form = raw_request.parse(
        "POST http://app.test:8080/kontak HTTP/2\n"
        "Content-Type: application/x-www-form-urlencoded\n\nnama=a&pesan=b&nama=c"
    )
    assert form.url == "http://app.test:8080/kontak"
    assert form.body_params == [
        {"name": "nama", "location": "form"},
        {"name": "pesan", "location": "form"},
    ]
    multipart = raw_request.parse(
        "POST /upload HTTP/1.1\nHost: app.test\nContent-Type: multipart/form-data; boundary=X\n\n"
        '--X\nContent-Disposition: form-data; name="berkas"; filename="a.txt"\n\nisi\n--X--'
    )
    assert multipart.body_params == [{"name": "berkas", "location": "multipart"}]
    for bad in ("halo", "GET /x HTTP/1.1\nAccept: */*\n\n", "GET x HTTP/1.1\nHost: a\n"):
        with pytest.raises(ValidationFailed):
            raw_request.parse(bad)


@pytest.fixture
def keystore(tmp_path: Path) -> KeyStore:
    return KeyStore(tmp_path)


@pytest.fixture
def scan(db_session: Session, keystore: KeyStore) -> Scan:
    engagement = engagements.create(
        db_session, keystore, {"name": "x", "target_url": "http://testapp:8080/"}
    )
    started = scans.start(db_session, engagement, "full")
    started.status, started.stage = "awaiting_checkpoint", "planning"
    started.checkpoint_deadline = scans.utcnow() + timedelta(minutes=15)
    inventory.record(
        db_session,
        engagement.id,
        started.id,
        [
            EndpointSeen("GET", "http://testapp:8080/akun/1", "crawl"),
            EndpointSeen("GET", "http://testapp:8080/logout", "crawl"),
            EndpointSeen("GET", "http://testapp:8080/cari?q=1", "crawl"),
        ],
        ["testapp"],
        exclude_patterns=["logout"],
    )
    return started


def _rows(session: Session, scan: Scan) -> dict[str, Endpoint]:
    return {e.path_template: e for e in inventory.list_for(session, scan.engagement_id)}


def test_inventory_rows_get_rule_tags(db_session: Session, scan: Scan) -> None:
    rows = _rows(db_session, scan)
    assert rows["/akun/{id}"].tags == ["idor_candidate", "profile"]
    assert rows["/akun/{id}"].tag_source == "rule"
    assert rows["/cari"].tags == ["has_params"]
    # New parameters found later recompute rule tags...
    inventory.record(
        db_session,
        scan.engagement_id,
        scan.id,
        [EndpointSeen("GET", "http://testapp:8080/cari", "fuzz", query_params=("next",))],
        ["testapp"],
    )
    assert _rows(db_session, scan)["/cari"].tags == ["has_params", "redirect_param"]


def test_checkpoint_view(db_session: Session, scan: Scan) -> None:
    view = planning.checkpoint(db_session, scan, {"information_gathering"}, {"waf": None})
    assert view["editable"] is True
    endpoints = {e["path_template"]: e for e in view["endpoints"]}
    assert endpoints["/logout"]["modules"] == []
    # Profile order; an HTML page is also tested by Client-Side.
    assert endpoints["/akun/{id}"]["modules"] == ["identity", "authorization", "client_side"]
    modules = {m["name"]: m for m in view["modules"]}
    assert modules["information_gathering"]["skipped_reason"] is None
    assert modules["input_validation"]["skipped_reason"] == "not_available"
    assert modules["input_validation"]["endpoints"] == 1
    assert view["recon_summary"]["estimated_requests"] > 0


def test_edits_hold_the_countdown_and_change_the_plan(
    db_session: Session, scan: Scan, keystore: KeyStore
) -> None:
    rows = _rows(db_session, scan)
    changes = planning.edit(
        db_session,
        keystore,
        scan,
        {
            "modules": ["authorization", "input_validation"],
            "endpoints": [
                {"id": rows["/logout"].id, "excluded": False},
                {"id": rows["/cari"].id, "excluded": "true", "tags": "has_params, upload"},
            ],
            "add_endpoints": [
                {"method": "post", "url": "http://testapp:8080/api/v1/transfer"},
                {
                    "raw_request": "PUT /api/v1/keranjang HTTP/1.1\nHost: testapp:8080\n"
                    'Content-Type: application/json\n\n{"jumlah": 3}'
                },
            ],
            "add_scope": ["cdn.luar.test"],
        },
    )
    assert len(changes) == 4
    assert scan.checkpoint_deadline is None  # editing stops the countdown
    assert scan.modules == ["authorization", "input_validation"]
    rows = _rows(db_session, scan)
    assert (rows["/logout"].excluded, rows["/logout"].exclude_reason) == (False, None)
    assert (rows["/cari"].excluded, rows["/cari"].exclude_reason) == (True, "user")
    assert (rows["/cari"].tags, rows["/cari"].tag_source) == (["has_params", "upload"], "user")
    assert rows["/api/v1/transfer"].source == "manual"
    cart = db_session.scalars(
        select(Endpoint).where(Endpoint.path_template == "/api/v1/keranjang")
    ).one()
    assert cart.method == "PUT" and cart.source == "burp_paste"
    assert cart.body_params == [{"name": "jumlah", "location": "json"}]
    engagement = db_session.get(Engagement, scan.engagement_id)
    sample = engagements.cipher(keystore, engagement).decrypt_text(
        "endpoint", "sample_request_enc", cart.sample_request_enc
    )
    assert sample.startswith("PUT /api/v1/keranjang")
    assert "cdn.luar.test" in engagements.scope_patterns(db_session, scan.engagement_id)
    messages = [
        e.message for e in db_session.scalars(select(ScanEvent).where(ScanEvent.scan_id == scan.id))
    ]
    assert "Hitung mundur checkpoint ditahan oleh asesor." in messages
    assert any(m.startswith("Rencana disunting:") for m in messages)

    # A user's tags survive later recon.
    inventory.record(
        db_session,
        scan.engagement_id,
        scan.id,
        [EndpointSeen("GET", "http://testapp:8080/cari", "fuzz", query_params=("file",))],
        ["testapp"],
    )
    assert _rows(db_session, scan)["/cari"].tags == ["has_params", "upload"]


@pytest.mark.parametrize(
    ("data", "field"),
    [
        ({"modules": []}, "modules"),
        ({"modules": ["sqlmap"]}, "modules"),
        ({"endpoints": [{"id": 999999, "excluded": True}]}, "endpoints"),
        ({"endpoints": [{"id": None, "tags": "bogus"}]}, "endpoints"),
        ({"add_endpoints": [{"method": "TRACE", "url": "http://testapp:8080/x"}]}, "method"),
        ({"add_endpoints": [{"method": "GET", "url": "http://other.test/x"}]}, "url"),
        ({"add_endpoints": [{"method": "GET", "url": "ftp://testapp/x"}]}, "url"),
        ({"add_endpoints": [{"raw_request": "nonsense"}]}, "raw_request"),
        ({"add_scope": ["*"]}, "pattern"),
    ],
)
def test_edit_validation(
    db_session: Session, scan: Scan, keystore: KeyStore, data: dict, field: str
) -> None:
    if field == "endpoints" and data["endpoints"][0]["id"] is None:
        data = {"endpoints": [{"id": _rows(db_session, scan)["/cari"].id, "tags": "bogus"}]}
        field = "tags"
    with pytest.raises(ValidationFailed) as info:
        planning.edit(db_session, keystore, scan, data)
    assert info.value.field_errors[0].field == field


def test_edits_only_at_the_checkpoint(db_session: Session, scan: Scan, keystore: KeyStore) -> None:
    scan.status = "running"
    with pytest.raises(Conflict):
        planning.edit(db_session, keystore, scan, {"modules": ["session"]})
