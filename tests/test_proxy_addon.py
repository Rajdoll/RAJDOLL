"""Egress proxy addon logic with mitmproxy test flows and an in-memory store (TRD 4.2)."""

import asyncio
import base64
import os
from typing import Any

import pytest

if os.environ.get("RAJDOLL_REQUIRE_PROXY_TESTS") != "1":
    pytest.importorskip("mitmproxy", reason="mitmproxy is installed only for proxy tests")

from mitmproxy import http
from mitmproxy.test import tflow

from tools.proxy.addon import EgressProxy, TokenBucket, parse_credentials

TOKEN = "s3cret-token"


class FakeStore:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.tasks = {7: (1, 3, {"rate_limit_rps": 1000})}
        self.engagements: dict[int, dict[str, Any]] = {
            1: {"identity_header": {"name": "X-VA-Team", "value": "BSSN"}},
            2: {},
        }
        self.scopes = {1: ["app.instansi.test", "*.api.instansi.test"], 2: ["other.test"]}

    def task(self, task_id: int) -> tuple[int, int, dict[str, Any]] | None:
        return self.tasks.get(task_id)

    def engagement_settings(self, engagement_id: int) -> dict[str, Any] | None:
        return self.engagements.get(engagement_id)

    def scope(self, engagement_id: int) -> list[str]:
        return self.scopes.get(engagement_id, [])

    def write(self, row: dict[str, Any]) -> None:
        self.rows.append(row)


def _auth(username: str, token: str = TOKEN) -> str:
    return "Basic " + base64.b64encode(f"{username}:{token}".encode()).decode()


def _flow(method: str, host: str, *, port: int = 443, auth: str | None = None) -> http.HTTPFlow:
    flow = tflow.tflow()
    flow.request.method = method
    flow.request.scheme = "https" if port == 443 else "http"
    flow.request.host = host
    flow.request.port = port
    flow.request.path = "/" if method != "CONNECT" else ""
    flow.request.headers["Host"] = host
    if auth is not None:
        flow.request.headers["Proxy-Authorization"] = auth
    return flow


@pytest.fixture
def store() -> FakeStore:
    return FakeStore()


@pytest.fixture
def proxy(store: FakeStore) -> EgressProxy:
    return EgressProxy(store, TOKEN)


# Credentials --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("username", "token", "expected"),
    [
        ("task.7.nuclei", TOKEN, ("task", 7, "nuclei")),
        ("eng.12.session_check", TOKEN, ("eng", 12, "session_check")),
        ("task.7.nuclei", "wrong", None),
        ("admin", TOKEN, None),
        ("task.x.nuclei", TOKEN, None),
        ("task.7.Nuclei Scanner", TOKEN, None),
    ],
)
def test_parse_credentials(username: str, token: str, expected: tuple | None) -> None:
    creds = parse_credentials(_auth(username, token), TOKEN)
    assert (None if creds is None else (creds.kind, creds.ident, creds.label)) == expected


def test_parse_credentials_rejects_garbage() -> None:
    assert parse_credentials(None, TOKEN) is None
    assert parse_credentials("Bearer abc", TOKEN) is None
    assert parse_credentials("Basic !!!not-base64", TOKEN) is None


def test_empty_token_is_refused(store: FakeStore) -> None:
    with pytest.raises(ValueError):
        EgressProxy(store, "")


# CONNECT (HTTPS) ----------------------------------------------------------------------


def test_connect_without_credentials_gets_407(proxy: EgressProxy, store: FakeStore) -> None:
    flow = _flow("CONNECT", "app.instansi.test")
    asyncio.run(proxy.http_connect(flow))
    assert flow.response is not None
    assert flow.response.status_code == 407
    assert "Proxy-Authenticate" in flow.response.headers
    assert store.rows == []  # no engagement to attribute it to


def test_connect_outside_scope_is_blocked_and_logged(proxy: EgressProxy, store: FakeStore) -> None:
    flow = _flow("CONNECT", "evil.example", auth=_auth("task.7.nuclei"))
    asyncio.run(proxy.http_connect(flow))
    assert flow.response is not None
    assert flow.response.status_code == 403
    assert flow.response.headers["X-Rajdoll-Blocked"] == "scope"
    assert len(store.rows) == 1
    row = store.rows[0]
    assert (row["engagement_id"], row["scan_id"], row["task_id"]) == (1, 3, 7)
    assert (row["outcome"], row["method"], row["tool"]) == ("blocked_scope", "CONNECT", "nuclei")


def test_tunnel_request_in_scope_is_forwarded_with_identity_header(
    proxy: EgressProxy, store: FakeStore
) -> None:
    connect = _flow("CONNECT", "app.instansi.test", auth=_auth("task.7.nuclei"))
    asyncio.run(proxy.http_connect(connect))
    assert connect.response is None
    assert "Proxy-Authorization" not in connect.request.headers

    inner = _flow("GET", "app.instansi.test")
    inner.client_conn = connect.client_conn  # same TLS tunnel
    asyncio.run(proxy.request(inner))
    assert inner.response is None
    assert inner.request.headers["X-VA-Team"] == "BSSN"

    inner.response = http.Response.make(200, b"hello")
    proxy.response(inner)
    assert store.rows[-1]["outcome"] == "forwarded"
    assert store.rows[-1]["status"] == 200
    assert store.rows[-1]["response_bytes"] == 5

    proxy.client_disconnected(connect.client_conn)
    orphan = _flow("GET", "app.instansi.test")
    orphan.client_conn = connect.client_conn
    asyncio.run(proxy.request(orphan))
    assert orphan.response is not None
    assert orphan.response.status_code == 407


def test_host_header_mismatch_inside_tunnel_is_blocked(
    proxy: EgressProxy, store: FakeStore
) -> None:
    connect = _flow("CONNECT", "app.instansi.test", auth=_auth("task.7.nuclei"))
    asyncio.run(proxy.http_connect(connect))
    inner = _flow("GET", "app.instansi.test")
    inner.client_conn = connect.client_conn
    inner.request.headers["Host"] = "evil.example"
    asyncio.run(proxy.request(inner))
    assert inner.response is not None
    assert inner.response.status_code == 403
    assert store.rows[-1]["outcome"] == "blocked_scope"


# Plain HTTP ---------------------------------------------------------------------------


def test_plain_http_direct_context(proxy: EgressProxy, store: FakeStore) -> None:
    flow = _flow("GET", "deep.api.instansi.test", port=80, auth=_auth("eng.1.session_check"))
    asyncio.run(proxy.request(flow))
    assert flow.response is None
    assert "Proxy-Authorization" not in flow.request.headers
    flow.response = http.Response.make(302, b"")
    proxy.response(flow)
    row = store.rows[-1]
    assert (row["engagement_id"], row["scan_id"], row["task_id"]) == (1, None, None)
    assert (row["tool"], row["status"]) == ("session_check", 302)


def test_wildcard_does_not_cover_its_base_domain(proxy: EgressProxy) -> None:
    flow = _flow("GET", "api.instansi.test", port=80, auth=_auth("eng.1.session_check"))
    asyncio.run(proxy.request(flow))
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_unknown_task_or_engagement_is_refused(proxy: EgressProxy) -> None:
    for username in ("task.999.nuclei", "eng.999.session_check"):
        flow = _flow("GET", "app.instansi.test", port=80, auth=_auth(username))
        asyncio.run(proxy.request(flow))
        assert flow.response is not None
        assert flow.response.status_code == 407


def test_scopes_do_not_leak_between_engagements(proxy: EgressProxy) -> None:
    flow = _flow("GET", "app.instansi.test", port=80, auth=_auth("eng.2.session_check"))
    asyncio.run(proxy.request(flow))
    assert flow.response is not None
    assert flow.response.status_code == 403


def test_upstream_error_is_logged(proxy: EgressProxy, store: FakeStore) -> None:
    flow = _flow("GET", "app.instansi.test", port=80, auth=_auth("eng.1.session_check"))
    asyncio.run(proxy.request(flow))
    proxy.error(flow)
    assert store.rows[-1]["outcome"] == "error"


# Rate limiting ------------------------------------------------------------------------


def test_token_bucket_spaces_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [0.0]
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    bucket = TokenBucket(2.0, clock=lambda: now[0])

    async def run() -> None:
        for _ in range(6):
            await bucket.acquire()

    asyncio.run(run())
    # Burst of two, then one request every 0.5 s.
    assert sleeps == pytest.approx([0.5, 0.5, 0.5, 0.5])
    assert now[0] == pytest.approx(2.0)


def test_token_bucket_rate_change_caps_burst() -> None:
    bucket = TokenBucket(10.0)
    bucket.set_rate(1.0)
    assert bucket.capacity == 1.0
