"""End-to-end egress proxy: real mitmdump, real PostgreSQL, local HTTP and HTTPS targets.

Covers the F3 exit criteria for the proxy: out-of-scope requests are refused and logged as
`blocked_scope`, every forwarded request leaves an audit row, and the rate limit holds.
"""

import datetime
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url

from rajdoll.core.bootstrap import enable_tools_login
from rajdoll.services.session_check import make_prober, proxy_url

REPO = Path(__file__).resolve().parent.parent
TOKEN = "integration-token"
TOOLS_PASSWORD = "integration-tools-password"
MITMDUMP = Path(sys.executable).parent / "mitmdump"

if not MITMDUMP.exists():
    if os.environ.get("RAJDOLL_REQUIRE_PROXY_TESTS") == "1":
        pytest.fail(f"mitmdump not found next to {sys.executable}", pytrace=False)
    pytest.skip("mitmdump is installed only for proxy tests", allow_module_level=True)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"nothing listening on {port}")


# Upstream target ----------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    seen: list[dict[str, Any]] = []

    def do_GET(self) -> None:  # noqa: N802
        _Handler.seen.append({"path": self.path, "headers": dict(self.headers.items())})
        if self.path.startswith("/profil"):
            logged_in = "sid=valid" in self.headers.get("Cookie", "")
            body = "<p>Halo, Budi</p>" if logged_in else "<form>Masuk</form>"
        else:
            body = json.dumps({"path": self.path})
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_: Any) -> None:
        pass


def _self_signed(tmp: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / "cert.pem", tmp / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _serve(server: ThreadingHTTPServer) -> None:
    threading.Thread(target=server.serve_forever, daemon=True).start()


@dataclass
class Env:
    engine: Engine
    proxy_port: int
    http_port: int
    https_port: int
    engagement_id: int
    task_id: int
    scan_id: int
    slow_engagement_id: int

    def proxy(self, username: str, token: str = TOKEN) -> str:
        return f"http://{username}:{token}@127.0.0.1:{self.proxy_port}"

    def rows(self, where: str, params: dict[str, Any], expected: int) -> list[Any]:
        query = text(f"SELECT * FROM request_log WHERE {where} ORDER BY id")  # noqa: S608
        deadline = time.monotonic() + 10
        while True:
            with self.engine.connect() as conn:
                rows = conn.execute(query, params).mappings().all()
            if len(rows) >= expected or time.monotonic() > deadline:
                return list(rows)
            time.sleep(0.2)


@pytest.fixture(scope="module")
def env(db_engine: Engine, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Env]:
    tmp = tmp_path_factory.mktemp("proxy")
    enable_tools_login(db_engine, TOOLS_PASSWORD)
    with db_engine.begin() as conn:

        def engagement(snapshot: dict[str, Any], identity: dict[str, Any] | None) -> tuple:
            settings = {"identity_header": identity} if identity else {}
            eid = conn.execute(
                text(
                    "INSERT INTO engagement (name, target_url, key_id, settings) "
                    "VALUES ('t', 'http://127.0.0.1/', :k, CAST(:s AS jsonb)) RETURNING id"
                ),
                {"k": uuid.uuid4(), "s": json.dumps(settings)},
            ).scalar_one()
            conn.execute(
                text("INSERT INTO scope_rule (engagement_id, pattern) VALUES (:e, '127.0.0.1')"),
                {"e": eid},
            )
            sid = conn.execute(
                text(
                    "INSERT INTO scan (engagement_id, kind, number, profile, status, "
                    "settings_snapshot) VALUES (:e, 'scan', 1, 'full', 'running', "
                    "CAST(:s AS jsonb)) RETURNING id"
                ),
                {"e": eid, "s": json.dumps(snapshot)},
            ).scalar_one()
            tid = conn.execute(
                text(
                    "INSERT INTO task (scan_id, stage, module, engine) "
                    "VALUES (:s, 'testing', 'input_validation', 'nuclei') RETURNING id"
                ),
                {"s": sid},
            ).scalar_one()
            return eid, sid, tid

        main = engagement({"rate_limit_rps": 1000}, {"name": "X-VA-Team", "value": "BSSN"})
        slow = engagement({"rate_limit_rps": 2}, None)

    http_server = ThreadingHTTPServer(("127.0.0.1", _free_port()), _Handler)
    https_server = ThreadingHTTPServer(("127.0.0.1", _free_port()), _Handler)
    cert, key = _self_signed(tmp)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    https_server.socket = context.wrap_socket(https_server.socket, server_side=True)
    _serve(http_server)
    _serve(https_server)

    db_url = make_url(db_engine.url).set(
        drivername="postgresql", username="rajdoll_tools", password=TOOLS_PASSWORD
    )
    proxy_port = _free_port()
    process = subprocess.Popen(  # noqa: S603
        [
            str(MITMDUMP),
            "--quiet",
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(proxy_port),
            "--set",
            f"confdir={tmp / 'mitm'}",
            "--set",
            "connection_strategy=lazy",
            "--set",
            "ssl_insecure=true",
            "-s",
            str(REPO / "tools" / "proxy" / "mitm_script.py"),
        ],
        env={
            **os.environ,
            "PYTHONPATH": str(REPO),
            "RAJDOLL_PROXY_DATABASE_URL": db_url.render_as_string(hide_password=False),
            "RAJDOLL_TOOLS_TOKEN": TOKEN,
        },
    )
    try:
        _wait_for_port(proxy_port)
        yield Env(
            engine=db_engine,
            proxy_port=proxy_port,
            http_port=http_server.server_address[1],
            https_port=https_server.server_address[1],
            engagement_id=main[0],
            scan_id=main[1],
            task_id=main[2],
            slow_engagement_id=slow[0],
        )
    finally:
        process.terminate()
        process.wait(timeout=10)
        http_server.shutdown()
        https_server.shutdown()


def test_http_in_scope_is_forwarded_with_identity_and_logged(env: Env) -> None:
    _Handler.seen.clear()
    with httpx.Client(proxy=env.proxy(f"task.{env.task_id}.nuclei")) as client:
        response = client.get(f"http://127.0.0.1:{env.http_port}/hello?x=1")
    assert response.status_code == 200
    seen = _Handler.seen[-1]["headers"]
    assert seen.get("X-VA-Team") == "BSSN"
    assert "Proxy-Authorization" not in seen

    rows = env.rows("task_id = :t AND outcome = 'forwarded'", {"t": env.task_id}, 1)
    row = rows[-1]
    assert (row["engagement_id"], row["scan_id"], row["tool"]) == (
        env.engagement_id,
        env.scan_id,
        "nuclei",
    )
    assert row["url"].endswith("/hello?x=1")
    assert (row["method"], row["status"], row["host"]) == ("GET", 200, "127.0.0.1")


def test_http_out_of_scope_is_refused_and_never_reaches_target(env: Env) -> None:
    _Handler.seen.clear()
    with httpx.Client(proxy=env.proxy(f"task.{env.task_id}.nuclei")) as client:
        response = client.get(f"http://localhost:{env.http_port}/secret")
    assert response.status_code == 403
    assert response.headers["X-Rajdoll-Blocked"] == "scope"
    assert _Handler.seen == []
    rows = env.rows("host = 'localhost' AND outcome = 'blocked_scope'", {}, 1)
    assert rows[-1]["task_id"] == env.task_id


def test_https_through_tunnel(env: Env) -> None:
    _Handler.seen.clear()
    with httpx.Client(proxy=env.proxy(f"task.{env.task_id}.nuclei"), verify=False) as client:  # noqa: S501
        response = client.get(f"https://127.0.0.1:{env.https_port}/tls")
    assert response.status_code == 200
    assert _Handler.seen[-1]["headers"].get("X-VA-Team") == "BSSN"
    rows = env.rows("url LIKE 'https://%/tls'", {}, 1)
    assert rows[-1]["outcome"] == "forwarded"


def test_https_connect_out_of_scope_is_refused_before_connecting(env: Env) -> None:
    _Handler.seen.clear()
    with (
        httpx.Client(proxy=env.proxy(f"task.{env.task_id}.nuclei"), verify=False) as client,  # noqa: S501
        pytest.raises(httpx.ProxyError),
    ):
        client.get(f"https://localhost:{env.https_port}/tls")
    assert _Handler.seen == []
    rows = env.rows("method = 'CONNECT' AND outcome = 'blocked_scope'", {}, 1)
    assert rows[-1]["url"] == f"localhost:{env.https_port}"


def test_missing_or_wrong_credentials_are_refused(env: Env) -> None:
    with httpx.Client(proxy=f"http://127.0.0.1:{env.proxy_port}") as client:
        assert client.get(f"http://127.0.0.1:{env.http_port}/").status_code == 407
    with httpx.Client(proxy=env.proxy(f"task.{env.task_id}.nuclei", token="wrong")) as client:
        assert client.get(f"http://127.0.0.1:{env.http_port}/").status_code == 407


def test_rate_limit_spaces_requests(env: Env) -> None:
    proxy = env.proxy(f"eng.{env.slow_engagement_id}.ratetest")
    started = time.monotonic()
    with httpx.Client(proxy=proxy) as client:
        for _ in range(6):
            assert client.get(f"http://127.0.0.1:{env.http_port}/r").status_code == 200
    elapsed = time.monotonic() - started
    # Engagement settings have no rate, so direct requests use the default of 5/s:
    # a burst of 5, then 0.2 s for the sixth.
    assert elapsed >= 0.15

    with env.engine.begin() as conn:
        conn.execute(
            text("UPDATE engagement SET settings = '{\"rate_limit_rps\": 2}' WHERE id = :e"),
            {"e": env.slow_engagement_id},
        )
    time.sleep(5.2)  # let the proxy's 5-second context cache expire
    started = time.monotonic()
    with httpx.Client(proxy=proxy) as client:
        for _ in range(6):
            client.get(f"http://127.0.0.1:{env.http_port}/r")
    # Burst capacity drops to 2 with the new rate, then 0.5 s per request.
    assert time.monotonic() - started >= 1.6


def test_session_check_through_real_proxy(env: Env) -> None:
    probe = make_prober(f"http://127.0.0.1:{env.proxy_port}", TOKEN)
    url = f"http://127.0.0.1:{env.http_port}/profil"
    valid = probe(url, "Budi", {"cookies": {"sid": "valid"}}, env.engagement_id)
    assert (valid.checked, valid.valid) == (True, True)
    expired = probe(url, "Budi", {"cookies": {"sid": "expired"}}, env.engagement_id)
    assert (expired.checked, expired.valid) == (True, False)
    outside = probe(
        f"http://localhost:{env.http_port}/profil", "Budi", {"cookies": {}}, env.engagement_id
    )
    assert (outside.checked, outside.valid) == (True, False)
    assert "di luar scope" in outside.message
    rows = env.rows("tool = 'session_check'", {}, 3)
    assert {r["outcome"] for r in rows} == {"forwarded", "blocked_scope"}
    assert proxy_url("http://x:1", TOKEN, 5, "session_check").startswith("http://eng.5.")
