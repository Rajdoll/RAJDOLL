import asyncio

from multi_agent_system.agents import input_validation_agent as iva
import multi_agent_system.utils.session_service as ss


class _CM:
    def __init__(self, scan_creds=None, secret=None):
        self._sc, self._secret = scan_creds, secret

    def read(self, k):
        return self._sc if k == "scan_credentials" else None

    def read_secret(self, ref):
        return self._secret


def _agent(cm):
    a = iva.InputValidationAgent.__new__(iva.InputValidationAgent)
    a.context_manager = cm
    a.log = lambda *args, **kw: None
    return a


class _Resp:
    def __init__(self, url):
        self.url = url


class _Client:
    def __init__(self, url):
        self._url = url

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, u, cookies=None):
        return _Resp(self._url)


def test_resolve_creds_full():
    a = _agent(_CM({"credential_ref": "r1"}, {"username": "admin", "password": "password"}))
    assert a._resolve_scan_credentials() == [("admin", "password")]


def test_resolve_creds_missing():
    assert _agent(_CM(None, None))._resolve_scan_credentials() is None


def test_reauth_noop_when_no_auth():
    a = _agent(_CM())
    assert asyncio.run(a._reauth_if_session_dead("http://t/", ["/x"], None)) is None


def test_reauth_noop_when_session_alive(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client("http://t/vulnerabilities/xss_s/"))
    a = _agent(_CM({"credential_ref": "r1"}, {"username": "admin", "password": "password"}))
    auth = {"cookies": {"PHPSESSID": "old"}}
    out = asyncio.run(a._reauth_if_session_dead("http://t/", ["/vulnerabilities/xss_s/"], auth))
    assert out is auth


def test_reauth_refreshes_when_dead(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _Client("http://t/login.php"))

    async def fake_cas(target, credentials=None):
        return True, {"cookies": {"PHPSESSID": "new"}, "headers": {}, "jwt_token": None, "username": "admin"}

    monkeypatch.setattr(ss, "create_authenticated_session", fake_cas)
    a = _agent(_CM({"credential_ref": "r1"}, {"username": "admin", "password": "password"}))
    out = asyncio.run(a._reauth_if_session_dead("http://t/", ["/vulnerabilities/xss_s/"], {"cookies": {"PHPSESSID": "old"}}))
    assert out["cookies"] == {"PHPSESSID": "new"}
