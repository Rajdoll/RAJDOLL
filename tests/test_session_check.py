import httpx
import pytest

from rajdoll.services.session_check import (
    _request_headers,
    evaluate,
    make_prober,
    proxy_url,
)


def _response(status: int, body: str = "", **headers: str) -> httpx.Response:
    return httpx.Response(status, text=body, headers=headers)


@pytest.mark.parametrize(
    ("response", "checked", "valid", "fragment"),
    [
        (_response(200, "<p>Halo, Budi</p>"), True, True, "Sesi valid"),
        (_response(200, "<p>Halo, BUDI</p>"), True, True, "Sesi valid"),
        (_response(200, "<form>Login</form>"), True, False, "Penanda login tidak ditemukan"),
        (_response(401, "no"), True, False, "401"),
        (_response(403, "", **{"X-Rajdoll-Blocked": "scope"}), True, False, "di luar scope"),
        (_response(407, "", **{"X-Rajdoll-Blocked": "auth"}), False, False, "TOOLS_TOKEN"),
    ],
)
def test_evaluate(response: httpx.Response, checked: bool, valid: bool, fragment: str) -> None:
    result = evaluate(response, "Budi")
    assert (result.checked, result.valid) == (checked, valid)
    assert fragment in result.message


def test_proxy_url_carries_engagement_and_quotes_token() -> None:
    url = proxy_url("http://tools:8081", "a/b:c@d", 42, "session_check")
    assert url == "http://eng.42.session_check:a%2Fb%3Ac%40d@tools:8081"


def test_request_headers_send_cookies_as_one_header() -> None:
    headers = _request_headers(
        {"cookies": {"sid": "1", "theme": "dark"}, "headers": {"Authorization": "Bearer x"}}
    )
    assert headers == {"Authorization": "Bearer x", "Cookie": "sid=1; theme=dark"}


def test_unreachable_proxy_is_not_a_verdict() -> None:
    probe = make_prober("http://127.0.0.1:9", "token")  # nothing listens on port 9
    result = probe("http://app.test/profil", "Budi", {"cookies": {"sid": "1"}}, 1)
    assert result.checked is False
    assert "Tidak bisa menghubungi" in result.message
