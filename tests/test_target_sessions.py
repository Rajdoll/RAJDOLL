import pytest

from rajdoll.services.target_sessions import (
    SessionParseError,
    parse_session_text,
    session_from_parts,
)


def test_header_lines() -> None:
    session = parse_session_text(
        "Cookie: session=abc123; theme=dark\nAuthorization: Bearer eyJhbGciOi.x.y\n"
    )
    assert session.cookies == {"session": "abc123", "theme": "dark"}
    assert session.headers == {"Authorization": "Bearer eyJhbGciOi.x.y"}


def test_bare_cookie_string() -> None:
    session = parse_session_text("PHPSESSID=deadbeef; csrftoken=a:b=c")
    assert session.cookies == {"PHPSESSID": "deadbeef", "csrftoken": "a:b=c"}
    assert session.headers == {}


def test_raw_request_from_burp_keeps_only_identity_headers() -> None:
    raw = (
        "POST /api/profile HTTP/1.1\r\n"
        "Host: app.instansi.test\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: application/json\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 17\r\n"
        "Cookie: sid=s3cr3t\r\n"
        "X-CSRF-Token: tok\r\n"
        "\r\n"
        '{"name": "Budi"}'
    )
    session = parse_session_text(raw)
    assert session.cookies == {"sid": "s3cr3t"}
    assert session.headers == {"X-CSRF-Token": "tok"}


def test_summary_has_names_only() -> None:
    session = parse_session_text("Cookie: sid=s3cr3t\nAuthorization: Bearer abc")
    summary = session.summary()
    assert summary == {"cookie_names": ["sid"], "header_names": ["Authorization"]}
    assert "s3cr3t" not in str(summary)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "Tempel"),
        ("   \n  ", "Tempel"),
        ("Host: app.instansi.test\nAccept: */*", "Tidak ada cookie atau header"),
        ("this is not a header\nnor this", "bukan header"),
        ("Bad Header Name: x", "bukan header"),
        ("Cookie: novalue", "cookie tidak valid"),
    ],
)
def test_rejects_unusable_input(text: str, message: str) -> None:
    with pytest.raises(SessionParseError, match=message):
        parse_session_text(text)


def test_structured_session_validation() -> None:
    session = session_from_parts({"sid": "x"}, {"Authorization": "Bearer y"})
    assert session.to_dict() == {"cookies": {"sid": "x"}, "headers": {"Authorization": "Bearer y"}}
    with pytest.raises(SessionParseError, match="karakter kontrol"):
        session_from_parts(None, {"X-Test": "a\r\nInjected: 1"})
    with pytest.raises(SessionParseError, match="Minimal satu"):
        session_from_parts({}, {})
    with pytest.raises(SessionParseError, match="Nama header tidak valid"):
        session_from_parts(None, {"Bad Name": "x"})
