"""Tool-level tests for authorization-testing/authorization.py.

These exercise the 5 real tool functions directly (mocking only httpx) and
check that their output shape, once fixed, satisfies the exact gate used by
AuthorizationAgent._confirmed_access_control_results() (a function nested
inside authorization_agent.py's run() method and therefore not importable).
_confirmed() below is a byte-for-byte mirror of that gate, copied from
multi_agent_system/agents/authorization_agent.py lines 196-215, used here only
to assert on tool-output SHAPE, not to test the agent itself (that's covered
by test_authorization_agent.py).
"""
import sys
import os
from unittest.mock import AsyncMock, patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "authorization-testing"))


def _confirmed(results):
    confirmed = []
    for item in results or []:
        if not isinstance(item, dict):
            continue
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        proof_flags = (
            item.get("owner_mismatch"),
            item.get("data_extracted"),
            item.get("sensitive_data"),
            item.get("state_change_verified"),
            evidence.get("owner_mismatch"),
            evidence.get("data_extracted"),
            evidence.get("sensitive_data"),
            evidence.get("state_change_verified"),
        )
        if item.get("status") == "VULNERABLE" and any(bool(flag) for flag in proof_flags):
            confirmed.append(item)
    return confirmed


def _mock_client(get_side_effect=None, request_side_effect=None):
    mock_httpx = MagicMock()
    client = AsyncMock()
    if get_side_effect is not None:
        client.get = AsyncMock(side_effect=get_side_effect)
    if request_side_effect is not None:
        client.request = AsyncMock(side_effect=request_side_effect)
    mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=client)
    mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock_httpx


def _resp(status_code, text="", headers=None):
    import json as _json_mod

    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.content = text.encode()
    r.headers = headers or {}
    r.json = MagicMock(side_effect=lambda: _json_mod.loads(text))
    return r


# --- 1. test_vertical_privilege_escalation ---

async def test_vertical_privilege_escalation_confirms_when_anon_blocked_and_data_returned():
    import authorization

    # First call: low-priv authenticated GET -> 200 with real admin content.
    # Second call: anonymous baseline GET (no session) -> 403 blocked.
    mock_httpx = _mock_client(get_side_effect=[
        _resp(200, text="<html>Admin Dashboard: 42 users</html>"),
        _resp(403, text="Forbidden"),
    ])
    with patch("authorization.httpx", mock_httpx):
        result = await authorization.test_vertical_privilege_escalation(
            ["https://example.com/admin"], {"cookies": {"session": "low-priv-token"}}
        )

    assert result["status"] == "success"
    results = result["data"]["results"]
    confirmed = _confirmed(results)
    assert confirmed, f"expected a confirmed finding, got {results}"


async def test_vertical_privilege_escalation_unconfirmed_when_anon_also_succeeds():
    import authorization

    # Endpoint is effectively public: anonymous access succeeds too, so the
    # low-priv 200 is not proof of cross-role access.
    mock_httpx = _mock_client(get_side_effect=[
        _resp(200, text="<html>Public page</html>"),
        _resp(200, text="<html>Public page</html>"),
    ])
    with patch("authorization.httpx", mock_httpx):
        result = await authorization.test_vertical_privilege_escalation(
            ["https://example.com/admin"], {"cookies": {"session": "low-priv-token"}}
        )

    results = result["data"]["results"]
    assert not _confirmed(results)


# --- 2. test_idor_vulnerability ---

async def test_idor_vulnerability_confirms_when_distinct_objects_returned():
    import authorization

    # id=1 and id=2 both return 200 with genuinely different body content ->
    # proves distinct objects were accessed across the ID range.
    mock_httpx = _mock_client(get_side_effect=[
        _resp(200, text='{"id":1,"name":"alice"}'),
        _resp(200, text='{"id":2,"name":"bob"}'),
    ])
    with patch("authorization.httpx", mock_httpx):
        result = await authorization.test_idor_vulnerability(
            "https://example.com/api/users/{ID}", {"cookies": {}}, start_id=1, count=2
        )

    results = result["data"]["results"]
    confirmed = _confirmed(results)
    assert confirmed, f"expected a confirmed finding, got {results}"


async def test_idor_vulnerability_unconfirmed_when_single_id_only():
    import authorization

    # Only one ID in the range returns 200; nothing to compare against, so
    # this must not be auto-confirmed.
    mock_httpx = _mock_client(get_side_effect=[
        _resp(200, text='{"id":1,"name":"alice"}'),
        _resp(404, text="not found"),
    ])
    with patch("authorization.httpx", mock_httpx):
        result = await authorization.test_idor_vulnerability(
            "https://example.com/api/users/{ID}", {"cookies": {}}, start_id=1, count=2
        )

    results = result["data"]["results"]
    assert not _confirmed(results)


# --- 3. test_idor_comprehensive ---

async def test_idor_comprehensive_confirms_when_real_json_data_returned():
    import authorization

    mock_httpx = _mock_client(get_side_effect=[
        _resp(200, text='{"id":1,"ssn":"123-45-6789"}', headers={"content-type": "application/json"}),
    ])
    with patch("authorization.httpx", mock_httpx):
        result = await authorization.test_idor_comprehensive(
            "https://example.com", endpoint_patterns=["/api/users/{id}"],
            session={}, id_range_start=1, id_range_end=1
        )

    findings = result["data"]["findings"]
    confirmed = _confirmed(findings)
    assert confirmed, f"expected a confirmed finding, got {findings}"


async def test_idor_comprehensive_unconfirmed_when_no_real_data():
    import authorization

    # 200 status but non-JSON/empty body - no real object data proven.
    mock_httpx = _mock_client(get_side_effect=[
        _resp(200, text="", headers={"content-type": "text/plain"}),
    ])
    with patch("authorization.httpx", mock_httpx):
        result = await authorization.test_idor_comprehensive(
            "https://example.com", endpoint_patterns=["/api/users/{id}"],
            session={}, id_range_start=1, id_range_end=1
        )

    findings = result["data"]["findings"]
    assert not _confirmed(findings)


# --- 4. test_http_method_tampering ---

async def test_http_method_tampering_confirms_when_delete_followup_shows_state_change():
    import authorization

    base = _resp(200, text="original")
    same_as_base = _resp(200, text="original")
    delete_resp = _resp(201, text="deleted?")
    followup_after_delete = _resp(404, text="gone")

    # methods_to_test order: HEAD, POST, PUT, DELETE, PATCH
    request_side_effect = [
        same_as_base,  # HEAD - no diff, skipped
        same_as_base,  # POST - no diff, skipped
        same_as_base,  # PUT - no diff, skipped
        delete_resp,   # DELETE - diff + 2xx -> triggers followup verification
        same_as_base,  # PATCH - no diff, skipped
    ]
    mock_httpx = _mock_client(
        get_side_effect=[base, followup_after_delete],
        request_side_effect=request_side_effect,
    )
    with patch("authorization.httpx", mock_httpx):
        result = await authorization.test_http_method_tampering(
            "https://example.com/api/resource/1", {"cookies": {}}
        )

    results = result["data"]["results"]
    confirmed = _confirmed(results)
    assert confirmed, f"expected a confirmed finding, got {results}"


async def test_http_method_tampering_unconfirmed_when_followup_shows_no_change():
    import authorization

    base = _resp(403, text="blocked")
    same_as_base = _resp(403, text="blocked")
    delete_resp = _resp(200, text="ok")
    followup_after_delete = _resp(200, text="ok")  # resource still there, unchanged

    request_side_effect = [
        same_as_base,  # HEAD
        same_as_base,  # POST
        same_as_base,  # PUT
        delete_resp,   # DELETE - diff + 2xx but followup shows nothing changed
        same_as_base,  # PATCH
    ]
    mock_httpx = _mock_client(
        get_side_effect=[base, followup_after_delete],
        request_side_effect=request_side_effect,
    )
    with patch("authorization.httpx", mock_httpx):
        result = await authorization.test_http_method_tampering(
            "https://example.com/api/resource/1", {"cookies": {}}
        )

    results = result["data"]["results"]
    assert not _confirmed(results)


# --- 5. test_user_spoofing ---

async def test_user_spoofing_confirms_nosql_mass_update_with_verified_state_change():
    import authorization

    # POST spoof attempts all fail/mismatch; PATCH NoSQL injection reports
    # modified > 1 (a real, verified mass state change).
    post_resp = _resp(403, text="forbidden")
    patch_resp = _resp(200, text='{"modified": 5}')

    mock_httpx = MagicMock()
    client = AsyncMock()
    client.post = AsyncMock(return_value=post_resp)
    client.patch = AsyncMock(return_value=patch_resp)
    mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=client)
    mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("authorization.httpx", mock_httpx):
        result = await authorization.test_user_spoofing("https://example.com/api/feedback")

    findings = result["data"]["findings"]
    confirmed = _confirmed(findings)
    assert confirmed, f"expected a confirmed nosql_mass_update finding, got {findings}"


async def test_user_spoofing_confirms_user_spoofing_with_echoed_uid():
    import authorization

    # POST with spoofed user_id=1 succeeds and the response echoes back
    # user_id=1 -> genuine, verified identity mismatch.
    def post_side_effect(endpoint_url, json=None):
        if json and json.get("user_id") == 1:
            return _resp(201, text='{"user_id": 1, "comment": "x"}',
                         headers={"content-type": "application/json"})
        return _resp(403, text="forbidden")

    patch_resp = _resp(404, text="not found")

    mock_httpx = MagicMock()
    client = AsyncMock()
    client.post = AsyncMock(side_effect=post_side_effect)
    client.patch = AsyncMock(return_value=patch_resp)
    mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=client)
    mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("authorization.httpx", mock_httpx):
        result = await authorization.test_user_spoofing("https://example.com/api/feedback")

    findings = result["data"]["findings"]
    confirmed = _confirmed(findings)
    assert confirmed, f"expected a confirmed user_spoofing finding, got {findings}"


async def test_user_spoofing_rate_limit_and_weak_nosql_stay_unconfirmed():
    import authorization

    # No spoofing echo, no mass update proof, but the endpoint accepts 5
    # repeated POSTs (missing_rate_limit) and accepts the $ne operator with a
    # bare 200 (nosql_operator_accepted, unconfirmed) - both must stay ungated.
    post_resp = _resp(200, text="{}", headers={"content-type": "application/json"})
    patch_resp = _resp(200, text="not json at all")

    mock_httpx = MagicMock()
    client = AsyncMock()
    client.post = AsyncMock(return_value=post_resp)
    client.patch = AsyncMock(return_value=patch_resp)
    mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=client)
    mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("authorization.httpx", mock_httpx):
        result = await authorization.test_user_spoofing("https://example.com/api/feedback")

    findings = result["data"]["findings"]
    assert not _confirmed(findings)
