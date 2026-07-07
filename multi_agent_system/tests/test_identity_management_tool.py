"""Tool-level tests for identity-management-testing/identity-management.py.

Covers three bugs fixed in Task 6:

1. test_username_policy: the enumeration check compared raw response_length
   across usernames of different lengths without normalizing for the fact
   that longer usernames naturally produce longer echoed responses. This is
   the CONFIRMED root cause of the job-164 false positive (admin/
   administrator/root all returned identical 404s; response_length only
   differed by each username's own string length). Same bug existed in the
   password-reset-enumeration sub-test. The timing sub-test used a single
   sample per username with a 0.5s threshold.

2. test_registration_mass_assignment: a second branch ("extra_fields_
   accepted") fired on ANY HTTP 201 with an extra field present in the
   payload, regardless of whether the server actually echoed/applied it.
   The genuine main branch (data.get(check) truthy in the response) is a
   real, already-verified true positive (job 167, "Register with admin
   role succeeded") and must be preserved exactly.

3. test_user_registration: sub-tests 1, 2 and 4 (weak password, invalid
   email, duplicate username) confirm on a bare "success" in resp.text.lower()
   substring match with no baseline, so a page that always contains the
   word "success" somewhere universally confirms them. NOTE: sub-test 3
   (special_character_injection) does NOT use this heuristic at all -- it
   only checks resp.status_code in [200, 302], so it is unaffected by this
   bug and is intentionally left untouched (discrepancy from the task brief,
   which described "all 4 sub-tests" as using the "success" heuristic).

Module-loading note: identity-management.py has a hyphen in its filename, so
it can't be `import`ed normally. Each test loads a *fresh* module object via
importlib.util.spec_from_file_location/module_from_spec. Because that module
is never registered in sys.modules, `mock.patch("name.attr", ...)`-style
dotted-string patching can't resolve it -- so httpx is swapped by directly
assigning `module.httpx = mock_httpx` (safe: it only rebinds a name in that
one throwaway module's own namespace, touching no global state). time.time
is different: `module.time` IS the real global stdlib `time` module object,
so that one goes through pytest's `monkeypatch` fixture for guaranteed revert.
"""
import importlib.util
import json as _json_mod
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock


def _load_identity_management_tool():
    path = Path(__file__).resolve().parents[2] / "identity-management-testing" / "identity-management.py"
    spec = importlib.util.spec_from_file_location("identity_management_tool", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _resp(status_code, text="", headers=None):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.headers = headers or {}
    r.json = MagicMock(side_effect=lambda: _json_mod.loads(text))
    return r


def _mock_client(post_side_effect=None, get_side_effect=None):
    mock_httpx = MagicMock()
    client = AsyncMock()
    if post_side_effect is not None:
        client.post = AsyncMock(side_effect=post_side_effect)
    if get_side_effect is not None:
        client.get = AsyncMock(side_effect=get_side_effect)
    mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=client)
    mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock_httpx


# ===========================================================================
# (a) test_username_policy -- job-164 reconstruction + regression guard
# ===========================================================================

def _flat_times(elapsed_list):
    """Monotonic time.time() sequence yielding exactly the given elapsed
    durations for consecutive (start, end) pairs -- lets us control
    `elapsed = time.time() - start` without any real sleeping."""
    times = []
    t = 0.0
    for e in elapsed_list:
        times.append(t)
        t += e
        times.append(t)
    return times


async def test_job_164_scenario_no_enumeration_once_length_normalized(monkeypatch):
    """admin/administrator/root all return 404; response_length differs ONLY
    by each username's own string length (job-164 exact shape). Once
    normalized, no enumeration should be flagged."""
    module = _load_identity_management_tool()
    usernames = ["admin", "administrator", "root"]
    base_len = 50  # constant page content unrelated to the username itself

    # 3 register-loop responses + 3 reset-loop responses, then 3 users x 3
    # timing samples = 9 more. All timing elapsed times identical (no jitter
    # signal) so the timing sub-test also stays quiet.
    register_responses = [_resp(404, text="x" * (base_len + len(u))) for u in usernames]
    reset_responses = [_resp(404, text="x" * (base_len + len(u))) for u in usernames]
    timing_responses = [_resp(404, text="") for _ in range(len(usernames) * 3)]

    module.httpx = _mock_client(post_side_effect=register_responses + reset_responses + timing_responses)
    monkeypatch.setattr(module.time, "time", MagicMock(side_effect=_flat_times([0.05] * (len(usernames) * 3))))

    result = await module.test_username_policy("https://example.com", test_usernames=usernames)

    findings = result["data"]["findings"]
    assert findings == [], f"expected no findings on the job-164 shape, got: {findings}"


async def test_real_job_164_registration_evidence_no_longer_flagged(monkeypatch):
    """Byte-for-byte reproduction of the real job-164 registration evidence
    from reports/job164_agoda_DRAFT_UNVALIDATED.md:
        admin:          status 404, response_length 89095
        administrator:  status 404, response_length 89098
        root:           status 404, response_length 89100
    Naive length-subtraction alone does NOT fully collapse this (normalized:
    89090 / 89085 / 89096 -- an 11-byte residual from page jitter unrelated
    to the username, e.g. csrf tokens/analytics ids on the ~89KB SPA page),
    which is why the tool needs a small noise tolerance, not exact equality."""
    module = _load_identity_management_tool()
    usernames = ["admin", "administrator", "root"]
    real_lengths = {"admin": 89095, "administrator": 89098, "root": 89100}

    register_responses = [_resp(404, text="x" * real_lengths[u]) for u in usernames]
    reset_responses = [_resp(404, text="x" * 89100) for _ in usernames]  # real reset evidence: all identical
    timing_responses = [_resp(404, text="") for _ in range(len(usernames) * 3)]

    module.httpx = _mock_client(post_side_effect=register_responses + reset_responses + timing_responses)
    monkeypatch.setattr(module.time, "time", MagicMock(side_effect=_flat_times([0.05] * (len(usernames) * 3))))

    result = await module.test_username_policy("https://example.com", test_usernames=usernames)

    findings = result["data"]["findings"]
    assert findings == [], f"expected job-164 real evidence to no longer be flagged, got: {findings}"


async def test_identical_length_usernames_with_real_difference_still_flagged(monkeypatch):
    """Regression guard: two usernames of IDENTICAL length where the server
    response genuinely differs beyond that -- enumeration must still fire."""
    module = _load_identity_management_tool()
    usernames = ["admin", "roots"]  # both length 5

    # Genuine signal: "admin" exists (longer/different real content),
    # "roots" does not -- difference is NOT explained by username length
    # since both are the same length. Gap (500) is comfortably beyond the
    # tool's noise tolerance for ordinary per-request jitter.
    register_responses = [_resp(200, text="x" * 600), _resp(200, text="x" * 100)]
    reset_responses = [_resp(200, text="x" * 600), _resp(200, text="x" * 100)]
    timing_responses = [_resp(200, text="") for _ in range(len(usernames) * 3)]

    module.httpx = _mock_client(post_side_effect=register_responses + reset_responses + timing_responses)
    monkeypatch.setattr(module.time, "time", MagicMock(side_effect=_flat_times([0.05] * (len(usernames) * 3))))

    result = await module.test_username_policy("https://example.com", test_usernames=usernames)

    findings = result["data"]["findings"]
    types = [f["type"] for f in findings]
    assert "username_enumeration_registration" in types, f"expected enumeration still flagged, got: {findings}"


async def test_timing_subtest_uses_repeated_samples_and_median(monkeypatch):
    """A single one-off slow request for one username (out of several
    repeated samples) must not trip the timing signal -- the median across
    repeats should absorb the outlier. This also demonstrates the sample
    count was widened beyond one request per username."""
    module = _load_identity_management_tool()
    usernames = ["admin", "administrator", "root"]

    # Register/reset sub-tests: identical responses so only the timing
    # sub-test is under test.
    register_responses = [_resp(200, text="x" * 50) for _ in usernames]
    reset_responses = [_resp(200, text="x" * 50) for _ in usernames]
    timing_responses = [_resp(200, text="") for _ in range(len(usernames) * 3)]

    module.httpx = _mock_client(post_side_effect=register_responses + reset_responses + timing_responses)

    # admin: samples [0.05, 0.05, 2.0] -- one outlier out of 3, median stays 0.05
    # administrator: [0.05, 0.05, 0.05]
    # root: [0.05, 0.05, 0.05]
    elapsed = [0.05, 0.05, 2.0] + [0.05, 0.05, 0.05] + [0.05, 0.05, 0.05]
    monkeypatch.setattr(module.time, "time", MagicMock(side_effect=_flat_times(elapsed)))

    result = await module.test_username_policy("https://example.com", test_usernames=usernames)

    findings = result["data"]["findings"]
    types = [f["type"] for f in findings]
    assert "timing_based_enumeration" not in types, f"single-sample outlier should not trip timing signal: {findings}"

    # Sanity: sample count was actually widened (>1 request per username for timing).
    assert len(timing_responses) > len(usernames), "expected more than 1 timing request per username"


# ===========================================================================
# (b) test_registration_mass_assignment -- false-positive branch removed,
#     genuine main branch preserved
# ===========================================================================

def _mass_assignment_client(post_responses):
    """probe endpoint 1 -> 200 (active), endpoints 2-5 -> 404 (skipped).
    Then 4 posts (admin_role, isAdmin_flag, deluxe_token, empty_fields) run
    against the active endpoint only."""
    get_side_effect = [_resp(200), _resp(404), _resp(404), _resp(404), _resp(404)]
    return _mock_client(get_side_effect=get_side_effect, post_side_effect=post_responses)


async def test_extra_field_present_without_server_confirmation_produces_no_finding():
    """201 + extra field present in the payload, but the server response
    never echoes/confirms the field -- must produce NO finding once the
    false-positive 'extra_fields_accepted' branch is removed."""
    module = _load_identity_management_tool()

    post_responses = [
        _resp(201, text=_json_mod.dumps({"id": 20})),   # admin_role: no "role" key back
        _resp(201, text=_json_mod.dumps({"id": 21})),   # isAdmin_flag: no "isAdmin" key back
        _resp(201, text=_json_mod.dumps({"id": 22})),   # deluxe_token: no "deluxeToken" key back
        _resp(400, text=""),                            # empty_fields: rejected
    ]
    module.httpx = _mass_assignment_client(post_responses)

    result = await module.test_registration_mass_assignment("https://example.com/api/Users")

    findings = result["data"]["findings"]
    assert findings == [], f"expected no findings when extra field isn't server-confirmed, got: {findings}"


async def test_genuine_admin_role_mass_assignment_main_branch_unaffected():
    """job-167 genuine case: registering with role=admin, and the server
    echoes role=admin back -- the MAIN branch must still fire unchanged."""
    module = _load_identity_management_tool()

    post_responses = [
        _resp(201, text=_json_mod.dumps({"role": "admin", "id": 10})),  # admin_role: server confirms
        _resp(201, text=_json_mod.dumps({"id": 11})),                   # isAdmin_flag: not confirmed
        _resp(201, text=_json_mod.dumps({"id": 12})),                   # deluxe_token: not confirmed
        _resp(400, text=""),                                           # empty_fields: rejected
    ]
    module.httpx = _mass_assignment_client(post_responses)

    result = await module.test_registration_mass_assignment("https://example.com/api/Users")

    findings = result["data"]["findings"]
    assert len(findings) == 1, f"expected exactly the genuine admin_role finding, got: {findings}"
    assert findings[0]["type"] == "mass_assignment"
    assert findings[0]["test"] == "admin_role"
    assert "Register with admin role succeeded" in findings[0]["description"]


# ===========================================================================
# (c) test_user_registration -- baseline-gated success signal
# ===========================================================================

async def test_baseline_containing_success_does_not_confirm_weak_password_or_invalid_email_or_duplicate():
    """Sub-tests 1 (weak password), 2 (invalid email), 4 (duplicate username)
    all rely on 'success' in resp.text.lower(). If the baseline (a
    deliberately-invalid registration attempt) ALSO contains 'success'
    somewhere, none of them should confirm."""
    module = _load_identity_management_tool()

    always_success_text = "<html>operation success boilerplate footer</html>"
    validation_checks = {
        "weak_passwords": ["123"],
        "invalid_emails": ["notanemail"],
        "special_usernames": [],  # skip sub-test 3, not part of this bug
    }

    # Order: baseline, weak_password post, invalid_email post,
    # duplicate-username resp1, duplicate-username resp2.
    responses = [
        _resp(200, text=always_success_text),  # baseline
        _resp(200, text=always_success_text),  # weak password attempt
        _resp(200, text=always_success_text),  # invalid email attempt
        _resp(200, text=always_success_text),  # duplicate: first registration
        _resp(200, text=always_success_text),  # duplicate: second registration
    ]
    module.httpx = _mock_client(post_side_effect=responses)

    result = await module.test_user_registration("https://example.com/register", validation_checks=validation_checks)

    findings = result["data"]["findings"]
    types = [f["type"] for f in findings]
    assert "weak_password_accepted" not in types, f"got: {findings}"
    assert "invalid_email_accepted" not in types, f"got: {findings}"
    assert "duplicate_username_allowed" not in types, f"got: {findings}"


async def test_genuinely_differing_response_still_confirms_weak_password_and_invalid_email_and_duplicate():
    """When the test response contains 'success' but the baseline does NOT,
    that's a genuine differential signal -- sub-tests 1, 2 and 4 must still fire."""
    module = _load_identity_management_tool()

    validation_checks = {
        "weak_passwords": ["123"],
        "invalid_emails": ["notanemail"],
        "special_usernames": [],
    }

    responses = [
        _resp(200, text="<html>Invalid input, please try again</html>"),  # baseline (no "success")
        _resp(200, text="<html>Registration success!</html>"),            # weak password: genuine success
        _resp(200, text="<html>Registration success!</html>"),            # invalid email: genuine success
        _resp(200, text="<html>Invalid input, please try again</html>"),  # duplicate: first registration
        _resp(200, text="<html>Registration success!</html>"),            # duplicate: second registration succeeds too
    ]
    module.httpx = _mock_client(post_side_effect=responses)

    result = await module.test_user_registration("https://example.com/register", validation_checks=validation_checks)

    findings = result["data"]["findings"]
    types = [f["type"] for f in findings]
    assert "weak_password_accepted" in types, f"got: {findings}"
    assert "invalid_email_accepted" in types, f"got: {findings}"
    assert "duplicate_username_allowed" in types, f"got: {findings}"
