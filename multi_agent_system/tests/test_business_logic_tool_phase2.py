"""Tool-level tests for business-logic-testing/business-logic.py's
test_shopping_cart_manipulation, its 6 sub-tests (NEGATIVE_QUANTITY,
PRICE_MANIPULATION, BASKET_IDOR, COUPON_REPLAY, QUANTITY_TAMPERING,
ZERO_PRICE_CHECKOUT).

Prior to this fix, every sub-test used nothing but `resp.status_code in
[200, 201]` (or ==200 for IDOR) as proof. This suite pins down the fixed
behavior: (a) a baseline/control request must behave differently from the
tampered request before anything is flagged (guards against SPA catch-alls
that return 200 for everything); (b) price/quantity tampering requires a
read-back proving the tampered value was actually persisted; (c) BASKET_IDOR
requires the returned owner identifier to differ from the authenticated
session's own identifiers; (d) COUPON_REPLAY requires a read-back proving the
discount was actually doubled/reapplied.

business-logic.py has a hyphen in its filename, so it can't be `import`ed
normally -- it's loaded via importlib, same approach as
test_file_upload_mcp.py uses for its sibling tool file.
"""
import importlib.util
import json as json_mod
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock


def _load_business_logic():
    path = Path(__file__).resolve().parents[2] / "business-logic-testing" / "business-logic.py"
    spec = importlib.util.spec_from_file_location("business_logic_tool", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


business_logic = _load_business_logic()


def _resp(status_code, text=""):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.content = text.encode()
    r.headers = {}
    r.json = MagicMock(side_effect=lambda: json_mod.loads(text))
    return r


def _client(post=None, get=None, put=None):
    c = MagicMock()
    if post is not None:
        c.post = post
    if get is not None:
        c.get = get
    if put is not None:
        c.put = put
    return c


def _mock_client_ctx(client):
    """Wraps a bare client mock so `async with httpx.AsyncClient(...) as client` works."""
    mock_httpx = MagicMock()
    mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(return_value=client)
    mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock_httpx


# --- (a) SPA catch-all: whole-function integration test ---
# One endpoint returns an identical generic 200 HTML body for every GET/POST/PUT
# regardless of payload -- the classic false-positive source when a scanner
# probes a client-side-routed SPA. None of the 6 sub-tests should fire.

async def test_no_findings_when_endpoint_is_spa_catchall():
    generic = _resp(200, text="<html><body>App Shell</body></html>")
    client = _client(
        post=AsyncMock(return_value=generic),
        get=AsyncMock(return_value=generic),
        put=AsyncMock(return_value=generic),
    )
    business_logic.httpx = _mock_client_ctx(client)

    result = await business_logic.test_shopping_cart_manipulation(
        "https://example.com/api/basket/1", auth_session={"username": "victim1"}
    )

    assert result["status"] == "success"
    assert result["data"]["findings"] == [], f"expected no findings, got {result['data']['findings']}"
    assert result["data"]["vulnerable"] is False


# --- NEGATIVE_QUANTITY (_check_negative_quantity) ---

async def test_negative_quantity_confirmed_when_persisted():
    tampered_resp = _resp(201, text='{"data":{"quantity":-100}}')
    control_resp = _resp(200, text='{"data":{"quantity":1}}')
    readback_resp = _resp(200, text='{"data":{"quantity":-100}}')
    client = _client(
        post=AsyncMock(side_effect=[tampered_resp, control_resp]),
        get=AsyncMock(return_value=readback_resp),
    )

    finding = await business_logic._check_negative_quantity(client, "https://example.com/basket", {})

    assert finding is not None
    assert finding["type"] == "NEGATIVE_QUANTITY"


async def test_negative_quantity_unconfirmed_when_not_persisted():
    tampered_resp = _resp(201, text='{"data":{"quantity":-100}}')
    control_resp = _resp(200, text='{"data":{"quantity":1}}')
    readback_resp = _resp(200, text='{"data":{"quantity":1}}')  # original value, not persisted
    client = _client(
        post=AsyncMock(side_effect=[tampered_resp, control_resp]),
        get=AsyncMock(return_value=readback_resp),
    )

    finding = await business_logic._check_negative_quantity(client, "https://example.com/basket", {})

    assert finding is None


async def test_negative_quantity_unconfirmed_when_control_behaves_identically():
    same = _resp(200, text="<html>App Shell</html>")
    get_mock = AsyncMock()
    client = _client(post=AsyncMock(side_effect=[same, same]), get=get_mock)

    finding = await business_logic._check_negative_quantity(client, "https://example.com/basket", {})

    assert finding is None
    get_mock.assert_not_called()  # must short-circuit before even attempting a read-back


# --- PRICE_MANIPULATION (_check_price_manipulation) ---

async def test_price_manipulation_confirmed_when_persisted():
    tampered_resp = _resp(201, text='{"data":{"price":0.01}}')
    control_resp = _resp(200, text='{"data":{"price":9.99}}')
    readback_resp = _resp(200, text='{"data":{"price":0.01}}')
    client = _client(
        post=AsyncMock(side_effect=[tampered_resp, control_resp]),
        get=AsyncMock(return_value=readback_resp),
    )

    finding = await business_logic._check_price_manipulation(client, "https://example.com/basket", {})

    assert finding is not None
    assert finding["type"] == "PRICE_MANIPULATION"


async def test_price_manipulation_unconfirmed_when_not_persisted():
    tampered_resp = _resp(201, text='{"data":{"price":0.01}}')
    control_resp = _resp(200, text='{"data":{"price":9.99}}')
    readback_resp = _resp(200, text='{"data":{"price":9.99}}')  # original price, not persisted
    client = _client(
        post=AsyncMock(side_effect=[tampered_resp, control_resp]),
        get=AsyncMock(return_value=readback_resp),
    )

    finding = await business_logic._check_price_manipulation(client, "https://example.com/basket", {})

    assert finding is None


# --- BASKET_IDOR (_check_basket_idor) ---

async def test_basket_idor_confirmed_when_owner_differs():
    resp = _resp(200, text='{"data":{"UserId":"someoneelse","Products":[]}}')
    client = _client(get=AsyncMock(return_value=resp))

    finding = await business_logic._check_basket_idor(
        client, "https://example.com/basket", {}, {"victim1"}
    )

    assert finding is not None
    assert finding["type"] == "BASKET_IDOR"


async def test_basket_idor_unconfirmed_when_same_user():
    resp = _resp(200, text='{"data":{"UserId":"victim1","Products":[]}}')
    client = _client(get=AsyncMock(return_value=resp))

    finding = await business_logic._check_basket_idor(
        client, "https://example.com/basket", {}, {"victim1"}
    )

    assert finding is None


async def test_basket_idor_unconfirmed_when_no_own_identifier_known():
    # Can't prove a mismatch if we don't know who "we" are -- must not flag.
    resp = _resp(200, text='{"data":{"UserId":"someoneelse","Products":[]}}')
    client = _client(get=AsyncMock(return_value=resp))

    finding = await business_logic._check_basket_idor(
        client, "https://example.com/basket", {}, set()
    )

    assert finding is None


# --- COUPON_REPLAY (_check_coupon_replay) ---

async def test_coupon_replay_confirmed_when_discount_doubled():
    first_resp = _resp(200, text='{"discount":10}')
    second_resp = _resp(200, text='{"discount":10}')
    readback_resp = _resp(200, text='{"data":{"discount":20}}')
    client = _client(
        put=AsyncMock(side_effect=[first_resp, second_resp]),
        get=AsyncMock(return_value=readback_resp),
    )

    finding = await business_logic._check_coupon_replay(client, "https://example.com/basket", {})

    assert finding is not None
    assert finding["type"] == "COUPON_REPLAY"


async def test_coupon_replay_unconfirmed_when_discount_not_reapplied():
    first_resp = _resp(200, text='{"discount":10}')
    second_resp = _resp(200, text='{"discount":10}')
    readback_resp = _resp(200, text='{"data":{"discount":10}}')  # not doubled
    client = _client(
        put=AsyncMock(side_effect=[first_resp, second_resp]),
        get=AsyncMock(return_value=readback_resp),
    )

    finding = await business_logic._check_coupon_replay(client, "https://example.com/basket", {})

    assert finding is None


async def test_coupon_replay_unconfirmed_when_zero_discount_both_times():
    # Unrecognized/inert coupon: server echoes discount=0 both before and after
    # replay. 0 < 0*2 is False, so the naive doubling check would wrongly fire.
    first_resp = _resp(200, text='{"discount":0}')
    second_resp = _resp(200, text='{"discount":0}')
    readback_resp = _resp(200, text='{"data":{"discount":0}}')
    client = _client(
        put=AsyncMock(side_effect=[first_resp, second_resp]),
        get=AsyncMock(return_value=readback_resp),
    )

    finding = await business_logic._check_coupon_replay(client, "https://example.com/basket", {})

    assert finding is None


# --- QUANTITY_TAMPERING (_check_quantity_tampering) ---

async def test_quantity_tampering_confirmed_when_persisted():
    tampered_resp = _resp(200, text='{"data":{"quantity":-999}}')
    control_resp = _resp(200, text='{"data":{"quantity":1}}')
    readback_resp = _resp(200, text='{"data":{"quantity":-999}}')
    client = _client(
        put=AsyncMock(side_effect=[tampered_resp, control_resp]),
        get=AsyncMock(return_value=readback_resp),
    )

    finding = await business_logic._check_quantity_tampering(client, "https://example.com/basket", {})

    assert finding is not None
    assert finding["type"] == "QUANTITY_TAMPERING"


async def test_quantity_tampering_unconfirmed_when_not_persisted():
    tampered_resp = _resp(200, text='{"data":{"quantity":-999}}')
    control_resp = _resp(200, text='{"data":{"quantity":1}}')
    readback_resp = _resp(200, text='{"data":{"quantity":1}}')  # original, not persisted
    client = _client(
        put=AsyncMock(side_effect=[tampered_resp, control_resp]),
        get=AsyncMock(return_value=readback_resp),
    )

    finding = await business_logic._check_quantity_tampering(client, "https://example.com/basket", {})

    assert finding is None


# --- ZERO_PRICE_CHECKOUT (_check_zero_price_checkout) ---

async def test_zero_price_checkout_confirmed_when_total_zero():
    zero_add_resp = _resp(201, text='{"data":{}}')
    checkout_resp = _resp(200, text='{"totalPrice":0}')
    control_add_resp = _resp(201, text='{"data":{}}')
    control_checkout_resp = _resp(200, text='{"totalPrice":9.99}')
    client = _client(
        post=AsyncMock(side_effect=[zero_add_resp, checkout_resp, control_add_resp, control_checkout_resp]),
    )

    finding = await business_logic._check_zero_price_checkout(client, "https://example.com/basket", {})

    assert finding is not None
    assert finding["type"] == "ZERO_PRICE_CHECKOUT"


async def test_zero_price_checkout_unconfirmed_when_checkout_behaves_same_as_control():
    zero_add_resp = _resp(201, text='{"data":{}}')
    checkout_resp = _resp(200, text='{"status":"ok"}')
    control_add_resp = _resp(201, text='{"data":{}}')
    control_checkout_resp = _resp(200, text='{"status":"ok"}')  # identical to checkout_resp
    client = _client(
        post=AsyncMock(side_effect=[zero_add_resp, checkout_resp, control_add_resp, control_checkout_resp]),
    )

    finding = await business_logic._check_zero_price_checkout(client, "https://example.com/basket", {})

    assert finding is None


# --- end-to-end wiring sanity: the public function still surfaces a real finding ---

async def test_shopping_cart_manipulation_surfaces_confirmed_idor():
    idor_resp = _resp(200, text='{"data":{"UserId":"someoneelse","Products":[]}}')
    deny = _resp(403, text="Forbidden")
    client = _client(
        post=AsyncMock(return_value=deny),
        put=AsyncMock(return_value=deny),
        get=AsyncMock(return_value=idor_resp),
    )
    business_logic.httpx = _mock_client_ctx(client)

    result = await business_logic.test_shopping_cart_manipulation(
        "https://example.com/basket", auth_session={"username": "victim1"}
    )

    assert result["status"] == "success"
    findings = result["data"]["findings"]
    assert any(f["type"] == "BASKET_IDOR" for f in findings), f"expected BASKET_IDOR, got {findings}"
    assert result["data"]["vulnerable"] is True
    assert result["data"]["tests_performed"] == 6


# --- test_parameter_tampering ---
# Was completely non-functional: called urlencode() at line 106 but the file
# only imported urlparse/parse_qs/urlunparse from urllib.parse (line 23),
# never urlencode. Every call raised NameError, silently caught by the
# function's own broad except, so it returned status: "error" on every
# invocation. Fixed by adding urlencode to the urllib.parse import. These
# tests exercise the real (now reachable) detection logic.

async def test_parameter_tampering_flags_when_response_unchanged():
    # Removing the parameter yields a behaviorally identical response ->
    # server isn't re-validating after the param is stripped.
    original_resp = _resp(200, text="a" * 100)
    stripped_resp = _resp(200, text="a" * 100)

    async def fake_req(method, url, auth_session=None, **kwargs):
        return original_resp if "remove=x" in url else stripped_resp

    business_logic.req = fake_req

    result = await business_logic.test_parameter_tampering(
        "https://example.com/x?keep=1&remove=x", "remove"
    )

    assert result["status"] == "success"
    assert result["data"]["tampering_detected"] is True


async def test_parameter_tampering_no_finding_when_response_differs():
    # Removing the parameter changes the response (different status) ->
    # server is validating it; not a finding.
    original_resp = _resp(200, text="a" * 100)
    stripped_resp = _resp(400, text="missing required parameter")

    async def fake_req(method, url, auth_session=None, **kwargs):
        return original_resp if "remove=x" in url else stripped_resp

    business_logic.req = fake_req

    result = await business_logic.test_parameter_tampering(
        "https://example.com/x?keep=1&remove=x", "remove"
    )

    assert result["status"] == "success"
    assert result["data"]["tampering_detected"] is False


# --- regression: test_application_misuse_defenses was already confirmed good
# in an earlier audit pass and must stay unaffected by this fix. Lightweight
# smoke test only.


async def test_application_misuse_defenses_unaffected():
    rate_limited_resp = _resp(429, text="slow down")
    client = _client(
        get=AsyncMock(return_value=rate_limited_resp),
        post=AsyncMock(return_value=rate_limited_resp),
    )
    business_logic.httpx = _mock_client_ctx(client)

    result = await business_logic.test_application_misuse_defenses("https://example.com/login")

    assert result["status"] == "success"
    # Rate limiting present everywhere -> no "missing defenses" findings.
    assert result["data"]["findings"] == []
