import importlib.util, pathlib
_p = pathlib.Path(__file__).parent / "input-validation.py"
_s = importlib.util.spec_from_file_location("iv_mod", _p)
iv = importlib.util.module_from_spec(_s); _s.loader.exec_module(iv)

_GUESTBOOK = '''
<form method="post" name="guestform">
    <input name="txtName" type="text" size="30" maxlength="10">
    <textarea name="mtxMessage" cols="50" rows="3" maxlength="50"></textarea>
    <input name="btnSign" type="submit" value="Sign Guestbook">
    <input name="btnClear" type="submit" value="Clear Guestbook">
</form>
<input type="button" value="View Help" name="HelpBtn">
'''

_GET_ONLY = '<form method="GET"><input name="id"><input type="submit" name="Submit" value="Submit"></form>'


def test_parse_post_form_guestbook():
    out = iv._parse_post_form(_GUESTBOOK)
    assert out["method"] == "POST"
    assert out["fields"]["btnSign"] == "Sign Guestbook"
    types = {f["name"]: f["type"] for f in out["typed"]}
    assert types["txtName"] == "text"
    assert types["mtxMessage"] == "textarea"
    assert types["btnSign"] == "submit"
    # out-of-form button excluded
    assert "HelpBtn" not in out["fields"]


def test_parse_post_form_none_when_no_post_form():
    assert iv._parse_post_form(_GET_ONLY) is None
    assert iv._parse_post_form("") is None


def test_parse_form_fields_dict_shape_unchanged():
    # regression: the typed extension must not break the SQLi parser
    out = iv._parse_form_fields(_GET_ONLY, "id")
    assert out == {"method": "GET", "fields": {"Submit": "Submit"}}


def test_stored_xss_form_plan_guestbook():
    form = iv._parse_post_form(_GUESTBOOK)
    form_data, injectable = iv._stored_xss_form_plan(form)
    assert injectable == ["txtName", "mtxMessage"]
    assert form_data["btnSign"] == "Sign Guestbook"
    assert "btnClear" not in form_data          # only the first submit kept
    assert set(form_data) == {"txtName", "mtxMessage", "btnSign"}


def test_stored_xss_uses_real_fields(monkeypatch):
    posted = {}

    class _Resp:
        def __init__(self, text, ct="text/html"):
            self.text = text; self.headers = {"content-type": ct}

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url): return _Resp(_GUESTBOOK)
        async def post(self, url, data=None):
            posted.update(data or {}); return _Resp(_GUESTBOOK)

    monkeypatch.setattr(iv.httpx, "AsyncClient", _Client)
    import asyncio
    asyncio.run(iv.test_stored_xss("http://dvwa/vulnerabilities/xss_s/"))
    # the POST used the REAL fields, not the old guesses
    assert "mtxMessage" in posted and "btnSign" in posted
    assert "comment" not in posted and "message" not in posted
