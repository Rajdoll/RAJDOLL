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
