import importlib.util, pathlib
_p = pathlib.Path(__file__).parent / "client-side.py"
_s = importlib.util.spec_from_file_location("client_side_mod", _p)
cs = importlib.util.module_from_spec(_s); _s.loader.exec_module(cs)

def test_inject_payload_query_path():
    assert cs._inject_payload("http://t/search", "q", "PL") == "http://t/search?q=PL"
    assert cs._inject_payload("http://t/search?x=1", "q", "PL") == "http://t/search?x=1&q=PL"

def test_inject_payload_spa_hash_route():
    # payload must land in the client route's query, after the hash
    assert cs._inject_payload("http://t/#/search", "q", "PL") == "http://t/#/search?q=PL"
    assert cs._inject_payload("http://t/#/track?id=1", "id", "PL") == "http://t/#/track?id=1&id=PL"

def test_classify_xss_result():
    assert cs._classify_xss_result(True, False) is True    # dialog fired
    assert cs._classify_xss_result(False, True) is True     # marker executed
    assert cs._classify_xss_result(False, False) is False   # neither

def test_no_target_specific_literals():
    # G1 binds the NEW detector code only. client-side.py already references "Juice Shop"
    # in unrelated legacy tools, so scope the check to the new functions via getsource.
    import inspect
    new_src = (inspect.getsource(cs.verify_xss_headless)
               + inspect.getsource(cs._inject_payload)
               + inspect.getsource(cs._classify_xss_result)
               + inspect.getsource(cs._default_xss_payloads)).lower()
    for bad in ["juice", "owasp_promo", "epilogue", "/#/search?q=<"]:
        assert bad not in new_src, f"hardcoded literal in new XSS code: {bad}"
