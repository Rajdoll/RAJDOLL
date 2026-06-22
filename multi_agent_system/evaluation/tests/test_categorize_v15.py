import importlib.util, pathlib
_p = pathlib.Path(__file__).parents[1] / "categorize_v15.py"
_s = importlib.util.spec_from_file_location("categorize_v15", _p)
cat = importlib.util.module_from_spec(_s); _s.loader.exec_module(cat)

def test_osint_and_chatbot_are_non_automatable():
    assert cat.classify_challenge("Bully Chatbot", "Miscellaneous", "Receive a coupon code from the support chatbot.")[0] is False
    assert cat.classify_challenge("Leaked Access Logs", "Sensitive Data Exposure", "Dumpster dive the Internet for a leaked password")[0] is False
    assert cat.classify_challenge("Visual Geo Stalking", "Sensitive Data Exposure", "looking at an upload of her to the Photo Wall")[0] is False

def test_technical_vulns_are_automatable():
    assert cat.classify_challenge("User Credentials", "Injection", "Retrieve a list of all user credentials via SQL Injection.")[0] is True
    assert cat.classify_challenge("Reflected XSS", "XSS", "Perform a reflected XSS attack")[0] is True

def test_overrides_carry_rationale():
    # The categorization tool IS the answer-key builder, so naming challenges here is correct
    # (G1's no-hardcode rule binds DETECTORS, built in Plan 2 — not this GT builder).
    # This asserts every manual override carries a non-empty rationale for the review gate.
    for name, (flag, reason) in cat.OVERRIDES.items():
        assert reason and len(reason) > 3

def test_propose_wstg_returns_valid_code():
    code = cat.propose_wstg("User Credentials", "Injection")
    assert code.startswith("WSTG-") and len(code.split("-")) == 3
    # NOTE: the G3a anti-hardcode test (no challenge-name literals in DETECTOR code) lives in
    # Plan 2, where the SCA/secret/EXIF detectors are built. Plan 1 has no detectors.
