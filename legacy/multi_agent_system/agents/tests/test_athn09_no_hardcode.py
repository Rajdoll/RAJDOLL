import pathlib
SRC = pathlib.Path(__file__).parents[1] / "authentication_agent.py"

def test_no_hardcoded_juiceshop_athn09_literals():
    src = SRC.read_text()
    for forbidden in ["jim%40example.com", "jim@example.com", "other side",
                      "/rest/security-question?email=", "To get to the other side"]:
        assert forbidden not in src, f"hardcoded ATHN-09 literal still present: {forbidden}"
