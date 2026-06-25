import importlib.util, pathlib, re
_p = pathlib.Path(__file__).parent / "input-validation.py"
_s = importlib.util.spec_from_file_location("iv_mod", _p)
iv = importlib.util.module_from_spec(_s); _s.loader.exec_module(iv)


def test_boundary_matrix_is_generic_and_ordered():
    m = iv._sqli_boundary_matrix()
    suffixes = [b["suffix"] for b in m]
    # enumerates quote x paren-depth x comment (generic contexts)
    assert "'" in suffixes
    assert "'--" in suffixes
    assert "')--" in suffixes
    assert "'))--" in suffixes
    # bare-quote context comes before deeper paren contexts (prevalence order)
    assert suffixes.index("'--") < suffixes.index("'))--")
    # no target-specific literal anywhere in the matrix
    blob = " ".join(suffixes).lower()
    assert "juice" not in blob


def test_error_regex_matches_real_dbms_errors_not_generic_5xx():
    assert iv._SQLI_ERROR_RE.search("Error: SQLITE_ERROR: incomplete input")
    assert iv._SQLI_ERROR_RE.search("You have an error in your SQL syntax near")
    assert iv._SQLI_ERROR_RE.search("ORA-00933: SQL command not properly ended")
    # generic server errors must NOT match
    assert not iv._SQLI_ERROR_RE.search("500 Internal Server Error")
    assert not iv._SQLI_ERROR_RE.search("B2B customer complaints have been deprecated")


def test_error_regex_rejects_benign_substring_collisions():
    assert not iv._SQLI_ERROR_RE.search("psql: connection refused")
    assert not iv._SQLI_ERROR_RE.search("mysql_fetcher is a great metaphor")
    assert not iv._SQLI_ERROR_RE.search('near "the end": syntax error free zone')
    assert not iv._SQLI_ERROR_RE.search("PG::connection pooling guide")
