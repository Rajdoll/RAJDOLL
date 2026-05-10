from multi_agent_system.core.wstg_catalog import (
    load_catalog, subtests_for_category, SubTest,
)


def test_catalog_has_all_categories():
    cat = load_catalog()
    cats = {st.category for st in cat.values()}
    assert {"WSTG-INFO", "WSTG-CONF", "WSTG-IDNT", "WSTG-ATHN",
            "WSTG-ATHZ", "WSTG-SESS", "WSTG-INPV", "WSTG-ERRH",
            "WSTG-CRYP", "WSTG-BUSL", "WSTG-CLNT", "WSTG-APIT"} <= cats


def test_catalog_total_size():
    cat = load_catalog()
    assert 80 <= len(cat) <= 110, f"WSTG v4.2 has ~92 sub-tests, got {len(cat)}"


def test_subtests_for_category_returns_input_validation_set():
    sts = subtests_for_category("WSTG-INPV")
    ids = {st.id for st in sts}
    assert "WSTG-INPV-01" in ids
    assert "WSTG-INPV-05" in ids
    assert all(st.category == "WSTG-INPV" for st in sts)


def test_subtest_has_required_fields():
    cat = load_catalog()
    st = cat["WSTG-INPV-05"]
    assert isinstance(st, SubTest)
    assert st.id == "WSTG-INPV-05"
    assert st.title
    assert st.category == "WSTG-INPV"
    assert st.owasp_agent
