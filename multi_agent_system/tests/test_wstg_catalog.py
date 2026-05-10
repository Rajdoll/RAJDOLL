from multi_agent_system.core.wstg_catalog import (
    load_catalog, subtests_for_category, subtests_for_agent, SubTest,
    subtests_for_tool, tools_for_subtest, all_mapped_tools,
)


def test_catalog_has_all_categories():
    cat = load_catalog()
    cats = {st.category for st in cat.values()}
    assert {"WSTG-INFO", "WSTG-CONF", "WSTG-IDNT", "WSTG-ATHN",
            "WSTG-ATHZ", "WSTG-SESS", "WSTG-INPV", "WSTG-ERRH",
            "WSTG-CRYP", "WSTG-BUSL", "WSTG-CLNT", "WSTG-APIT"} <= cats


def test_catalog_total_size():
    cat = load_catalog()
    assert len(cat) == 97, f"expected 97 WSTG v4.2 sub-tests, got {len(cat)}"


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


def test_subtests_for_agent_returns_correct_set():
    sts = subtests_for_agent("AuthenticationAgent")
    assert len(sts) == 10
    assert all(st.owasp_agent == "AuthenticationAgent" for st in sts)


def test_subtests_for_agent_unknown_returns_empty():
    assert subtests_for_agent("NonExistentAgent") == []


def test_tool_map_covers_at_least_one_subtest():
    cat = load_catalog()
    mapped = set()
    for st_id in cat:
        for tool in tools_for_subtest(st_id):
            mapped.add(tool)
    assert mapped, "tool map empty"


def test_known_sql_tool_maps_to_inpv_05():
    sts = subtests_for_tool("test_sqli")
    assert any(st.id == "WSTG-INPV-05" for st in sts)


def test_subtests_without_tool_below_threshold():
    cat = load_catalog()
    gaps = [st_id for st_id in cat if not tools_for_subtest(st_id)]
    assert len(gaps) / len(cat) < 0.4, f"Too many gaps: {len(gaps)}/{len(cat)}"


def test_all_mapped_tools_returns_list():
    tools = all_mapped_tools()
    assert isinstance(tools, list)
    assert len(tools) > 0


def test_tools_for_subtest_unknown_returns_empty():
    assert tools_for_subtest("WSTG-FAKE-99") == []
