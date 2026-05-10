import pytest
from multi_agent_system.utils.learned_patterns import (
    LearnedPatternStore, target_signature,
)


def test_signature_is_stable_for_same_props():
    a = target_signature({"server": "nginx/1.21", "tech": ["Node.js", "Express"]})
    b = target_signature({"server": "nginx/1.21", "tech": ["Express", "Node.js"]})
    assert a == b


def test_signature_differs_when_tech_changes():
    a = target_signature({"server": "nginx", "tech": ["Node.js"]})
    b = target_signature({"server": "nginx", "tech": ["Java"]})
    assert a != b


def test_signature_ignores_keys_beyond_server_and_tech():
    a = target_signature({"server": "apache", "tech": ["PHP"], "version": "7.4"})
    b = target_signature({"server": "apache", "tech": ["PHP"], "extra": "unrelated"})
    assert a == b


def test_signature_handles_missing_keys():
    a = target_signature({})
    b = target_signature({"server": None, "tech": []})
    assert a == b


def test_store_record_and_top_patterns(tmp_path):
    store = LearnedPatternStore(tmp_path / "lp.db")
    sig = "sig-abc"
    store.record(sig, "WSTG-INPV-05", "test_sqli", {"vector": "blind"}, success=True, finding_count=2)
    store.record(sig, "WSTG-INPV-05", "test_sqli", {"vector": "union"}, success=False, finding_count=0)
    top = store.top_patterns_for(sig, "WSTG-INPV", limit=5)
    assert len(top) == 1  # only successes
    assert top[0]["tool"] == "test_sqli"
    assert top[0]["args"] == {"vector": "blind"}
    assert top[0]["finding_count"] == 2


def test_top_patterns_filters_by_signature(tmp_path):
    store = LearnedPatternStore(tmp_path / "lp.db")
    store.record("sig-A", "WSTG-INPV-05", "test_sqli", {"a": 1}, True, 1)
    store.record("sig-B", "WSTG-INPV-05", "test_sqli", {"b": 2}, True, 1)
    assert len(store.top_patterns_for("sig-A", "WSTG-INPV")) == 1
    assert len(store.top_patterns_for("sig-B", "WSTG-INPV")) == 1


def test_top_patterns_orders_by_finding_count(tmp_path):
    store = LearnedPatternStore(tmp_path / "lp.db")
    sig = "x"
    store.record(sig, "WSTG-INPV-05", "test_sqli", {"v": "union"}, True, 1)
    store.record(sig, "WSTG-INPV-05", "test_sqli", {"v": "blind"}, True, 5)
    top = store.top_patterns_for(sig, "WSTG-INPV")
    assert top[0]["args"]["v"] == "blind"  # highest finding_count first


def test_top_patterns_limit_respected(tmp_path):
    store = LearnedPatternStore(tmp_path / "lp.db")
    sig = "lim"
    for i in range(10):
        store.record(sig, "WSTG-INPV-05", "test_sqli", {"i": i}, True, i)
    assert len(store.top_patterns_for(sig, "WSTG-INPV", limit=3)) == 3


def test_top_patterns_empty_when_none(tmp_path):
    store = LearnedPatternStore(tmp_path / "lp.db")
    assert store.top_patterns_for("sig-missing", "WSTG-INPV") == []


def test_store_creates_db_and_parent_dirs(tmp_path):
    nested = tmp_path / "a" / "b" / "lp.db"
    store = LearnedPatternStore(nested)
    assert nested.exists()


def test_store_thread_safe_concurrent_writes(tmp_path):
    import threading
    store = LearnedPatternStore(tmp_path / "lp.db")
    errors = []
    def write():
        try:
            store.record("sig", "WSTG-INPV-05", "test_sqli", {}, True, 1)
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=write) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    top = store.top_patterns_for("sig", "WSTG-INPV", limit=20)
    assert len(top) == 20


def test_get_default_store_returns_store_instance(tmp_path, monkeypatch):
    import multi_agent_system.utils.learned_patterns as lp_mod
    monkeypatch.setattr(lp_mod, "_DEFAULT_PATH", tmp_path / "lp.db")
    store = lp_mod.get_default_store()
    assert isinstance(store, LearnedPatternStore)


def test_category_derivation_bare_category_id(tmp_path):
    store = LearnedPatternStore(tmp_path / "lp.db")
    store.record("sig", "WSTG-INFO", "check_metafiles", {}, True, 1)
    top = store.top_patterns_for("sig", "WSTG-INFO")
    assert len(top) == 1
