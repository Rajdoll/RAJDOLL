import pytest
from multi_agent_system.core.slot_registry import TestSlot, TestSlotRegistry


def _catalog():
    from multi_agent_system.core.wstg_catalog import load_catalog
    return load_catalog()


def test_slot_id_is_deterministic():
    cat = _catalog()
    slot = TestSlot.make("http://t/api?id=1", "GET", "WSTG-INPV-05", cat)
    slot2 = TestSlot.make("http://t/api?id=1", "GET", "WSTG-INPV-05", cat)
    assert slot.id == slot2.id


def test_slot_has_correct_fields():
    cat = _catalog()
    slot = TestSlot.make("http://t/api/products", "GET", "WSTG-INPV-05", cat)
    assert slot.endpoint == "http://t/api/products"
    assert slot.wstg_id == "WSTG-INPV-05"
    assert slot.agent_owner == "InputValidationAgent"
    assert slot.high_risk is True
    assert slot.status == "pending"
    assert slot.finding_count == 0


def test_slot_unknown_wstg_id_raises():
    cat = _catalog()
    with pytest.raises(KeyError):
        TestSlot.make("http://t/", "GET", "WSTG-FAKE-99", cat)


def test_slot_roundtrip():
    cat = _catalog()
    slot = TestSlot.make("http://t/login", "POST", "WSTG-ATHN-01", cat)
    slot.status = "vulnerable"
    slot.finding_count = 2
    restored = TestSlot.from_dict(slot.to_dict())
    assert restored.id == slot.id
    assert restored.status == "vulnerable"
    assert restored.finding_count == 2


def test_registry_groups_by_agent():
    cat = _catalog()
    endpoint_map = {
        "http://t/api/products": ["WSTG-INPV-05", "WSTG-ATHZ-01"],
        "http://t/rest/user/login": ["WSTG-ATHN-01"],
    }
    endpoints_meta = [
        {"url": "http://t/api/products", "method": "GET", "params": ["q"]},
        {"url": "http://t/rest/user/login", "method": "POST", "params": ["email", "password"]},
    ]
    reg = TestSlotRegistry.build(endpoint_map, endpoints_meta, cat)
    inpv_slots = reg.slots_for_agent("InputValidationAgent")
    athn_slots = reg.slots_for_agent("AuthenticationAgent")
    assert len(inpv_slots) == 1  # WSTG-INPV-05
    assert len(athn_slots) == 1  # WSTG-ATHN-01
    assert inpv_slots[0].wstg_id == "WSTG-INPV-05"


def test_registry_high_risk_slots_come_first():
    cat = _catalog()
    slot_hr = TestSlot.make("http://t/", "GET", "WSTG-INPV-05", cat)
    slot_lr = TestSlot.make("http://t/", "GET", "WSTG-INFO-01", cat)
    assert slot_hr.high_risk is True
    assert slot_lr.high_risk is False


def test_registry_roundtrip():
    cat = _catalog()
    endpoint_map = {"http://t/api": ["WSTG-INPV-05"]}
    endpoints_meta = [{"url": "http://t/api", "method": "GET", "params": []}]
    reg = TestSlotRegistry.build(endpoint_map, endpoints_meta, cat)
    reg2 = TestSlotRegistry.from_dict(reg.to_dict())
    assert reg2.total == reg.total


def test_registry_coverage_summary():
    cat = _catalog()
    endpoint_map = {"http://t/api": ["WSTG-INPV-05", "WSTG-ATHN-01"]}
    endpoints_meta = [{"url": "http://t/api", "method": "GET", "params": []}]
    reg = TestSlotRegistry.build(endpoint_map, endpoints_meta, cat)
    all_slots = reg.slots_for_agent("InputValidationAgent") + reg.slots_for_agent("AuthenticationAgent")
    all_slots[0].status = "vulnerable"
    summary = reg.coverage_summary()
    assert summary["total"] == 2
    assert summary["vulnerable"] == 1
