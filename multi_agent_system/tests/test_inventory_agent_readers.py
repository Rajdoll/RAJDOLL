"""Verify each refactored agent reads from endpoint_inventory[by_tag] correctly."""
from multi_agent_system.core.endpoint_inventory import read_tag, build_inventory


def test_authorization_agent_reads_idor_and_admin():
    inv = build_inventory([
        {"id": "ep_1", "path": "/api/users/{id}", "method": "GET", "tags": ["idor_candidate"]},
        {"id": "ep_2", "path": "/admin", "method": "GET", "tags": ["admin_panel"]},
        {"id": "ep_3", "path": "/x", "method": "GET", "tags": []},
    ])
    idor = read_tag(inv, "idor_candidate")
    admin = read_tag(inv, "admin_panel")
    assert [e["id"] for e in idor] == ["ep_1"]
    assert [e["id"] for e in admin] == ["ep_2"]


def test_business_logic_reads_money_and_resource():
    inv = build_inventory([
        {"id": "ep_1", "path": "/checkout", "method": "POST", "tags": ["state_changing_money"]},
        {"id": "ep_2", "path": "/feedback", "method": "POST", "tags": ["state_changing_resource"]},
    ])
    assert [e["id"] for e in read_tag(inv, "state_changing_money")] == ["ep_1"]
    assert [e["id"] for e in read_tag(inv, "state_changing_resource")] == ["ep_2"]


def test_identity_reads_three_tags():
    inv = build_inventory([
        {"id": "ep_1", "path": "/register", "method": "POST", "tags": ["user_registration"]},
        {"id": "ep_2", "path": "/me", "method": "GET", "tags": ["user_profile"]},
        {"id": "ep_3", "path": "/forgot", "method": "POST", "tags": ["password_recovery"]},
    ])
    assert read_tag(inv, "user_registration")[0]["id"] == "ep_1"
    assert read_tag(inv, "user_profile")[0]["id"] == "ep_2"
    assert read_tag(inv, "password_recovery")[0]["id"] == "ep_3"


def test_configdeploy_reads_admin_and_hidden():
    inv = build_inventory([
        {"id": "ep_1", "path": "/admin", "method": "GET", "tags": ["admin_panel"]},
        {"id": "ep_2", "path": "/.git/HEAD", "method": "GET", "tags": ["hidden_path"]},
    ])
    assert read_tag(inv, "admin_panel")[0]["id"] == "ep_1"
    assert read_tag(inv, "hidden_path")[0]["id"] == "ep_2"
