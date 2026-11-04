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


def test_clientside_reads_sink_and_params():
    inv = build_inventory([
        {"id": "ep_1", "path": "/search", "method": "GET", "tags": ["client_render_sink", "error_prone_param"]},
    ])
    assert read_tag(inv, "client_render_sink")[0]["id"] == "ep_1"
    assert read_tag(inv, "error_prone_param")[0]["id"] == "ep_1"


def test_weakcrypto_reads_token_and_login():
    inv = build_inventory([
        {"id": "ep_1", "path": "/login", "method": "POST", "tags": ["user_login", "auth_token_endpoint"]},
    ])
    assert read_tag(inv, "auth_token_endpoint")[0]["id"] == "ep_1"
    assert read_tag(inv, "user_login")[0]["id"] == "ep_1"


def test_errorhandling_reads_error_prone():
    inv = build_inventory([
        {"id": "ep_1", "path": "/search", "method": "GET", "tags": ["error_prone_param"]},
    ])
    assert read_tag(inv, "error_prone_param")[0]["id"] == "ep_1"


def test_fileupload_reads_file_upload():
    inv = build_inventory([
        {"id": "ep_1", "path": "/upload", "method": "POST", "tags": ["file_upload"]},
    ])
    assert read_tag(inv, "file_upload")[0]["id"] == "ep_1"


def test_api_and_react_read_api_generic():
    inv = build_inventory([
        {"id": "ep_1", "path": "/api/x", "method": "GET", "tags": ["api_generic"]},
    ])
    assert read_tag(inv, "api_generic")[0]["id"] == "ep_1"


def test_authentication_reads_three_tags():
    inv = build_inventory([
        {"id": "ep_1", "path": "/login", "method": "POST", "tags": ["user_login"]},
        {"id": "ep_2", "path": "/forgot", "method": "POST", "tags": ["password_recovery"]},
        {"id": "ep_3", "path": "/oauth/token", "method": "POST", "tags": ["auth_token_endpoint"]},
    ])
    assert read_tag(inv, "user_login")[0]["id"] == "ep_1"
    assert read_tag(inv, "password_recovery")[0]["id"] == "ep_2"
    assert read_tag(inv, "auth_token_endpoint")[0]["id"] == "ep_3"


def test_session_reads_token_and_login():
    inv = build_inventory([
        {"id": "ep_1", "path": "/login", "method": "POST", "tags": ["user_login", "auth_token_endpoint"]},
    ])
    assert read_tag(inv, "auth_token_endpoint")[0]["id"] == "ep_1"
    assert read_tag(inv, "user_login")[0]["id"] == "ep_1"


def test_inputvalidation_reads_error_prone_and_api():
    inv = build_inventory([
        {"id": "ep_1", "path": "/search", "method": "GET", "tags": ["error_prone_param"]},
        {"id": "ep_2", "path": "/api/items", "method": "GET", "tags": ["api_generic"]},
    ])
    assert read_tag(inv, "error_prone_param")[0]["id"] == "ep_1"
    assert read_tag(inv, "api_generic")[0]["id"] == "ep_2"
