from multi_agent_system.core.endpoint_inventory import augment_tags_heuristic


def test_query_param_endpoint_gets_error_prone_param_tag():
    ep = {"id": "e1", "path": "/api/search", "method": "GET", "params": ["q"], "tags": []}
    out = augment_tags_heuristic([ep])
    assert "error_prone_param" in out[0]["tags"]


def test_numeric_id_path_gets_idor_candidate():
    ep = {"id": "e2", "path": "/api/users/{id}", "method": "GET", "tags": []}
    out = augment_tags_heuristic([ep])
    assert "idor_candidate" in out[0]["tags"]


def test_json_post_gets_state_changing_resource():
    ep = {"id": "e3", "path": "/api/comments", "method": "POST", "content_type": "application/json", "tags": []}
    out = augment_tags_heuristic([ep])
    assert "state_changing_resource" in out[0]["tags"]


def test_multipart_post_gets_file_upload():
    ep = {"id": "e4", "path": "/upload", "method": "POST", "content_type": "multipart/form-data", "tags": []}
    out = augment_tags_heuristic([ep])
    assert "file_upload" in out[0]["tags"]


def test_registration_path_gets_user_registration():
    ep = {"id": "e5", "path": "/api/users", "method": "POST", "tags": []}
    out = augment_tags_heuristic([ep])
    assert "user_registration" in out[0]["tags"]


def test_api_prefix_gets_api_generic():
    ep = {"id": "e6", "path": "/api/anything", "method": "GET", "tags": []}
    out = augment_tags_heuristic([ep])
    assert "api_generic" in out[0]["tags"]


def test_existing_llm_tags_preserved():
    ep = {"id": "e7", "path": "/login", "method": "POST", "tags": ["user_login"]}
    out = augment_tags_heuristic([ep])
    assert "user_login" in out[0]["tags"]
    assert "state_changing_resource" in out[0]["tags"]


def test_no_duplicate_tags():
    ep = {"id": "e8", "path": "/api/foo", "method": "GET", "params": ["x"], "tags": ["error_prone_param"]}
    out = augment_tags_heuristic([ep])
    assert out[0]["tags"].count("error_prone_param") == 1
