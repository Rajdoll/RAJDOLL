from multi_agent_system.agents.file_upload_agent import build_upload_endpoint_candidates


def test_upload_candidates_are_absolute_and_include_lab_defaults():
    candidates = build_upload_endpoint_candidates("http://juice-shop:3000", {})
    urls = [item["url"] for item in candidates]

    assert urls[0] == "http://juice-shop:3000/file-upload"
    assert "http://juice-shop:3000/file-upload" in urls
    assert "http://juice-shop:3000/api/upload" in urls
    assert all(url.startswith("http://juice-shop:3000/") for url in urls)


def test_upload_candidates_deduplicate_inventory_and_defaults():
    inventory = {
        "by_tag": {
            "file_upload": ["upload-1", "upload-2"]
        },
        "endpoints": [
            {"id": "upload-1", "path": "/file-upload"},
            {"id": "upload-2", "url": "http://juice-shop:3000/file-upload"},
            {"id": "image-1", "path": "/profile/image"},
            {"id": "api-upload-1", "url": "http://juice-shop:3000/api/upload"},
        ],
    }

    candidates = build_upload_endpoint_candidates("http://juice-shop:3000", inventory)
    urls = [item["url"] for item in candidates]

    assert urls.count("http://juice-shop:3000/file-upload") == 1
    assert urls.count("http://juice-shop:3000/api/upload") == 1
    assert "http://juice-shop:3000/profile/image" in urls
