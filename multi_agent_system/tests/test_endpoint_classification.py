# multi_agent_system/tests/test_endpoint_classification.py
"""Unit tests for classify_endpoint() and build_classified_payload()."""
import pytest

from multi_agent_system.agents.reconnaissance_agent import (
    classify_endpoint,
    build_classified_payload,
)


# ---------------------------------------------------------------------------
# classify_endpoint parametrized tests
# ---------------------------------------------------------------------------

class TestClassifyEndpoint:
    @pytest.mark.parametrize("path,expected", [
        ("/login", ["login"]),
        ("/auth/login", ["login"]),
        ("/signin", ["login"]),
        ("/sign-in", ["login"]),
        ("/api/authenticate", ["login", "api"]),
    ])
    def test_login(self, path, expected):
        assert classify_endpoint(path) == expected

    @pytest.mark.parametrize("path,expected", [
        ("/register", ["registration"]),
        ("/signup", ["registration"]),
        ("/sign-up", ["registration"]),
        ("/join", ["registration"]),
        ("/create-account", ["registration"]),
        ("/create_account", ["registration"]),
    ])
    def test_registration(self, path, expected):
        assert classify_endpoint(path) == expected

    @pytest.mark.parametrize("path,expected", [
        ("/checkout", ["checkout"]),
        ("/cart", ["checkout"]),
        ("/basket", ["checkout"]),
        ("/payment", ["checkout"]),
        ("/api/order", ["checkout", "api"]),
    ])
    def test_checkout(self, path, expected):
        assert classify_endpoint(path) == expected

    @pytest.mark.parametrize("path,expected", [
        ("/feedback", ["feedback"]),
        ("/comment", ["feedback"]),
        ("/review", ["feedback"]),
        ("/contact", ["feedback"]),
        ("/complaint", ["feedback"]),
    ])
    def test_feedback(self, path, expected):
        assert classify_endpoint(path) == expected

    @pytest.mark.parametrize("path,expected", [
        ("/upload", ["upload"]),
        ("/file-upload", ["upload"]),
        ("/fileupload", ["upload"]),
    ])
    def test_upload(self, path, expected):
        assert classify_endpoint(path) == expected

    @pytest.mark.parametrize("path,expected", [
        ("/admin", ["admin"]),
        ("/dashboard", ["admin"]),
        ("/management", ["admin"]),
    ])
    def test_admin(self, path, expected):
        assert classify_endpoint(path) == expected

    @pytest.mark.parametrize("path,expected", [
        ("/search", ["search"]),
        ("/api/search", ["search", "api"]),
    ])
    def test_search(self, path, expected):
        assert classify_endpoint(path) == expected

    @pytest.mark.parametrize("path,expected", [
        ("/api/products", ["api", "data"]),
        ("/rest/items", ["api", "data"]),
        ("/data.json", ["api", "data"]),
    ])
    def test_api_data(self, path, expected):
        assert classify_endpoint(path) == expected

    def test_js_file(self):
        assert classify_endpoint("/main.js") == ["js_file"]
        assert classify_endpoint("/vendor.bundle.js") == ["js_file"]

    @pytest.mark.parametrize("path", [
        "/style.css",
        "/logo.png",
        "/photo.jpg",
        "/favicon.ico",
    ])
    def test_static_assets_return_empty(self, path):
        assert classify_endpoint(path) == []

    def test_generic_path_returns_empty(self):
        assert classify_endpoint("/about") == []
        assert classify_endpoint("/") == []
        assert classify_endpoint("/products/123") == []

    def test_multi_tag(self):
        """A path matching multiple categories gets all tags."""
        result = classify_endpoint("/api/login")
        assert "login" in result
        assert "api" in result
        # login is a specific category, so 'data' should NOT be added
        assert "data" not in result


# ---------------------------------------------------------------------------
# build_classified_payload tests
# ---------------------------------------------------------------------------

class TestBuildClassifiedPayload:
    def test_empty_list(self):
        result = build_classified_payload([])
        assert result["count"] == 0
        assert result["endpoints"] == []
        assert result["api_endpoints"] == []
        assert result["login_endpoints"] == []

    def test_mixed_endpoints(self):
        endpoints = [
            {"endpoint": "/api/products", "type": "api"},
            {"endpoint": "/login", "type": "other"},
            {"endpoint": "/admin/users", "type": "admin"},
            {"endpoint": "/main.js", "type": "js_file"},
            {"endpoint": "/search?q=test", "type": "search"},
            {"endpoint": "/upload", "type": "other"},
            {"endpoint": "/api/feedback", "type": "api"},
            {"endpoint": "/checkout", "type": "other"},
            {"endpoint": "/register", "type": "other"},
            {"endpoint": "/reset-password", "type": "other"},
            {"url": "/rest/data", "type": "other"},
            {"endpoint": "/page", "type": "form"},
            {"endpoint": "/xhr-call", "type": "xhr"},
        ]
        result = build_classified_payload(endpoints)

        assert result["count"] == len(endpoints)
        assert len(result["api_endpoints"]) >= 2  # /api/products + /api/feedback + /rest/data
        assert len(result["admin_endpoints"]) >= 1
        assert len(result["js_files"]) >= 1
        assert len(result["search_endpoints"]) >= 1
        assert len(result["upload_endpoints"]) >= 1
        assert len(result["file_endpoints"]) >= 1  # mirrors upload
        assert len(result["login_endpoints"]) >= 1
        assert len(result["registration_endpoints"]) >= 1
        assert len(result["password_reset_endpoints"]) >= 1
        assert len(result["checkout_endpoints"]) >= 1
        assert len(result["feedback_endpoints"]) >= 1
        assert len(result["forms"]) >= 1
        assert len(result["xhr_endpoints"]) >= 1

    def test_type_based_classification_preserved(self):
        """Endpoints with legacy 'type' field are still classified correctly."""
        ep = {"endpoint": "/some-path", "type": "api"}
        result = build_classified_payload([ep])
        assert ep in result["api_endpoints"]

    def test_tag_based_classification(self):
        """Endpoints without a matching 'type' are classified by path tags."""
        ep = {"endpoint": "/api/basket/checkout", "type": "other"}
        result = build_classified_payload([ep])
        assert ep in result["api_endpoints"]
        assert ep in result["checkout_endpoints"]

    def test_data_endpoints_only_for_generic_api(self):
        """'data' tag only applies to API endpoints without a specific category."""
        generic_api = {"endpoint": "/api/items", "type": "other"}
        login_api = {"endpoint": "/api/login", "type": "other"}
        result = build_classified_payload([generic_api, login_api])
        assert generic_api in result["data_endpoints"]
        assert login_api not in result["data_endpoints"]

