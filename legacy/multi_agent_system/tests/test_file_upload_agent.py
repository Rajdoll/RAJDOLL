from multi_agent_system.agents.file_upload_agent import (
    FileUploadAgent,
    build_upload_endpoint_candidates,
)


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


# ============================================================================
# Task 4: proof_type must reflect what the tool actually confirmed, not a
# self-stamped "validated_*" string based purely on data.get("vulnerable").
# ============================================================================

def _agent(tool_name):
    a = FileUploadAgent.__new__(FileUploadAgent)
    a.log = lambda *args, **kw: None
    a.log_tool_execution_plan = lambda: None
    a.get_auth_session = lambda: None
    a._get_target = lambda: "https://example.com"
    a._shared_context_snapshot = {"endpoint_inventory": {}}
    a.should_run_tool = lambda name: name == tool_name
    a.findings = []
    a.add_finding = lambda *args, **kw: a.findings.append((args, kw))
    return a


def _fake_mcp(payload):
    class FakeMCP:
        async def call_tool(self, server, tool, args, timeout=300, auth_session=None):
            return payload
    return FakeMCP()


# --- test_unrestricted_upload: tool only confirms via follow-up GET when it
# found an upload_url; the "_unverified" finding type has none. ---------------

async def test_unrestricted_upload_with_verified_url_is_validated(monkeypatch):
    agent = _agent("test_unrestricted_upload")
    monkeypatch.setattr(
        "multi_agent_system.agents.file_upload_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "vulnerable": True,
                "findings": [{
                    "type": "unrestricted_upload",
                    "extension": ".php",
                    "filename": "malicious.php",
                    "upload_url": "https://example.com/uploads/malicious.php",
                    "severity": "critical",
                    "evidence": "File uploaded and accessible at .../malicious.php",
                    "description": "Dangerous file type .php was accepted and stored",
                }],
            },
        }),
    )

    await agent.run()

    assert any(
        kw["evidence"]["proof_type"] == "validated_file_upload"
        for args, kw in agent.findings if args[0] == "WSTG-BUSL-08"
    )


async def test_unrestricted_upload_without_verification_is_heuristic(monkeypatch):
    agent = _agent("test_unrestricted_upload")
    monkeypatch.setattr(
        "multi_agent_system.agents.file_upload_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "vulnerable": True,
                "findings": [{
                    "type": "unrestricted_upload_unverified",
                    "extension": ".php",
                    "filename": "malicious.php",
                    "severity": "high",
                    "evidence": "HTTP 200: ...",
                    "description": "File type .php was accepted (HTTP 200)",
                }],
            },
        }),
    )

    await agent.run()

    assert agent.findings
    assert all(kw["evidence"]["proof_type"] == "heuristic" for args, kw in agent.findings)


# --- test_path_traversal_upload: tool never re-fetches to confirm; it only
# pattern-matches the initial upload response's own body. Always a lead. -----

async def test_path_traversal_upload_is_always_heuristic(monkeypatch):
    agent = _agent("test_path_traversal_upload")
    monkeypatch.setattr(
        "multi_agent_system.agents.file_upload_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "vulnerable": True,
                "findings": [{
                    "type": "path_traversal_upload",
                    "filename": "../../../etc/passwd",
                    "attack_type": "unix_relative",
                    "severity": "high",
                    "evidence": "passwd",
                    "description": "Path traversal filename accepted: ../../../etc/passwd",
                }],
            },
        }),
    )

    await agent.run()

    assert agent.findings
    assert all(kw["evidence"]["proof_type"] == "heuristic" for args, kw in agent.findings)


# --- test_xxe_via_svg: some finding types reflect the actual malicious-payload
# effect (leaked /etc/passwd content, SSRF metadata, entity-expansion size) —
# real confirmation. Others ("xxe_possible", "xxe_xml_upload_accepted") are
# admittedly speculative in the tool's own description text. ------------------

async def test_xxe_file_disclosure_is_validated(monkeypatch):
    agent = _agent("test_xxe_via_svg")
    monkeypatch.setattr(
        "multi_agent_system.agents.file_upload_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "vulnerable": True,
                "findings": [{
                    "type": "xxe_file_disclosure",
                    "attack_type": "file_disclosure_etc_passwd",
                    "filename": "malicious_file_disclosure_etc_passwd.svg",
                    "severity": "critical",
                    "evidence": "root:x:0:0:root:/root:/bin/bash",
                    "description": "/etc/passwd content disclosed via XXE",
                }],
            },
        }),
    )

    await agent.run()

    assert any(
        kw["evidence"]["proof_type"] == "validated_xxe_upload"
        for args, kw in agent.findings if args[0] == "WSTG-INPV-07"
    )


async def test_xxe_possible_is_heuristic(monkeypatch):
    agent = _agent("test_xxe_via_svg")
    monkeypatch.setattr(
        "multi_agent_system.agents.file_upload_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "vulnerable": True,
                "findings": [{
                    "type": "xxe_possible",
                    "attack_type": "file_disclosure_etc_passwd",
                    "filename": "malicious_file_disclosure_etc_passwd.svg",
                    "upload_url": "https://example.com/uploads/malicious.svg",
                    "severity": "medium",
                    "evidence": "SVG file uploaded and processed",
                    "description": "SVG upload may be vulnerable to XXE",
                }],
            },
        }),
    )

    await agent.run()

    assert agent.findings
    assert all(kw["evidence"]["proof_type"] == "heuristic" for args, kw in agent.findings)


# --- test_mime_type_bypass: "code_execution" and "upload" both re-fetch the
# stored file via a follow-up GET (upload_url present); "accepted" never
# re-fetches, it only trusts the initial POST's status code. -----------------

async def test_mime_bypass_code_execution_is_validated(monkeypatch):
    agent = _agent("test_mime_type_bypass")
    monkeypatch.setattr(
        "multi_agent_system.agents.file_upload_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "vulnerable": True,
                "findings": [{
                    "type": "mime_bypass_code_execution",
                    "filename": "malicious.php.jpg",
                    "technique": "double_extension",
                    "upload_url": "https://example.com/uploads/malicious.php.jpg",
                    "severity": "critical",
                    "evidence": "uid=0(root) gid=0(root)",
                    "description": "Code executed via double_extension bypass",
                }],
            },
        }),
    )

    await agent.run()

    assert any(
        kw["evidence"]["proof_type"] == "validated_mime_bypass"
        for args, kw in agent.findings if args[0] == "WSTG-BUSL-08"
    )


async def test_mime_bypass_accepted_without_verification_is_heuristic(monkeypatch):
    agent = _agent("test_mime_type_bypass")
    monkeypatch.setattr(
        "multi_agent_system.agents.file_upload_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "vulnerable": True,
                "findings": [{
                    "type": "mime_bypass_accepted",
                    "filename": "malicious.jpg",
                    "technique": "content_type_mismatch",
                    "severity": "high",
                    "evidence": "Upload accepted with HTTP 200",
                    "description": "MIME bypass accepted using content_type_mismatch",
                }],
            },
        }),
    )

    await agent.run()

    assert agent.findings
    assert all(kw["evidence"]["proof_type"] == "heuristic" for args, kw in agent.findings)


# --- test_upload_size_limit: both finding types only check the initial
# upload POST's own status code, never a confirming second request. ----------

async def test_upload_size_limit_is_always_heuristic(monkeypatch):
    agent = _agent("test_upload_size_limit")
    monkeypatch.setattr(
        "multi_agent_system.agents.file_upload_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "vulnerable": True,
                "findings": [{
                    "type": "no_size_limit",
                    "file_size": "150KB",
                    "severity": "medium",
                    "evidence": "Uploaded >100KB PDF successfully (HTTP 204)",
                    "description": "Server accepts a file larger than the documented client-side upload size limit",
                }],
            },
        }),
    )

    await agent.run()

    assert agent.findings
    assert all(kw["evidence"]["proof_type"] == "heuristic" for args, kw in agent.findings)


# --- Regression: the already-clean 6th site (test_path_traversal_download)
# never self-stamped a proof_type and must stay that way. --------------------

async def test_path_traversal_download_has_no_self_certified_proof_type(monkeypatch):
    agent = _agent("test_path_traversal_download")
    monkeypatch.setattr(
        "multi_agent_system.agents.file_upload_agent.MCPClient",
        lambda: _fake_mcp({
            "status": "success",
            "data": {
                "vulnerable": True,
                "findings": [{
                    "type": "path_traversal",
                    "url": "https://example.com/?file=../../etc/passwd",
                    "severity": "critical",
                    "description": "Path traversal: read etc/passwd",
                }],
            },
        }),
    )

    await agent.run()

    assert agent.findings
    assert all("proof_type" not in kw["evidence"] for args, kw in agent.findings)
