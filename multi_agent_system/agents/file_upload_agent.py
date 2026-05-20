from __future__ import annotations

from .base_agent import BaseAgent, AgentRegistry
from typing import Any, ClassVar, Dict, List
from urllib.parse import urljoin
from ..utils.mcp_client import MCPClient
from ..core.endpoint_inventory import read_tag


COMMON_UPLOAD_PATHS = (
    "/file-upload",
    "/upload",
    "/uploads",
    "/api/upload",
    "/api/uploads",
    "/rest/upload",
)


def _absolute_target_url(target: str, candidate: str) -> str:
    if candidate.startswith(("http://", "https://")):
        return candidate
    return urljoin(target.rstrip("/") + "/", candidate.lstrip("/"))


def build_upload_endpoint_candidates(target: str, inventory: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build deterministic upload candidates even when crawler tagging misses forms."""
    candidates: List[str] = []

    upload_eps = read_tag(inventory, "file_upload")
    candidates.extend(ep.get("url") or ep.get("path") for ep in upload_eps if ep.get("url") or ep.get("path"))
    candidates.extend(COMMON_UPLOAD_PATHS)

    for endpoint in inventory.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        value = endpoint.get("url") or endpoint.get("path") or ""
        if any(kw in value.lower() for kw in ("upload", "file", "image", "photo", "avatar", "attachment")):
            candidates.append(value)

    seen: set[str] = set()
    normalized: List[Dict[str, str]] = []
    for candidate in candidates:
        if not candidate:
            continue
        url = _absolute_target_url(target, str(candidate))
        if url in seen:
            continue
        seen.add(url)
        normalized.append({"url": url})

    return normalized


@AgentRegistry.register("FileUploadAgent")
class FileUploadAgent(BaseAgent):
    system_prompt: ClassVar[str] = """
You are FileUploadAgent, OWASP WSTG-BUSL-08/09 expert specializing in file upload security testing.

🎯 PRIMARY MISSION: Test file upload mechanisms using MCP tools to identify unrestricted upload, path traversal, XXE, MIME bypass, and RCE vulnerabilities.

🧠 ADAPTIVE STRATEGY:
1. Read discovered endpoints from shared_context
2. Identify file upload endpoints:
   - Explicit upload forms → Profile pictures, document uploads
   - API upload endpoints → /api/upload, /file-upload
   - Hidden upload parameters → Discovered via reconnaissance
3. Analyze upload restrictions:
   - Extension filtering → Test bypass techniques
   - MIME type validation → Test Content-Type manipulation
   - File size limits → Test with various sizes
   - Content validation → Test polyglot files
4. Select appropriate testing tools:
   - discover_upload_endpoints → Find upload forms
   - test_unrestricted_upload → Test file type restrictions
   - test_xxe_via_svg → Test XML External Entity
   - test_path_traversal_upload → Test filename manipulation
   - test_rce_upload → Test code execution via upload
5. Execute tools to test 20+ bypass techniques (tools handle this)
6. Test both authenticated and unauthenticated uploads
7. Report findings with exploitation steps

⚠️ EXECUTION GUIDELINES:
- Execute all file upload testing tools
- Test 20+ bypass techniques (extension, MIME, magic bytes, path traversal)
- Test EVERY discovered upload endpoint
- Test XXE via SVG/XML uploads
- Test RCE payloads (PHP, JSP, ASP based on tech stack)
- Continue comprehensive testing across all upload vectors
"""
    
    async def run(self) -> None:
        client = MCPClient()
        
        # 🔑 AUTHENTICATED SESSION SUPPORT (via Orchestrator auto-login)
        auth_data = self.get_auth_session()
        if auth_data:
            self.log("info", f"✅ Using authenticated session: {auth_data.get('username')}")
        else:
            self.log("warning", "⚠ No authenticated session available")
        
        target = self._get_target()
        if not target:
            self.log("error", "Target missing; aborting FileUploadAgent")
            return
        
        # Log tool execution plan
        self.log_tool_execution_plan()

        inventory = self.shared_context.get("endpoint_inventory", {})
        upload_endpoints = build_upload_endpoint_candidates(target, inventory)
        if not upload_endpoints:
            upload_endpoints = [{"url": target}]
            self.log("info", "no upload candidates found — using base target as last resort")
        else:
            self.log("info", f"Prepared {len(upload_endpoints)} upload endpoint candidate(s)")
        
        # Step 2: Test each discovered endpoint
        for endpoint in upload_endpoints[:2]:  # Test up to 2 endpoints (5 caused cascading timeout issues)
            upload_url = endpoint.get("url")
            self.log("info", f"🔥 Testing upload endpoint: {upload_url}")
            
            # Test 2.1: Unrestricted file upload
            if self.should_run_tool("test_unrestricted_upload"):
                try:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="file-upload-testing",
                            tool="test_unrestricted_upload",
                            args={"url": upload_url, "file_param": "file"},
                            auth_session=auth_data
                        ),
                        timeout=60
                    )
                    
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data") or res
                        if data.get("vulnerable"):
                            findings = data.get("findings", [])
                            for finding in findings:
                                self.add_finding(
                                    "WSTG-BUSL-08",
                                    f"Unrestricted file upload: {finding.get('filename', 'unknown')}",
                                    severity="critical",
                                    evidence={
                                        "url": upload_url,
                                        "filename": finding.get('filename', 'unknown'),
                                        "extension": finding.get('extension', ''),
                                        "proof_type": "validated_file_upload",
                                        "description": finding.get('description', ''),
                                        "recommendation": finding.get('recommendation', 'Review upload security controls')
                                    }
                                )
                            self.log("info", f"✓ Found {len(findings)} unrestricted upload vulnerabilities")
                except Exception as e:
                    self.log("warning", f"Unrestricted upload test failed: {e}")
            
            # Test 2.2: Path traversal via filename
            if self.should_run_tool("test_path_traversal_upload"):
                try:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="file-upload-testing",
                            tool="test_path_traversal_upload",
                            args={"url": upload_url, "file_param": "file"},
                            auth_session=auth_data
                        ),
                        timeout=60
                    )
                    
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data") or res
                        if data.get("vulnerable"):
                            findings = data.get("findings", [])
                            for finding in findings:
                                self.add_finding(
                                    "WSTG-BUSL-08",
                                    f"Path traversal in upload: {finding.get('filename', 'unknown')}",
                                    severity="high",
                                    evidence={
                                        "url": upload_url,
                                        "filename": finding.get('filename', 'unknown'),
                                        "proof_type": "validated_file_upload_path_traversal",
                                        "description": finding.get('description', ''),
                                        "recommendation": finding.get('recommendation', 'Review upload security controls')
                                    }
                                )
                            self.log("info", f"✓ Found {len(findings)} path traversal upload vulnerabilities")
                except Exception as e:
                    self.log("warning", f"Path traversal upload test failed: {e}")
            
            # Test 2.3: XXE via SVG upload
            if self.should_run_tool("test_xxe_via_svg"):
                try:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="file-upload-testing",
                            tool="test_xxe_via_svg",
                            args={"url": upload_url, "file_param": "file"},
                            auth_session=auth_data
                        ),
                        timeout=60
                    )
                    
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data") or res
                        if data.get("vulnerable"):
                            findings = data.get("findings", [])
                            for finding in findings:
                                self.add_finding(
                                    "WSTG-INPV-07",
                                    f"XXE via SVG upload: {finding.get('filename', 'unknown')}",
                                    severity="critical",
                                    evidence={
                                        "url": upload_url,
                                        "filename": finding.get('filename', 'unknown'),
                                        "proof_type": "validated_xxe_upload",
                                        "description": finding.get('description', ''),
                                        "evidence": finding['evidence'][:200],
                                        "recommendation": finding.get('recommendation', 'Review upload security controls')
                                    }
                                )
                            self.log("info", f"✓ Found {len(findings)} XXE via SVG vulnerabilities")
                except Exception as e:
                    self.log("warning", f"XXE via SVG test failed: {e}")
            
            # Test 2.4: MIME type bypass
            if self.should_run_tool("test_mime_type_bypass"):
                try:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="file-upload-testing",
                            tool="test_mime_type_bypass",
                            args={"url": upload_url, "file_param": "file"},
                            auth_session=auth_data
                        ),
                        timeout=60
                    )
                    
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data") or res
                        if data.get("vulnerable"):
                            findings = data.get("findings", [])
                            for finding in findings:
                                self.add_finding(
                                    "WSTG-BUSL-08",
                                    f"MIME type bypass: {finding.get('filename', 'unknown')}",
                                    severity="high",
                                    evidence={
                                        "url": upload_url,
                                        "filename": finding.get('filename', 'unknown'),
                                        "mime_type": finding.get('mime_type', 'unknown'),
                                        "proof_type": "validated_mime_bypass",
                                        "description": finding.get('description', ''),
                                        "recommendation": finding.get('recommendation', 'Review upload security controls')
                                    }
                                )
                            self.log("info", f"✓ Found {len(findings)} MIME type bypass vulnerabilities")
                except Exception as e:
                    self.log("warning", f"MIME type bypass test failed: {e}")
        
        # Test upload size limits
        if self.should_run_tool("test_upload_size_limit"):
            for endpoint in upload_endpoints[:3]:
                upload_url = endpoint.get("url")
                try:
                    res = await self.run_tool_with_timeout(
                        client.call_tool(
                            server="file-upload-testing",
                            tool="test_upload_size_limit",
                            args={"url": upload_url, "file_param": "file"},
                            auth_session=auth_data
                        ),
                        timeout=90
                    )
                    if isinstance(res, dict) and res.get("status") == "success":
                        data = res.get("data") or res
                        if data.get("vulnerable"):
                            findings = data.get("findings", [])
                            for finding in findings:
                                self.add_finding(
                                    "WSTG-BUSL-08",
                                    f"Upload size limit bypass: {finding.get('file_size', 'unknown')}",
                                    severity=finding.get("severity", "medium"),
                                    evidence={
                                        "url": upload_url,
                                        "proof_type": "validated_upload_size_bypass",
                                        "description": finding.get("description", ""),
                                    }
                                )
                            self.log("info", f"Found {len(findings)} size limit issues")
                except Exception as e:
                    self.log("warning", f"Upload size limit test failed: {e}")

        # Test path traversal in file downloads
        if self.should_run_tool("test_path_traversal_download"):
            try:
                res = await self.run_tool_with_timeout(
                    client.call_tool(
                        server="file-upload-testing",
                        tool="test_path_traversal_download",
                        args={"url": target},
                        auth_session=auth_data
                    ),
                    timeout=120
                )
                if isinstance(res, dict) and res.get("status") == "success":
                    data = res.get("data") or res
                    if data.get("vulnerable"):
                        findings = data.get("findings", [])
                        for finding in findings:
                            self.add_finding(
                                "WSTG-BUSL-09",
                                f"Path traversal download: {finding.get('type', 'unknown')}",
                                severity=finding.get("severity", "high"),
                                evidence={"url": finding.get("url", ""), "description": finding.get("description", "")}
                            )
                        self.log("info", f"Found {len(findings)} path traversal download vulnerabilities")
            except Exception as e:
                self.log("warning", f"Path traversal download test failed: {e}")

        self.log("info", "File upload testing complete")
    
    def _get_target(self) -> str | None:
        from ..core.db import get_db
        from ..models.models import Job
        with get_db() as db:
            job = db.query(Job).get(self.job_id)
            return job.target if job else None
    
    def _get_tool_info(self) -> dict:
        return {
            "test_unrestricted_upload":    {"priority": "CRITICAL", "description": "Unrestricted file upload (WSTG-BUSL-08)"},
            "test_upload_size_limit":      {"priority": "HIGH",     "description": "Upload size limit bypass (WSTG-BUSL-08)"},
            "test_mime_type_bypass":       {"priority": "HIGH",     "description": "MIME type bypass (WSTG-BUSL-08)"},
            "test_xxe_via_svg":            {"priority": "HIGH",     "description": "XXE via SVG upload (WSTG-INPV-07)"},
            "test_path_traversal_upload":  {"priority": "HIGH",     "description": "Path traversal via upload"},
        }

    def _get_available_tools(self) -> list[str]:
        return [
            'test_unrestricted_upload',
            'test_path_traversal_upload',
            'test_xxe_via_svg',
            'test_mime_type_bypass',
            'test_upload_size_limit',
            'test_path_traversal_download',
        ]

    def _get_tool_server_map(self) -> Dict[str, str]:
        return {tool: "file-upload-testing" for tool in self._get_available_tools()}
