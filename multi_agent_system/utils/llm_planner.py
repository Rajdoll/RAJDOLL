"""
LLM-Driven Agent Planning System
=================================

Poin Kebaruan Penelitian:
LLM menggunakan MCP tools untuk merencanakan testing strategy secara dinamis
berdasarkan OWASP WSTG 4.2 dan hasil reconnaissance.

Architecture:
1. LLM menerima hasil reconnaissance
2. LLM memilih MCP tools yang relevan untuk testing
3. LLM membuat execution plan (agent + tool combinations)
4. Agents execute plan dengan MCP tools yang sudah dipilih LLM

Supported LLM Providers:
- OpenAI (GPT-4, GPT-5)
- Anthropic (Claude 3.5 Sonnet)
- Google Gemini (1.5 Flash/Pro)
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

import httpx

from ..core.config import settings
from ..utils.toon_encoder import encode_toon_table, encode_mapping, join_toon_sections


class LLMPlanner:
    """
    LLM-based test planning system yang menggunakan MCP tool selection
    untuk membuat dynamic testing strategy sesuai OWASP WSTG 4.2
    
    Supports multiple LLM providers: OpenAI (GPT), Anthropic (Claude), and Gemini
    """

    class NotConfiguredError(RuntimeError):
        pass

    def __init__(self):
        if not settings.llm_api_key:
            raise LLMPlanner.NotConfiguredError("LLM_API_KEY is not set")
        
        self.provider = settings.llm_provider.lower()
        self.model = settings.llm_model
        self._use_responses_api = False
        
        if self.provider == "openai":
            try:
                from openai import OpenAI
            except Exception as e:
                raise RuntimeError("openai package not installed") from e
            
            # Support custom base_url for LM Studio/local LLMs with extended timeout for planning
            # For 8B model with Q4 quantization on limited GPU (RTX 3050), 20 minutes is realistic
            self.base_url = settings.llm_base_url  # Store for later use
            client_kwargs = {"api_key": settings.llm_api_key, "timeout": 1200.0}  # 20 minutes for strategic planning
            if settings.llm_base_url:
                client_kwargs["base_url"] = settings.llm_base_url
                print(f"[LLMPlanner] Using custom endpoint: {settings.llm_base_url}")
            
            print(f"[LLMPlanner] Initializing OpenAI client with 20-minute timeout for planning")
            self._client = OpenAI(**client_kwargs)
            print(f"[LLMPlanner] OpenAI client initialized successfully")
            self._use_responses_api = self._model_requires_responses_endpoint(self.model)
        elif self.provider == "gemini":
            self._gemini_api_key = settings.llm_api_key
            if not self._gemini_api_key:
                raise LLMPlanner.NotConfiguredError("LLM_API_KEY or GOOGLE_API_KEY must be set for Gemini")
            if not self.model:
                self.model = "gemini-1.5-flash"
            self._gemini_endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
            
        elif self.provider == "anthropic":
            try:
                from anthropic import Anthropic
            except Exception as e:
                raise RuntimeError("anthropic package not installed") from e
            
            self._client = Anthropic(
                api_key=settings.llm_api_key,
                base_url=settings.llm_base_url
            )
            self.model = settings.llm_model or "claude-3-5-sonnet-20241022"
            
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

    def plan_testing_strategy(self, recon_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        LLM menganalisis hasil reconnaissance dan membuat testing plan
        dengan memilih MCP tools yang sesuai untuk setiap kategori OWASP WSTG

        Args:
            recon_results: Hasil dari ReconnaissanceAgent

        Returns:
            {
                "strategy": "description",
                "owasp_categories": [
                    {
                        "category": "WSTG-INPV",
                        "priority": "high",
                        "agent": "InputValidationAgent",
                        "mcp_tools": [
                            {"tool": "test_xss_reflected", "reason": "..."},
                            {"tool": "test_sqli", "reason": "..."}
                        ]
                    }
                ],
                "execution_plan": {
                    "sequence": [...],
                    "parallel": [...]
                }
            }
        """

        # Valid agent names (imported from orchestrator)
        from ..orchestrator import AGENT_TO_OWASP_MAP
        valid_agents = {agent: category for agent, category in AGENT_TO_OWASP_MAP.items()}

        # MCP Tools catalog untuk LLM
        mcp_tools_catalog = self._get_mcp_tools_catalog()

        # Ultra-compressed prompt for small context models
        tools_summary = self._get_compact_tools_summary()
        agent_list = ", ".join(valid_agents.keys())
        
        # Simplified prompt - reduce context for faster response
        tech = recon_results.get("tech_stack", {})
        endpoints = recon_results.get("entry_points", [])
        tech_str = ", ".join(list(tech.keys())[:5]) if tech else "unknown"
        
        prompt = f"""Plan security test. Tech: {tech_str}, Endpoints: {len(endpoints)}

Valid Agents (EXACT NAMES REQUIRED): {agent_list}

Return JSON:
{{
  "strategy": "test all",
  "execution_plan": {{"sequence": ["ReconnaissanceAgent", "InputValidationAgent", "AuthenticationAgent", "SessionManagementAgent", "AuthorizationAgent", "IdentityManagementAgent", "ConfigDeploymentAgent", "ErrorHandlingAgent", "WeakCryptographyAgent", "BusinessLogicAgent", "ClientSideAgent", "APITestingAgent", "FileUploadAgent"]}}
}}

CRITICAL: Use EXACT agent names from the Valid Agents list above. Output valid JSON only."""

        try:
            # Call LLM based on provider
            if self.provider == "openai":
                messages = [
                    {
                        "role": "system",
                        "content": "You are a security testing expert. Return ONLY valid JSON. No markdown, no code fences, no backticks, no prose.",
                    },
                    {"role": "user", "content": prompt},
                ]
                temperature = None if self._use_responses_api or self.model.startswith("o1") else 0.2
                raw_text = self._invoke_openai(
                    messages,
                    max_tokens=1000,  # Reduced drastically for faster response
                    response_format={"type": "json_object"},
                    temperature=temperature,
                )
                print(f"[LLMPlanner] RAW response received (length {len(raw_text)} chars)")
                print(f"[LLMPlanner] First 500 chars: {raw_text[:500]}")
                
                # Strip <think> tags before parsing (critical for Qwen models)
                text = self._strip_thinking_tags(raw_text)
                print(f"[LLMPlanner] After strip_thinking: {len(text)} chars (removed {len(raw_text) - len(text)} chars)")
                
                if len(text) == 0:
                    print("[LLMPlanner] ERROR: All content was thinking tags! Response: " + raw_text[:1000])
                    raise ValueError("LLM response contained only <think> tags, no JSON")
                
                # Show snippet for debugging
                _snippet = (str(text).replace("\n", " ")[:400])
                print(f"[LLMPlanner] JSON content preview: {_snippet}")
                
                # Attempt JSON parsing with timeout protection
                print("[LLMPlanner] Parsing JSON...")

            elif self.provider == "gemini":
                messages = [
                    {
                        "role": "system",
                        "content": "You are a security testing expert. Return ONLY valid JSON. No markdown, no prose.",
                    },
                    {"role": "user", "content": prompt},
                ]
                text = self._invoke_gemini(messages, max_tokens=8000, temperature=0.2)
                # Strip <think> tags before parsing
                text = self._strip_thinking_tags(text)
                _snippet = (str(text).replace("\n", " ")[:400])
                print(f"[LLMPlanner] Raw plan response (first 400): {_snippet}")
                print(f"[LLMPlanner] Full response length: {len(text)} chars")
                if len(text) > 400:
                    print(f"[LLMPlanner] Response continues... (last 200 chars): {str(text)[-200:]}")

            elif self.provider == "anthropic":
                msg = self._client.messages.create(
                    model=self.model,
                    max_tokens=8000,
                    temperature=0.2,
                    system="You are a security testing expert. Return ONLY valid JSON. No explanations.",
                    messages=[{"role": "user", "content": prompt}],
                )
                text = (msg.content[0].text if isinstance(msg.content, list) else str(msg.content)) or ""

            # Parse JSON (hardened)
            try:
                plan = self._parse_json_safe(text)
            except Exception as pe:
                print(f"[LLMPlanner] Plan JSON parse error: {pe}")
                raise
            return plan

        except Exception as e:
            # Fallback to static plan
            print(f"[LLMPlanner] Error calling {self.provider} API: {e}")
            print("[LLMPlanner] Using fallback plan")
            return self._get_fallback_plan(recon_results)

    def select_tools_for_agent(self, agent_name: str, context: Dict[str, Any], system_prompt: str | None = None) -> List[Dict[str, Any]]:
        """
        LLM memilih MCP tools spesifik untuk agent berdasarkan context
        
        Args:
            agent_name: Nama agent (e.g., "InputValidationAgent")
            context: Context dari shared context dan findings sejauh ini
            
        Returns:
            [
                {
                    "tool": "test_xss_reflected",
                    "arguments": {"target_url": "..."},
                    "reason": "Reflected parameters detected in recon"
                }
            ]
        """
        
        tools_for_agent = self._get_agent_tools(agent_name)
        
        # Enhanced comprehensive tool selection prompt
        ctx_compressed = self._compress_context_for_tools(context)
        tools_list = ", ".join([t.get("tool", "") for t in tools_for_agent[:20]])  # Show more tools
        
        # Extract discovered endpoints from context for specific test case generation
        endpoints = context.get("entry_points", [])
        endpoints_str = ", ".join([str(ep.get("url", "")) for ep in endpoints[:10]]) if endpoints else "No endpoints yet"
        
        prompt = f"""{agent_name} COMPREHENSIVE TEST CASE GENERATOR

CONTEXT: {ctx_compressed}

DISCOVERED ENDPOINTS: {endpoints_str}

AVAILABLE TOOLS: {tools_list}

CRITICAL REQUIREMENT: Generate COMPREHENSIVE test cases with SPECIFIC URLs, parameters, and MULTIPLE payloads for EACH tool.

For SQL Injection tools: Provide specific endpoint URLs with query parameters + SQL injection payloads (UNION, blind, time-based, error-based)
For XSS tools: Provide form endpoints + multiple XSS payloads (reflected, stored, DOM-based)
For IDOR tools: Provide resource endpoints with ID parameters + sequential/predictable ID test cases
For Authentication tools: Provide login/register endpoints + credential lists, brute force patterns

JSON OUTPUT FORMAT:
[
  {{
    "tool": "test_sqli",
    "arguments": {{
      "url": "http://target:3000/rest/products/search?q=test",
      "parameter": "q",
      "payloads": ["' OR '1'='1--", "1' UNION SELECT NULL--", "1' AND SLEEP(5)--"],
      "injection_types": ["union", "blind", "time-based"]
    }},
    "priority": "CRITICAL",
    "reason": "Search endpoint accepts user input, high SQL injection risk"
  }},
  {{
    "tool": "test_xss_reflected",
    "arguments": {{
      "url": "http://target:3000/search",
      "parameters": ["q", "query"],
      "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"]
    }},
    "priority": "HIGH",
    "reason": "Multiple form inputs that reflect user data"
  }}
]

IMPORTANT:
- Generate 10-20 comprehensive test cases with ACTUAL discovered endpoints
- Use specific URLs from DISCOVERED ENDPOINTS above
- Include MULTIPLE payloads per vulnerability type (not just 1)
- Each test case must have detailed arguments dict
- Prioritize high-impact vulnerabilities (SQLi, XSS, IDOR, Auth Bypass)

Select ALL relevant tools (10-15 tools minimum) for comprehensive OWASP WSTG coverage."""

        try:
            if self.provider == "openai":
                messages = [
                    {
                        "role": "system",
                        "content": (system_prompt or "You are an OWASP WSTG expert.") + " Return ONLY JSON array. No markdown, no code fences, no backticks, no prose.",
                    },
                    {"role": "user", "content": prompt},
                ]
                temperature = None if self._use_responses_api or self.model.startswith("o1") else 0.2
                # Increase max_tokens for comprehensive test cases
                text = self._invoke_openai(messages, max_tokens=4000, response_format={"type": "json_object"}, temperature=temperature)
                _snippet2 = (str(text).replace("\n", " ")[:400])
                print(f"[LLMPlanner] Raw tool-select response for {agent_name} (first 400): {_snippet2}")
            elif self.provider == "gemini":
                messages = [
                    {
                        "role": "system",
                        "content": (system_prompt or "You are an OWASP WSTG expert.") + " Return ONLY JSON array. No markdown, no prose.",
                    },
                    {"role": "user", "content": prompt},
                ]
                text = self._invoke_gemini(messages, max_tokens=1000, temperature=0.2)
                _snippet2 = (str(text).replace("\n", " ")[:400])
                print(f"[LLMPlanner] Raw tool-select response for {agent_name} (first 400): {_snippet2}")
            else:
                msg = self._client.messages.create(
                    model=self.model or "claude-3-5-sonnet-20241022",
                    max_tokens=1000,
                    temperature=0.2,
                    system=(system_prompt or "You are an OWASP WSTG expert.") + " Return ONLY JSON array. No explanations.",
                    messages=[{"role": "user", "content": prompt}],
                )
                text = (msg.content[0].text if isinstance(msg.content, list) else str(msg.content)) or ""

            try:
                tools = self._parse_json_safe(text, expect_array=True)
            except Exception as pe:
                print(f"[LLMPlanner] Tool JSON parse error for {agent_name}: {pe}")
                raise
            return tools

        except Exception:
            # Return default tools for agent
            return self._get_default_tools_for_agent(agent_name)

    def _strip_thinking_tags(self, text: str) -> str:
        """Remove <think>...</think> tags and similar reasoning artifacts that some models add"""
        import re
        # Remove <think>...</think> blocks (Qwen models)
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL | re.IGNORECASE)
        # Remove <reasoning>...</reasoning> blocks
        text = re.sub(r'<reasoning>.*?</reasoning>', '', text, flags=re.DOTALL | re.IGNORECASE)
        # Remove <thought>...</thought> blocks
        text = re.sub(r'<thought>.*?</thought>', '', text, flags=re.DOTALL | re.IGNORECASE)
        # Remove opening tags without closing (edge case)
        text = re.sub(r'<think>.*', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<reasoning>.*', '', text, flags=re.DOTALL | re.IGNORECASE)
        return text.strip()
    
    def _strip_code_fences(self, text: str) -> str:
        """Remove leading/trailing markdown code fences like ```json ... ``` if present."""
        t = text.strip()
        if t.startswith("```"):
            # Remove the first line (``` or ```json)
            parts = t.splitlines()
            # drop first fence line
            parts = parts[1:]
            # drop trailing fence line if exists
            if parts and parts[-1].strip().startswith("```"):
                parts = parts[:-1]
            return "\n".join(parts).strip()
        return t

    def _extract_first_json_block(self, text: str) -> str | None:
        """Attempt to extract the first top-level JSON object or array from free-form text.

        Scans for balanced braces/brackets and returns the substring if a valid block is found.
        """
        s = text
        # Try object blocks
        for opener, closer in [("{", "}"), ("[", "]")]:
            start_indices = [m.start() for m in re.finditer(re.escape(opener), s)]
            for start in start_indices:
                depth = 0
                for i in range(start, len(s)):
                    ch = s[i]
                    if ch == opener:
                        depth += 1
                    elif ch == closer:
                        depth -= 1
                        if depth == 0:
                            candidate = s[start : i + 1]
                            try:
                                # verify it's valid JSON
                                json.loads(candidate)
                                return candidate
                            except Exception:
                                pass
                # if no closing found, continue with next start
        return None

    def _compress_recon_for_llm(self, recon_results: Dict[str, Any]) -> str:
        """Compress reconnaissance data to fit within context limits (target: <3000 tokens)"""
        compressed = []
        
        # Tech stack (most important - keep full)
        tech_stack = recon_results.get("tech_stack") or {}
        if tech_stack:
            compressed.append(f"TECH STACK: {json.dumps(tech_stack, indent=None)}")
        
        # Entry points (limit to 15 most important)
        entry_points = recon_results.get("entry_points") or []
        if entry_points and isinstance(entry_points, list):
            # Prioritize POST endpoints and those with parameters
            sorted_eps = sorted(
                entry_points[:50] if len(entry_points) > 50 else entry_points, 
                key=lambda x: (
                    x.get("method") == "POST", 
                    len(x.get("parameters", [])) if isinstance(x.get("parameters"), list) else 0,
                    bool(x.get("form_fields"))
                ),
                reverse=True
            )
            top_eps = sorted_eps[:15] if len(sorted_eps) > 15 else sorted_eps
            ep_summary = [
                f"{ep.get('method', 'GET')} {ep.get('endpoint', '/')} "
                f"(params: {len(ep.get('parameters', []))}, forms: {len(ep.get('form_fields', []))})"
                for ep in top_eps
            ]
            compressed.append(f"KEY ENDPOINTS ({len(entry_points)} total, showing top 15):\n" + "\n".join(ep_summary))
        
        # Findings (summarize by severity)
        findings = recon_results.get("findings") or []
        if findings:
            by_severity = {}
            for f in findings:
                sev = f.get("severity", "info")
                by_severity.setdefault(sev, []).append(f.get("title", "Unknown"))
            summary = []
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in by_severity:
                    summary.append(f"{sev.upper()}: {len(by_severity[sev])} issues - {', '.join(by_severity[sev][:5])}")
            compressed.append(f"FINDINGS:\n" + "\n".join(summary))
        
        # Security headers
        sec_headers = recon_results.get("security_headers") or {}
        if sec_headers and isinstance(sec_headers, dict):
            missing = [k for k, v in sec_headers.items() if isinstance(v, dict) and not v.get("present")]
            if missing:
                top_missing = missing[:10] if len(missing) > 10 else missing
                compressed.append(f"MISSING SECURITY HEADERS: {', '.join(top_missing)}")
        
        return "\n\n".join(compressed)

    def _build_recon_toon(self, recon_results: Dict[str, Any]) -> str:
        sections: List[str] = []
        entry_points = recon_results.get("entry_points") or []
        if isinstance(entry_points, list) and entry_points:
            sections.append(
                encode_toon_table(
                    "entry_points",
                    entry_points,
                    max_rows=40,
                    max_fields=6,
                )
            )

        findings = recon_results.get("findings") or []
        if isinstance(findings, list) and findings:
            sections.append(
                encode_toon_table(
                    "recon_findings",
                    findings,
                    max_rows=30,
                    max_fields=6,
                )
            )

        tech_stack = recon_results.get("tech_stack") or {}
        if isinstance(tech_stack, dict) and tech_stack:
            sections.append(encode_mapping("tech_stack", tech_stack, max_items=20))

        return join_toon_sections(sections)

    def _parse_json_safe(self, text: str, expect_array: bool = False) -> Any:
        """Robust JSON parsing for LLM outputs.

        Strategies:
        1) Direct json.loads
        2) Strip code fences and retry
        3) Extract first balanced JSON block (object/array) and parse
        4) If expect_array=True and object parsed with key 'items' or 'tools', unwrap
        Raises ValueError if all strategies fail.
        """
        if not text or not isinstance(text, str):
            raise ValueError("Empty LLM response")

        candidates: List[str] = []
        t = text.strip()
        candidates.append(t)
        stripped = self._strip_code_fences(t)
        if stripped != t:
            candidates.append(stripped)
        block = self._extract_first_json_block(t)
        if block:
            candidates.append(block)
        if stripped and stripped != t:
            block2 = self._extract_first_json_block(stripped)
            if block2:
                candidates.append(block2)

        last_err: Exception | None = None
        for c in candidates:
            try:
                data = json.loads(c)
                # optional unwrapping for array expectations
                if expect_array and isinstance(data, dict):
                    for key in ("items", "tools", "data", "list"):
                        if key in data and isinstance(data[key], list):
                            return data[key]
                if expect_array and not isinstance(data, list):
                    # If a single object is returned but array expected, wrap it
                    return [data]
                return data
            except Exception as e:
                last_err = e
                continue
        # If still failing, raise concise error with snippet
        snippet = (text[:200] + ("…" if len(text) > 200 else "")).replace("\n", " ")
        raise ValueError(f"Failed to parse LLM JSON output. Last error: {last_err}; snippet: {snippet}")

    def _compress_context_for_tools(self, context: Dict[str, Any]) -> str:
        """Provide detailed context with ACTUAL endpoints for comprehensive test case generation"""
        parts = []
        
        # Technology stack
        if "tech_stack" in context:
            tech = list(context["tech_stack"].keys())[:5]
            parts.append(f"Tech: {', '.join(tech)}")
        
        # CRITICAL: Include ACTUAL discovered endpoint URLs, not just count
        if "entry_points" in context:
            entry_points = context["entry_points"]
            if isinstance(entry_points, list) and entry_points:
                ep_count = len(entry_points)
                parts.append(f"{ep_count} endpoints:")
                # Include first 10 actual URLs for LLM to generate specific test cases
                endpoint_urls = []
                for ep in entry_points[:10]:
                    if isinstance(ep, dict):
                        url = ep.get("url") or ep.get("endpoint", "")
                    else:
                        url = str(ep)
                    if url:
                        endpoint_urls.append(url)
                if endpoint_urls:
                    parts.append(f"URLs: {', '.join(endpoint_urls)}")
        
        # Include discovered endpoints from reconnaissance
        if "discovered_endpoints" in context:
            disc_eps = context["discovered_endpoints"]
            if disc_eps.get("endpoints"):
                urls = [ep.get("url", "") for ep in disc_eps["endpoints"][:10] if ep.get("url")]
                if urls:
                    parts.append(f"Discovered: {', '.join(urls[:5])}")
        
        return " | ".join(parts) if parts else "minimal context"
    
    def _get_compact_tools_summary(self) -> str:
        """One-line tools summary for compressed prompts"""
        catalog = self._get_mcp_tools_catalog()
        return "; ".join([f"{cat}: {', '.join([t['tool'][:20] for t in tools[:4]])}..." for cat, tools in list(catalog.items())[:8]])

    def _get_mcp_tools_catalog(self) -> Dict[str, List[Dict[str, str]]]:
        """Compact MCP tools catalog"""
        return {
            "WSTG-INFO": [{"tool": "run_whois_lookup"}, {"tool": "run_dig_lookup"}, {"tool": "run_comprehensive_scan"}, {"tool": "advanced_technology_fingerprinting"}, {"tool": "find_entry_points"}],
            "WSTG-CONF": [{"tool": "check_meta_files"}, {"tool": "test_http_methods_and_headers"}, {"tool": "find_sensitive_files_and_dirs"}, {"tool": "test_network_infrastructure"}],
            "WSTG-ATHN": [{"tool": "test_tls_credentials"}, {"tool": "test_cache_headers"}, {"tool": "test_default_credentials"}, {"tool": "test_auth_bypass"}, {"tool": "test_password_policy"}],
            "WSTG-AUTHZ": [{"tool": "test_vertical_privilege_escalation"}, {"tool": "test_idor_vulnerability"}, {"tool": "test_http_method_tampering"}],
            "WSTG-SESS": [{"tool": "analyze_cookies"}, {"tool": "test_session_fixation"}, {"tool": "test_logout_functionality"}, {"tool": "test_session_timeout"}, {"tool": "test_cors_misconfiguration"}, {"tool": "test_exposed_session_vars"}],
            "WSTG-INPV": [{"tool": "find_reflected_params"}, {"tool": "test_xss_reflected"}, {"tool": "test_sqli"}, {"tool": "test_lfi"}, {"tool": "test_http_smuggling"}],
            "WSTG-ERRH": [{"tool": "check_generic_error_pages"}, {"tool": "probe_for_error_leaks"}],
            "WSTG-CRYP": [{"tool": "test_tls_configuration"}, {"tool": "test_cleartext_info"}, {"tool": "analyze_token_randomness"}],
            "WSTG-CLNT": [{"tool": "security_headers_analysis"}],
            "WSTG-IDNT": [{"tool": "generate_test_usernames"}, {"tool": "test_account_enumeration"}],
        }
    
    def _get_compact_tools_summary(self) -> str:
        """One-line tools summary for compressed prompts"""
        catalog = self._get_mcp_tools_catalog()
        return "; ".join([f"{cat}: {', '.join([t['tool'][:20] for t in tools[:4]])}" for cat, tools in catalog.items()])
    
    def _compress_context_for_tools(self, context: Dict[str, Any]) -> str:
        """Compress context to <200 chars for tool selection"""
        parts = []
        if "tech_stack" in context:
            tech = list(context["tech_stack"].keys())[:5]
            parts.append(f"Tech: {', '.join(tech)}")
        if "entry_points" in context:
            ep_count = len(context["entry_points"]) if isinstance(context["entry_points"], list) else 0
            parts.append(f"{ep_count} endpoints")
        return " | ".join(parts) if parts else "minimal context"

    def _get_agent_tools(self, agent_name: str) -> List[Dict[str, str]]:
        """Get tools available for specific agent"""
        catalog = self._get_mcp_tools_catalog()
        
        agent_category_map = {
            "ReconnaissanceAgent": "WSTG-INFO",
            "ConfigDeploymentAgent": "WSTG-CONF",
            "AuthenticationAgent": "WSTG-ATHN",
            "AuthorizationAgent": "WSTG-AUTHZ",
            "SessionManagementAgent": "WSTG-SESS",
            "InputValidationAgent": "WSTG-INPV",
            "ErrorHandlingAgent": "WSTG-ERRH",
            "WeakCryptographyAgent": "WSTG-CRYP",
            "ClientSideAgent": "WSTG-CLNT",
            "IdentityManagementAgent": "WSTG-IDNT",
        }
        
        category = agent_category_map.get(agent_name, "")
        return catalog.get(category, [])

    def _get_default_tools_for_agent(self, agent_name: str) -> List[Dict[str, Any]]:
        """Fallback default tools if LLM selection fails"""
        defaults = {
            "InputValidationAgent": [
                {"tool": "find_reflected_params", "priority": "high"},
                {"tool": "quick_xss_probe", "priority": "high"},
                {"tool": "test_sqli", "priority": "high"},
            ],
            "AuthenticationAgent": [
                {"tool": "test_tls_credentials", "priority": "high"},
                {"tool": "test_csrf_token", "priority": "medium"},
            ],
            "SessionManagementAgent": [
                {"tool": "analyze_cookies", "priority": "high"},
                {"tool": "test_session_fixation", "priority": "medium"},
            ],
        }
        return defaults.get(agent_name, [])

    def _get_fallback_plan(self, recon_results: Dict[str, Any]) -> Dict[str, Any]:
        """Static fallback plan jika LLM gagal (expanded to maximize coverage)."""
        return {
            "strategy": "Expanded fallback: run broad multi-agent OWASP WSTG 4.2 coverage with safe parallel phases",
            "owasp_categories": [
                {"category": "WSTG-CONF", "priority": "high", "agent": "ConfigDeploymentAgent", "mcp_tools": [{"tool": "test_http_methods_and_headers", "reason": "Headers & methods"}]},
                {"category": "WSTG-CLNT", "priority": "medium", "agent": "ClientSideAgent", "mcp_tools": [{"tool": "security_headers_analysis", "reason": "Client-side headers"}]},
                {"category": "WSTG-ATHN", "priority": "high", "agent": "AuthenticationAgent", "mcp_tools": [{"tool": "test_password_reset", "reason": "AO takeover risk"}, {"tool": "test_cache_headers", "reason": "Sensitive cache"}]},
                {"category": "WSTG-INPV", "priority": "critical", "agent": "InputValidationAgent", "mcp_tools": [{"tool": "test_xss_reflected", "reason": "High prevalence"}, {"tool": "test_sqli", "reason": "Critical impact"}, {"tool": "test_lfi", "reason": "File read risk"}]},
                {"category": "WSTG-APIT", "priority": "high", "agent": "APITestingAgent", "mcp_tools": []},
                {"category": "WSTG-AUTHZ", "priority": "high", "agent": "AuthorizationAgent", "mcp_tools": [{"tool": "test_vertical_privilege_escalation", "reason": "Admin access"}, {"tool": "test_idor_vulnerability", "reason": "Object access"}]},
                {"category": "WSTG-SESS", "priority": "high", "agent": "SessionManagementAgent", "mcp_tools": [{"tool": "analyze_cookies", "reason": "Cookie flags"}, {"tool": "test_session_fixation", "reason": "Fixation"}]},
                {"category": "WSTG-ERRH", "priority": "medium", "agent": "ErrorHandlingAgent", "mcp_tools": [{"tool": "probe_for_error_leaks", "reason": "Stack traces"}]},
                {"category": "WSTG-CRYP", "priority": "medium", "agent": "WeakCryptographyAgent", "mcp_tools": [{"tool": "test_tls_configuration", "reason": "TLS config"}, {"tool": "test_cleartext_info", "reason": "HTTP leaks"}]},
                {"category": "WSTG-BUSL", "priority": "medium", "agent": "BusinessLogicAgent", "mcp_tools": []},
                {"category": "WSTG-IDNT", "priority": "medium", "agent": "IdentityManagementAgent", "mcp_tools": [{"tool": "generate_test_usernames", "reason": "Enumeration"}]},
                {"category": "WSTG-BUSL", "priority": "medium", "agent": "FileUploadAgent", "mcp_tools": []},
            ],
            "execution_plan": {
                "sequence": [
                    "ReconnaissanceAgent",
                    {"parallel": ["ConfigDeploymentAgent", "ClientSideAgent"]},
                    "AuthenticationAgent",
                    {"parallel": ["InputValidationAgent", "APITestingAgent"]},
                    "AuthorizationAgent",
                    "SessionManagementAgent",
                    "ErrorHandlingAgent",
                    "WeakCryptographyAgent",
                    "BusinessLogicAgent",
                    "IdentityManagementAgent",
                    "FileUploadAgent"
                ]
            },
        }

    def _invoke_openai(
        self,
        messages: List[Dict[str, str]],
        *,
        max_tokens: int,
        response_format: Dict[str, Any] | None = None,
        temperature: float | None = None,
    ) -> str:
        """Route OpenAI calls to chat or responses endpoint depending on model support."""
        if self._use_responses_api:
            formatted = self._format_responses_messages(messages)
            kwargs: Dict[str, Any] = {
                "model": self.model,
                "input": formatted,
                "max_output_tokens": max_tokens,
            }
            text_format = self._build_text_format(response_format)
            if text_format is not None:
                kwargs["text"] = {"format": text_format}
            if temperature is not None:
                kwargs["temperature"] = temperature
            resp = self._client.responses.create(**kwargs)
            return self._extract_responses_text(resp)

        token_param = "max_completion_tokens" if (self.model.startswith("gpt-5") or self.model.startswith("o1")) else "max_tokens"
        kwargs = {
            "model": self.model,
            token_param: max_tokens,
            "messages": messages,
        }
        # Skip response_format for custom endpoints (LM Studio compatibility)
        if response_format and not self.base_url:
            kwargs["response_format"] = response_format
        if temperature is not None:
            kwargs["temperature"] = temperature
        resp = self._client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content or ""

    def _invoke_gemini(
        self,
        messages: List[Dict[str, Any]],
        *,
        max_tokens: int,
        temperature: float | None = None,
    ) -> str:
        payload = self._build_gemini_payload(messages, max_tokens, temperature)
        url = f"{self._gemini_endpoint}?key={self._gemini_api_key}"
        with httpx.Client(timeout=60) as client:
            response = client.post(url, json=payload)
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                detail = (exc.response.text or "")[:400]
                print(f"[LLMPlanner] Gemini HTTP error {exc.response.status_code}: {detail}")
                raise
            data = response.json()
            text = self._extract_gemini_text(data)
            if not text:
                raw_preview = json.dumps(data)[:400]
                print(f"[LLMPlanner] Gemini response had no text. Raw payload preview: {raw_preview}")
            _snippet = (str(text).replace("\n", " ")[:400])
            print(f"[LLMPlanner] Raw Gemini response (first 400): {_snippet}")
            return text

    def _build_gemini_payload(
        self,
        messages: List[Dict[str, Any]],
        max_tokens: int,
        temperature: float | None,
    ) -> Dict[str, Any]:
        system_parts: List[str] = []
        contents: List[Dict[str, Any]] = []
        for msg in messages:
            role = (msg.get("role") or "user").lower()
            parts = self._normalize_gemini_parts(msg.get("content"))
            if role == "system":
                system_text = " ".join(part.get("text", "") for part in parts if isinstance(part, dict))
                if system_text:
                    system_parts.append(system_text)
                continue
            gem_role = "user" if role == "user" else "model"
            contents.append({"role": gem_role, "parts": parts})
        payload: Dict[str, Any] = {"contents": contents}
        if system_parts:
            payload["system_instruction"] = {
                "parts": [{"text": "\n".join(system_parts).strip()}]
            }
        generation_config: Dict[str, Any] = {
            "maxOutputTokens": max_tokens,
            "responseMimeType": "application/json",
        }
        if temperature is not None:
            generation_config["temperature"] = temperature
        payload["generationConfig"] = generation_config
        return payload

    def _normalize_gemini_parts(self, content: Any) -> List[Dict[str, str]]:
        if isinstance(content, list):
            parts: List[Dict[str, str]] = []
            for item in content:
                if isinstance(item, dict):
                    text_val = item.get("text") or item.get("value") or item.get("content")
                    if isinstance(text_val, str):
                        parts.append({"text": text_val})
                elif isinstance(item, str):
                    parts.append({"text": item})
            return parts or [{"text": ""}]
        if isinstance(content, str):
            return [{"text": content}]
        return [{"text": str(content)}]

    def _extract_gemini_text(self, payload: Dict[str, Any]) -> str:
        candidates = payload.get("candidates") or []
        extracted: List[str] = []

        for cand in candidates:
            content = cand.get("content") or {}
            parts = content.get("parts") or []
            for part in parts:
                if not isinstance(part, dict):
                    continue
                if part.get("text"):
                    extracted.append(str(part["text"]))
                    continue
                if part.get("functionCall"):
                    fn = part["functionCall"]
                    args = fn.get("args")
                    if isinstance(args, str):
                        extracted.append(args)
                    else:
                        extracted.append(json.dumps(fn))
                    continue
                if part.get("json"):
                    extracted.append(json.dumps(part["json"]))
                    continue
                if part.get("inlineData"):
                    extracted.append(json.dumps(part["inlineData"]))

        if extracted:
            return "\n".join(s.strip() for s in extracted if s).strip()
        return ""

    def _model_requires_responses_endpoint(self, model: str) -> bool:
        return model.startswith("gpt-5") or model.startswith("o1")

    def _build_text_format(self, response_format: Dict[str, Any] | None) -> Dict[str, Any] | None:
        """Normalize response_format into responses API text.format payload."""
        if not response_format:
            return None
        rtype = response_format.get("type") or ""
        if rtype == "json_schema":
            # Assume caller already supplied proper schema payload
            return response_format
        if rtype == "json_object":
            # Minimal schema describing generic object response
            return {
                "type": "json_schema",
                "name": "structured_response",
                "schema": {"type": "object"},
            }
        return None

    def _format_responses_messages(self, messages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        formatted: List[Dict[str, Any]] = []
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                text_content = content
            else:
                text_content = [{"type": "text", "text": str(content)}]
            formatted.append({"role": msg.get("role", "user"), "content": text_content})
        return formatted

    def _extract_responses_text(self, response: Any) -> str:
        if hasattr(response, "output_text"):
            text_val = response.output_text
            if isinstance(text_val, list):
                return "\n".join(text_val).strip()
            return (text_val or "").strip()

        if hasattr(response, "dict"):
            data = response.dict()
        elif hasattr(response, "model_dump"):
            data = response.model_dump()
        else:
            data = response

        outputs = data.get("output", []) if isinstance(data, dict) else []
        chunks: List[str] = []
        for block in outputs:
            content_items = block.get("content", []) if isinstance(block, dict) else []
            for item in content_items:
                if isinstance(item, dict):
                    txt = item.get("text") or item.get("value") or ""
                    if txt:
                        chunks.append(txt)
                elif isinstance(item, str):
                    chunks.append(item)
        return "\n".join(chunks).strip()
