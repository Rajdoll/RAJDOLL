"""
Simple LLM Client using direct HTTP calls
Bypasses OpenAI SDK to avoid httpx/proxies compatibility issues
"""
import json
import os
import httpx
from typing import Dict, Any, List, Optional


class SimpleLLMClient:
    """
    Direct HTTP-based LLM client for OpenAI/Anthropic
    No SDK dependencies - just pure HTTP calls
    """
    
    def __init__(self):
        """Initialize client with API key from environment"""
        self.provider = os.getenv("LLM_PROVIDER", "openai").lower()
        
        # Provider-specific configuration
        if self.provider == "gemini":
            self.api_key = os.getenv("GEMINI_API_KEY")
            self.model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash-latest")
        else:
            self.api_key = (
                os.getenv("LLM_API_KEY")
                or os.getenv("OPENAI_API_KEY")
                or os.getenv("ANTHROPIC_API_KEY")
                or os.getenv("GOOGLE_API_KEY")
            )
            self.model = os.getenv("LLM_MODEL", "gpt-4o-mini")
        
        self.base_url = os.getenv("LLM_BASE_URL")  # Support for custom endpoints (LM Studio)
        self.use_responses_api = False
        
        if not self.api_key:
            raise ValueError(f"No API key found for provider '{self.provider}' (check GEMINI_API_KEY or LLM_API_KEY)")
        
        # Set endpoints
        if self.provider == "openai":
            # Check if using custom base URL (LM Studio, etc)
            if self.base_url:
                self.endpoint = f"{self.base_url.rstrip('/')}/chat/completions"
                self.use_responses_api = False
                print(f"✓ [SimpleLLMClient] Using custom endpoint: {self.endpoint}")
            else:
                self.use_responses_api = self._model_requires_responses_endpoint(self.model)
                self.endpoint = (
                    "https://api.openai.com/v1/responses"
                    if self.use_responses_api
                    else "https://api.openai.com/v1/chat/completions"
                )
        elif self.provider == "anthropic":
            self.endpoint = "https://api.anthropic.com/v1/messages"
        elif self.provider == "gemini":
            if not self.model:
                self.model = "gemini-1.5-flash"
            self.endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    async def chat_completion(
        self, 
        messages: List[Dict[str, str]], 
        max_tokens: int = 1500,
        temperature: float = 0.7,
        response_schema: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Send chat completion request and return response text
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            
        Returns:
            str: LLM response content
        """
        async with httpx.AsyncClient(timeout=600.0) as client:  # 10 minutes for tool execution
            if self.provider == "openai":
                if self.use_responses_api:
                    payload = {
                        "model": self.model,
                        "input": self._format_responses_messages(messages),
                        "max_output_tokens": max_tokens,
                    }
                    if response_schema:
                        payload["text"] = {
                            "format": {
                                "type": "json_schema",
                                "name": response_schema.get("title", "structured_response"),
                                "schema": response_schema,
                            }
                        }
                else:
                    token_param = "max_completion_tokens" if (self.model.startswith("gpt-5") or self.model.startswith("o1")) else "max_tokens"
                    payload = {
                        "model": self.model,
                        "messages": messages,
                        token_param: max_tokens,
                    }
                    if not (self.model.startswith("gpt-5") or self.model.startswith("o1")):
                        payload["temperature"] = temperature
                    # DISABLED: LM Studio qwen models don't support json_object mode
                    # if (self.model.startswith("gpt-5") or self.model.startswith("gpt-4o")) and response_schema is not None:
                    #     payload["response_format"] = {"type": "json_object"}

                response = await client.post(
                    self.endpoint,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json=payload
                )
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    detail = (exc.response.text or "")[:400]
                    print(
                        f"[SimpleLLMClient] HTTP error {exc.response.status_code}: {detail}"
                    )
                    raise
                result = response.json()

                # Track token usage for cost monitoring
                usage = result.get('usage', {})
                if usage:
                    prompt_tokens = usage.get('prompt_tokens', 0)
                    completion_tokens = usage.get('completion_tokens', 0)
                    total_tokens = usage.get('total_tokens', 0) or (prompt_tokens + completion_tokens)

                    # Log token usage with cost estimation (GPT-4o-mini pricing)
                    # Input: $0.15/1M tokens, Output: $0.60/1M tokens
                    input_cost = prompt_tokens * 0.15 / 1_000_000
                    output_cost = completion_tokens * 0.60 / 1_000_000
                    total_cost = input_cost + output_cost

                    print(f"[SimpleLLMClient] Token usage: {prompt_tokens} prompt + {completion_tokens} completion = {total_tokens} total tokens")
                    print(f"[SimpleLLMClient] Estimated cost: ${total_cost:.6f} USD (input: ${input_cost:.6f}, output: ${output_cost:.6f})")
                else:
                    print(f"[SimpleLLMClient] Warning: No usage data in response (local model or API doesn't report usage)")

                if self.use_responses_api:
                    text = self._extract_text_from_responses(result)
                else:
                    text = result["choices"][0]["message"]["content"]

                _snippet = (str(text).replace("\n", " ")[:400])
                print(f"[SimpleLLMClient] Raw response (first 400): {_snippet}")
                
                # FIX #1: Strip <think> tags that Claude Sonnet adds
                text = self._strip_thinking_tags(text)
                
                return text
                
            elif self.provider == "anthropic":
                # Convert messages format for Anthropic
                system_msg = next((m["content"] for m in messages if m["role"] == "system"), "")
                user_messages = [m for m in messages if m["role"] != "system"]
                
                response = await client.post(
                    self.endpoint,
                    headers={
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "max_tokens": max_tokens,
                        "system": system_msg,
                        "messages": user_messages,
                        "temperature": temperature
                    }
                )
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    detail = (exc.response.text or "")[:400]
                    print(
                        f"[SimpleLLMClient] HTTP error {exc.response.status_code}: {detail}"
                    )
                    raise
                result = response.json()
                return result["content"][0]["text"]

            elif self.provider == "gemini":
                payload = self._format_gemini_payload(messages, max_tokens, temperature)
                url = f"{self.endpoint}?key={self.api_key}"
                response = await client.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json=payload,
                )
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    detail = (exc.response.text or "")[:400]
                    print(
                        f"[SimpleLLMClient] HTTP error {exc.response.status_code}: {detail}"
                    )
                    raise
                result = response.json()
                text = self._extract_text_from_gemini(result)
                if not text:
                    raw_preview = json.dumps(result)[:400]
                    print(f"[SimpleLLMClient] Gemini response had no text. Raw payload preview: {raw_preview}")
                _snippet = (str(text).replace("\n", " ")[:400])
                print(f"[SimpleLLMClient] Raw response (first 400): {_snippet}")
                return text
    
    async def select_tools_for_agent(
        self,
        agent_name: str,
        shared_context: Dict[str, Any],
        available_tools: List[str],
        system_prompt: str = None
    ) -> List[Dict[str, Any]]:
        """
        Use LLM to select relevant tools for an agent based on context

        Args:
            agent_name: Name of the agent
            shared_context: Current shared context from previous agents
            available_tools: List of available tool names
            system_prompt: Agent-specific system prompt

        Returns:
            List of selected tools with reasoning
        """
        print(f"[SimpleLLMClient] select_tools_for_agent() called for {agent_name} with {len(available_tools)} tools")

        # Build planning prompt
        context_summary = self._summarize_context(shared_context)

        # ENHANCED: Few-shot examples for intelligent tool selection
        few_shot_examples = self._get_few_shot_examples(agent_name)

        # Dynamic tool count based on agent tool surface
        if len(available_tools) > 15:
            tool_count_guidance = f"Select 8-15 tools for comprehensive coverage (total available: {len(available_tools)})"
        elif len(available_tools) > 8:
            tool_count_guidance = f"Select 5-10 tools for thorough testing (total available: {len(available_tools)})"
        else:
            tool_count_guidance = f"Select ALL relevant tools from {len(available_tools)} available"

        # CRITICAL FIX: Extract actual target URL from shared_context
        target_url = shared_context.get("target", "") or shared_context.get("target_url", "") or shared_context.get("base_url", "")
        if not target_url:
            # Fallback: try to get from entry_points
            eps = shared_context.get("entry_points", [])
            if eps and isinstance(eps, list) and len(eps) > 0:
                ep = eps[0]
                if isinstance(ep, dict):
                    target_url = ep.get("url", "") or ep.get("base_url", "")
                elif isinstance(ep, str):
                    from urllib.parse import urlparse, urlunparse
                    parsed = urlparse(ep)
                    target_url = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        
        print(f"[SimpleLLMClient] Target URL from context: {target_url}")
        
        # Extract endpoints for specific test case generation
        endpoints = shared_context.get("entry_points", [])
        if endpoints and isinstance(endpoints, list):
            # FIX: Safely extract URLs (handle dict/string mixed types)
            endpoint_urls = []
            for ep in endpoints[:5]:
                if isinstance(ep, dict):
                    url = ep.get("url") or ep.get("endpoint") or ""
                else:
                    url = str(ep) if ep else ""
                if url:
                    endpoint_urls.append(url)
            endpoints_str = ", ".join(endpoint_urls) if endpoint_urls else "No specific endpoints yet"
        else:
            endpoints_str = "No endpoints discovered yet"

        # Build example URLs using actual target (not placeholder!)
        example_base = target_url if target_url else "http://ACTUAL_TARGET_URL"
        
        prompt = (
            f"You are a security testing expert selecting tools for {agent_name}.\n\n"
            f"**IMPORTANT: The target URL is: {target_url}**\n"
            f"You MUST use this exact target URL in all your test cases. Do NOT use placeholder URLs like 'http://target:3000'.\n\n"
            f"Available tools: {', '.join(available_tools)}\n\n"
            f"Discovered endpoints: {endpoints_str}\n\n"
            f"Reconnaissance context:\n{context_summary[:800]}\n\n"
            f"Few-shot examples:\n{few_shot_examples}\n\n"
            f"{tool_count_guidance}\n\n"
            "CRITICAL REQUIREMENT: Generate COMPREHENSIVE test cases with SPECIFIC URLs, parameters, and MULTIPLE payloads!\n\n"
            "For SQL Injection: Provide endpoint URLs + SQL payloads (UNION, blind, time-based)\n"
            "For XSS: Provide form endpoints + XSS payloads (reflected, stored, DOM-based)\n"
            "For IDOR: Provide resource endpoints with ID parameters + sequential ID tests\n\n"
            "Return ONLY valid JSON (no markdown, no code fences):\n"
            "{\n"
            '  "tools": [\n'
            '    {\n'
            '      "tool": "test_sqli",\n'
            '      "reason": "Search endpoint accepts user input",\n'
            '      "arguments": {\n'
            f'        "url": "{example_base}/rest/products/search?q=test",\n'
            '        "parameter": "q",\n'
            '        "payloads": ["\' OR \'1\'=\'1--", "1\' UNION SELECT NULL--"],\n'
            '        "injection_types": ["union", "blind"]\n'
            '      }\n'
            '    },\n'
            '    {\n'
            '      "tool": "test_xss_reflected",\n'
            '      "reason": "Form inputs reflect user data",\n'
            '      "arguments": {\n'
            f'        "url": "{example_base}/search",\n'
            '        "parameters": ["q", "query"],\n'
            '        "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]\n'
            '      }\n'
            '    }\n'
            '  ],\n'
            '  "reasoning": "overall strategy"\n'
            "}"
        )

        messages = [
            {"role": "system", "content": (system_prompt or f"You are an OWASP expert for {agent_name}") + ". Return ONLY valid JSON. No markdown, no code fences, no backticks, no prose."},
            {"role": "user", "content": prompt}
        ]

        print(f"[SimpleLLMClient] Calling LLM for {agent_name} with {len(available_tools)} tools, prompt length: {len(prompt)} chars")

        try:
            schema = {
                "title": "agent_tool_plan",
                "type": "object",
                "properties": {
                    "tools": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "tool": {"type": "string"},
                                "reason": {"type": "string"},
                                "arguments": {
                                    "type": "object",
                                    "description": "Detailed test case arguments with specific URLs, parameters, and payloads"
                                },
                            },
                            "required": ["tool", "arguments"],
                            "additionalProperties": False,
                        },
                        "minItems": 1,
                    },
                    "reasoning": {"type": "string"},
                },
                "required": ["tools", "reasoning"],
                "additionalProperties": False,
            }

            # CRITICAL: Increase max_tokens for comprehensive test cases with URLs and payloads
            # LOW TEMPERATURE: 0.2 for deterministic, consistent tool selection
            response = await self.chat_completion(messages, max_tokens=4000, temperature=0.5, response_schema=schema)
            # Parse JSON from response (robust)
            import json
            import re
            
            # FIX #1: Strip <think> tags before parsing
            response = self._strip_thinking_tags(response)

            def _strip_code_fences(text: str) -> str:
                t = text.strip()
                if t.startswith("```"):
                    parts = t.splitlines()[1:]
                    if parts and parts[-1].strip().startswith("```"):
                        parts = parts[:-1]
                    return "\n".join(parts).strip()
                return t

            def _extract_first_json(text: str) -> str | None:
                s = text
                for opener, closer in [("{", "}"), ("[", "]")]:
                    starts = [m.start() for m in re.finditer(re.escape(opener), s)]
                    for st in starts:
                        depth = 0
                        for i in range(st, len(s)):
                            ch = s[i]
                            if ch == opener:
                                depth += 1
                            elif ch == closer:
                                depth -= 1
                                if depth == 0:
                                    candidate = s[st:i+1]
                                    try:
                                        json.loads(candidate)
                                        return candidate
                                    except Exception:
                                        pass
                return None

            candidates = [response]
            stripped = _strip_code_fences(response)
            if stripped != response:
                candidates.append(stripped)
            block = _extract_first_json(response)
            if block:
                candidates.append(block)
            if stripped != response:
                block2 = _extract_first_json(stripped)
                if block2:
                    candidates.append(block2)

            plan = None
            last_err = None
            for c in candidates:
                try:
                    plan = json.loads(c)
                    break
                except Exception as e:
                    last_err = e
                    continue
            if plan is None:
                snippet = (response[:200] + ('…' if len(response) > 200 else '')).replace("\n", " ")
                print(f"[SimpleLLMClient] Tool selection failed: Failed to parse LLM JSON: {last_err}; snippet={snippet}")
                raise ValueError(f"Failed to parse LLM JSON: {last_err}; snippet={snippet}")
            selections = []
            for entry in plan.get("tools", []) or []:
                if isinstance(entry, str):
                    selections.append({
                        "tool": entry,
                        "reason": plan.get("reasoning", ""),
                    })
                elif isinstance(entry, dict):
                    tool_name = entry.get("tool") or entry.get("name")
                    if not tool_name:
                        continue
                    selection = {
                        "tool": tool_name,
                        "reason": entry.get("reason") or plan.get("reasoning", ""),
                    }
                    if isinstance(entry.get("arguments"), dict):
                        selection["arguments"] = entry.get("arguments")
                    selections.append(selection)
            return selections
        except Exception as e:
            print(f"[SimpleLLMClient] Tool selection failed: {e}")
            # Fallback: return all tools
            return [{"tool": t, "reason": "Fallback - LLM planning failed"} for t in available_tools]
    
    def _strip_thinking_tags(self, text: str) -> str:
        """Remove <think>...</think> tags that Claude adds to responses
        
        Claude Sonnet sometimes wraps responses in thinking process tags.
        This causes JSON parsing to fail. Strip them out.
        
        Args:
            text: Raw LLM response that may contain <think> tags
            
        Returns:
            Clean text with thinking tags removed
        """
        import re
        if not text:
            return text
            
        # Remove <think>...</think> blocks (non-greedy, multiline)
        text = re.sub(r'<think>.*?</think>\s*', '', text, flags=re.DOTALL | re.IGNORECASE)
        
        # Also remove orphaned opening/closing tags
        text = re.sub(r'</?think>\s*', '', text, flags=re.IGNORECASE)

        return text.strip()

    def _get_few_shot_examples(self, agent_name: str) -> str:
        """
        Provide few-shot examples for intelligent tool selection based on agent type.

        These examples teach the LLM to select appropriate tools based on reconnaissance context.
        """
        # Common examples for all agents
        common_examples = """
Example 1 (Node.js app with REST API):
Context: "50 endpoints, Technologies: Node.js, Express, MongoDB"
Selected: ["test_sql_injection", "test_nosql_injection", "test_api_auth"]
Reasoning: "Node.js + MongoDB indicates NoSQL backend, Express exposes REST endpoints"

Example 2 (PHP app with forms):
Context: "12 endpoints, Technologies: PHP, MySQL, Apache, /login, /search endpoints"
Selected: ["test_sql_injection", "test_xss", "test_auth_bypass"]
Reasoning: "PHP + MySQL suggests SQLi risk, /search indicates XSS targets"
"""

        # Agent-specific examples
        agent_examples = {
            "InputValidationAgent": """
Example 3 (Juice Shop SPA):
Context: "85 endpoints, Technologies: Angular, Node.js, SQLite, /api/Products, /api/Users"
Selected: ["test_sql_injection", "test_xss", "test_xxe", "test_command_injection"]
Reasoning: "SQLite backend = SQLi risk, Angular SPA = XSS DOM targets, API endpoints = XXE/injection"

Example 4 (Admin panel detected):
Context: "30 endpoints, /admin/users, /admin/config endpoints found"
Selected: ["test_idor", "test_privilege_escalation", "test_forced_browsing"]
Reasoning: "Admin endpoints = IDOR/AuthZ risks, config files = sensitive data exposure"
""",
            "AuthenticationAgent": """
Example 3 (JWT detected):
Context: "Login endpoint /api/auth/login, JWT token in response headers"
Selected: ["test_jwt_alg_none", "test_jwt_weak_secret", "test_session_fixation"]
Reasoning: "JWT usage = algorithm confusion & weak secret risks"

Example 4 (Session cookies):
Context: "Set-Cookie: sessionid=abc123; HttpOnly"
Selected: ["test_session_fixation", "test_credential_stuffing", "test_brute_force"]
Reasoning: "Session cookies = fixation/hijacking risks, login form = brute force target"
""",
        }

        # Return common + agent-specific examples
        agent_specific = agent_examples.get(agent_name, "")
        return common_examples + agent_specific

    def _summarize_context(self, context: Dict[str, Any]) -> str:
        """Create a concise summary of shared context with ACTUAL discovered endpoints"""
        summary_parts = []
        
        # CRITICAL: Pass ACTUAL endpoint URLs, not just count
        if context.get("discovered_endpoints"):
            endpoints = context["discovered_endpoints"]
            endpoint_count = endpoints.get('count', 0)
            summary_parts.append(f"- {endpoint_count} endpoints discovered:")
            
            # Extract and include ACTUAL endpoint URLs (up to 30 for comprehensive testing)
            if endpoints.get("endpoints"):
                endpoint_urls = []
                for ep in endpoints["endpoints"][:30]:  # Include up to 30 endpoints
                    # FIX: ReconnaissanceAgent stores with key 'endpoint', not 'url'
                    url = ep.get("endpoint", "") or ep.get("url", "")
                    if url:
                        endpoint_urls.append(url)
                
                if endpoint_urls:
                    summary_parts.append(f"  ACTUAL ENDPOINTS: {', '.join(endpoint_urls[:15])}")
                    if len(endpoint_urls) > 15:
                        summary_parts.append(f"  ... and {len(endpoint_urls) - 15} more endpoints")
        
        # Include entry points with parameters for injection testing
        if context.get("entry_points"):
            entry_points = context["entry_points"]
            if isinstance(entry_points, list) and entry_points:
                summary_parts.append(f"- {len(entry_points)} entry points with parameters:")
                # FIX: Safely extract URLs from entry points (handle dict/string mixed types)
                entry_urls = []
                for ep in entry_points[:10]:
                    if isinstance(ep, dict):
                        url = ep.get("url") or ep.get("endpoint") or str(ep)
                    else:
                        url = str(ep)
                    entry_urls.append(url)
                summary_parts.append(f"  {', '.join(entry_urls)}")
        
        if context.get("findings_count"):
            summary_parts.append(f"- {context['findings_count']} vulnerabilities found by previous agents")
        
        if context.get("technologies") or context.get("tech_stack"):
            tech_list = context.get("technologies") or list(context.get("tech_stack", {}).keys())
            summary_parts.append(f"- Technologies: {', '.join(tech_list[:5])}")
        
        if context.get("authentication") or context.get("authenticated_sessions"):
            auth_status = context.get("authentication", {}).get('status') or 'session available'
            summary_parts.append(f"- Authentication: {auth_status}")
        
        return "\n".join(summary_parts) if summary_parts else "No previous context available"

    def _model_requires_responses_endpoint(self, model: str) -> bool:
        return model.startswith("gpt-5") or model.startswith("o1")

    def _format_responses_messages(self, messages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        formatted = []
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                text_blocks = content
            else:
                text_blocks = [{"type": "input_text", "text": str(content)}]
            formatted.append({
                "role": msg.get("role", "user"),
                "content": text_blocks,
            })
        return formatted

    def _extract_text_from_responses(self, payload: Dict[str, Any]) -> str:
        outputs = payload.get("output", []) or payload.get("choices", [])
        chunks: List[str] = []
        for block in outputs:
            content_items = block.get("content") or block.get("messages") or []
            for item in content_items:
                if isinstance(item, dict):
                    text_val = item.get("text") or item.get("value") or item.get("content")
                    if isinstance(text_val, str):
                        chunks.append(text_val)
                elif isinstance(item, str):
                    chunks.append(item)
        return "\n".join(chunks).strip()

    def _format_gemini_payload(
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
                text_blob = " ".join(part.get("text", "") for part in parts if isinstance(part, dict))
                if text_blob:
                    system_parts.append(text_blob)
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

    def _extract_text_from_gemini(self, payload: Dict[str, Any]) -> str:
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
