"""
Simple LLM Client using direct HTTP calls
Bypasses OpenAI SDK to avoid httpx/proxies compatibility issues
"""
import asyncio
import json
import os
import httpx
from typing import Dict, Any, List, Optional

_MAX_GAP_SUBTESTS_IN_PROMPT = 10


def _recover_json_objects(text: str, key: str) -> list:
    """Salvage the complete objects of a JSON array `key` the local LLM truncated
    at max_tokens. Skips the cut-off trailing object."""
    marker = text.find(f'"{key}"')
    if marker == -1:
        return []
    bracket = text.find("[", marker)
    if bracket == -1:
        return []
    s = text[bracket + 1:]
    objs, depth, in_str, esc, start = [], 0, False, False, None
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    try:
                        objs.append(json.loads(s[start:i + 1]))
                    except Exception:
                        pass
                    start = None
        elif ch == "]" and depth == 0:
            break
    return objs


_VALID_VERDICTS = {"true_positive", "false_positive", "needs_review"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _parse_triage_verdicts(text: str) -> list:
    """Parse the triage LLM response into a list of verdict dicts. Tolerant of
    truncation: recovers the complete objects from the 'verdicts' array (reuses the
    same salvage used elsewhere). Invalid/garbage -> []."""
    if not text:
        return []
    try:
        obj = json.loads(text)
        raw = obj.get("verdicts", []) if isinstance(obj, dict) else []
    except Exception:
        raw = _recover_json_objects(text, "verdicts")
    out = []
    for v in raw or []:
        if not isinstance(v, dict) or "id" not in v:
            continue
        verdict = str(v.get("verdict", "")).lower()
        sev = str(v.get("severity", "")).lower()
        out.append({
            "id": v["id"],
            "verdict": verdict if verdict in _VALID_VERDICTS else "needs_review",
            "severity": sev if sev in _VALID_SEVERITIES else None,
            "confidence": v.get("confidence"),
            "reason": str(v.get("reason", ""))[:500],
        })
    return out


def _salvage_agent_analysis(text: str) -> Optional[dict]:
    """Best-effort recovery of a truncated summarize_agent_findings JSON: pulls the
    'summary' string (even when the trailing arrays are cut off) plus any complete
    root_causes / impact_chains objects. Returns None if nothing usable."""
    import re
    summary = ""
    m = re.search(r'"summary"\s*:\s*"', text)
    if m:
        i, buf, esc = m.end(), [], False
        while i < len(text):
            ch = text[i]
            if esc:
                buf.append(ch)
                esc = False
            elif ch == "\\":
                buf.append(ch)
                esc = True
            elif ch == '"':
                break
            else:
                buf.append(ch)
            i += 1
        raw = "".join(buf)
        try:
            summary = json.loads('"' + raw + '"')
        except Exception:
            summary = raw
    root_causes = _recover_json_objects(text, "root_causes")
    impact_chains = _recover_json_objects(text, "impact_chains")
    if not summary and not root_causes and not impact_chains:
        return None
    return {"summary": summary, "root_causes": root_causes, "impact_chains": impact_chains}


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
                    # Enable structured JSON output via json_schema (LM Studio compatible)
                    # Skip for thinking models — they output <think> tags that break json_schema enforcement
                    is_thinking_model = "thinking" in self.model.lower() or "think" in self.model.lower()
                    if response_schema is not None and not is_thinking_model:
                        payload["response_format"] = {
                            "type": "json_schema",
                            "json_schema": {
                                "name": response_schema.get("title", "structured_response"),
                                "strict": True,
                                "schema": response_schema,
                            }
                        }

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
            # No response_schema: OpenAI rejects strict json_schema when arguments object has no properties
            response = await self.chat_completion(messages, max_tokens=4000, temperature=0.5, response_schema=None)
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
                        in_str = False
                        esc = False
                        for i in range(st, len(s)):
                            ch = s[i]
                            if in_str:
                                if esc:
                                    esc = False
                                elif ch == "\\":
                                    esc = True
                                elif ch == '"':
                                    in_str = False
                                continue
                            if ch == '"':
                                in_str = True
                            elif ch == opener:
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

            def _recover_tools(text: str) -> list:
                """Salvage complete objects from a 'tools' array the LLM corrupted
                (a malformed entry mid-stream) or truncated (cut-off tail). Local
                models occasionally emit a broken entry like '"tool":: ...' which
                makes json.loads fail and _extract_first_json grab only the first
                object — silently dropping every valid tool. This skips the bad/
                truncated entries and keeps the rest."""
                marker = text.find('"tools"')
                if marker == -1:
                    return []
                bracket = text.find("[", marker)
                if bracket == -1:
                    return []
                s = text[bracket + 1:]
                objs, depth, in_str, esc, start = [], 0, False, False, None
                for i, ch in enumerate(s):
                    if in_str:
                        if esc:
                            esc = False
                        elif ch == "\\":
                            esc = True
                        elif ch == '"':
                            in_str = False
                        continue
                    if ch == '"':
                        in_str = True
                    elif ch == "{":
                        if depth == 0:
                            start = i
                        depth += 1
                    elif ch == "}":
                        if depth > 0:
                            depth -= 1
                            if depth == 0 and start is not None:
                                try:
                                    objs.append(json.loads(s[start:i + 1]))
                                except Exception:
                                    pass
                                start = None
                    elif ch == "]" and depth == 0:
                        break
                return objs

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
            # Robust tools extraction: if the parsed object lacks a usable "tools"
            # array (e.g. _extract_first_json grabbed a single inner tool object
            # from corrupted/truncated JSON), salvage the array from the raw text.
            tools_list = plan.get("tools") if isinstance(plan, dict) else None
            if not tools_list:
                tools_list = _recover_tools(response)
            selections = []
            for entry in tools_list or []:
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
            if not selections:
                # Parsed OK but yielded no tools — log the FULL response and parsed
                # keys so the real structure (wrong key? prose prefix?) is visible.
                print(
                    f"[SimpleLLMClient] Tool selection empty after parse for {agent_name}. "
                    f"plan_keys={list(plan.keys()) if isinstance(plan, dict) else type(plan).__name__}; "
                    f"full_response={response!r}"
                )
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

    async def summarize_agent_findings(
        self,
        agent_name: str,
        raw_outputs: str,
        task_tree: str = "",
    ) -> dict:
        """Summarize agent findings with root cause and impact chain analysis.

        Returns a dict with keys: summary, root_causes, impact_chains.
        Falls back to {"summary": truncated_raw, "root_causes": [], "impact_chains": []} on error.
        """
        max_input = 6000
        if len(raw_outputs) > max_input:
            raw_outputs = raw_outputs[:max_input] + "\n... [truncated]"

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a senior penetration tester analyzing security tool outputs. "
                    "Given raw tool outputs from a security testing agent, produce a structured analysis. "
                    "For each vulnerability found:\n"
                    "1. Explain the ROOT CAUSE — why does this vulnerability exist technically?\n"
                    "2. Explain the IMPACT CHAIN — what can an attacker do step-by-step, and what is the worst case?\n"
                    "If no vulnerabilities were found, return empty arrays for root_causes and impact_chains. "
                    "Be specific and technical. Do NOT speculate beyond the evidence."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Agent: {agent_name}\n\n"
                    f"Current Testing Status:\n{task_tree}\n\n"
                    f"Raw Tool Outputs:\n{raw_outputs}\n\n"
                    "Produce a structured analysis."
                ),
            },
        ]

        json_schema = {
            "title": "agent_analysis",
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Concise summary of findings (under 300 words, bullet points)"
                },
                "root_causes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "finding": {"type": "string"},
                            "root_cause": {"type": "string"},
                            "why_it_exists": {"type": "string"}
                        },
                        "required": ["finding", "root_cause", "why_it_exists"],
                        "additionalProperties": False
                    }
                },
                "impact_chains": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "finding": {"type": "string"},
                            "steps": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "worst_case": {"type": "string"}
                        },
                        "required": ["finding", "steps", "worst_case"],
                        "additionalProperties": False
                    }
                }
            },
            "required": ["summary", "root_causes", "impact_chains"],
            "additionalProperties": False
        }

        fallback = {"summary": raw_outputs[:1000], "root_causes": [], "impact_chains": []}

        response = ""
        try:
            response = await self.chat_completion(
                messages,
                max_tokens=2000,  # 1000 was too tight for summary+root_causes+impact_chains; salvage still covers the rest
                temperature=0.3,
                response_schema=json_schema
            )
            text = self._strip_thinking_tags(response)
            import json as _json
            parsed = _json.loads(text)
            parsed.setdefault("root_causes", [])
            parsed.setdefault("impact_chains", [])
            parsed.setdefault("summary", "")
            return parsed
        except Exception as e:
            # Local models often truncate this JSON at max_tokens (Unterminated string).
            # Salvage the summary + any complete objects before degrading to raw output.
            salvaged = _salvage_agent_analysis(self._strip_thinking_tags(response)) if response else None
            if salvaged:
                print(
                    f"[SimpleLLMClient] summarize_agent_findings salvaged after {type(e).__name__} "
                    f"(summary {len(salvaged['summary'])} chars, {len(salvaged['root_causes'])} root_causes, "
                    f"{len(salvaged['impact_chains'])} impact_chains)"
                )
                return salvaged
            print(f"[SimpleLLMClient] summarize_agent_findings failed: {e}")
            return fallback

    async def analyze_all_findings(
        self,
        cumulative_summary: str,
        task_tree: str,
        target: str = "",
    ) -> str:
        """Final analysis: correlate findings across all agents, identify attack
        chains, and flag likely false positives.

        Called once at the end of the scan, before report generation.

        Returns:
            Analysis string with attack chains, confidence adjustments, and
            prioritized remediation recommendations.
        """
        max_input = 8000
        if len(cumulative_summary) > max_input:
            cumulative_summary = cumulative_summary[:max_input] + "\n... [truncated]"

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a senior penetration tester reviewing findings from a multi-agent "
                    "security assessment. Your tasks:\n"
                    "1. ATTACK CHAINS: Identify how individual vulnerabilities combine into "
                    "   multi-step attack paths (e.g., SQLi + Auth Bypass = Account Takeover)\n"
                    "2. FALSE POSITIVES: Flag findings that are likely false positives with reasoning\n"
                    "3. SEVERITY ADJUSTMENT: Re-assess severity considering the full context\n"
                    "4. PRIORITIZED REMEDIATION: Top 5 fixes ordered by impact\n"
                    "Be concise and actionable."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Target: {target}\n\n"
                    f"Testing Status:\n{task_tree}\n\n"
                    f"Cumulative Findings Summary:\n{cumulative_summary}\n\n"
                    "Provide your analysis."
                ),
            },
        ]
        try:
            response = await self.chat_completion(messages, max_tokens=1000, temperature=0.3)
            return self._strip_thinking_tags(response)
        except Exception as e:
            print(f"[SimpleLLMClient] analyze_all_findings failed: {e}")
            return f"Analysis failed: {e}"

    async def triage_findings(self, items: list, target_ctx: dict, chunk_size: int = 8,
                              max_rounds: int = 3) -> list:
        """Judge findings (validity + severity) from evidence. Returns one verdict per
        input id. The local model often closes its array early and omits ids, so unanswered
        ids are re-sent in shrinking rounds; whatever is still missing defaults to needs_review."""
        schema = {
            "title": "triage", "type": "object",
            "properties": {"verdicts": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "needs_review"]},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "confidence": {"type": "number"},
                    "reason": {"type": "string"},
                },
                "required": ["id", "verdict", "severity"], "additionalProperties": False,
            }}},
            "required": ["verdicts"], "additionalProperties": False,
        }
        system = (
            "You are a senior penetration-test triager. For each finding decide, FROM THE "
            "EVIDENCE ONLY: verdict (true_positive/false_positive/needs_review) and severity "
            "(critical/high/medium/low/info by impact x exploitability). Rules: a finding marked "
            "[tool-confirmed] is from an authoritative scanner (sqlmap/dalfox/ffuf/nmap/nikto) — "
            "do NOT mark it false_positive unless the evidence is clearly contradictory; you MAY "
            "adjust its severity. Prefer needs_review over guessing. Do not invent vulnerabilities."
        )
        results = []
        pending = items
        for _ in range(max_rounds):
            if not pending:
                break
            round_results = []
            for start in range(0, len(pending), chunk_size):
                chunk = pending[start:start + chunk_size]
                lines = [
                    f'"id": {it["id"]} [{it.get("source","heuristic")}] {it.get("category","")} '
                    f'sev={it.get("current_severity","")} agent={it.get("agent","")}\n'
                    f'  title: {it.get("title","")}\n  evidence: {str(it.get("evidence",""))[:600]}'
                    for it in chunk
                ]
                user = (
                    f"Target: {target_ctx.get('target','')}  Tech: {target_ctx.get('tech','')}\n\n"
                    f"Findings (return one verdict object per id):\n" + "\n".join(lines)
                )
                try:
                    resp = await self.chat_completion(
                        [{"role": "system", "content": system}, {"role": "user", "content": user}],
                        max_tokens=2000, temperature=0.0, response_schema=schema,
                    )
                    round_results.extend(_parse_triage_verdicts(self._strip_thinking_tags(resp)))
                except Exception as e:
                    print(f"[SimpleLLMClient] triage chunk failed: {e}")
            results.extend(round_results)
            answered = {v["id"] for v in round_results}
            pending = [it for it in pending if it["id"] not in answered]
        # Fill any id still missing after all retry rounds (never drop a finding).
        seen = {v["id"] for v in results}
        for it in items:
            if it["id"] not in seen:
                results.append({"id": it["id"], "verdict": "needs_review", "severity": None,
                                "confidence": None, "reason": "not returned after retries"})
        return results

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

    async def generate_orchestrator_directive(
        self,
        completed_agent: str,
        remaining_agents: list,
        agent_summary: str,
        cumulative_summary: str,
    ):
        """After an agent completes, ask LLM to generate an OrchestratorDirective.

        Returns an OrchestratorDirective on success, None on any failure.
        """
        import re
        from .orchestrator_directive import OrchestratorDirective

        prompt = (
            f"You are the orchestrator for an OWASP WSTG penetration test.\n\n"
            f"Completed agent: {completed_agent}\n"
            f"Agent findings summary:\n{agent_summary[:1000]}\n\n"
            f"Cumulative findings so far:\n{cumulative_summary[-2000:]}\n\n"
            f"Remaining agents (in order): {', '.join(remaining_agents)}\n\n"
            "Generate an OrchestratorDirective to guide the remaining agents.\n"
            "All remaining agents WILL run; you cannot skip any of them.\n"
            "Rules:\n"
            "- focus_instructions: specific guidance per agent name (empty string if no change needed)\n"
            "- inject_tools: additional tool calls per agent (empty list if none needed)\n"
            "- reasoning: 1-2 sentences explaining your choices\n\n"
            "Return ONLY valid JSON (no markdown):\n"
            "{\n"
            '  "focus_instructions": {"AgentName": "focus text"},\n'
            '  "inject_tools": {"AgentName": [{"tool": "tool_name", "arguments": {}}]},\n'
            '  "reasoning": "explanation"\n'
            "}"
        )
        messages = [
            {"role": "system", "content": "You are a security testing orchestrator. Return ONLY valid JSON."},
            {"role": "user", "content": prompt},
        ]
        try:
            raw = await self.chat_completion(messages, max_tokens=800, temperature=0.3)
            raw = self._strip_thinking_tags(raw)
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if not match:
                return None
            data = json.loads(match.group())
            return OrchestratorDirective.from_dict(data)
        except Exception as e:
            print(f"[SimpleLLMClient] generate_orchestrator_directive failed: {e}")
            return None

    async def generate_strategic_plan(
        self,
        recon_summary: str,
        endpoint_inventory: dict,
        tech_stack: dict,
        remaining_agents: list,
        wordlist_catalog: dict,
    ):
        """After Recon, ask LLM to generate a comprehensive attack plan for all agents.

        Returns an OrchestratorDirective with an extra 'wordlists' attribute,
        or None on any failure.
        """
        import re
        from .orchestrator_directive import OrchestratorDirective

        by_tag = endpoint_inventory.get("by_tag", {})
        tag_summary = ", ".join(
            f"{tag}({len(ids)})" for tag, ids in by_tag.items() if ids
        ) or "none tagged"
        tech_str = ", ".join(
            f"{k}:{v}" for k, v in (tech_stack or {}).items()
        ) or "unknown"
        catalog_str = json.dumps(wordlist_catalog.get("tech_specific", {}), indent=2)

        prompt = (
            f"You are the RAJDOLL penetration testing orchestrator. "
            f"ReconnaissanceAgent has completed.\n\n"
            f"Tech stack: {tech_str}\n"
            f"Tagged endpoints: {tag_summary}\n"
            f"Recon findings summary:\n{recon_summary[:2000]}\n\n"
            f"Remaining agents (all will run): {', '.join(remaining_agents)}\n\n"
            "Generate a strategic attack plan. All agents WILL run - do NOT skip any.\n"
            "Rules:\n"
            "- focus_instructions: specific attack scenario per agent (non-empty for important agents)\n"
            "- inject_tools: extra tool calls per agent with arguments (empty list if none needed)\n"
            "- wordlists: 0-2 additional tech-specific wordlist paths from catalog below (for ffuf)\n"
            "- reasoning: 2-3 sentences on strategy\n\n"
            f"Tech-specific wordlist catalog (select by detected tech):\n{catalog_str}\n\n"
            "Return ONLY valid JSON (no markdown):\n"
            "{\n"
            '  "focus_instructions": {"AgentName": "specific scenario"},\n'
            '  "inject_tools": {"AgentName": [{"tool": "tool_name", "arguments": {}}]},\n'
            '  "wordlists": [],\n'
            '  "reasoning": "explanation"\n'
            "}"
        )
        messages = [
            {"role": "system", "content": "You are a security testing strategist. Return ONLY valid JSON."},
            {"role": "user", "content": prompt},
        ]
        try:
            raw = await self.chat_completion(messages, max_tokens=1200, temperature=0.3)
            raw = self._strip_thinking_tags(raw)
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if not match:
                return None
            data = json.loads(match.group())
            directive = OrchestratorDirective.from_dict(data)
            directive.wordlists = data.get("wordlists") or []
            return directive
        except Exception as e:
            print(f"[SimpleLLMClient] generate_strategic_plan failed: {e}")
            return None

    async def propose_subtest_directive(
        self,
        *,
        agent_name: str,
        gap_subtests: List[Dict[str, Any]],
        candidate_tools: List[str],
        target_props: Dict[str, Any],
    ):
        """After an agent finishes with high-risk pending WSTG sub-tests, ask LLM for focus
        instructions + preferred tools. Returns dict {focus_instructions, preferred_tools} or None.
        """
        import re
        if not gap_subtests:
            return None
        gap_lines = "\n".join(f"- {g['id']}: {g.get('title','')}" for g in gap_subtests[:_MAX_GAP_SUBTESTS_IN_PROMPT])
        tools_str = ", ".join(candidate_tools) or "(none mapped)"
        target_str = json.dumps(target_props, default=str)[:600]
        prompt = (
            f"Agent {agent_name} just completed but missed these high-risk WSTG sub-tests:\n"
            f"{gap_lines}\n\n"
            f"Available MCP tools that map to these sub-tests: {tools_str}\n"
            f"Target properties: {target_str}\n\n"
            "Emit JSON only:\n"
            "{\n"
            '  "focus_instructions": "<one paragraph guidance for re-running the agent>",\n'
            '  "preferred_tools": [<subset of available MCP tools>]\n'
            "}\n"
            "Constraint: only suggest tools from the list above. Do not invent tool names."
        )
        messages = [
            {"role": "system", "content": "You are a security testing strategist. Return ONLY valid JSON."},
            {"role": "user", "content": prompt},
        ]
        try:
            raw = await self.chat_completion(messages, max_tokens=600, temperature=0.3)
            raw = self._strip_thinking_tags(raw)
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if not match:
                return None
            data = json.loads(match.group())
            return {
                "focus_instructions": data.get("focus_instructions", "") or "",
                "preferred_tools": data.get("preferred_tools", []) or [],
            }
        except Exception as e:
            print(f"[SimpleLLMClient] propose_subtest_directive failed: {e}")
            return None

    async def propose_agent_reorder(
        self,
        *,
        remaining_agents: List[str],
        findings_summary: str,
        attack_signals: Optional[Dict[str, Any]] = None,
    ) -> Optional[List[str]]:
        """Reorder not-yet-run specialist agents to chase the strongest leads first.

        Returns a permutation of `remaining_agents` (same set, reordered) or None
        on failure / non-permutation output. All agents must still run - this only
        changes order, never drops an agent (full WSTG coverage is preserved).
        """
        import re
        if len(remaining_agents) < 2:
            return None
        agents_str = ", ".join(remaining_agents)
        signals_str = json.dumps(attack_signals or {}, default=str)[:600]
        prompt = (
            "You are orchestrating a sequential web security assessment. "
            "EVERY listed agent MUST still run (full WSTG coverage) - you may only "
            "REORDER them to prioritize chasing the strongest leads first.\n\n"
            f"Remaining agents: {agents_str}\n"
            f"Findings so far:\n{findings_summary[:2000]}\n"
            f"Attack-chain signals: {signals_str}\n\n"
            "Emit JSON only:\n"
            '{ "order": [<every remaining agent exactly once, reordered>] }\n'
            "Constraint: the array MUST contain the same agents as the list above - "
            "no additions, no removals, no duplicates."
        )
        messages = [
            {"role": "system", "content": "You are a security testing strategist. Return ONLY valid JSON."},
            {"role": "user", "content": prompt},
        ]
        try:
            raw = await self.chat_completion(messages, max_tokens=400, temperature=0.3)
            raw = self._strip_thinking_tags(raw)
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if not match:
                return None
            order = json.loads(match.group()).get("order", [])
            if not isinstance(order, list):
                return None
            seen = set()
            cleaned = []
            for a in order:
                if isinstance(a, str) and a in remaining_agents and a not in seen:
                    seen.add(a)
                    cleaned.append(a)
            if set(cleaned) != set(remaining_agents):
                return None
            return cleaned
        except Exception as e:
            print(f"[SimpleLLMClient] propose_agent_reorder failed: {e}")
            return None

    async def propose_followup_probes(
        self,
        *,
        analysis: str,
        findings_summary: str,
        available_agents: List[str],
    ) -> List[Dict[str, str]]:
        """From the final cross-agent analysis, propose targeted follow-up probes
        that re-test the SURFACE of confirmed/suspected leads with adjacent classes.

        Returns a list of {agent, focus, reason} dicts (each agent must be in
        `available_agents`), capped by the caller. Returns [] on failure / no
        actionable leads. Additive only - never drops first-pass coverage.
        """
        import re
        if not available_agents:
            return []
        agents_str = ", ".join(available_agents)
        prompt = (
            "A full WSTG security pass just finished. Using the cross-agent analysis "
            "below, propose a SHORT list of targeted follow-up tests that deepen the "
            "investigation ON THE SAME SURFACE where a lead was found - e.g. if SQLi "
            "was confirmed on an endpoint/parameter, probe XSS/SSTI/command-injection "
            "on that exact endpoint/parameter with that context.\n\n"
            f"Agents you may assign (pick from these only): {agents_str}\n"
            f"Final analysis:\n{analysis[:2500]}\n"
            f"Findings summary:\n{findings_summary[:1500]}\n\n"
            "Emit JSON only:\n"
            '{ "probes": [ { "agent": <one of the listed agents>, '
            '"focus": <specific instruction naming the endpoint/parameter and class to test>, '
            '"reason": <why this lead is worth deepening> } ] }\n'
            "Only include probes that chase a concrete lead. If there are none, return "
            '{ "probes": [] }. Do not invent agents outside the list.'
        )
        messages = [
            {"role": "system", "content": "You are a security testing strategist. Return ONLY valid JSON."},
            {"role": "user", "content": prompt},
        ]
        try:
            raw = await self.chat_completion(messages, max_tokens=600, temperature=0.3)
            raw = self._strip_thinking_tags(raw)
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if not match:
                return []
            probes = json.loads(match.group()).get("probes", [])
            if not isinstance(probes, list):
                return []
            cleaned = []
            for p in probes:
                if not isinstance(p, dict):
                    continue
                agent = p.get("agent")
                if agent in available_agents:
                    cleaned.append({
                        "agent": agent,
                        "focus": str(p.get("focus", "")),
                        "reason": str(p.get("reason", "")),
                    })
            return cleaned
        except Exception as e:
            print(f"[SimpleLLMClient] propose_followup_probes failed: {e}")
            return []

    async def tag_endpoints_with_subtests(
        self,
        *,
        endpoints: List[Dict[str, Any]],
        catalog_summary: List[Dict[str, Any]],
        tech_stack: Dict[str, Any],
        known_ids: Optional[set] = None,
        timeout_s: int = 90,
    ) -> Dict[str, List[str]]:
        """For each endpoint, return which WSTG sub-test IDs are applicable.

        Returns {url: [wstg_id, ...]} or {} on failure.
        """
        import re
        if not endpoints:
            return {}
        ep_lines = "\n".join(
            f"  {e.get('method','GET')} {e['url']}"
            f"{' params:' + str(e.get('params',[])) if e.get('params') else ''}"
            for e in endpoints[:60]
        )
        cat_lines = "\n".join(
            f"  {c['id']}: {c['title']}"
            for c in catalog_summary[:80]
        )
        tech_str = ", ".join(f"{k}:{v}" for k, v in (tech_stack or {}).items()) or "unknown"
        prompt = (
            f"You are a penetration tester. For each endpoint below, list which WSTG v4.2 "
            f"sub-test IDs are applicable based on the URL, HTTP method, parameters, and tech stack.\n\n"
            f"Tech stack: {tech_str}\n\n"
            f"Endpoints:\n{ep_lines}\n\n"
            f"WSTG sub-tests to consider:\n{cat_lines}\n\n"
            f"Return ONLY valid JSON: {{\"<url>\": [\"<WSTG-XXX-YY>\", ...], ...}}\n"
            f"Only include IDs from the list above. If no sub-tests apply to an endpoint, omit it."
        )
        messages = [
            {"role": "system", "content": "You are a security testing strategist. Return ONLY valid JSON."},
            {"role": "user", "content": prompt},
        ]
        try:
            raw = await asyncio.wait_for(
                self.chat_completion(messages, max_tokens=2000, temperature=0.2),
                timeout=timeout_s,
            )
            raw = self._strip_thinking_tags(raw)
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if not match:
                return {}
            data = json.loads(match.group())
            if not isinstance(data, dict):
                return {}
            valid_prefix = "WSTG-"
            result = {}
            for url, ids in data.items():
                if not isinstance(ids, list):
                    continue
                filtered = [
                    i for i in ids
                    if isinstance(i, str) and i.startswith(valid_prefix)
                    and (known_ids is None or i in known_ids)
                ]
                if filtered:
                    result[url] = filtered
            return result
        except Exception as e:
            print(f"[SimpleLLMClient] tag_endpoints_with_subtests failed: {e}")
            return {}

    async def propose_retry_arguments(
        self,
        *,
        tool_name: str,
        subtest_id: str,
        subtest_title: str,
        prior_args: Dict[str, Any],
        target_props: Dict[str, Any],
    ):
        """After 0-finding tool result, propose alternative arguments. Returns dict
        {args: {...}, rationale: "..."} or None.
        """
        import re
        prompt = (
            f"The MCP tool `{tool_name}` was run for WSTG sub-test {subtest_id} "
            f"({subtest_title}) but returned 0 findings.\n"
            f"Prior arguments: {json.dumps(prior_args, default=str)[:600]}\n"
            f"Target properties: {json.dumps(target_props, default=str)[:600]}\n\n"
            "Emit JSON only:\n"
            "{\n"
            '  "args": { ... different args, same tool ... },\n'
            '  "rationale": "<one sentence>"\n'
            "}\n"
            "Constraint: same tool, different vector/parameter/payload class. "
            "Do not suggest a different tool."
        )
        messages = [
            {"role": "system", "content": "You are a security testing strategist. Return ONLY valid JSON."},
            {"role": "user", "content": prompt},
        ]
        try:
            raw = await self.chat_completion(messages, max_tokens=400, temperature=0.4)
            raw = self._strip_thinking_tags(raw)
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if not match:
                return None
            data = json.loads(match.group())
            if not isinstance(data.get("args"), dict):
                return None
            return {"args": data["args"], "rationale": data.get("rationale", "")}
        except Exception as e:
            print(f"[SimpleLLMClient] propose_retry_arguments failed: {e}")
            return None

    async def review_round1_for_escalation(
        self,
        agent_name: str,
        tool_server_map: dict,
        round1_summary: str,
    ) -> list:
        """LLM reviews Round 1 findings and selects 0-5 targeted escalation tools.

        Returns list of {tool, server, arguments, reason} dicts. Empty list = no escalation.
        tool_server_map: {tool_name: server_name} for all tools this agent can run.
        """
        import json, re
        if not tool_server_map:
            return []

        tool_list = "\n".join(
            f"- {tool} (server: {server})" for tool, server in sorted(tool_server_map.items())
        )
        prompt = (
            f"You reviewed Round 1 results for {agent_name}.\n\n"
            f"Round 1 findings summary:\n{round1_summary[:1500]}\n\n"
            f"Available tools for Round 2 escalation:\n{tool_list}\n\n"
            "Select 0-5 tools for targeted Round 2 testing.\n"
            "ONLY select tools if you have HIGH CONFIDENCE a specific vulnerability needs deeper probing.\n"
            "Return empty round2_tools if Round 1 coverage was sufficient.\n\n"
            "Return ONLY valid JSON (no markdown):\n"
            "{\n"
            '  "round2_tools": [\n'
            '    {"tool": "tool_name", "server": "server_name", "arguments": {}, "reason": "why"}\n'
            '  ]\n'
            "}"
        )
        messages = [
            {"role": "system", "content": f"You are an OWASP expert reviewing {agent_name} results. Return ONLY valid JSON."},
            {"role": "user", "content": prompt},
        ]
        try:
            raw = await self.chat_completion(messages, max_tokens=600, temperature=0.2)
            raw = self._strip_thinking_tags(raw)
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if not match:
                return []
            data = json.loads(match.group())
            tools = data.get("round2_tools") or []
            valid = [
                t for t in tools
                if isinstance(t, dict) and t.get("tool") in tool_server_map
            ]
            return valid[:5]
        except Exception as e:
            print(f"[SimpleLLMClient] review_round1_for_escalation failed: {e}")
            return []
