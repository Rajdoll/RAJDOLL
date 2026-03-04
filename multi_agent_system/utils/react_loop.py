"""
ReAct (Reasoning + Acting) Loop Implementation
===============================================

Implements Claude Code / Codex style iterative agent behavior:
1. THOUGHT: LLM analyzes current state and decides what to do
2. ACTION: Execute a tool with specific parameters  
3. OBSERVATION: Get the result and analyze it
4. REPEAT: Until vulnerability confirmed or max iterations reached

This is the KEY DIFFERENTIATOR from static tool execution.

Benchmark Target: >80% detection rate per category (Izzat et al.)
- SQL Injection
- XSS
- Command Injection
- LDAP/XPath/NoSQL Injection
- SSTI/XXE/CRLF Injection
- LFI/Path Traversal

Author: RAJDOLL Security Scanner
Version: 2.0 - Benchmark-Aligned Implementation (Phase 1)
"""

import json
import asyncio
import re
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .simple_llm_client import SimpleLLMClient
from .mcp_client import MCPClient

# Import comprehensive injection payloads
try:
    from ..payloads.injection_payloads import (
        get_techniques_for_type,
        get_all_payloads_for_type,
        get_indicators_for_type,
        get_critical_payloads,
        InjectionType,
        SQLI_TECHNIQUES as SQLI_PAYLOADS,
        XSS_TECHNIQUES as XSS_PAYLOADS,
        COMMAND_INJECTION_TECHNIQUES,
        LDAP_INJECTION_TECHNIQUES,
        XPATH_INJECTION_TECHNIQUES,
        NOSQL_INJECTION_TECHNIQUES,
        SSTI_TECHNIQUES,
        XXE_TECHNIQUES,
        CRLF_TECHNIQUES,
        LFI_TECHNIQUES as LFI_PAYLOADS,
    )
    PAYLOADS_AVAILABLE = True
except ImportError:
    PAYLOADS_AVAILABLE = False

# Import SSRF payloads
try:
    from ..payloads.ssrf_payloads import (
        get_all_ssrf_payloads,
        get_ssrf_payloads_by_category,
        get_ssrf_detection_patterns,
        get_ssrf_test_endpoints,
        INTERNAL_NETWORK_PAYLOADS,
        CLOUD_METADATA_PAYLOADS,
        PROTOCOL_SMUGGLING_PAYLOADS,
        IP_OBFUSCATION_PAYLOADS,
        URL_PARSER_BYPASS_PAYLOADS,
    )
    SSRF_PAYLOADS_AVAILABLE = True
except ImportError:
    SSRF_PAYLOADS_AVAILABLE = False


class ActionType(Enum):
    """Types of actions the ReAct agent can take"""
    EXECUTE_TOOL = "execute_tool"
    ADJUST_PAYLOAD = "adjust_payload"
    TRY_DIFFERENT_TECHNIQUE = "try_different_technique"
    ESCALATE_ATTACK = "escalate_attack"
    CONFIRM_VULNERABILITY = "confirm_vulnerability"
    MARK_NOT_VULNERABLE = "mark_not_vulnerable"
    NEED_MORE_INFO = "need_more_info"


@dataclass
class ReActState:
    """State maintained across ReAct iterations"""
    target_url: str
    test_type: str  # sqli, xss, lfi, etc.
    iteration: int = 0
    max_iterations: int = 10
    
    # History of actions and observations
    thoughts: List[str] = field(default_factory=list)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    
    # Findings
    vulnerabilities_found: List[Dict[str, Any]] = field(default_factory=list)
    confirmed: bool = False
    
    # Context
    auth_session: Optional[Dict[str, Any]] = None
    parameters: List[str] = field(default_factory=lambda: ['id', 'q', 'search'])
    tech_stack: Dict[str, Any] = field(default_factory=dict)
    
    # Payloads tried (to avoid repetition)
    payloads_tried: List[str] = field(default_factory=list)
    techniques_tried: List[str] = field(default_factory=list)


class ReActLoop:
    """
    ReAct Loop Engine for iterative vulnerability testing.
    
    Unlike static tool execution, this:
    1. Analyzes results after each tool execution
    2. Decides next action based on observations
    3. Adjusts payloads/techniques based on errors
    4. Confirms vulnerabilities through multiple proofs
    
    Supports injection types:
    - SQLi (error-based, union, blind, time-based, stacked, WAF bypass)
    - XSS (reflected, DOM, event handlers, SVG, encoded, polyglot)
    - Command Injection (Unix/Windows, blind, filter bypass)
    - LDAP/XPath/NoSQL Injection
    - SSTI (Jinja2, Twig, Freemarker, Velocity, ERB)
    - XXE (basic, parameter entities, OOB, file upload)
    - CRLF (header injection, response splitting)
    - LFI (path traversal, PHP wrappers, log poisoning)
    """
    
    # Use comprehensive payloads from injection_payloads.py if available
    # Fallback to basic payloads if import fails
    
    if PAYLOADS_AVAILABLE:
        # Convert InjectionTechnique dataclass to dict format for compatibility
        SQLI_TECHNIQUES = {
            name: {"payloads": tech.payloads, "indicators": tech.indicators}
            for name, tech in SQLI_PAYLOADS.items()
        }
        XSS_TECHNIQUES = {
            name: {"payloads": tech.payloads, "indicators": tech.indicators}
            for name, tech in XSS_PAYLOADS.items()
        }
        LFI_TECHNIQUES = {
            name: {"payloads": tech.payloads, "indicators": tech.indicators}
            for name, tech in LFI_PAYLOADS.items()
        }
        COMMAND_TECHNIQUES = {
            name: {"payloads": tech.payloads, "indicators": tech.indicators}
            for name, tech in COMMAND_INJECTION_TECHNIQUES.items()
        }
        LDAP_TECHNIQUES = {
            name: {"payloads": tech.payloads, "indicators": tech.indicators}
            for name, tech in LDAP_INJECTION_TECHNIQUES.items()
        }
        XPATH_TECHNIQUES = {
            name: {"payloads": tech.payloads, "indicators": tech.indicators}
            for name, tech in XPATH_INJECTION_TECHNIQUES.items()
        }
        NOSQL_TECHNIQUES = {
            name: {"payloads": tech.payloads, "indicators": tech.indicators}
            for name, tech in NOSQL_INJECTION_TECHNIQUES.items()
        }
        SSTI_TECHNIQUES_DICT = {
            name: {"payloads": tech.payloads, "indicators": tech.indicators}
            for name, tech in SSTI_TECHNIQUES.items()
        }
        XXE_TECHNIQUES_DICT = {
            name: {"payloads": tech.payloads, "indicators": tech.indicators}
            for name, tech in XXE_TECHNIQUES.items()
        }
        CRLF_TECHNIQUES_DICT = {
            name: {"payloads": tech.payloads, "indicators": tech.indicators}
            for name, tech in CRLF_TECHNIQUES.items()
        }
    else:
        # Fallback: Basic techniques if comprehensive payloads not available
        SQLI_TECHNIQUES = {
            "error_based": {
                "payloads": ["'", "\"", "' OR '1'='1", "1' ORDER BY 1--", "1' UNION SELECT NULL--"],
                "indicators": ["sql", "mysql", "sqlite", "postgresql", "oracle", "syntax", "query", "database"]
            },
            "union_based": {
                "payloads": [
                    "' UNION SELECT NULL--", 
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT 1,2,3--",
                    "1 UNION SELECT username,password FROM users--"
                ],
                "indicators": ["union", "select", "column"]
            },
            "blind_boolean": {
                "payloads": ["' AND '1'='1", "' AND '1'='2", "1 AND 1=1", "1 AND 1=2"],
                "indicators": []
            },
            "time_based": {
                "payloads": ["'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--", "1; SELECT SLEEP(5)--"],
                "indicators": []
            },
        }
        
        XSS_TECHNIQUES = {
            "reflected_basic": {
                "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
                "indicators": ["<script>", "<img", "<svg", "onerror", "onload"]
            },
            "attribute_injection": {
                "payloads": ["\" onmouseover=\"alert(1)", "' onclick='alert(1)'"],
                "indicators": ["onmouseover", "onclick", "onfocus"]
            },
        }
        
        LFI_TECHNIQUES = {
            "basic_traversal": {
                "payloads": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
                "indicators": ["root:", "bin:", "[fonts]", "[extensions]"]
            },
        }
        
        COMMAND_TECHNIQUES = {
            "basic_unix": {
                "payloads": ["; id", "; whoami", "| id", "$(id)"],
                "indicators": ["uid=", "gid=", "root:"]
            },
        }
        
        LDAP_TECHNIQUES = {}
        XPATH_TECHNIQUES = {}
        NOSQL_TECHNIQUES = {}
        SSTI_TECHNIQUES_DICT = {
            "ssti_detection": {
                "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
                "indicators": ["49", "7777777"]
            },
        }
        XXE_TECHNIQUES_DICT = {}
        CRLF_TECHNIQUES_DICT = {}
    
    # SSRF Techniques - loaded from ssrf_payloads.py
    if SSRF_PAYLOADS_AVAILABLE:
        SSRF_TECHNIQUES = {
            "internal_network": {
                "payloads": INTERNAL_NETWORK_PAYLOADS,
                "indicators": ["127.0.0.1", "localhost", "10.", "172.16", "192.168", "internal", "Connection refused"]
            },
            "cloud_metadata": {
                "payloads": CLOUD_METADATA_PAYLOADS,
                "indicators": ["ami-", "i-", "arn:aws:", "AccessKeyId", "SecretAccessKey", "metadata", "computeMetadata"]
            },
            "protocol_smuggling": {
                "payloads": PROTOCOL_SMUGGLING_PAYLOADS,
                "indicators": ["root:", "bin:", "[fonts]", "[extensions]", "Redis", "MongoDB", "mysql"]
            },
            "ip_obfuscation": {
                "payloads": IP_OBFUSCATION_PAYLOADS,
                "indicators": ["127.0.0.1", "localhost", "::1", "internal"]
            },
            "url_parser_bypass": {
                "payloads": URL_PARSER_BYPASS_PAYLOADS,
                "indicators": ["127.0.0.1", "localhost", "internal", "refused"]
            },
        }
    else:
        SSRF_TECHNIQUES = {
            "basic_ssrf": {
                "payloads": [
                    "http://127.0.0.1/",
                    "http://localhost/",
                    "http://169.254.169.254/",
                    "http://[::1]/",
                    "file:///etc/passwd",
                ],
                "indicators": ["127.0.0.1", "localhost", "root:", "metadata"]
            }
        }
    
    def __init__(self, llm_client: SimpleLLMClient = None, mcp_client: MCPClient = None):
        """Initialize ReAct loop with LLM and MCP clients"""
        self.llm_client = llm_client or SimpleLLMClient()
        self.mcp_client = mcp_client or MCPClient()
        self._log_callback = None
        self._signal_check_callback = None   # HITL: check for intervention signals
        self._broadcast_callback = None       # HITL: broadcast execution status

    def set_log_callback(self, callback):
        """Set callback for logging (integrates with agent logging)"""
        self._log_callback = callback

    def set_hitl_callbacks(self, signal_check=None, broadcast=None):
        """Set HITL callbacks for live intervention from dashboard."""
        self._signal_check_callback = signal_check
        self._broadcast_callback = broadcast
    
    def _log(self, level: str, message: str):
        """Log message via callback or print"""
        if self._log_callback:
            self._log_callback(level, f"[ReAct] {message}")
        else:
            print(f"[ReAct] [{level.upper()}] {message}")
    
    def _get_payload_examples(self, test_type: str, num_examples: int = 5) -> str:
        """
        Get example payloads for LLM context - helps LLM understand patterns
        so it can generate variations or new payloads based on observations.
        """
        techniques = self._get_techniques_for_test(test_type)
        examples = []
        
        for tech_name, tech_data in list(techniques.items())[:3]:
            payloads = tech_data.get("payloads", [])[:num_examples] if isinstance(tech_data, dict) else tech_data.payloads[:num_examples]
            examples.append(f"{tech_name}: {payloads}")
        
        return "\n".join(examples)
    
    async def _generate_adaptive_payload(
        self, 
        state: ReActState, 
        observation: Dict[str, Any]
    ) -> str:
        """
        LLM generates NEW payload based on observations.
        This enables dynamic payload generation beyond hardcoded lists.
        
        Example adaptations:
        - Saw WAF blocking 'UNION' → Try 'UniOn' or '/*!UNION*/'
        - Saw MySQL version → Use MySQL-specific functions
        - Saw HTML encoding → Try double encoding or unicode
        """
        prompt = f"""Based on the following observation, generate an IMPROVED payload for {state.test_type} testing.

OBSERVATION:
- Status Code: {observation.get('status_code')}
- Response Length: {observation.get('response_length')}
- Evidence: {observation.get('evidence', [])}
- Response Snippet: {observation.get('response_snippet', '')[:300]}
- Previous Payload: {observation.get('payload', '')}

ANALYSIS REQUIRED:
1. Did the payload get blocked by WAF?
2. Was the payload reflected but not executed?
3. What database/technology does the response suggest?
4. What encoding/escaping is being applied?

Generate a SINGLE improved payload that addresses the observed issues.
Respond with ONLY the payload string, no explanation.

PAYLOAD GENERATION STRATEGIES:
- If WAF blocked: Try case variation (UniOn), comments (UN/**/ION), encoding (%55NION)
- If reflected but sanitized: Try different quote types, escape sequences
- If DB detected: Use DB-specific functions (MySQL: EXTRACTVALUE, MSSQL: @@version)
- If HTML context: Try event handlers (onerror, onload), different tags (<svg>, <img>)
"""
        
        try:
            response = await self.llm_client.chat_completion(
                messages=[
                    {"role": "system", "content": "You are a payload generation expert. Output ONLY the payload, nothing else."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.7  # Higher creativity for payload generation
            )
            
            # Clean the response - just the payload
            payload = response.strip().strip('"').strip("'")
            if payload and len(payload) < 500:  # Sanity check
                self._log("info", f"🧠 LLM generated adaptive payload: {payload[:100]}...")
                return payload
            
        except Exception as e:
            self._log("warning", f"Adaptive payload generation failed: {e}")
        
        return None  # Fallback to predefined payloads
    
    async def run(
        self,
        target_url: str,
        test_type: str,
        parameters: List[str] = None,
        auth_session: Dict[str, Any] = None,
        tech_stack: Dict[str, Any] = None,
        max_iterations: int = 10
    ) -> Dict[str, Any]:
        """
        Execute ReAct loop for a specific vulnerability test.
        
        Args:
            target_url: URL to test
            test_type: Type of test (sqli, xss, lfi, xxe, ssrf, ssti)
            parameters: URL parameters to test
            auth_session: Authentication session for requests
            tech_stack: Technology stack info from recon
            max_iterations: Maximum iterations before giving up
            
        Returns:
            Dict with vulnerabilities found, confidence, and evidence
        """
        # Initialize state
        state = ReActState(
            target_url=target_url,
            test_type=test_type,
            max_iterations=max_iterations,
            auth_session=auth_session,
            parameters=parameters or ['id', 'q', 'search'],
            tech_stack=tech_stack or {}
        )
        
        self._log("info", f"Starting ReAct loop for {test_type.upper()} on {target_url}")
        self._log("info", f"Parameters: {state.parameters}, Max iterations: {max_iterations}")
        
        # Main ReAct loop
        while state.iteration < state.max_iterations and not state.confirmed:
            state.iteration += 1
            self._log("info", f"=== Iteration {state.iteration}/{state.max_iterations} ===")

            # HITL: Check for intervention signal before each iteration
            if self._signal_check_callback:
                signal = self._signal_check_callback()
                if signal:
                    action_type = signal.get("action", "")
                    if action_type in ("cancel_test", "skip_test"):
                        self._log("warning", f"HITL: Test cancelled by user — {signal.get('reason', '')}")
                        break
                    elif action_type == "change_technique":
                        # Will be picked up in _think via injected technique
                        state._hitl_technique_override = signal.get("technique")
                        self._log("info", f"HITL: Technique override → {signal.get('technique')}")

            # HITL: Broadcast current iteration status to dashboard
            if self._broadcast_callback:
                self._broadcast_callback({
                    "phase": "react_loop",
                    "test_type": test_type,
                    "url": target_url,
                    "iteration": state.iteration,
                    "max_iterations": state.max_iterations,
                    "techniques_tried": state.techniques_tried[-3:],
                    "findings_count": len(state.vulnerabilities_found),
                })

            # STEP 1: THOUGHT - LLM analyzes state and decides action
            thought, action = await self._think(state)
            state.thoughts.append(thought)
            
            self._log("info", f"💭 THOUGHT: {thought[:200]}...")
            self._log("info", f"🎯 ACTION: {action.get('type')} - {action.get('description', '')[:100]}")
            
            # Check for terminal actions
            if action.get("type") == ActionType.CONFIRM_VULNERABILITY.value:
                state.confirmed = True
                self._log("info", f"✅ CONFIRMED: Vulnerability confirmed with evidence")
                break
            elif action.get("type") == ActionType.MARK_NOT_VULNERABLE.value:
                self._log("info", f"❌ NOT VULNERABLE: {action.get('reason', 'No evidence found')}")
                break
            
            # STEP 2: ACTION - Execute the decided action
            observation = await self._act(state, action)
            state.actions.append(action)
            state.observations.append(observation)
            
            self._log("info", f"👁️ OBSERVATION: {str(observation)[:200]}...")
            
            # STEP 3: Track payloads/techniques tried
            if action.get("payload"):
                state.payloads_tried.append(action["payload"])
            if action.get("technique"):
                state.techniques_tried.append(action["technique"])
            
            # STEP 4: Check if we found something
            if observation.get("vulnerable"):
                finding = {
                    "type": test_type,
                    "url": target_url,
                    "payload": action.get("payload"),
                    "technique": action.get("technique"),
                    "evidence": observation.get("evidence"),
                    "response_snippet": observation.get("response_snippet", ""),
                    "iteration": state.iteration
                }
                state.vulnerabilities_found.append(finding)
                self._log("info", f"🚨 POTENTIAL FINDING: {test_type.upper()} detected!")
            
            # STEP 5: ADAPTIVE PAYLOAD GENERATION
            # If we got interesting response but not confirmed vulnerable, 
            # let LLM generate an improved payload for next iteration
            elif observation.get("status_code") and not observation.get("error"):
                # Check if response suggests we're close (partial reflection, interesting errors)
                response_snippet = observation.get("response_snippet", "").lower()
                interesting_signals = [
                    "blocked", "forbidden", "invalid", "error", "syntax",
                    "filtered", "detected", "denied", "waf", "firewall"
                ]
                
                if any(signal in response_snippet for signal in interesting_signals):
                    # LLM might be able to bypass this - generate adaptive payload
                    adaptive_payload = await self._generate_adaptive_payload(state, observation)
                    if adaptive_payload and adaptive_payload not in state.payloads_tried:
                        # Queue the adaptive payload for next iteration
                        state.adaptive_payloads = getattr(state, 'adaptive_payloads', [])
                        state.adaptive_payloads.append({
                            "payload": adaptive_payload,
                            "technique": action.get("technique", "adaptive"),
                            "reason": "LLM-generated based on WAF/filter observation"
                        })
                        self._log("info", f"📝 Queued adaptive payload for next iteration")
        
        # Compile final results
        return self._compile_results(state)
    
    async def _think(self, state: ReActState) -> Tuple[str, Dict[str, Any]]:
        """
        LLM THOUGHT phase - analyze state and decide next action.
        
        This is where the "intelligence" happens - LLM reasons about:
        1. What has been tried so far
        2. What worked/didn't work
        3. What to try next
        """
        # Build context for LLM
        history_summary = self._build_history_summary(state)
        techniques = self._get_techniques_for_test(state.test_type)
        untried_techniques = [t for t in techniques.keys() if t not in state.techniques_tried]
        
        prompt = f"""You are an expert penetration tester performing {state.test_type.upper()} testing.

TARGET: {state.target_url}
PARAMETERS TO TEST: {', '.join(state.parameters)}
TECHNOLOGY STACK: {json.dumps(state.tech_stack) if state.tech_stack else 'Unknown'}
ITERATION: {state.iteration}/{state.max_iterations}

HISTORY:
{history_summary}

UNTRIED TECHNIQUES: {', '.join(untried_techniques) if untried_techniques else 'All tried'}

Based on the history and observations, decide your NEXT ACTION.

You MUST respond with a JSON object containing:
{{
    "thought": "Your reasoning about what you've learned and what to try next",
    "action": {{
        "type": "execute_tool|adjust_payload|try_different_technique|confirm_vulnerability|mark_not_vulnerable",
        "technique": "technique_name (e.g., error_based, union_based, reflected_basic)",
        "payload": "the exact payload to use",
        "parameter": "which parameter to inject into",
        "description": "brief description of why this action"
    }}
}}

DECISION GUIDELINES:
1. If you see SQL error messages → Try union-based or error-based extraction
2. If payload is reflected but not executed → Try encoding or different context
3. If response differs between payloads → Boolean-based blind might work
4. If you've tried 3+ techniques with no results → Consider mark_not_vulnerable
5. If you have CLEAR evidence (error message, data extraction) → confirm_vulnerability

IMPORTANT: 
- If previous observation shows "vulnerable": true with evidence → CONFIRM the vulnerability
- Don't keep testing once you have solid evidence
- Vary your payloads - don't repeat the same one
- You CAN generate NEW payloads based on observations (not limited to predefined ones)
- If you see a WAF blocking, try encoding variations (URL encode, double encode, Unicode)
- If error reveals database type, craft DB-specific payloads

AVAILABLE TECHNIQUE PAYLOADS (use as starting point, modify as needed):
{self._get_payload_examples(state.test_type, 5)}
"""
        
        try:
            response = await self.llm_client.chat_completion(
                messages=[
                    {"role": "system", "content": "You are a security expert. Respond ONLY with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.3
            )
            
            # Parse LLM response
            result = self._parse_llm_json(response)
            thought = result.get("thought", "Analyzing...")
            action = result.get("action", {})
            
            # Check if we have adaptive payloads queued from previous iteration
            adaptive_payloads = getattr(state, 'adaptive_payloads', [])
            if adaptive_payloads and not action.get("payload"):
                # Use LLM-generated adaptive payload
                adaptive = adaptive_payloads.pop(0)
                action["payload"] = adaptive["payload"]
                action["technique"] = adaptive.get("technique", action.get("technique", "adaptive"))
                thought += f" [Using adaptive payload: {adaptive.get('reason', 'LLM-generated')}]"
            
            # Ensure action has required fields
            if not action.get("type"):
                # Default to trying next technique
                if untried_techniques:
                    action = {
                        "type": "try_different_technique",
                        "technique": untried_techniques[0],
                        "payload": techniques[untried_techniques[0]]["payloads"][0],
                        "parameter": state.parameters[0] if state.parameters else "id",
                        "description": f"Try {untried_techniques[0]} technique"
                    }
                else:
                    action = {"type": "mark_not_vulnerable", "reason": "All techniques exhausted"}
            
            return thought, action
            
        except Exception as e:
            self._log("warning", f"LLM thinking failed: {e}, using fallback")
            # Fallback: Try next untried technique
            if untried_techniques:
                tech = untried_techniques[0]
                return (
                    f"LLM unavailable, trying {tech} technique",
                    {
                        "type": "execute_tool",
                        "technique": tech,
                        "payload": techniques[tech]["payloads"][0],
                        "parameter": state.parameters[0] if state.parameters else "id",
                        "description": f"Fallback: Try {tech}"
                    }
                )
            else:
                return ("All techniques exhausted", {"type": "mark_not_vulnerable", "reason": "All techniques tried"})
    
    async def _act(self, state: ReActState, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        ACTION phase - execute the decided action and observe results.
        Supports all 12+ injection types for comprehensive vulnerability detection.
        """
        action_type = action.get("type", "")
        
        if action_type in ["confirm_vulnerability", "mark_not_vulnerable"]:
            return {"status": "terminal", "type": action_type}
        
        # Execute injection test
        technique = action.get("technique", "")
        payload = action.get("payload", "")
        parameter = action.get("parameter", state.parameters[0] if state.parameters else "id")
        
        # Route to appropriate execution method based on test type
        test_type = state.test_type.lower()
        
        # SQL Injection
        if test_type in ["sqli", "sql", "sql_injection"]:
            return await self._execute_sqli_injection(state, technique, payload, parameter)
        
        # Cross-Site Scripting
        elif test_type in ["xss", "cross_site_scripting"]:
            return await self._execute_xss_injection(state, technique, payload, parameter)
        
        # Local File Inclusion / Path Traversal
        elif test_type in ["lfi", "path_traversal", "file_inclusion"]:
            return await self._execute_lfi_injection(state, technique, payload, parameter)
        
        # Command Injection
        elif test_type in ["command", "cmd", "os_command", "command_injection"]:
            return await self._execute_command_injection(state, technique, payload, parameter)
        
        # LDAP Injection
        elif test_type in ["ldap", "ldap_injection"]:
            return await self._execute_ldap_injection(state, technique, payload, parameter)
        
        # XPath Injection
        elif test_type in ["xpath", "xpath_injection"]:
            return await self._execute_xpath_injection(state, technique, payload, parameter)
        
        # NoSQL Injection
        elif test_type in ["nosql", "nosql_injection", "mongodb"]:
            return await self._execute_nosql_injection(state, technique, payload, parameter)
        
        # Server-Side Template Injection
        elif test_type in ["ssti", "template_injection", "server_side_template_injection"]:
            return await self._execute_ssti_injection(state, technique, payload, parameter)
        
        # XML External Entity Injection
        elif test_type in ["xxe", "xml_external_entity"]:
            return await self._execute_xxe_injection(state, technique, payload, parameter)
        
        # CRLF / Header Injection
        elif test_type in ["crlf", "header_injection"]:
            return await self._execute_crlf_injection(state, technique, payload, parameter)
        
        else:
            # Generic injection test for unknown types
            return await self._execute_generic_injection(state, payload, parameter)
    
    async def _execute_sqli_injection(
        self, 
        state: ReActState, 
        technique: str, 
        payload: str, 
        parameter: str
    ) -> Dict[str, Any]:
        """Execute SQL injection test and analyze response"""
        import httpx
        import time
        
        url = state.target_url
        indicators = self.SQLI_TECHNIQUES.get(technique, {}).get("indicators", [])
        
        # Build request
        headers = {}
        cookies = {}
        if state.auth_session:
            if state.auth_session.get("headers"):
                headers.update(state.auth_session["headers"])
            if state.auth_session.get("cookies"):
                cookies.update(state.auth_session["cookies"])
            if state.auth_session.get("token"):
                headers["Authorization"] = f"Bearer {state.auth_session['token']}"
        
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                start_time = time.time()
                
                # Try GET with parameter
                if "?" in url:
                    test_url = f"{url}&{parameter}={payload}"
                else:
                    test_url = f"{url}?{parameter}={payload}"
                
                response = await client.get(test_url, headers=headers, cookies=cookies)
                elapsed = time.time() - start_time
                
                response_text = response.text.lower()
                status_code = response.status_code
                
                # Analyze response for SQLi indicators
                vulnerable = False
                evidence = []
                
                # Check for error-based indicators
                for indicator in indicators:
                    if indicator.lower() in response_text:
                        vulnerable = True
                        evidence.append(f"SQL indicator found: '{indicator}'")
                
                # Check for common SQL errors
                sql_errors = [
                    "you have an error in your sql syntax",
                    "mysql_fetch",
                    "ora-01756",
                    "sqlite_error",
                    "pg_query",
                    "unclosed quotation mark",
                    "quoted string not properly terminated",
                    "sqlstate",
                    "odbc drivers error"
                ]
                for error in sql_errors:
                    if error in response_text:
                        vulnerable = True
                        evidence.append(f"SQL error message: '{error}'")
                
                # Check for time-based blind (if technique is time_based)
                if technique == "time_based" and elapsed > 4.5:
                    vulnerable = True
                    evidence.append(f"Response delayed {elapsed:.2f}s (expected >5s for time-based)")
                
                # Check for boolean-based blind (compare response lengths)
                if technique == "blind_boolean":
                    # Store for comparison in next iteration
                    pass
                
                return {
                    "status_code": status_code,
                    "response_length": len(response_text),
                    "elapsed_time": elapsed,
                    "vulnerable": vulnerable,
                    "evidence": evidence,
                    "response_snippet": response_text[:500] if vulnerable else response_text[:200],
                    "technique": technique,
                    "payload": payload
                }
                
        except Exception as e:
            return {
                "status_code": 0,
                "error": str(e),
                "vulnerable": False,
                "evidence": []
            }
    
    async def _execute_xss_injection(
        self, 
        state: ReActState, 
        technique: str, 
        payload: str, 
        parameter: str
    ) -> Dict[str, Any]:
        """Execute XSS test and analyze response"""
        import httpx
        from urllib.parse import quote
        
        url = state.target_url
        indicators = self.XSS_TECHNIQUES.get(technique, {}).get("indicators", [])
        
        headers = {}
        cookies = {}
        if state.auth_session:
            if state.auth_session.get("headers"):
                headers.update(state.auth_session["headers"])
            if state.auth_session.get("cookies"):
                cookies.update(state.auth_session["cookies"])
            if state.auth_session.get("token"):
                headers["Authorization"] = f"Bearer {state.auth_session['token']}"
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                # URL encode payload for GET
                encoded_payload = quote(payload, safe='')
                
                if "?" in url:
                    test_url = f"{url}&{parameter}={encoded_payload}"
                else:
                    test_url = f"{url}?{parameter}={encoded_payload}"
                
                response = await client.get(test_url, headers=headers, cookies=cookies)
                response_text = response.text
                
                vulnerable = False
                evidence = []
                
                # Check if payload is reflected unencoded (critical for XSS)
                if payload in response_text:
                    vulnerable = True
                    evidence.append(f"Payload reflected unencoded in response")
                    
                    # Find context
                    idx = response_text.find(payload)
                    context = response_text[max(0, idx-50):min(len(response_text), idx+len(payload)+50)]
                    evidence.append(f"Context: ...{context}...")
                
                # Check for partial reflection (might need different encoding)
                elif any(ind in response_text for ind in indicators):
                    vulnerable = True
                    evidence.append(f"XSS indicator found in response")
                
                return {
                    "status_code": response.status_code,
                    "response_length": len(response_text),
                    "vulnerable": vulnerable,
                    "evidence": evidence,
                    "response_snippet": response_text[:500] if vulnerable else response_text[:200],
                    "technique": technique,
                    "payload": payload,
                    "reflected": payload in response_text
                }
                
        except Exception as e:
            return {
                "status_code": 0,
                "error": str(e),
                "vulnerable": False,
                "evidence": []
            }
    
    async def _execute_lfi_injection(
        self, 
        state: ReActState, 
        technique: str, 
        payload: str, 
        parameter: str
    ) -> Dict[str, Any]:
        """Execute LFI test and analyze response"""
        import httpx
        from urllib.parse import quote
        
        url = state.target_url
        indicators = self.LFI_TECHNIQUES.get(technique, {}).get("indicators", [])
        
        headers = {}
        cookies = {}
        if state.auth_session:
            if state.auth_session.get("headers"):
                headers.update(state.auth_session["headers"])
            if state.auth_session.get("cookies"):
                cookies.update(state.auth_session["cookies"])
            if state.auth_session.get("token"):
                headers["Authorization"] = f"Bearer {state.auth_session['token']}"
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                encoded_payload = quote(payload, safe='')
                
                if "?" in url:
                    test_url = f"{url}&{parameter}={encoded_payload}"
                else:
                    test_url = f"{url}?{parameter}={encoded_payload}"
                
                response = await client.get(test_url, headers=headers, cookies=cookies)
                response_text = response.text
                
                vulnerable = False
                evidence = []
                
                # Check for file content indicators
                for indicator in indicators:
                    if indicator in response_text:
                        vulnerable = True
                        evidence.append(f"File content indicator found: '{indicator}'")
                
                # Check for /etc/passwd content
                if "root:" in response_text and ":0:0:" in response_text:
                    vulnerable = True
                    evidence.append("Linux /etc/passwd content detected")
                
                # Check for win.ini content
                if "[fonts]" in response_text.lower() or "[extensions]" in response_text.lower():
                    vulnerable = True
                    evidence.append("Windows win.ini content detected")
                
                return {
                    "status_code": response.status_code,
                    "response_length": len(response_text),
                    "vulnerable": vulnerable,
                    "evidence": evidence,
                    "response_snippet": response_text[:500] if vulnerable else response_text[:200],
                    "technique": technique,
                    "payload": payload
                }
                
        except Exception as e:
            return {
                "status_code": 0,
                "error": str(e),
                "vulnerable": False,
                "evidence": []
            }
    
    async def _execute_generic_injection(
        self, 
        state: ReActState, 
        payload: str, 
        parameter: str
    ) -> Dict[str, Any]:
        """Execute generic injection test"""
        import httpx
        from urllib.parse import quote
        
        url = state.target_url
        
        headers = {}
        cookies = {}
        if state.auth_session:
            if state.auth_session.get("headers"):
                headers.update(state.auth_session["headers"])
            if state.auth_session.get("cookies"):
                cookies.update(state.auth_session["cookies"])
            if state.auth_session.get("token"):
                headers["Authorization"] = f"Bearer {state.auth_session['token']}"
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                encoded_payload = quote(payload, safe='')
                
                if "?" in url:
                    test_url = f"{url}&{parameter}={encoded_payload}"
                else:
                    test_url = f"{url}?{parameter}={encoded_payload}"
                
                response = await client.get(test_url, headers=headers, cookies=cookies)
                
                return {
                    "status_code": response.status_code,
                    "response_length": len(response.text),
                    "vulnerable": False,  # Generic test doesn't auto-detect
                    "evidence": [],
                    "response_snippet": response.text[:200],
                    "payload": payload
                }
                
        except Exception as e:
            return {
                "status_code": 0,
                "error": str(e),
                "vulnerable": False,
                "evidence": []
            }

    async def _execute_command_injection(
        self, 
        state: ReActState, 
        technique: str, 
        payload: str, 
        parameter: str
    ) -> Dict[str, Any]:
        """Execute OS Command Injection test and analyze response"""
        import httpx
        import time
        from urllib.parse import quote
        
        url = state.target_url
        techniques_dict = self._get_techniques_for_test("command")
        indicators = techniques_dict.get(technique, {}).get("indicators", [])
        
        headers = {}
        cookies = {}
        if state.auth_session:
            if state.auth_session.get("headers"):
                headers.update(state.auth_session["headers"])
            if state.auth_session.get("cookies"):
                cookies.update(state.auth_session["cookies"])
            if state.auth_session.get("token"):
                headers["Authorization"] = f"Bearer {state.auth_session['token']}"
        
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                start_time = time.time()
                
                # Don't fully encode command injection payloads (need special chars)
                if "?" in url:
                    test_url = f"{url}&{parameter}={quote(payload, safe='|;&`$')}"
                else:
                    test_url = f"{url}?{parameter}={quote(payload, safe='|;&`$')}"
                
                response = await client.get(test_url, headers=headers, cookies=cookies)
                elapsed = time.time() - start_time
                
                response_text = response.text.lower()
                
                vulnerable = False
                evidence = []
                
                # Check for command output indicators
                cmd_indicators = [
                    # Unix indicators
                    "root:x:0:0:", "uid=", "gid=", "/bin/bash", "/usr/sbin",
                    "linux", "darwin", "sunos", "freebsd",
                    "total ", "drwx", "-rw-", "permission denied",
                    # Windows indicators  
                    "volume in drive", "directory of", "windows",
                    "<dir>", "bytes free", "command not found",
                    # Error messages that indicate command execution attempted
                    "sh:", "bash:", "cmd:", "/bin/sh:",
                    "syntax error", "unexpected token"
                ]
                
                for indicator in cmd_indicators + indicators:
                    if indicator.lower() in response_text:
                        vulnerable = True
                        evidence.append(f"Command output indicator: '{indicator}'")
                
                # Time-based detection for blind command injection
                if "sleep" in payload.lower() or "timeout" in payload.lower():
                    if elapsed > 4.5:
                        vulnerable = True
                        evidence.append(f"Time-based: Response delayed {elapsed:.2f}s")
                
                # Check for ping-based detection (ICMP)
                if "ping" in payload.lower() and "ttl=" in response_text:
                    vulnerable = True
                    evidence.append("Ping command execution detected (TTL in response)")
                
                return {
                    "status_code": response.status_code,
                    "response_length": len(response_text),
                    "elapsed_time": elapsed,
                    "vulnerable": vulnerable,
                    "evidence": evidence,
                    "response_snippet": response_text[:500] if vulnerable else response_text[:200],
                    "technique": technique,
                    "payload": payload
                }
                
        except Exception as e:
            return {
                "status_code": 0,
                "error": str(e),
                "vulnerable": False,
                "evidence": []
            }

    async def _execute_ldap_injection(
        self, 
        state: ReActState, 
        technique: str, 
        payload: str, 
        parameter: str
    ) -> Dict[str, Any]:
        """Execute LDAP Injection test and analyze response"""
        import httpx
        from urllib.parse import quote
        
        url = state.target_url
        techniques_dict = self._get_techniques_for_test("ldap")
        indicators = techniques_dict.get(technique, {}).get("indicators", [])
        
        headers = {}
        cookies = {}
        if state.auth_session:
            if state.auth_session.get("headers"):
                headers.update(state.auth_session["headers"])
            if state.auth_session.get("cookies"):
                cookies.update(state.auth_session["cookies"])
            if state.auth_session.get("token"):
                headers["Authorization"] = f"Bearer {state.auth_session['token']}"
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                encoded_payload = quote(payload, safe='')
                
                if "?" in url:
                    test_url = f"{url}&{parameter}={encoded_payload}"
                else:
                    test_url = f"{url}?{parameter}={encoded_payload}"
                
                response = await client.get(test_url, headers=headers, cookies=cookies)
                response_text = response.text.lower()
                
                vulnerable = False
                evidence = []
                
                # LDAP-specific error indicators
                ldap_errors = [
                    "ldap_search", "ldap_bind", "ldap error",
                    "invalid dn syntax", "bad search filter",
                    "an invalid dn syntax", "ldap server",
                    "size limit exceeded", "object class violation",
                    "javax.naming.directory", "ldapexception",
                    "unbalanced parentheses", "filter error"
                ]
                
                for indicator in ldap_errors + indicators:
                    if indicator.lower() in response_text:
                        vulnerable = True
                        evidence.append(f"LDAP error indicator: '{indicator}'")
                
                # Check for successful bypass (unexpected data returned)
                if "cn=" in response_text or "dn=" in response_text or "uid=" in response_text:
                    vulnerable = True
                    evidence.append("LDAP attribute data in response (possible bypass)")
                
                return {
                    "status_code": response.status_code,
                    "response_length": len(response_text),
                    "vulnerable": vulnerable,
                    "evidence": evidence,
                    "response_snippet": response_text[:500] if vulnerable else response_text[:200],
                    "technique": technique,
                    "payload": payload
                }
                
        except Exception as e:
            return {
                "status_code": 0,
                "error": str(e),
                "vulnerable": False,
                "evidence": []
            }

    async def _execute_xpath_injection(
        self, 
        state: ReActState, 
        technique: str, 
        payload: str, 
        parameter: str
    ) -> Dict[str, Any]:
        """Execute XPath Injection test and analyze response"""
        import httpx
        from urllib.parse import quote
        
        url = state.target_url
        techniques_dict = self._get_techniques_for_test("xpath")
        indicators = techniques_dict.get(technique, {}).get("indicators", [])
        
        headers = {}
        cookies = {}
        if state.auth_session:
            if state.auth_session.get("headers"):
                headers.update(state.auth_session["headers"])
            if state.auth_session.get("cookies"):
                cookies.update(state.auth_session["cookies"])
            if state.auth_session.get("token"):
                headers["Authorization"] = f"Bearer {state.auth_session['token']}"
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                encoded_payload = quote(payload, safe='')
                
                if "?" in url:
                    test_url = f"{url}&{parameter}={encoded_payload}"
                else:
                    test_url = f"{url}?{parameter}={encoded_payload}"
                
                response = await client.get(test_url, headers=headers, cookies=cookies)
                response_text = response.text.lower()
                
                vulnerable = False
                evidence = []
                
                # XPath-specific error indicators
                xpath_errors = [
                    "xpath", "xmlpathexpr", "invalid xpath",
                    "xpath syntax", "xpathexception", "xml path",
                    "invalid predicate", "invalid expression",
                    "unterminated string literal",
                    "domxpath", "simplexml_load", "xmlquery"
                ]
                
                for indicator in xpath_errors + indicators:
                    if indicator.lower() in response_text:
                        vulnerable = True
                        evidence.append(f"XPath error indicator: '{indicator}'")
                
                return {
                    "status_code": response.status_code,
                    "response_length": len(response_text),
                    "vulnerable": vulnerable,
                    "evidence": evidence,
                    "response_snippet": response_text[:500] if vulnerable else response_text[:200],
                    "technique": technique,
                    "payload": payload
                }
                
        except Exception as e:
            return {
                "status_code": 0,
                "error": str(e),
                "vulnerable": False,
                "evidence": []
            }

    async def _execute_nosql_injection(
        self, 
        state: ReActState, 
        technique: str, 
        payload: str, 
        parameter: str
    ) -> Dict[str, Any]:
        """Execute NoSQL Injection test and analyze response"""
        import httpx
        from urllib.parse import quote
        
        url = state.target_url
        techniques_dict = self._get_techniques_for_test("nosql")
        indicators = techniques_dict.get(technique, {}).get("indicators", [])
        
        headers = {"Content-Type": "application/json"}
        cookies = {}
        if state.auth_session:
            if state.auth_session.get("headers"):
                headers.update(state.auth_session["headers"])
            if state.auth_session.get("cookies"):
                cookies.update(state.auth_session["cookies"])
            if state.auth_session.get("token"):
                headers["Authorization"] = f"Bearer {state.auth_session['token']}"
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                vulnerable = False
                evidence = []
                
                # Try GET request first
                encoded_payload = quote(payload, safe='')
                if "?" in url:
                    test_url = f"{url}&{parameter}={encoded_payload}"
                else:
                    test_url = f"{url}?{parameter}={encoded_payload}"
                
                response = await client.get(test_url, headers=headers, cookies=cookies)
                response_text = response.text.lower()
                
                # NoSQL-specific error indicators
                nosql_errors = [
                    "mongodb", "mongoclient", "mongoerror",
                    "bson", "documentdb", "couchdb",
                    "unexpected token", "json parse error",
                    "syntaxerror", "$where", "$regex",
                    "uncaught exception", "invalid operator"
                ]
                
                for indicator in nosql_errors + indicators:
                    if indicator.lower() in response_text:
                        vulnerable = True
                        evidence.append(f"NoSQL indicator: '{indicator}'")
                
                # Check for authentication bypass indicators
                if response.status_code == 200 and len(response_text) > 100:
                    # Check if we got more data than expected
                    if "[$ne]" in payload or '{"$ne"' in payload:
                        evidence.append("Possible NoSQL auth bypass (data returned with $ne operator)")
                        vulnerable = True
                
                # Also try as POST with JSON body for NoSQL
                if not vulnerable and "{" in payload:
                    try:
                        post_response = await client.post(
                            url, 
                            headers=headers, 
                            cookies=cookies,
                            content=payload
                        )
                        post_text = post_response.text.lower()
                        
                        for indicator in nosql_errors:
                            if indicator.lower() in post_text:
                                vulnerable = True
                                evidence.append(f"NoSQL indicator (POST): '{indicator}'")
                    except:
                        pass
                
                return {
                    "status_code": response.status_code,
                    "response_length": len(response_text),
                    "vulnerable": vulnerable,
                    "evidence": evidence,
                    "response_snippet": response_text[:500] if vulnerable else response_text[:200],
                    "technique": technique,
                    "payload": payload
                }
                
        except Exception as e:
            return {
                "status_code": 0,
                "error": str(e),
                "vulnerable": False,
                "evidence": []
            }

    async def _execute_ssti_injection(
        self, 
        state: ReActState, 
        technique: str, 
        payload: str, 
        parameter: str
    ) -> Dict[str, Any]:
        """Execute Server-Side Template Injection test and analyze response"""
        import httpx
        from urllib.parse import quote
        
        url = state.target_url
        techniques_dict = self._get_techniques_for_test("ssti")
        indicators = techniques_dict.get(technique, {}).get("indicators", [])
        
        headers = {}
        cookies = {}
        if state.auth_session:
            if state.auth_session.get("headers"):
                headers.update(state.auth_session["headers"])
            if state.auth_session.get("cookies"):
                cookies.update(state.auth_session["cookies"])
            if state.auth_session.get("token"):
                headers["Authorization"] = f"Bearer {state.auth_session['token']}"
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                encoded_payload = quote(payload, safe='')
                
                if "?" in url:
                    test_url = f"{url}&{parameter}={encoded_payload}"
                else:
                    test_url = f"{url}?{parameter}={encoded_payload}"
                
                response = await client.get(test_url, headers=headers, cookies=cookies)
                response_text = response.text
                
                vulnerable = False
                evidence = []
                
                # SSTI math-based detection ({{7*7}} = 49, {{7*'7'}} = 7777777)
                ssti_math_results = [
                    "49", "7777777", "42", "12345678987654321",
                    "9", "81", "343"  # Other common math results
                ]
                
                for result in ssti_math_results:
                    if result in response_text:
                        # Make sure it's likely from our payload
                        if "7*7" in payload or "7*'7'" in payload or "3*3" in payload:
                            vulnerable = True
                            evidence.append(f"SSTI math result detected: {result}")
                
                # SSTI error indicators
                ssti_errors = [
                    "jinja2", "mako", "twig", "freemarker",
                    "velocity", "smarty", "thymeleaf",
                    "template", "render", "templateerror",
                    "undefined variable", "undefined method",
                    "erubis", "erb", "haml"
                ]
                
                for indicator in ssti_errors + indicators:
                    if indicator.lower() in response_text.lower():
                        vulnerable = True
                        evidence.append(f"SSTI indicator: '{indicator}'")
                
                # Check for code execution results
                if "uid=" in response_text or "root:" in response_text:
                    vulnerable = True
                    evidence.append("Possible code execution via SSTI")
                
                return {
                    "status_code": response.status_code,
                    "response_length": len(response_text),
                    "vulnerable": vulnerable,
                    "evidence": evidence,
                    "response_snippet": response_text[:500] if vulnerable else response_text[:200],
                    "technique": technique,
                    "payload": payload
                }
                
        except Exception as e:
            return {
                "status_code": 0,
                "error": str(e),
                "vulnerable": False,
                "evidence": []
            }

    async def _execute_xxe_injection(
        self, 
        state: ReActState, 
        technique: str, 
        payload: str, 
        parameter: str
    ) -> Dict[str, Any]:
        """Execute XML External Entity Injection test and analyze response"""
        import httpx
        
        url = state.target_url
        techniques_dict = self._get_techniques_for_test("xxe")
        indicators = techniques_dict.get(technique, {}).get("indicators", [])
        
        headers = {"Content-Type": "application/xml"}
        cookies = {}
        if state.auth_session:
            if state.auth_session.get("headers"):
                headers.update(state.auth_session["headers"])
            if state.auth_session.get("cookies"):
                cookies.update(state.auth_session["cookies"])
            if state.auth_session.get("token"):
                headers["Authorization"] = f"Bearer {state.auth_session['token']}"
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                # XXE typically requires POST with XML body
                response = await client.post(
                    url, 
                    content=payload,
                    headers=headers, 
                    cookies=cookies
                )
                response_text = response.text
                
                vulnerable = False
                evidence = []
                
                # Check for file content (etc/passwd, win.ini)
                if "root:" in response_text and ":0:0:" in response_text:
                    vulnerable = True
                    evidence.append("XXE: /etc/passwd content detected")
                
                if "[fonts]" in response_text.lower() or "[extensions]" in response_text.lower():
                    vulnerable = True
                    evidence.append("XXE: Windows win.ini content detected")
                
                # XXE error indicators
                xxe_errors = [
                    "xml parsing error", "xmlparseentityref",
                    "entity", "dtd", "doctype",
                    "external entity", "systemliteral",
                    "undefined entity", "entityref"
                ]
                
                for indicator in xxe_errors + indicators:
                    if indicator.lower() in response_text.lower():
                        vulnerable = True
                        evidence.append(f"XXE indicator: '{indicator}'")
                
                # Also try with different content types
                for content_type in ["text/xml", "application/x-www-form-urlencoded"]:
                    if not vulnerable:
                        headers["Content-Type"] = content_type
                        try:
                            alt_response = await client.post(
                                url, 
                                content=payload,
                                headers=headers, 
                                cookies=cookies
                            )
                            alt_text = alt_response.text
                            
                            if "root:" in alt_text or "[fonts]" in alt_text.lower():
                                vulnerable = True
                                evidence.append(f"XXE successful with Content-Type: {content_type}")
                        except:
                            pass
                
                return {
                    "status_code": response.status_code,
                    "response_length": len(response_text),
                    "vulnerable": vulnerable,
                    "evidence": evidence,
                    "response_snippet": response_text[:500] if vulnerable else response_text[:200],
                    "technique": technique,
                    "payload": payload
                }
                
        except Exception as e:
            return {
                "status_code": 0,
                "error": str(e),
                "vulnerable": False,
                "evidence": []
            }

    async def _execute_crlf_injection(
        self, 
        state: ReActState, 
        technique: str, 
        payload: str, 
        parameter: str
    ) -> Dict[str, Any]:
        """Execute CRLF / HTTP Header Injection test and analyze response"""
        import httpx
        from urllib.parse import quote
        
        url = state.target_url
        techniques_dict = self._get_techniques_for_test("crlf")
        indicators = techniques_dict.get(technique, {}).get("indicators", [])
        
        headers = {}
        cookies = {}
        if state.auth_session:
            if state.auth_session.get("headers"):
                headers.update(state.auth_session["headers"])
            if state.auth_session.get("cookies"):
                cookies.update(state.auth_session["cookies"])
            if state.auth_session.get("token"):
                headers["Authorization"] = f"Bearer {state.auth_session['token']}"
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                # CRLF payloads shouldn't be fully encoded
                partial_encoded = payload.replace("%0d", "\r").replace("%0a", "\n")
                
                if "?" in url:
                    test_url = f"{url}&{parameter}={quote(payload, safe='%')}"
                else:
                    test_url = f"{url}?{parameter}={quote(payload, safe='%')}"
                
                response = await client.get(
                    test_url, 
                    headers=headers, 
                    cookies=cookies,
                    follow_redirects=False  # Important: don't follow redirects for CRLF
                )
                
                vulnerable = False
                evidence = []
                
                # Check response headers for injected headers
                response_headers = dict(response.headers)
                header_str = str(response_headers).lower()
                
                # Common injected header indicators
                injected_indicators = [
                    "x-injected", "set-cookie", "location:",
                    "x-xss", "x-crlf", "injected-header"
                ]
                
                for indicator in injected_indicators + indicators:
                    if indicator.lower() in header_str:
                        vulnerable = True
                        evidence.append(f"CRLF: Injected header detected - '{indicator}'")
                
                # Check if our payload created a new header
                if "set-cookie:" in header_str and "crlf" in payload.lower():
                    vulnerable = True
                    evidence.append("CRLF: Set-Cookie header injection possible")
                
                # Check response body for header reflection
                response_text = response.text.lower()
                if "http/1." in response_text or "http/2" in response_text:
                    vulnerable = True
                    evidence.append("CRLF: HTTP protocol in body (possible response splitting)")
                
                return {
                    "status_code": response.status_code,
                    "response_length": len(response_text),
                    "vulnerable": vulnerable,
                    "evidence": evidence,
                    "response_headers": response_headers,
                    "response_snippet": response_text[:500] if vulnerable else response_text[:200],
                    "technique": technique,
                    "payload": payload
                }
                
        except Exception as e:
            return {
                "status_code": 0,
                "error": str(e),
                "vulnerable": False,
                "evidence": []
            }
    
    def _build_history_summary(self, state: ReActState) -> str:
        """Build a summary of actions and observations for LLM context"""
        if not state.actions:
            return "No actions taken yet."
        
        summary_parts = []
        for i, (action, obs) in enumerate(zip(state.actions, state.observations), 1):
            summary_parts.append(
                f"Iteration {i}:\n"
                f"  Action: {action.get('type')} - {action.get('technique', 'N/A')}\n"
                f"  Payload: {action.get('payload', 'N/A')[:50]}...\n"
                f"  Result: Status {obs.get('status_code')}, "
                f"{'VULNERABLE' if obs.get('vulnerable') else 'Not vulnerable'}\n"
                f"  Evidence: {', '.join(obs.get('evidence', [])) if obs.get('evidence') else 'None'}"
            )
        
        return "\n".join(summary_parts)
    
    def _get_techniques_for_test(self, test_type: str) -> Dict[str, Any]:
        """Get available techniques for a test type - supports all injection types"""
        technique_map = {
            "sqli": self.SQLI_TECHNIQUES,
            "sql": self.SQLI_TECHNIQUES,
            "sql_injection": self.SQLI_TECHNIQUES,
            "xss": self.XSS_TECHNIQUES,
            "cross_site_scripting": self.XSS_TECHNIQUES,
            "lfi": self.LFI_TECHNIQUES,
            "path_traversal": self.LFI_TECHNIQUES,
            "file_inclusion": self.LFI_TECHNIQUES,
            "command": self.COMMAND_TECHNIQUES,
            "cmd": self.COMMAND_TECHNIQUES,
            "os_command": self.COMMAND_TECHNIQUES,
            "command_injection": self.COMMAND_TECHNIQUES,
            "ldap": self.LDAP_TECHNIQUES,
            "ldap_injection": self.LDAP_TECHNIQUES,
            "xpath": self.XPATH_TECHNIQUES,
            "xpath_injection": self.XPATH_TECHNIQUES,
            "nosql": self.NOSQL_TECHNIQUES,
            "nosql_injection": self.NOSQL_TECHNIQUES,
            "mongodb": self.NOSQL_TECHNIQUES,
            "ssti": self.SSTI_TECHNIQUES_DICT,
            "template_injection": self.SSTI_TECHNIQUES_DICT,
            "server_side_template_injection": self.SSTI_TECHNIQUES_DICT,
            "xxe": self.XXE_TECHNIQUES_DICT,
            "xml_external_entity": self.XXE_TECHNIQUES_DICT,
            "crlf": self.CRLF_TECHNIQUES_DICT,
            "header_injection": self.CRLF_TECHNIQUES_DICT,
            # SSRF techniques
            "ssrf": self.SSRF_TECHNIQUES,
            "server_side_request_forgery": self.SSRF_TECHNIQUES,
            "url_redirect": self.SSRF_TECHNIQUES,
            "open_redirect": self.SSRF_TECHNIQUES,
        }
        return technique_map.get(test_type.lower(), {})
    
    def _parse_llm_json(self, response: str) -> Dict[str, Any]:
        """Parse LLM response, handling various formats"""
        # Remove markdown code blocks if present
        response = re.sub(r'```json\s*', '', response)
        response = re.sub(r'```\s*', '', response)
        response = response.strip()
        
        # Try to find JSON object
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        
        # Return empty dict if parsing fails
        return {}
    
    def _compile_results(self, state: ReActState) -> Dict[str, Any]:
        """Compile final results from ReAct loop"""
        return {
            "target_url": state.target_url,
            "test_type": state.test_type,
            "iterations": state.iteration,
            "confirmed": state.confirmed,
            "vulnerabilities": state.vulnerabilities_found,
            "techniques_tried": state.techniques_tried,
            "payloads_tried": len(state.payloads_tried),
            "final_status": "VULNERABLE" if state.vulnerabilities_found else "NOT_VULNERABLE",
            "confidence": self._calculate_confidence(state),
            "summary": self._generate_summary(state)
        }
    
    def _calculate_confidence(self, state: ReActState) -> str:
        """Calculate confidence level based on evidence"""
        if not state.vulnerabilities_found:
            return "N/A"
        
        total_evidence = sum(len(v.get("evidence", [])) for v in state.vulnerabilities_found)
        
        if state.confirmed and total_evidence >= 3:
            return "HIGH"
        elif total_evidence >= 2:
            return "MEDIUM"
        elif total_evidence >= 1:
            return "LOW"
        else:
            return "UNCERTAIN"
    
    def _generate_summary(self, state: ReActState) -> str:
        """Generate human-readable summary"""
        if state.vulnerabilities_found:
            vuln = state.vulnerabilities_found[0]
            return (
                f"{state.test_type.upper()} vulnerability found at {state.target_url} "
                f"using {vuln.get('technique', 'unknown')} technique. "
                f"Evidence: {', '.join(vuln.get('evidence', []))}"
            )
        else:
            return (
                f"No {state.test_type.upper()} vulnerability found at {state.target_url} "
                f"after {state.iteration} iterations testing {len(state.techniques_tried)} techniques."
            )


# Convenience function for direct usage
async def react_test(
    target_url: str,
    test_type: str,
    parameters: List[str] = None,
    auth_session: Dict[str, Any] = None,
    max_iterations: int = 10
) -> Dict[str, Any]:
    """
    Convenience function to run ReAct loop for vulnerability testing.
    
    Example:
        result = await react_test(
            "http://example.com/search",
            "sqli",
            parameters=["q", "id"],
            max_iterations=10
        )
        if result["confirmed"]:
            print(f"SQLi found! Evidence: {result['vulnerabilities']}")
    """
    loop = ReActLoop()
    return await loop.run(
        target_url=target_url,
        test_type=test_type,
        parameters=parameters,
        auth_session=auth_session,
        max_iterations=max_iterations
    )
