# Agent Reference

Overview of the 13 specialist agents that make up RAJDOLL's sequential pipeline. Each agent owns one OWASP WSTG v4.2 category, reads the shared cumulative summary from prior agents, selects tools via its MCP server, and hands its own summary to the next agent.

| # | Agent | WSTG Category | MCP Server | Primary Tools |
|---|-------|---------------|------------|----------------|
| 1 | `ReconnaissanceAgent` | WSTG-INFO | info-mcp, katana-mcp | nmap, ffuf, dirsearch, feroxbuster, subfinder, subjack, whatweb, katana |
| 2 | `AuthenticationAgent` | WSTG-ATHN | auth-mcp | httpx (custom auth scanners) |
| 3 | `SessionManagementAgent` | WSTG-SESS | session-mcp | httpx (custom session scanners) |
| 4 | `InputValidationAgent` | WSTG-INPV | input-mcp | sqlmap, dalfox, commix, ssrfmap, tplmap, ffuf |
| 5 | `AuthorizationAgent` | WSTG-ATHZ | authorz-mcp | httpx (custom authz scanners) |
| 6 | `ConfigDeploymentAgent` | WSTG-CONF | confdep-mcp | nmap, httpx |
| 7 | `ClientSideAgent` | WSTG-CLNT | client-mcp | retire.js, whatweb, httpx |
| 8 | `FileUploadAgent` | WSTG-BUSL (file upload) | fileupload-mcp | httpx (custom upload scanners) |
| 9 | `ErrorHandlingAgent` | WSTG-ERRH | error-mcp | httpx (custom error scanners) |
| 10 | `WeakCryptographyAgent` | WSTG-CRYP | crypto-mcp | httpx (custom crypto scanners) |
| 11 | `BusinessLogicAgent` | WSTG-BUSL (business logic) | biz-mcp | httpx (custom business logic scanners) |
| 12 | `IdentityManagementAgent` | WSTG-IDNT | identity-mcp | httpx (custom identity scanners) |
| 13 | `ReportGenerationAgent` | — (no WSTG category) | — | reads all findings, produces the final OWASP WSTG 4.2 PDF/Markdown report |

Shared infrastructure (not a specialist agent on its own):
- `base_agent.py` — base class all specialist agents inherit from: LLM tool planning, MCP execution, HITL checkpoint, cumulative summary read/write
- `react_agent.py` — ReAct (Reasoning + Acting) loop used by agents to observe/think/act/repeat instead of single-shot planning

## Execution flow

1. Agent reads the cumulative summary produced by every agent that ran before it (not raw logs — see `shared_context_manager.py`).
2. LLM (`select_tools_for_agent()`) picks which of the agent's own tools to call and generates their arguments, constrained by each MCP tool's declared input schema.
3. Agent executes the selected tools through its MCP server (JSON-RPC 2.0).
4. LLM summarizes the agent's findings; the summary is appended to the shared cumulative summary for the next agent.
5. HITL checkpoint: user reviews findings so far and chooses Izinkan / Izinkan Semua / Beri Arahan Lain before the next agent starts.

## Why 12 category agents (not fewer)

The category-to-agent split follows OWASP WSTG v4.2's own 11 categories, with one exception: WSTG-BUSL is split across `BusinessLogicAgent` and `FileUploadAgent` because file-upload testing needs different tooling than general business-logic checks. Categories are not merged further because the local model (Qwen3-4B via LM Studio) has a 4096-token context length — combining categories into one agent would lengthen its prompt enough to risk truncation before the LLM finishes processing it.
