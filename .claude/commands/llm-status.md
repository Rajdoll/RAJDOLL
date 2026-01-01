---
description: Check LLM status and verify planning is working
allowed-tools: Bash, Read, Grep
---

Check LLM integration status:

**Checks:**

1. **LM Studio Connection:**
   ```bash
   curl -s http://localhost:1234/v1/models
   ```
   - Verify server responding
   - Show loaded model

2. **Configuration:**
   - Check .env file for LLM_* variables
   - Verify DISABLE_LLM_PLANNING=false
   - Show current LLM_MODEL

3. **Recent LLM Activity:**
   - Grep Docker logs for:
     - "SimpleLLMClient initialized"
     - "LLM selected tools"
     - "Using LLM arguments"
     - "final_args"
   - Show last 10 LLM planning events

4. **Validation:**
   - Run: python fix_validation.py
   - Confirm all checks PASS

**Output format:**
```
🧠 LLM Integration Status

✅ LM Studio Server:
   Status: Running
   Model: qwen2.5-7b-instruct-q4_k_m
   Endpoint: http://localhost:1234/v1

📝 Configuration:
   LLM_PROVIDER: openai
   LLM_BASE_URL: http://localhost:1234/v1
   LLM_MODEL: qwen2.5-7b-instruct-q4_k_m
   DISABLE_LLM_PLANNING: false ✅

📊 Recent Activity (last 10 events):
   [09:15:23] SimpleLLMClient initialized successfully
   [09:16:10] LLM selected 15 tools for InputValidationAgent
   [09:16:15] ✓ Using LLM arguments for test_sqli
   [09:16:15]   final_args: {"url": "...", "payloads": [...]}
   ...

🔍 Validation:
   [Running python fix_validation.py...]
   ✅ PASS _before_tool_execution() call exists
   ✅ PASS Approval check exists
   ✅ PASS Merged arguments usage
   ...
   🎉 ALL CHECKS PASSED!

💡 Status: LLM planning is WORKING correctly ✅
```
