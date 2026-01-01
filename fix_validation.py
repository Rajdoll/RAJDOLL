#!/usr/bin/env python3
"""
LLM Planning Fix Validation Script
Verifies that LLM-generated arguments are properly merged and used
"""

import re
import sys
from pathlib import Path

def validate_fix():
    """Validate that the LLM planning fix is correctly applied"""

    print("="*70)
    print("🔍 Validating LLM Planning Fix")
    print("="*70 + "\n")

    base_agent_path = Path(__file__).parent / "multi_agent_system" / "agents" / "base_agent.py"

    if not base_agent_path.exists():
        print(f"❌ File not found: {base_agent_path}")
        return False

    with open(base_agent_path, "r", encoding="utf-8") as f:
        content = f.read()

    checks = []

    # Check 1: _before_tool_execution call exists in execute_tool
    check1 = "await self._before_tool_execution(server, tool, args)" in content
    checks.append(("_before_tool_execution() call exists", check1))

    # Check 2: Approval check exists
    check2 = 'if not approval.get("approved", True):' in content
    checks.append(("Approval check exists", check2))

    # Check 3: Merged arguments usage
    check3 = 'args = approval.get("arguments", args)' in content
    checks.append(("Merged arguments usage", check3))

    # Check 4: Final args logging
    check4 = '"final_args": args' in content or '"final_args"' in content
    checks.append(("Final args logging exists", check4))

    # Check 5: _merge_planned_arguments method exists
    check5 = "def _merge_planned_arguments(self, tool_name: str, args: Dict[str, Any])" in content
    checks.append(("_merge_planned_arguments() method exists", check5))

    # Check 6: _tool_arguments_map is populated
    check6 = "self._tool_arguments_map" in content and "self._tool_arguments_map.get(tool_name)" in content
    checks.append(("_tool_arguments_map usage exists", check6))

    # Check 7: set_tool_plan stores arguments
    check7 = 'arguments = t.get("arguments")' in content or 'self._tool_arguments_map[tool_name] = dict(arguments)' in content
    checks.append(("set_tool_plan() stores LLM arguments", check7))

    # Print results
    all_passed = True
    for check_name, passed in checks:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status:12s} {check_name}")
        if not passed:
            all_passed = False

    print("\n" + "="*70)

    if all_passed:
        print("🎉 ALL CHECKS PASSED! LLM planning fix is correctly applied.")
        print("\n📋 What was fixed:")
        print("   1. execute_tool() now calls _before_tool_execution() hook")
        print("   2. LLM-generated arguments are merged via _merge_planned_arguments()")
        print("   3. Merged arguments are used for tool execution")
        print("   4. Arguments are logged for debugging (final_args)")
        print("\n🔧 How to verify it works:")
        print("   1. Set DISABLE_LLM_PLANNING=false in .env")
        print("   2. Start a scan")
        print("   3. Check logs for: 'Using LLM arguments for <tool_name>'")
        print("   4. Verify tool commands use LLM-specified payloads/parameters")
        print("="*70)
        return True
    else:
        print("⚠️  SOME CHECKS FAILED - Fix may not be complete!")
        print("\n🔧 Troubleshooting:")
        print("   1. Ensure the Edit operation completed successfully")
        print("   2. Check base_agent.py for merge conflicts")
        print("   3. Review the execute_tool() method manually")
        print("="*70)
        return False

def check_code_pattern():
    """Show before/after code comparison"""
    print("\n📝 Expected Code Pattern in execute_tool():\n")

    expected_pattern = """
    # After line: args = dict(args or {})

    # ✅ FIX: Call hook to merge LLM-generated arguments BEFORE execution
    approval = await self._before_tool_execution(server, tool, args)
    if not approval.get("approved", True):
        self.log("warning", "Tool execution blocked by HITL or policy", {"tool": tool})
        return {"status": "blocked", "message": "Execution denied"}

    # ✅ FIX: Use merged arguments from hook (includes LLM args)
    args = approval.get("arguments", args)

    # Normalize LLM-generated arguments to MCP signatures
    if args:
        args = self._normalize_llm_arguments(tool, args)
    """

    print(expected_pattern)

def show_test_instructions():
    """Show how to test the fix"""
    print("\n🧪 Testing Instructions:\n")
    print("1️⃣  Setup LM Studio or local LLM:")
    print("   - Download Qwen2.5-7B-Instruct-Q4_K_M (~4.4GB)")
    print("   - Start server on port 1234")
    print("   - Update .env with LM Studio config")
    print()
    print("2️⃣  Enable LLM planning in .env:")
    print("   DISABLE_LLM_PLANNING=false")
    print("   LLM_PROVIDER=openai")
    print("   LLM_BASE_URL=http://localhost:1234/v1")
    print("   LLM_MODEL=qwen2.5-7b-instruct-q4_k_m")
    print()
    print("3️⃣  Restart system:")
    print("   docker compose down")
    print("   docker compose up -d")
    print()
    print("4️⃣  Start a test scan:")
    print("   curl -X POST http://localhost:8000/api/scans \\")
    print('     -H "Content-Type: application/json" \\')
    print('     -d \'{"target": "http://juice-shop:3000"}\'')
    print()
    print("5️⃣  Monitor logs for LLM argument usage:")
    print("   docker compose logs -f rajdoll-api | grep 'Using LLM arguments'")
    print("   docker compose logs -f rajdoll-api | grep 'final_args'")
    print()
    print("6️⃣  Expected log output:")
    print('   ✓ "Using LLM arguments for test_sqli"')
    print('   ✓ "final_args": {"url": "...", "payloads": [...], ...}')
    print('   ✓ Tool executes with LLM-specified parameters')
    print()

if __name__ == "__main__":
    success = validate_fix()

    if len(sys.argv) > 1 and sys.argv[1] == "--show-pattern":
        check_code_pattern()

    if len(sys.argv) > 1 and sys.argv[1] == "--show-test":
        show_test_instructions()

    if not success:
        print("\n💡 Tip: Run with --show-pattern to see expected code")
        print("💡 Tip: Run with --show-test to see testing instructions")

    sys.exit(0 if success else 1)
