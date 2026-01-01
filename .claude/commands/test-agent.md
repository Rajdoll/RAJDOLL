---
description: Test specific agent module with coverage report
allowed-tools: Bash, Read, Grep
---

Test the agent module: **$1**

**Steps:**
1. Run pytest for the agent module with verbose output
2. Show coverage report (aim for ≥80%)
3. List any uncovered lines with line numbers
4. Identify edge cases that aren't tested
5. Suggest 3-5 additional test cases to improve coverage

**Focus areas:**
- Error handling paths
- Async timeout scenarios
- LLM argument merging
- Tool execution failures
- Context sharing between agents

**Output format:**
```
✅ Test Results: X/Y passed
📊 Coverage: XX%
❌ Uncovered lines: [list with file:line]
💡 Suggested tests:
   1. Test <scenario>
   2. Test <scenario>
   ...
```
