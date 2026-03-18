---
description: Quick findings summary from a scan job with severity breakdown
allowed-tools: Bash, Read, Grep
---

Check findings for scan job: **$1**

If no job ID provided, check the latest scan.

**Steps:**

1. **Get job status:**
   ```bash
   curl -s http://localhost:8000/api/scans/$1 | jq
   ```

2. **Get all findings:**
   ```bash
   curl -s http://localhost:8000/api/scans/$1/findings | jq
   ```

3. **Analyze findings:**
   - Count by severity (critical, high, medium, low, info)
   - Count by WSTG category
   - Count by agent
   - List unique vulnerability types
   - Show top 10 most critical findings with evidence

4. **Check agent completion:**
   - Which agents completed vs failed vs timed out
   - Total scan duration
   - Time per agent

5. **Compare with thesis targets:**
   - Total findings vs previous best
   - Coverage across WSTG categories

**Output format:**
```
📊 Scan #$1 Results

🎯 Target: <target_url>
⏱️  Duration: Xh Ym Zs
📋 Status: completed/failed

📈 Findings Summary: X total
   🔴 Critical: X
   🟠 High:     X
   🟡 Medium:   X
   🔵 Low:      X
   ⚪ Info:     X

📋 By WSTG Category:
   WSTG-INPV: X findings (SQLi, XSS, etc.)
   WSTG-ATHN: X findings (Auth bypass, etc.)
   WSTG-ATHZ: X findings (IDOR, privesc, etc.)
   ...

🤖 Agent Status:
   ✅ ReconnaissanceAgent    (2m 15s) - 3 findings
   ✅ AuthenticationAgent    (5m 30s) - 5 findings
   ❌ InputValidationAgent   (timeout) - 12 findings
   ...

🔝 Top Critical/High Findings:
   1. [CRITICAL] SQL Injection login bypass - /rest/user/login
   2. [HIGH] IDOR on user profiles - /api/Users/{id}
   3. [HIGH] Missing rate limiting - /rest/user/login
   ...
```
