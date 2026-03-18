---
description: Compare findings between two scans to detect regressions or improvements
allowed-tools: Bash, Read, Grep
---

Compare scan **$1** (baseline) with scan **$2** (new).

If only one argument given, compare the two most recent scans.

**Steps:**

1. **Fetch findings from both scans:**
   ```bash
   curl -s http://localhost:8000/api/scans/$1/findings | jq
   curl -s http://localhost:8000/api/scans/$2/findings | jq
   ```

2. **Fetch job metadata (duration, agent status):**
   ```bash
   curl -s http://localhost:8000/api/scans/$1 | jq
   curl -s http://localhost:8000/api/scans/$2 | jq
   ```

3. **Compare metrics:**
   - Total findings count (baseline vs new)
   - Findings by severity
   - Findings by WSTG category
   - Findings by agent
   - New findings not in baseline (improvements)
   - Missing findings that were in baseline (regressions)
   - Duration comparison

4. **Identify regressions:**
   - Vulnerabilities found in baseline but missing in new scan
   - Agents that failed in new scan but succeeded in baseline
   - Categories with reduced coverage

5. **Identify improvements:**
   - New vulnerability types found
   - Additional findings per category
   - Better severity classification

**Output format:**
```
📊 Scan Comparison: #$1 (baseline) vs #$2 (new)

📈 Overview:
                    Baseline    New      Delta
   Total findings:  43          55       +12 ✅
   Critical:         5           7       +2  ✅
   High:            15          20       +5  ✅
   Medium:          18          22       +4  ✅
   Low:              5           6       +1  ✅
   Duration:        2h 15m      2h 30m   +15m

🟢 New Findings (not in baseline):
   1. [HIGH] 2FA bypass - /rest/2fa/verify
   2. [HIGH] Open redirect - /redirect?to=
   3. [MEDIUM] CSP bypass - missing script-src
   ...

🔴 Regressions (in baseline, missing in new):
   1. [HIGH] SQLi in /rest/products/search
   2. [MEDIUM] XSS in /api/Feedbacks
   ...

📋 By Category:
   WSTG-INPV:  15 → 18  (+3 ✅)
   WSTG-ATHN:   5 → 7   (+2 ✅)
   WSTG-ATHZ:   3 → 5   (+2 ✅)
   WSTG-BUSL:   4 → 6   (+2 ✅)
   WSTG-CLNT:   6 → 8   (+2 ✅)
   ...

💡 Analysis:
   - Overall improvement: +28% more findings
   - X regressions need investigation
   - Recommendations: ...
```
