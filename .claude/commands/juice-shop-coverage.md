---
description: Map scan findings to Juice Shop challenges for thesis coverage analysis
allowed-tools: Bash, Read, Grep
---

Analyze Juice Shop challenge coverage for scan: **$1**

If no job ID provided, use the latest completed scan.

**Steps:**

1. **Fetch all findings from the scan:**
   ```bash
   curl -s http://localhost:8000/api/scans/$1/findings | jq
   ```

2. **Load Juice Shop challenge categories** (90 challenges across 6 difficulty levels):
   - Trivial (1-star): Score Board, Bonus Payload, DOM XSS, etc.
   - Easy (2-star): Login Admin, Password Strength, etc.
   - Medium (3-star): Admin Section, CAPTCHA Bypass, CSRF, etc.
   - Hard (4-star): Christmas Special, Easter Egg, etc.
   - Challenging (5-star): Change Bender Password, Expired Coupon, etc.
   - Expert (6-star): Forged Coupon, SSRF, etc.

3. **Map findings to challenges by vulnerability type:**
   | Finding Type | Juice Shop Challenges |
   |-------------|----------------------|
   | SQL Injection | Login Admin, Login Bender, Login Jim, Christmas Special |
   | XSS (Reflected) | Reflected XSS, Bonus Payload |
   | XSS (DOM) | DOM XSS |
   | XSS (Stored) | Stored XSS via API |
   | IDOR | View Basket, Admin Section access |
   | File access | Confidential Document, Forgotten Developer Backup |
   | Null byte bypass | Poison Null Byte (access encrypt.pyc) |
   | NoSQL injection | NoSQL DoS, NoSQL Exfiltration |
   | Open redirect | Allowlist Bypass (crypto redirect) |
   | Missing rate limit | CAPTCHA Bypass, Multiple Likes |
   | Coupon abuse | Expired Coupon, Forged Coupon |
   | Mass assignment | Admin Registration |
   | User spoofing | Forged Feedback, Forged Review |
   | 2FA bypass | Two Factor Authentication |
   | JWT manipulation | Forged Signed JWT |
   | Path traversal | Access Log, Directory Listing |

4. **Calculate coverage:**
   - Total challenges mappable to automated testing (~47 of 90)
   - Challenges covered by findings
   - Challenges missed
   - Challenges that require manual/OSINT (not automatable)

5. **Group by difficulty level** and show coverage percentage per level.

**Output format:**
```
🧃 Juice Shop Challenge Coverage — Scan #$1

📊 Overall: X/47 automatable challenges covered (XX.X%)

⭐ Trivial (1-star):     X/Y covered
⭐⭐ Easy (2-star):       X/Y covered
⭐⭐⭐ Medium (3-star):    X/Y covered
⭐⭐⭐⭐ Hard (4-star):     X/Y covered
⭐⭐⭐⭐⭐ Challenging:      X/Y covered
⭐⭐⭐⭐⭐⭐ Expert:          X/Y covered

✅ Covered Challenges:
   [SQLi] Login Admin ← "SQL Injection login bypass"
   [SQLi] Login Bender ← "SQLi bypass: bender@juice-sh.op"
   [IDOR] View Basket ← "IDOR vulnerability detected"
   [XSS]  DOM XSS ← "DOM-based XSS detected"
   ...

❌ Missed (automatable but not found):
   [XSS]  Stored XSS — Check InputValidationAgent XSS tools
   [JWT]  Forged Signed JWT — Need JWT manipulation tool
   ...

🚫 Not Automatable (43 challenges):
   [OSINT] Meta Geo Stalking, Visual Geo Stalking
   [Chatbot] Kill Chatbot, Bullying Chatbot
   [Cultural] Bjoern's Favorite Pet, etc.
   ...

📈 Thesis Metrics:
   Recall (automatable): XX.X% (target: ≥80%)
   WSTG categories covered: X/12
```
