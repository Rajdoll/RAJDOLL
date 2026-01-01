---
description: Security audit for credential leaks and vulnerabilities
allowed-tools: Grep, Read, Glob
---

Perform comprehensive security audit:

**Check for:**

1. **Credential Leaks:**
   - Hardcoded passwords, API keys, tokens
   - Database credentials in code
   - AWS/GCP keys
   - Private keys or certificates

2. **Common Vulnerabilities:**
   - SQL injection (raw SQL queries)
   - Command injection (subprocess, os.system with user input)
   - Path traversal (file operations with user paths)
   - Unsafe deserialization (pickle, yaml.load)
   - SSRF (requests without URL validation)

3. **Configuration Issues:**
   - Debug mode in production
   - CORS misconfiguration
   - Missing authentication decorators
   - Weak session configuration

4. **Dependency Vulnerabilities:**
   - Check requirements.txt for known CVEs

**Exclusions:**
- Test files (tests/)
- Documentation (.md files)
- Environment templates (.env.example is OK)

**Output format:**
```
🔴 CRITICAL Issues: X found
   📁 path/to/file.py:line
      Issue: <description>
      Risk: <impact>
      Fix: <remediation>

🟡 MEDIUM Issues: Y found
   ...

✅ No issues found in: [list of checked areas]

📋 Summary:
   Total files scanned: X
   Critical: X | High: X | Medium: X | Low: X
```
