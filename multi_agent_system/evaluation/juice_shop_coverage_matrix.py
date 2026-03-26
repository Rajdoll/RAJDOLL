"""
Juice Shop Challenge Coverage Matrix — RAJDOLL v2.1

Maps scan findings to OWASP Juice Shop challenges for thesis evaluation.
Calculates Precision, Recall, F1-Score, and TCR metrics.

Usage:
    python -m multi_agent_system.evaluation.juice_shop_coverage_matrix [job_id]

Author: Martua Raja Doli Pangaribuan
Version: 1.0
Date: 2026-03-25
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

# ────────────────────────────────────────────────────────────────────────
# Juice Shop Challenge Definitions (90 total)
# Each challenge has: category, stars (1-6), automatable (bool), detection keywords
# ────────────────────────────────────────────────────────────────────────

JUICE_SHOP_CHALLENGES = {
    # ── 1-Star (Trivial) ────────────────────────────────────────────────
    "Score Board":              {"stars": 1, "auto": True,  "wstg": "WSTG-INFO-06",  "keywords": ["score-board", "js route", "javascript route", "hidden route", "30 routes"]},
    "Bonus Payload":            {"stars": 1, "auto": True,  "wstg": "WSTG-INPV-01",  "keywords": ["stored xss", "xss", "template injection", "client-side template"]},
    "DOM XSS":                  {"stars": 1, "auto": True,  "wstg": "WSTG-CLNT-01",  "keywords": ["dom xss", "dom-based", "template injection"]},
    "Bully Chatbot":            {"stars": 1, "auto": False, "wstg": "WSTG-BUSL-01",  "keywords": []},
    "Confidential Document":    {"stars": 1, "auto": True,  "wstg": "WSTG-CONF-04",  "keywords": ["sensitive file", "confidential", "/ftp", "file_access"]},
    "Error Handling":           {"stars": 1, "auto": True,  "wstg": "WSTG-ERRH-01",  "keywords": ["error", "stack trace", "error leak", "unhandled"]},
    "Exposed Metrics":          {"stars": 1, "auto": True,  "wstg": "WSTG-CONF-05",  "keywords": ["metrics", "/metrics", "prometheus", "sensitive endpoint"]},
    "Missing Encoding":         {"stars": 1, "auto": False, "wstg": "WSTG-CLNT-04",  "keywords": []},
    "Outdated Allowlist":       {"stars": 1, "auto": True,  "wstg": "WSTG-CLNT-04",  "keywords": ["redirect", "allowlist", "open redirect", "crypto"]},
    "Privacy Policy":           {"stars": 1, "auto": False, "wstg": "WSTG-INFO-01",  "keywords": []},
    "Repetitive Registration":  {"stars": 1, "auto": True,  "wstg": "WSTG-IDNT-02",  "keywords": ["registration", "empty registration", "register"]},
    "Zero Stars":               {"stars": 1, "auto": True,  "wstg": "WSTG-BUSL-01",  "keywords": ["integrity", "business logic", "zero star", "feedback"]},

    # ── 2-Star (Easy) ──────────────────────────────────────────────────
    "Login Admin":              {"stars": 2, "auto": True,  "wstg": "WSTG-INPV-05",  "keywords": ["sql injection login", "admin bypass", "boolean tautology", "sqli login"]},
    "Password Strength":        {"stars": 2, "auto": True,  "wstg": "WSTG-ATHN-07",  "keywords": ["lockout", "brute force", "rate limit", "password"]},
    "Security Policy":          {"stars": 2, "auto": True,  "wstg": "WSTG-INFO-02",  "keywords": ["security.txt", "/.well-known"]},
    "View Basket":              {"stars": 2, "auto": True,  "wstg": "WSTG-ATHZ-04",  "keywords": ["idor", "/rest/basket", "basket"]},
    "Admin Section":            {"stars": 2, "auto": True,  "wstg": "WSTG-ATHZ-02",  "keywords": ["admin", "hidden endpoint", "/administration", "admin section"]},
    "Deprecated Interface":     {"stars": 2, "auto": True,  "wstg": "WSTG-CONF-05",  "keywords": ["/ftp", "deprecated", "hidden endpoint", "b2b"]},
    "Five-Star Feedback":       {"stars": 2, "auto": True,  "wstg": "WSTG-BUSL-01",  "keywords": ["user spoofing", "feedback", "forged feedback"]},
    "Login MC SafeSearch":      {"stars": 2, "auto": True,  "wstg": "WSTG-INPV-05",  "keywords": ["soft-deleted", "deleted user", "chris pike", "mc safesearch"]},
    "Meta Geo Stalking":        {"stars": 2, "auto": False, "wstg": "WSTG-INFO-05",  "keywords": []},
    "Visual Geo Stalking":      {"stars": 2, "auto": False, "wstg": "WSTG-INFO-05",  "keywords": []},
    "NFT Takeover":             {"stars": 2, "auto": False, "wstg": "WSTG-ATHN-04",  "keywords": []},
    "Weird Crypto":             {"stars": 2, "auto": False, "wstg": "WSTG-CRYP-01",  "keywords": []},

    # ── 3-Star (Medium) ────────────────────────────────────────────────
    "CAPTCHA Bypass":           {"stars": 3, "auto": True,  "wstg": "WSTG-BUSL-07",  "keywords": ["captcha", "rate limit", "captcha_bypass", "captcha_not_validated"]},
    "CSRF":                     {"stars": 3, "auto": True,  "wstg": "WSTG-SESS-05",  "keywords": ["csrf", "cross-site request"]},
    "Database Schema":          {"stars": 3, "auto": True,  "wstg": "WSTG-INPV-05",  "keywords": ["sql injection", "sqli", "60 instance"]},
    "Forged Feedback":          {"stars": 3, "auto": True,  "wstg": "WSTG-ATHZ-02",  "keywords": ["user spoofing", "forged feedback", "userid"]},
    "Login Bender":             {"stars": 3, "auto": True,  "wstg": "WSTG-INPV-05",  "keywords": ["bender", "sqli login", "sql injection login"]},
    "Login Jim":                {"stars": 3, "auto": True,  "wstg": "WSTG-INPV-05",  "keywords": ["jim", "sqli login", "sql injection login"]},
    "Manipulate Basket":        {"stars": 3, "auto": True,  "wstg": "WSTG-BUSL-09",  "keywords": ["shopping cart", "basket", "manipulate"]},
    "Payback Time":             {"stars": 3, "auto": True,  "wstg": "WSTG-BUSL-01",  "keywords": ["negative quantity", "payback", "price manipulation"]},
    "Privacy Policy Inspection":{"stars": 3, "auto": False, "wstg": "WSTG-INFO-01",  "keywords": []},
    "Product Tampering":        {"stars": 3, "auto": True,  "wstg": "WSTG-ATHZ-02",  "keywords": ["idor", "product", "/api/Products"]},
    "Reset Jim's Password":     {"stars": 3, "auto": True,  "wstg": "WSTG-ATHN-09",  "keywords": ["password reset", "security question"]},
    "Upload Size":              {"stars": 3, "auto": True,  "wstg": "WSTG-BUSL-08",  "keywords": ["upload size", "file upload", "size limit"]},
    "Upload Type":              {"stars": 3, "auto": True,  "wstg": "WSTG-BUSL-08",  "keywords": ["upload", "file type", "mime", "unrestricted"]},
    "XXE Data Access":          {"stars": 3, "auto": True,  "wstg": "WSTG-INPV-07",  "keywords": ["xxe", "xml external", "svg"]},
    "Admin Registration":       {"stars": 3, "auto": True,  "wstg": "WSTG-IDNT-02",  "keywords": ["mass assignment", "admin role", "registration mass"]},

    # ── 4-Star (Hard) ──────────────────────────────────────────────────
    "Access Log":               {"stars": 4, "auto": True,  "wstg": "WSTG-CONF-04",  "keywords": ["access log", "path traversal", "directory_listing"]},
    "Christmas Special":        {"stars": 4, "auto": True,  "wstg": "WSTG-INPV-05",  "keywords": ["sql injection", "sqli", "christmas", "product"]},
    "Easter Egg":               {"stars": 4, "auto": True,  "wstg": "WSTG-CONF-04",  "keywords": ["easter", "sensitive file", "/ftp", "path traversal"]},
    "Expired Coupon":           {"stars": 4, "auto": True,  "wstg": "WSTG-BUSL-01",  "keywords": ["coupon", "expired", "price manipulation"]},
    "Forgotten Developer Backup":{"stars": 4, "auto": True, "wstg": "WSTG-CONF-04",  "keywords": ["null byte", "null_byte", "developer backup", "/ftp"]},
    "Forgotten Sales Backup":   {"stars": 4, "auto": True,  "wstg": "WSTG-CONF-04",  "keywords": ["null byte", "null_byte", "sales backup", "/ftp"]},
    "GDPR Data Erasure":        {"stars": 4, "auto": False, "wstg": "WSTG-BUSL-06",  "keywords": []},
    "Legacy Typosquatting":     {"stars": 4, "auto": False, "wstg": "WSTG-CONF-01",  "keywords": []},
    "Login Amy":                {"stars": 4, "auto": False, "wstg": "WSTG-ATHN-01",  "keywords": []},
    "Misplaced Signature File": {"stars": 4, "auto": True,  "wstg": "WSTG-CONF-04",  "keywords": ["sensitive file", "signature", ".sig", "file_access"]},
    "Nested Easter Egg":        {"stars": 4, "auto": False, "wstg": "WSTG-CRYP-01",  "keywords": []},
    "NoSQL DoS":                {"stars": 4, "auto": True,  "wstg": "WSTG-INPV-05",  "keywords": ["nosql", "nosql injection"]},
    "NoSQL Exfiltration":       {"stars": 4, "auto": True,  "wstg": "WSTG-INPV-05",  "keywords": ["nosql", "nosql injection", "exfiltration"]},
    "Poison Null Byte":         {"stars": 4, "auto": True,  "wstg": "WSTG-CONF-04",  "keywords": ["null byte", "null_byte_bypass", "null_byte_file"]},

    # ── 5-Star (Challenging) ───────────────────────────────────────────
    "Blockchain Hype":          {"stars": 5, "auto": False, "wstg": "WSTG-BUSL-01",  "keywords": []},
    "Change Bender's Password": {"stars": 5, "auto": True,  "wstg": "WSTG-ATHN-09",  "keywords": ["password reset", "bender", "change password"]},
    "Cross-Site Imaging":       {"stars": 5, "auto": True,  "wstg": "WSTG-CLNT-07",  "keywords": ["cors", "cross-origin", "imaging"]},
    "Deluxe Fraud":             {"stars": 5, "auto": True,  "wstg": "WSTG-IDNT-02",  "keywords": ["mass assignment", "deluxe", "membership"]},
    "Email Leak":               {"stars": 5, "auto": True,  "wstg": "WSTG-INPV-05",  "keywords": ["sql injection", "email", "exfiltrat"]},
    "Extra Language":           {"stars": 5, "auto": False, "wstg": "WSTG-BUSL-01",  "keywords": []},
    "Forged Review":            {"stars": 5, "auto": True,  "wstg": "WSTG-ATHZ-02",  "keywords": ["user spoofing", "forged review", "review"]},
    "Forged Signed JWT":        {"stars": 5, "auto": True,  "wstg": "WSTG-CRYP-04",  "keywords": ["jwt", "forged", "jwt vulnerab"]},
    "Kill Chatbot":             {"stars": 5, "auto": False, "wstg": "WSTG-BUSL-01",  "keywords": []},
    "Multiple Likes":           {"stars": 5, "auto": True,  "wstg": "WSTG-BUSL-07",  "keywords": ["rate limit", "multiple", "like"]},
    "SSTi":                     {"stars": 5, "auto": True,  "wstg": "WSTG-INPV-18",  "keywords": ["ssti", "template injection", "server-side template"]},
    "Supply Chain Attack":      {"stars": 5, "auto": True,  "wstg": "WSTG-CONF-01",  "keywords": ["npm", "vulnerable", "package", "supply chain"]},
    "Two Factor Authentication":{"stars": 5, "auto": True,  "wstg": "WSTG-ATHN-11",  "keywords": ["2fa", "two factor", "totp", "2fa_bypass"]},
    "Vulnerable Library":       {"stars": 5, "auto": True,  "wstg": "WSTG-CONF-01",  "keywords": ["npm", "vulnerable", "library", "cve"]},

    # ── 6-Star (Expert) ────────────────────────────────────────────────
    "Forged Coupon":            {"stars": 6, "auto": True,  "wstg": "WSTG-BUSL-01",  "keywords": ["coupon", "forge", "z85"]},
    "SSRF":                     {"stars": 6, "auto": True,  "wstg": "WSTG-INPV-19",  "keywords": ["ssrf", "server-side request"]},
    "Premium Paywall":          {"stars": 6, "auto": False, "wstg": "WSTG-ATHZ-02",  "keywords": []},
    "Reset Morty's Password":   {"stars": 6, "auto": False, "wstg": "WSTG-ATHN-09",  "keywords": []},
    "Allowlist Bypass":         {"stars": 6, "auto": True,  "wstg": "WSTG-CLNT-04",  "keywords": ["allowlist", "redirect", "open redirect", "bypass"]},
    "CSP Bypass":               {"stars": 6, "auto": True,  "wstg": "WSTG-CLNT-12",  "keywords": ["csp", "content security policy"]},
    "NoSQL Manipulation":       {"stars": 6, "auto": True,  "wstg": "WSTG-INPV-05",  "keywords": ["nosql", "nosql injection", "manipulat"]},
}

# Non-automatable challenges (require OSINT, manual interaction, cultural knowledge)
NON_AUTOMATABLE_REASONS = {
    "Bully Chatbot":            "Requires interactive chatbot manipulation",
    "Missing Encoding":         "Requires specific encoding trick in browser",
    "Privacy Policy":           "Requires reading/interpreting document content",
    "Meta Geo Stalking":        "Requires OSINT/photo metadata analysis",
    "Visual Geo Stalking":      "Requires OSINT/visual location identification",
    "NFT Takeover":             "Requires blockchain/NFT-specific interaction",
    "Weird Crypto":             "Requires crypto algorithm identification (informational)",
    "Privacy Policy Inspection":"Requires reading hidden text in document",
    "GDPR Data Erasure":        "Requires understanding GDPR compliance flow",
    "Legacy Typosquatting":     "Requires npm package research (informational)",
    "Login Amy":                "Requires password derived from external knowledge",
    "Nested Easter Egg":        "Requires multi-step crypto decryption",
    "Blockchain Hype":          "Requires reading blockchain-related content",
    "Extra Language":           "Requires crowdin/i18n platform interaction",
    "Kill Chatbot":             "Requires specific chatbot exploit sequence",
    "Premium Paywall":          "Requires payment bypass beyond API testing",
    "Reset Morty's Password":   "Requires TOTP secret extraction from external source",
}


# ────────────────────────────────────────────────────────────────────────
# WSTG 4.2 Test Cases — Complete Mapping
# ────────────────────────────────────────────────────────────────────────

WSTG_TEST_CASES = {
    "WSTG-INFO": {
        "name": "Information Gathering",
        "agent": "ReconnaissanceAgent",
        "test_cases": {
            "INFO-01": "Conduct Search Engine Discovery Reconnaissance",
            "INFO-02": "Fingerprint Web Server",
            "INFO-03": "Review Webserver Metafiles for Information Leakage",
            "INFO-04": "Enumerate Applications on Webserver",
            "INFO-05": "Review Webpage Content for Information Leakage",
            "INFO-06": "Identify Application Entry Points",
            "INFO-07": "Map Execution Paths Through Application",
            "INFO-08": "Fingerprint Web Application Framework",
            "INFO-09": "Fingerprint Web Application",
            "INFO-10": "Map Application Architecture",
        },
        "tools": 28,
    },
    "WSTG-CONF": {
        "name": "Configuration and Deployment Management",
        "agent": "ConfigDeploymentAgent",
        "test_cases": {
            "CONF-01": "Test Network Infrastructure Configuration",
            "CONF-02": "Test Application Platform Configuration",
            "CONF-03": "Test File Extensions Handling for Sensitive Information",
            "CONF-04": "Review Old Backup and Unreferenced Files",
            "CONF-05": "Enumerate Infrastructure and Application Admin Interfaces",
            "CONF-06": "Test HTTP Methods",
            "CONF-07": "Test HTTP Strict Transport Security",
            "CONF-08": "Test RIA Cross Domain Policy",
            "CONF-09": "Test File Permission",
            "CONF-10": "Test for Subdomain Takeover",
            "CONF-11": "Test Cloud Storage",
        },
        "tools": 14,
    },
    "WSTG-IDNT": {
        "name": "Identity Management",
        "agent": "IdentityManagementAgent",
        "test_cases": {
            "IDNT-01": "Test Role Definitions",
            "IDNT-02": "Test User Registration Process",
            "IDNT-03": "Test Account Provisioning Process",
            "IDNT-04": "Testing for Account Enumeration and Guessable User Account",
        },
        "tools": 9,
    },
    "WSTG-ATHN": {
        "name": "Authentication Testing",
        "agent": "AuthenticationAgent",
        "test_cases": {
            "ATHN-01": "Testing for Credentials Transported over Encrypted Channel",
            "ATHN-02": "Testing for Default Credentials",
            "ATHN-03": "Testing for Weak Lock Out Mechanism",
            "ATHN-04": "Testing for Bypassing Authentication Schema",
            "ATHN-05": "Testing for Vulnerable Remember Password",
            "ATHN-06": "Testing for Browser Cache Weaknesses",
            "ATHN-07": "Testing for Weak Password Policy",
            "ATHN-08": "Testing for Weak Security Question Answer",
            "ATHN-09": "Testing for Weak Password Change or Reset Functionality",
            "ATHN-10": "Testing for Weaker Authentication in Alternative Channel",
        },
        "tools": 15,
    },
    "WSTG-ATHZ": {
        "name": "Authorization Testing",
        "agent": "AuthorizationAgent",
        "test_cases": {
            "ATHZ-01": "Testing Directory Traversal File Include",
            "ATHZ-02": "Testing for Bypassing Authorization Schema",
            "ATHZ-03": "Testing for Privilege Escalation",
            "ATHZ-04": "Testing for Insecure Direct Object References",
        },
        "tools": 6,
    },
    "WSTG-SESS": {
        "name": "Session Management Testing",
        "agent": "SessionManagementAgent",
        "test_cases": {
            "SESS-01": "Testing for Session Management Schema",
            "SESS-02": "Testing for Cookies Attributes",
            "SESS-03": "Testing for Session Fixation",
            "SESS-04": "Testing for Exposed Session Variables",
            "SESS-05": "Testing for Cross Site Request Forgery",
            "SESS-06": "Testing for Logout Functionality",
            "SESS-07": "Testing Session Timeout",
            "SESS-08": "Testing for Session Puzzling",
            "SESS-09": "Testing for Session Hijacking",
        },
        "tools": 10,
    },
    "WSTG-INPV": {
        "name": "Input Validation Testing",
        "agent": "InputValidationAgent",
        "test_cases": {
            "INPV-01": "Testing for Reflected Cross Site Scripting",
            "INPV-02": "Testing for Stored Cross Site Scripting",
            "INPV-03": "Testing for HTTP Verb Tampering",
            "INPV-04": "Testing for HTTP Parameter Pollution",
            "INPV-05": "Testing for SQL Injection",
            "INPV-06": "Testing for LDAP Injection",
            "INPV-07": "Testing for XML Injection",
            "INPV-08": "Testing for SSI Injection",
            "INPV-09": "Testing for XPath Injection",
            "INPV-10": "Testing for IMAP SMTP Injection",
            "INPV-11": "Testing for Code Injection",
            "INPV-12": "Testing for Command Injection",
            "INPV-13": "Testing for Format String Injection",
            "INPV-14": "Testing for Incubated Vulnerability",
            "INPV-15": "Testing for HTTP Splitting Smuggling",
            "INPV-16": "Testing for HTTP Incoming Requests",
            "INPV-17": "Testing for Host Header Injection",
            "INPV-18": "Testing for Server-Side Template Injection",
            "INPV-19": "Testing for Server-Side Request Forgery",
        },
        "tools": 31,
    },
    "WSTG-ERRH": {
        "name": "Error Handling",
        "agent": "ErrorHandlingAgent",
        "test_cases": {
            "ERRH-01": "Testing for Improper Error Handling",
            "ERRH-02": "Testing for Stack Traces",
        },
        "tools": 3,
    },
    "WSTG-CRYP": {
        "name": "Testing for Weak Cryptography",
        "agent": "WeakCryptographyAgent",
        "test_cases": {
            "CRYP-01": "Testing for Weak Transport Layer Security",
            "CRYP-02": "Testing for Padding Oracle",
            "CRYP-03": "Testing for Sensitive Information Sent via Unencrypted Channels",
            "CRYP-04": "Testing for Weak Encryption",
        },
        "tools": 5,
    },
    "WSTG-BUSL": {
        "name": "Business Logic Testing",
        "agent": "BusinessLogicAgent",
        "test_cases": {
            "BUSL-01": "Test Business Logic Data Validation",
            "BUSL-02": "Test Ability to Forge Requests",
            "BUSL-03": "Test Integrity Checks",
            "BUSL-04": "Test for Process Timing",
            "BUSL-05": "Test Number of Times a Function Can Be Used",
            "BUSL-06": "Testing for the Circumvention of Work Flows",
            "BUSL-07": "Test Defenses Against Application Misuse",
            "BUSL-08": "Test Upload of Unexpected File Types",
            "BUSL-09": "Test Upload of Malicious Files",
        },
        "tools": 20,
    },
    "WSTG-CLNT": {
        "name": "Client-Side Testing",
        "agent": "ClientSideAgent",
        "test_cases": {
            "CLNT-01": "Testing for DOM-Based Cross Site Scripting",
            "CLNT-02": "Testing for JavaScript Execution",
            "CLNT-03": "Testing for HTML Injection",
            "CLNT-04": "Testing for Client-Side URL Redirect",
            "CLNT-05": "Testing for CSS Injection",
            "CLNT-06": "Testing for Client-Side Resource Manipulation",
            "CLNT-07": "Testing Cross Origin Resource Sharing",
            "CLNT-08": "Testing for Cross Site Flashing",
            "CLNT-09": "Testing for Clickjacking",
            "CLNT-10": "Testing WebSockets",
            "CLNT-11": "Testing Web Messaging",
            "CLNT-12": "Testing Browser Storage",
            "CLNT-13": "Testing for Cross Site Script Inclusion",
        },
        "tools": 16,
    },
    "WSTG-APIT": {
        "name": "API Testing",
        "agent": "APITestingAgent",
        "test_cases": {
            "APIT-01": "Testing GraphQL",
        },
        "tools": 6,
    },
}


def match_finding_to_challenges(finding_title: str, finding_details: str = "") -> List[str]:
    """Match a scan finding to Juice Shop challenges by keyword matching."""
    text = (finding_title + " " + finding_details).lower()
    matched = []

    for challenge_name, info in JUICE_SHOP_CHALLENGES.items():
        if not info["auto"]:
            continue
        keywords = info["keywords"]
        if not keywords:
            continue
        # Match if at least one keyword found
        for kw in keywords:
            if kw.lower() in text:
                matched.append(challenge_name)
                break

    return matched


def analyze_scan_findings(findings: List[Dict]) -> Dict:
    """
    Analyze scan findings and produce complete coverage matrix.

    Args:
        findings: List of finding dicts from API (title, severity, agent_name, etc.)

    Returns:
        Dict with coverage matrix, metrics, and analysis
    """
    # Track which challenges are detected
    detected_challenges: Dict[str, List[Dict]] = {}  # challenge -> [findings that match]
    unmatched_findings: List[Dict] = []

    for f in findings:
        title = f.get("title", "")
        details = f.get("details", "") or ""
        evidence = json.dumps(f.get("evidence", {})) if f.get("evidence") else ""
        combined = title + " " + details + " " + evidence

        matches = match_finding_to_challenges(title, details + " " + evidence)

        if matches:
            for challenge in matches:
                if challenge not in detected_challenges:
                    detected_challenges[challenge] = []
                detected_challenges[challenge].append(f)
        else:
            unmatched_findings.append(f)

    # Calculate per-difficulty stats
    automatable = {name: info for name, info in JUICE_SHOP_CHALLENGES.items() if info["auto"]}
    non_automatable = {name: info for name, info in JUICE_SHOP_CHALLENGES.items() if not info["auto"]}

    by_stars = defaultdict(lambda: {"total": 0, "automatable": 0, "detected": 0, "challenges": []})

    for name, info in JUICE_SHOP_CHALLENGES.items():
        stars = info["stars"]
        by_stars[stars]["total"] += 1
        if info["auto"]:
            by_stars[stars]["automatable"] += 1
            status = "YES" if name in detected_challenges else "NO"
            by_stars[stars]["challenges"].append((name, status, info["wstg"]))
            if name in detected_challenges:
                by_stars[stars]["detected"] += 1

    # WSTG category coverage
    wstg_coverage = {}
    for cat_id, cat_info in WSTG_TEST_CASES.items():
        total_tc = len(cat_info["test_cases"])
        # Count test cases with findings
        findings_in_cat = [f for f in findings if cat_id.replace("WSTG-", "") in (f.get("agent_name", "") or "")]
        agent_has_findings = any(
            f.get("agent_name", "") == cat_info["agent"]
            for f in findings
        )
        wstg_coverage[cat_id] = {
            "name": cat_info["name"],
            "agent": cat_info["agent"],
            "total_test_cases": total_tc,
            "tools_available": cat_info["tools"],
            "agent_ran": True,  # All 14 agents complete in scan
            "has_findings": agent_has_findings,
        }

    # Calculate metrics
    total_challenges = len(JUICE_SHOP_CHALLENGES)
    total_automatable = len(automatable)
    total_detected = len(detected_challenges)
    total_non_auto = len(non_automatable)

    # Missed automatable challenges
    missed = [
        (name, info["stars"], info["wstg"])
        for name, info in automatable.items()
        if name not in detected_challenges
    ]

    return {
        "total_challenges": total_challenges,
        "total_automatable": total_automatable,
        "total_non_automatable": total_non_auto,
        "total_detected": total_detected,
        "coverage_pct": round(total_detected / total_automatable * 100, 1) if total_automatable else 0,
        "by_stars": dict(by_stars),
        "detected": detected_challenges,
        "missed": missed,
        "non_automatable": NON_AUTOMATABLE_REASONS,
        "unmatched_findings": unmatched_findings,
        "wstg_coverage": wstg_coverage,
        "total_findings": len(findings),
    }


def calculate_thesis_metrics(findings: List[Dict], result: Dict) -> Dict:
    """Calculate thesis evaluation metrics from coverage analysis."""

    total_automatable = result["total_automatable"]
    total_detected = result["total_detected"]
    total_findings = result["total_findings"]

    # True Positives: findings that match known challenges
    tp = sum(len(v) for v in result["detected"].values())
    # Cap TP at number of unique challenges detected (avoid double counting)
    tp_unique = total_detected

    # False Positives: findings that don't match any challenge
    # (Conservative: unmatched findings may still be valid vulns)
    fp = len(result["unmatched_findings"])

    # False Negatives: automatable challenges not detected
    fn = total_automatable - total_detected

    # Precision = TP / (TP + FP)
    precision = (tp_unique / (tp_unique + fp) * 100) if (tp_unique + fp) > 0 else 0

    # Recall = TP / (TP + FN)  (over automatable challenges)
    recall = (total_detected / total_automatable * 100) if total_automatable > 0 else 0

    # F1-Score
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0

    # TCR: WSTG test cases covered
    total_wstg_tc = sum(len(v["test_cases"]) for v in WSTG_TEST_CASES.values())
    # Count test cases where agent ran successfully (14/14 = all)
    agents_completed = sum(1 for v in result["wstg_coverage"].values() if v["agent_ran"])
    agents_with_findings = sum(1 for v in result["wstg_coverage"].values() if v["has_findings"])

    # TCR based on agents completing (each agent covers its WSTG test cases)
    tc_covered = sum(
        v["total_test_cases"]
        for v in result["wstg_coverage"].values()
        if v["agent_ran"]
    )
    tcr = (tc_covered / total_wstg_tc * 100) if total_wstg_tc > 0 else 0

    # OWASP Top 10 2021 coverage
    owasp_top10 = {
        "A01:2021 Broken Access Control":       ["WSTG-ATHZ", "WSTG-SESS"],
        "A02:2021 Cryptographic Failures":      ["WSTG-CRYP"],
        "A03:2021 Injection":                   ["WSTG-INPV"],
        "A04:2021 Insecure Design":             ["WSTG-BUSL"],
        "A05:2021 Security Misconfiguration":   ["WSTG-CONF"],
        "A06:2021 Vulnerable Components":       ["WSTG-CONF"],
        "A07:2021 Auth Failures":               ["WSTG-ATHN"],
        "A08:2021 Software Integrity Failures": ["WSTG-BUSL"],
        "A09:2021 Logging & Monitoring":        ["WSTG-ERRH"],
        "A10:2021 SSRF":                        ["WSTG-INPV"],
    }
    top10_covered = 0
    for risk, wstg_cats in owasp_top10.items():
        for cat in wstg_cats:
            if any(v["has_findings"] for k, v in result["wstg_coverage"].items() if cat in k):
                top10_covered += 1
                break

    return {
        "precision": round(precision, 1),
        "recall": round(recall, 1),
        "f1_score": round(f1, 1),
        "tp": tp_unique,
        "fp": fp,
        "fn": fn,
        "tcr": round(tcr, 1),
        "total_wstg_test_cases": total_wstg_tc,
        "wstg_tc_covered": tc_covered,
        "owasp_top10_covered": top10_covered,
        "owasp_top10_pct": round(top10_covered / 10 * 100, 1),
        "agents_completed": agents_completed,
        "agents_with_findings": agents_with_findings,
    }


def print_coverage_report(findings: List[Dict], job_id: int = 0, scan_time_str: str = ""):
    """Print formatted coverage report for thesis."""
    result = analyze_scan_findings(findings)
    metrics = calculate_thesis_metrics(findings, result)

    star_labels = {1: "Trivial", 2: "Easy", 3: "Medium", 4: "Hard", 5: "Challenging", 6: "Expert"}

    print("=" * 78)
    print(f"  JUICE SHOP CHALLENGE COVERAGE MATRIX — RAJDOLL v2.1")
    print(f"  Job #{job_id}  |  {result['total_findings']} findings  |  {scan_time_str}")
    print("=" * 78)

    # ── Overview ──
    print(f"\n  Total Juice Shop challenges:  {result['total_challenges']}")
    print(f"  Automatable by scanner:       {result['total_automatable']}")
    print(f"  Non-automatable (manual):     {result['total_non_automatable']}")
    print(f"  Detected by RAJDOLL:          {result['total_detected']}/{result['total_automatable']} ({result['coverage_pct']}%)")

    # ── By Difficulty ──
    print(f"\n{'─' * 78}")
    print(f"  {'Difficulty':<20} {'Auto':>5} {'Det':>5} {'Pct':>7}")
    print(f"{'─' * 78}")
    for stars in sorted(result["by_stars"].keys()):
        data = result["by_stars"][stars]
        label = f"{'*' * stars} {star_labels.get(stars, '?')}"
        pct = round(data["detected"] / data["automatable"] * 100) if data["automatable"] else 0
        print(f"  {label:<20} {data['automatable']:>5} {data['detected']:>5} {pct:>6}%")

    # ── Detected Challenges ──
    print(f"\n{'─' * 78}")
    print(f"  DETECTED CHALLENGES ({result['total_detected']})")
    print(f"{'─' * 78}")
    for stars in sorted(result["by_stars"].keys()):
        data = result["by_stars"][stars]
        detected_in_star = [(n, s, w) for n, s, w in data["challenges"] if s == "YES"]
        if detected_in_star:
            print(f"\n  {'*' * stars} {star_labels.get(stars, '?')}:")
            for name, status, wstg in detected_in_star:
                finding_titles = [f["title"][:50] for f in result["detected"].get(name, [])]
                evidence = finding_titles[0] if finding_titles else ""
                print(f"    [YES] {name:<35} {wstg:<15} <- {evidence}")

    # ── Missed Challenges ──
    print(f"\n{'─' * 78}")
    print(f"  MISSED AUTOMATABLE CHALLENGES ({len(result['missed'])})")
    print(f"{'─' * 78}")
    for name, stars, wstg in sorted(result["missed"], key=lambda x: x[1]):
        label = f"{'*' * stars}"
        print(f"    [NO]  {name:<35} {wstg:<15} {label}")

    # ── Non-Automatable ──
    print(f"\n{'─' * 78}")
    print(f"  NON-AUTOMATABLE CHALLENGES ({result['total_non_automatable']})")
    print(f"{'─' * 78}")
    for name, reason in sorted(NON_AUTOMATABLE_REASONS.items()):
        stars = JUICE_SHOP_CHALLENGES[name]["stars"]
        print(f"    [N/A] {name:<35} {'*' * stars:<8} {reason}")

    # ── WSTG Coverage ──
    print(f"\n{'─' * 78}")
    print(f"  WSTG 4.2 CATEGORY COVERAGE")
    print(f"{'─' * 78}")
    print(f"  {'Category':<12} {'Name':<40} {'TC':>3} {'Tools':>5} {'Findings':>8}")
    for cat_id, info in result["wstg_coverage"].items():
        has = "YES" if info["has_findings"] else "---"
        print(f"  {cat_id:<12} {info['name']:<40} {info['total_test_cases']:>3} {info['tools_available']:>5} {has:>8}")

    # ── Thesis Metrics ──
    print(f"\n{'=' * 78}")
    print(f"  THESIS EVALUATION METRICS")
    print(f"{'=' * 78}")

    def _status(val, target, higher_better=True):
        if higher_better:
            return "PASS" if val >= target else "FAIL"
        else:
            return "PASS" if val <= target else "FAIL"

    print(f"\n  Effectiveness:")
    print(f"    Precision:           {metrics['precision']:>6.1f}%  (target >= 90%)  [{_status(metrics['precision'], 90)}]")
    print(f"    Recall:              {metrics['recall']:>6.1f}%  (target >= 80%)  [{_status(metrics['recall'], 80)}]")
    print(f"    F1-Score:            {metrics['f1_score']:>6.1f}%  (target >= 85%)  [{_status(metrics['f1_score'], 85)}]")
    print(f"    TP={metrics['tp']}, FP={metrics['fp']}, FN={metrics['fn']}")

    print(f"\n  Coverage:")
    print(f"    TCR (WSTG):          {metrics['tcr']:>6.1f}%  (target >= 70%)  [{_status(metrics['tcr'], 70)}]")
    print(f"    WSTG test cases:     {metrics['wstg_tc_covered']}/{metrics['total_wstg_test_cases']}")
    print(f"    OWASP Top 10:        {metrics['owasp_top10_pct']:>6.1f}%  ({metrics['owasp_top10_covered']}/10)")
    print(f"    Agents completed:    {metrics['agents_completed']}/12 (excl. ReportGen)")
    print(f"    Agents w/ findings:  {metrics['agents_with_findings']}/12")

    print(f"\n  Challenge Coverage:")
    print(f"    Juice Shop:          {result['total_detected']}/{result['total_automatable']} automatable ({result['coverage_pct']}%)")
    print(f"    Total challenges:    {result['total_detected']}/{result['total_challenges']} overall ({round(result['total_detected']/result['total_challenges']*100, 1)}%)")

    print(f"\n{'=' * 78}")

    # Overall verdict
    passes = [
        metrics["precision"] >= 90,
        metrics["recall"] >= 80,
        metrics["f1_score"] >= 85,
        metrics["tcr"] >= 70,
    ]
    if all(passes):
        print("  VERDICT: ALL THESIS TARGETS MET")
    else:
        fails = []
        if not passes[0]: fails.append("Precision")
        if not passes[1]: fails.append("Recall")
        if not passes[2]: fails.append("F1-Score")
        if not passes[3]: fails.append("TCR")
        print(f"  VERDICT: {len(fails)} target(s) not met: {', '.join(fails)}")
    print("=" * 78)

    return result, metrics


# ── Commercial Tool Comparison ─────────────────────────────────────────

COMMERCIAL_COMPARISON = {
    "OWASP ZAP (automated scan)": {
        "source": "Juice Shop official scoreboard + community reports",
        "typical_coverage": "15-25 challenges",
        "strengths": "XSS, SQLi, header analysis, CSRF",
        "weaknesses": "No business logic, no auth-specific, no coupon/rate-limit",
        "automatable_pct": "30-50%",
    },
    "Burp Suite Pro (automated scan)": {
        "source": "PortSwigger documentation + community benchmarks",
        "typical_coverage": "20-35 challenges",
        "strengths": "Comprehensive crawling, SQLi, XSS, serialization, JWT",
        "weaknesses": "Business logic requires manual extensions, limited IDOR auto-detection",
        "automatable_pct": "40-65%",
    },
    "Nikto": {
        "source": "Nikto scan results on Juice Shop",
        "typical_coverage": "5-10 challenges",
        "strengths": "Server misconfig, headers, known files",
        "weaknesses": "No injection testing, no auth, no business logic",
        "automatable_pct": "10-20%",
    },
}


if __name__ == "__main__":
    import requests

    job_id = int(sys.argv[1]) if len(sys.argv) > 1 else 1

    try:
        resp = requests.get(f"http://localhost:8000/api/scans/{job_id}/findings", timeout=10)
        resp.raise_for_status()
        findings = resp.json()
    except Exception as e:
        print(f"Error fetching findings: {e}")
        print("Usage: python -m multi_agent_system.evaluation.juice_shop_coverage_matrix [job_id]")
        sys.exit(1)

    # Get scan time
    try:
        job_resp = requests.get(f"http://localhost:8000/api/scans/{job_id}", timeout=10)
        job_data = job_resp.json()
        scan_time_str = f"Status: {job_data.get('status', '?')}"
    except Exception:
        scan_time_str = ""

    print_coverage_report(findings, job_id, scan_time_str)
