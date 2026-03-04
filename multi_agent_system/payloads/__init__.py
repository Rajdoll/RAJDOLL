# Multi-Agent Security Testing System - Payloads Module
# Generic, application-agnostic payload collections for vulnerability assessment

"""
Payload management module for the multi-agent security testing system.

This module provides comprehensive, generic payloads aligned with Izzat et al.
benchmark research for vulnerability assessment tools comparison.

Target: >80% detection rate per vulnerability category to compete with:
- W3af, ZAP, Wapiti, Arachni, Vega, Nuclei

Key principles:
1. NO application-specific hardcoding
2. Generic payloads that work across any web application  
3. Comprehensive coverage of OWASP Top 10 categories
4. Multi-technique approach per vulnerability type
"""

from .injection_payloads import (
    # Enums and Types
    InjectionType,
    InjectionTechnique,
    
    # SQL Injection
    SQLI_TECHNIQUES,
    
    # Cross-Site Scripting
    XSS_TECHNIQUES,
    
    # Command Injection
    COMMAND_INJECTION_TECHNIQUES,
    
    # LDAP Injection
    LDAP_INJECTION_TECHNIQUES,
    
    # XPath Injection
    XPATH_INJECTION_TECHNIQUES,
    
    # NoSQL Injection
    NOSQL_INJECTION_TECHNIQUES,
    
    # Server-Side Template Injection
    SSTI_TECHNIQUES,
    
    # XML External Entity
    XXE_TECHNIQUES,
    
    # CRLF / Header Injection
    CRLF_TECHNIQUES,
    
    # Local File Inclusion / Path Traversal
    LFI_TECHNIQUES,
    
    # Helper Functions
    get_techniques_for_type,
    get_all_payloads_for_type,
    get_indicators_for_type,
    get_critical_payloads,
)

# Create aliases for shorter names (for react_loop.py compatibility)
LDAP_TECHNIQUES = LDAP_INJECTION_TECHNIQUES
XPATH_TECHNIQUES = XPATH_INJECTION_TECHNIQUES
NOSQL_TECHNIQUES = NOSQL_INJECTION_TECHNIQUES
COMMAND_TECHNIQUES = COMMAND_INJECTION_TECHNIQUES

__all__ = [
    # Types
    "InjectionType",
    "InjectionTechnique",
    
    # Technique Dictionaries (full names)
    "SQLI_TECHNIQUES",
    "XSS_TECHNIQUES",
    "COMMAND_INJECTION_TECHNIQUES",
    "LDAP_INJECTION_TECHNIQUES",
    "XPATH_INJECTION_TECHNIQUES",
    "NOSQL_INJECTION_TECHNIQUES",
    "SSTI_TECHNIQUES",
    "XXE_TECHNIQUES",
    "CRLF_TECHNIQUES",
    "LFI_TECHNIQUES",
    
    # Aliases (short names)
    "LDAP_TECHNIQUES",
    "XPATH_TECHNIQUES",
    "NOSQL_TECHNIQUES",
    "COMMAND_TECHNIQUES",
    
    # Functions
    "get_techniques_for_type",
    "get_all_payloads_for_type",
    "get_indicators_for_type",
    "get_critical_payloads",
]
