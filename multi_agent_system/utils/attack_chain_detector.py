"""
Attack Chain Detector untuk Multi-Agent Security Testing

Modul untuk mendeteksi dan menganalisis vulnerability chains -
sequences of vulnerabilities that can be chained together
for greater impact.

Examples:
- Auth Bypass → Session Hijack → Admin Access → Data Exfil
- Info Disclosure → Credential Leak → Privilege Escalation
- XSS → Session Stealing → Account Takeover

Author: RAJDOLL Research Project
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict

from .knowledge_graph import KnowledgeGraph, Entity, EntityType, Relationship, RelationType


class ChainImpact(str, Enum):
    """Impact levels for attack chains"""
    CRITICAL = "critical"  # Full system compromise
    HIGH = "high"          # Significant data breach or access
    MEDIUM = "medium"      # Limited unauthorized access
    LOW = "low"            # Minor security issue


class ChainCategory(str, Enum):
    """Categories of attack chains"""
    AUTHENTICATION_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    ACCOUNT_TAKEOVER = "account_takeover"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    LATERAL_MOVEMENT = "lateral_movement"


@dataclass
class AttackChain:
    """
    Represents a chain of vulnerabilities.
    """
    id: str
    name: str
    category: ChainCategory
    impact: ChainImpact
    steps: List[Dict[str, Any]]  # Ordered list of vulnerabilities
    description: str = ""
    prerequisites: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    confidence: float = 0.8
    discovered_by: str = ""
    discovered_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.utcnow()
    
    @property
    def chain_length(self) -> int:
        return len(self.steps)
    
    @property
    def severity_score(self) -> float:
        """Calculate overall severity score"""
        impact_scores = {
            ChainImpact.CRITICAL: 1.0,
            ChainImpact.HIGH: 0.8,
            ChainImpact.MEDIUM: 0.5,
            ChainImpact.LOW: 0.2,
        }
        base_score = impact_scores.get(self.impact, 0.5)
        
        # Longer chains with high impact are more severe
        length_multiplier = min(1.0 + (self.chain_length - 2) * 0.1, 1.3)
        
        return base_score * length_multiplier * self.confidence
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "impact": self.impact.value,
            "steps": self.steps,
            "description": self.description,
            "prerequisites": self.prerequisites,
            "mitigations": self.mitigations,
            "confidence": self.confidence,
            "chain_length": self.chain_length,
            "severity_score": self.severity_score,
            "discovered_by": self.discovered_by,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }


# Known attack chain patterns
CHAIN_PATTERNS = [
    # Authentication Bypass Chains
    {
        "name": "SQL Injection to Admin Access",
        "pattern": ["SQL_INJECTION", "AUTH_BYPASS", "ADMIN_ACCESS"],
        "category": ChainCategory.AUTHENTICATION_BYPASS,
        "impact": ChainImpact.CRITICAL,
        "description": "SQL injection bypasses authentication leading to admin panel access",
    },
    {
        "name": "JWT Manipulation Chain",
        "pattern": ["JWT_NONE_ALGORITHM", "AUTH_BYPASS", "PRIVILEGE_ESCALATION"],
        "category": ChainCategory.PRIVILEGE_ESCALATION,
        "impact": ChainImpact.CRITICAL,
        "description": "JWT none algorithm vulnerability allows role escalation",
    },
    {
        "name": "Password Reset Chain",
        "pattern": ["PASSWORD_RESET_BROKEN", "ACCOUNT_TAKEOVER"],
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "impact": ChainImpact.HIGH,
        "description": "Broken password reset allows account takeover",
    },
    
    # Session-based Chains
    {
        "name": "XSS to Session Hijack",
        "pattern": ["XSS", "SESSION_HIJACK", "ACCOUNT_TAKEOVER"],
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "impact": ChainImpact.HIGH,
        "description": "Stored XSS steals session cookies for account takeover",
    },
    {
        "name": "Session Fixation Chain",
        "pattern": ["SESSION_FIXATION", "SESSION_HIJACK"],
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "impact": ChainImpact.MEDIUM,
        "description": "Session fixation enables session hijacking",
    },
    
    # Data Exfiltration Chains
    {
        "name": "IDOR to Data Breach",
        "pattern": ["IDOR", "DATA_EXTRACTION", "SENSITIVE_DATA_EXPOSURE"],
        "category": ChainCategory.DATA_EXFILTRATION,
        "impact": ChainImpact.HIGH,
        "description": "IDOR vulnerability leads to mass data extraction",
    },
    {
        "name": "SQL Injection Data Dump",
        "pattern": ["SQL_INJECTION", "DATABASE_DUMP", "CREDENTIAL_LEAK"],
        "category": ChainCategory.DATA_EXFILTRATION,
        "impact": ChainImpact.CRITICAL,
        "description": "SQL injection enables full database dump including credentials",
    },
    {
        "name": "Path Traversal to Config Leak",
        "pattern": ["PATH_TRAVERSAL", "CONFIG_EXPOSURE", "CREDENTIAL_LEAK"],
        "category": ChainCategory.DATA_EXFILTRATION,
        "impact": ChainImpact.HIGH,
        "description": "Path traversal exposes configuration files with credentials",
    },
    
    # Privilege Escalation Chains
    {
        "name": "Horizontal to Vertical Escalation",
        "pattern": ["IDOR", "HORIZONTAL_ESCALATION", "VERTICAL_ESCALATION"],
        "category": ChainCategory.PRIVILEGE_ESCALATION,
        "impact": ChainImpact.CRITICAL,
        "description": "IDOR enables access to admin accounts",
    },
    {
        "name": "Business Logic Privilege Chain",
        "pattern": ["BUSINESS_LOGIC_FLAW", "ROLE_MANIPULATION", "ADMIN_ACCESS"],
        "category": ChainCategory.PRIVILEGE_ESCALATION,
        "impact": ChainImpact.HIGH,
        "description": "Business logic flaw allows role manipulation to admin",
    },
    
    # RCE Chains
    {
        "name": "File Upload to RCE",
        "pattern": ["UNRESTRICTED_FILE_UPLOAD", "WEBSHELL", "RCE"],
        "category": ChainCategory.REMOTE_CODE_EXECUTION,
        "impact": ChainImpact.CRITICAL,
        "description": "Unrestricted file upload enables webshell and RCE",
    },
    {
        "name": "Command Injection Chain",
        "pattern": ["COMMAND_INJECTION", "RCE", "LATERAL_MOVEMENT"],
        "category": ChainCategory.REMOTE_CODE_EXECUTION,
        "impact": ChainImpact.CRITICAL,
        "description": "Command injection leads to RCE and network pivoting",
    },
    {
        "name": "Deserialization to RCE",
        "pattern": ["INSECURE_DESERIALIZATION", "RCE"],
        "category": ChainCategory.REMOTE_CODE_EXECUTION,
        "impact": ChainImpact.CRITICAL,
        "description": "Insecure deserialization enables remote code execution",
    },
    
    # Information Disclosure Chains
    {
        "name": "Info Disclosure to Targeted Attack",
        "pattern": ["INFORMATION_DISCLOSURE", "VERSION_FINGERPRINT", "KNOWN_CVE_EXPLOIT"],
        "category": ChainCategory.LATERAL_MOVEMENT,
        "impact": ChainImpact.HIGH,
        "description": "Info disclosure reveals version for targeted CVE exploitation",
    },
]

# Vulnerability type normalization
VULN_TYPE_ALIASES = {
    # SQL Injection
    "sqli": "SQL_INJECTION",
    "sql_injection": "SQL_INJECTION",
    "blind_sqli": "SQL_INJECTION",
    "error_based_sqli": "SQL_INJECTION",
    
    # XSS
    "xss": "XSS",
    "xss_reflected": "XSS",
    "xss_stored": "XSS",
    "dom_xss": "XSS",
    "cross_site_scripting": "XSS",
    
    # Auth
    "auth_bypass": "AUTH_BYPASS",
    "authentication_bypass": "AUTH_BYPASS",
    "broken_auth": "AUTH_BYPASS",
    
    # Session
    "session_hijack": "SESSION_HIJACK",
    "session_stealing": "SESSION_HIJACK",
    "session_fixation": "SESSION_FIXATION",
    
    # Access Control
    "idor": "IDOR",
    "bola": "IDOR",
    "broken_access_control": "IDOR",
    "insecure_direct_object_reference": "IDOR",
    
    # File Upload
    "file_upload": "UNRESTRICTED_FILE_UPLOAD",
    "unrestricted_upload": "UNRESTRICTED_FILE_UPLOAD",
    
    # Command Injection
    "rce": "RCE",
    "command_injection": "COMMAND_INJECTION",
    "os_command_injection": "COMMAND_INJECTION",
    
    # Path Traversal
    "lfi": "PATH_TRAVERSAL",
    "rfi": "PATH_TRAVERSAL",
    "path_traversal": "PATH_TRAVERSAL",
    "directory_traversal": "PATH_TRAVERSAL",
}


class AttackChainDetector:
    """
    Detects attack chains from vulnerabilities.
    
    Usage:
        detector = AttackChainDetector(job_id=1)
        
        # Add vulnerabilities as they're found
        detector.add_vulnerability("SQL_INJECTION", "/api/search", "InputValidationAgent")
        detector.add_vulnerability("AUTH_BYPASS", "/admin", "AuthenticationAgent")
        
        # Detect chains
        chains = detector.detect_chains()
        
        for chain in chains:
            print(f"Chain: {chain.name} ({chain.impact.value})")
            for step in chain.steps:
                print(f"  - {step['type']} at {step['location']}")
    """
    
    def __init__(self, job_id: int, knowledge_graph: Optional[KnowledgeGraph] = None):
        self.job_id = job_id
        self.kg = knowledge_graph or KnowledgeGraph(job_id)
        self._vulnerabilities: List[Dict[str, Any]] = []
        self._detected_chains: List[AttackChain] = []
    
    def add_vulnerability(
        self,
        vuln_type: str,
        location: str,
        agent_name: str,
        severity: str = "medium",
        evidence: Optional[List[str]] = None,
        related_vulns: Optional[List[str]] = None,
    ) -> None:
        """Add a vulnerability for chain analysis"""
        normalized_type = self._normalize_vuln_type(vuln_type)
        
        vuln = {
            "type": normalized_type,
            "original_type": vuln_type,
            "location": location,
            "agent": agent_name,
            "severity": severity,
            "evidence": evidence or [],
            "related_vulns": related_vulns or [],
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        self._vulnerabilities.append(vuln)
    
    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type name"""
        normalized = vuln_type.lower().replace("-", "_").replace(" ", "_")
        return VULN_TYPE_ALIASES.get(normalized, vuln_type.upper())
    
    def detect_chains(self) -> List[AttackChain]:
        """
        Detect attack chains from collected vulnerabilities.
        
        Uses pattern matching against known chain patterns.
        """
        detected = []
        vuln_types = {v["type"] for v in self._vulnerabilities}
        
        for pattern in CHAIN_PATTERNS:
            # Check if we have enough matching vulnerability types
            pattern_types = set(pattern["pattern"])
            matches = pattern_types.intersection(vuln_types)
            
            # Require at least 2/3 of pattern to match
            match_ratio = len(matches) / len(pattern_types)
            
            if match_ratio >= 0.66:
                # Find the actual vulnerabilities that match
                chain_steps = []
                for ptype in pattern["pattern"]:
                    matching_vulns = [
                        v for v in self._vulnerabilities
                        if v["type"] == ptype or self._is_related_type(v["type"], ptype)
                    ]
                    if matching_vulns:
                        chain_steps.append(matching_vulns[0])
                    else:
                        # Add placeholder for inferred step
                        chain_steps.append({
                            "type": ptype,
                            "location": "inferred",
                            "agent": "AttackChainDetector",
                            "inferred": True,
                        })
                
                chain = AttackChain(
                    id=f"chain-{len(detected)+1}-{self.job_id}",
                    name=pattern["name"],
                    category=pattern["category"],
                    impact=pattern["impact"],
                    steps=chain_steps,
                    description=pattern["description"],
                    confidence=match_ratio,
                    discovered_by="AttackChainDetector",
                )
                
                detected.append(chain)
                
                # Add to knowledge graph
                self._add_chain_to_kg(chain)
        
        self._detected_chains = detected
        return detected
    
    def _is_related_type(self, type1: str, type2: str) -> bool:
        """Check if two vulnerability types are related"""
        relations = {
            ("AUTH_BYPASS", "BROKEN_AUTH"),
            ("XSS", "DOM_XSS"),
            ("SQL_INJECTION", "BLIND_SQLI"),
            ("IDOR", "BOLA"),
            ("COMMAND_INJECTION", "RCE"),
        }
        
        pair = (type1.upper(), type2.upper())
        reverse = (type2.upper(), type1.upper())
        
        return pair in relations or reverse in relations
    
    def _add_chain_to_kg(self, chain: AttackChain) -> None:
        """Add detected chain to knowledge graph"""
        vuln_ids = []
        
        for step in chain.steps:
            if not step.get("inferred"):
                vuln_id = f"vuln:{step['type']}:{step['location']}"
                vuln_ids.append(vuln_id)
        
        if len(vuln_ids) >= 2:
            self.kg.link_attack_chain(
                vuln_ids=vuln_ids,
                chain_name=chain.name,
                agent_name="AttackChainDetector",
                impact=chain.impact.value,
            )
    
    def detect_from_knowledge_graph(self) -> List[AttackChain]:
        """
        Detect chains using knowledge graph relationships.
        
        More sophisticated than pattern matching - uses actual
        vulnerability relationships.
        """
        chains = []
        
        # Get all vulnerabilities from KG
        vulns = self.kg.query_by_type(EntityType.VULNERABILITY)
        
        # Build adjacency from LEADS_TO relationships
        leads_to: Dict[str, List[str]] = defaultdict(list)
        for rel in self.kg.get_all_relationships():
            if rel.relation_type == RelationType.LEADS_TO:
                leads_to[rel.source_id].append(rel.target_id)
        
        # Find chains using DFS
        visited_starts = set()
        
        for vuln in vulns:
            if vuln.id in visited_starts:
                continue
            
            # Check if this vuln is a chain starter (not target of LEADS_TO)
            is_target = any(
                vuln.id in targets
                for targets in leads_to.values()
            )
            
            if not is_target and vuln.id in leads_to:
                # Start DFS from this vuln
                chain_vulns = self._dfs_chain(vuln.id, leads_to, set())
                
                if len(chain_vulns) >= 2:
                    chain_entities = [
                        self.kg.get_entity(vid)
                        for vid in chain_vulns
                        if self.kg.get_entity(vid)
                    ]
                    
                    if chain_entities:
                        chain = self._create_chain_from_entities(chain_entities)
                        chains.append(chain)
                        visited_starts.add(vuln.id)
        
        return chains
    
    def _dfs_chain(
        self,
        start: str,
        adjacency: Dict[str, List[str]],
        visited: Set[str]
    ) -> List[str]:
        """DFS to find chain of vulnerabilities"""
        if start in visited:
            return []
        
        visited.add(start)
        chain = [start]
        
        for next_vuln in adjacency.get(start, []):
            sub_chain = self._dfs_chain(next_vuln, adjacency, visited)
            chain.extend(sub_chain)
        
        return chain
    
    def _create_chain_from_entities(self, entities: List[Entity]) -> AttackChain:
        """Create AttackChain from knowledge graph entities"""
        steps = []
        for entity in entities:
            steps.append({
                "type": entity.properties.get("vulnerability_type", "UNKNOWN"),
                "location": entity.name,
                "severity": entity.properties.get("severity", "medium"),
                "confidence": entity.confidence,
            })
        
        # Determine impact based on vulnerability types
        impact = self._determine_chain_impact(steps)
        category = self._determine_chain_category(steps)
        
        return AttackChain(
            id=f"kg-chain-{datetime.utcnow().timestamp()}",
            name=f"Detected Chain: {' → '.join(s['type'] for s in steps)}",
            category=category,
            impact=impact,
            steps=steps,
            description="Chain detected from knowledge graph relationships",
            discovered_by="AttackChainDetector.KG",
        )
    
    def _determine_chain_impact(self, steps: List[Dict[str, Any]]) -> ChainImpact:
        """Determine impact based on vulnerability types in chain"""
        types = {s["type"].upper() for s in steps}
        
        # Critical if RCE or complete auth bypass
        critical_indicators = {"RCE", "COMMAND_INJECTION", "ADMIN_ACCESS", "DATABASE_DUMP"}
        if types.intersection(critical_indicators):
            return ChainImpact.CRITICAL
        
        # High if account takeover or significant data access
        high_indicators = {"ACCOUNT_TAKEOVER", "SESSION_HIJACK", "PRIVILEGE_ESCALATION", "DATA_EXTRACTION"}
        if types.intersection(high_indicators):
            return ChainImpact.HIGH
        
        # Medium for auth/session issues
        medium_indicators = {"AUTH_BYPASS", "SESSION_FIXATION", "IDOR"}
        if types.intersection(medium_indicators):
            return ChainImpact.MEDIUM
        
        return ChainImpact.LOW
    
    def _determine_chain_category(self, steps: List[Dict[str, Any]]) -> ChainCategory:
        """Determine category based on chain endpoints"""
        types = [s["type"].upper() for s in steps]
        
        # Check last step for chain goal
        if types:
            last_type = types[-1]
            
            if last_type in {"RCE", "COMMAND_INJECTION", "WEBSHELL"}:
                return ChainCategory.REMOTE_CODE_EXECUTION
            if last_type in {"ACCOUNT_TAKEOVER", "SESSION_HIJACK"}:
                return ChainCategory.ACCOUNT_TAKEOVER
            if last_type in {"DATA_EXTRACTION", "DATABASE_DUMP", "CREDENTIAL_LEAK"}:
                return ChainCategory.DATA_EXFILTRATION
            if last_type in {"PRIVILEGE_ESCALATION", "ADMIN_ACCESS", "VERTICAL_ESCALATION"}:
                return ChainCategory.PRIVILEGE_ESCALATION
        
        # Check first step for chain origin
        if types and types[0] in {"AUTH_BYPASS", "BROKEN_AUTH"}:
            return ChainCategory.AUTHENTICATION_BYPASS
        
        return ChainCategory.LATERAL_MOVEMENT
    
    def get_all_chains(self) -> List[AttackChain]:
        """Get all detected chains"""
        return self._detected_chains
    
    def get_critical_chains(self) -> List[AttackChain]:
        """Get only critical impact chains"""
        return [c for c in self._detected_chains if c.impact == ChainImpact.CRITICAL]
    
    def get_chains_by_category(self, category: ChainCategory) -> List[AttackChain]:
        """Get chains by category"""
        return [c for c in self._detected_chains if c.category == category]
    
    def to_summary_dict(self) -> Dict[str, Any]:
        """Get summary of all detected chains"""
        by_impact = defaultdict(int)
        by_category = defaultdict(int)
        
        for chain in self._detected_chains:
            by_impact[chain.impact.value] += 1
            by_category[chain.category.value] += 1
        
        return {
            "total_chains": len(self._detected_chains),
            "by_impact": dict(by_impact),
            "by_category": dict(by_category),
            "critical_count": by_impact.get(ChainImpact.CRITICAL.value, 0),
            "chains": [c.to_dict() for c in self._detected_chains],
        }
    
    def generate_report(self) -> str:
        """Generate markdown report of attack chains"""
        if not self._detected_chains:
            return "# Attack Chain Analysis\n\nNo attack chains detected."
        
        report = ["# Attack Chain Analysis\n"]
        report.append(f"**Total Chains Detected:** {len(self._detected_chains)}\n")
        
        # Group by impact
        critical = self.get_critical_chains()
        if critical:
            report.append("\n## 🔴 Critical Impact Chains\n")
            for chain in critical:
                report.append(self._format_chain(chain))
        
        high = [c for c in self._detected_chains if c.impact == ChainImpact.HIGH]
        if high:
            report.append("\n## 🟠 High Impact Chains\n")
            for chain in high:
                report.append(self._format_chain(chain))
        
        return "\n".join(report)
    
    def _format_chain(self, chain: AttackChain) -> str:
        """Format a single chain for report"""
        steps = " → ".join(s.get("type", "?") for s in chain.steps)
        return f"""
### {chain.name}
- **Category:** {chain.category.value}
- **Impact:** {chain.impact.value}
- **Confidence:** {chain.confidence:.0%}
- **Chain:** `{steps}`
- **Description:** {chain.description}
"""


# Convenience function
def detect_attack_chains(job_id: int) -> List[AttackChain]:
    """Quick function to detect chains for a job"""
    detector = AttackChainDetector(job_id)
    return detector.detect_chains()
