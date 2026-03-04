"""
Confidence Scoring System untuk Multi-Agent Security Testing

Sistem scoring yang memberikan confidence level pada setiap finding
berdasarkan evidence, tool verification, dan multiple indicators.

Author: RAJDOLL Research Project
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import hashlib
import json


class ConfidenceLevel(str, Enum):
    """Confidence levels for findings"""
    CONFIRMED = "confirmed"      # 0.9-1.0: Tool-verified exploit success
    HIGH = "high"                # 0.7-0.9: Multiple indicators
    MEDIUM = "medium"            # 0.5-0.7: Single indicator
    LOW = "low"                  # 0.3-0.5: Heuristic match
    SPECULATIVE = "speculative"  # 0.0-0.3: Needs manual verification
    
    @classmethod
    def from_score(cls, score: float) -> "ConfidenceLevel":
        """Convert numeric score to confidence level"""
        if score >= 0.9:
            return cls.CONFIRMED
        elif score >= 0.7:
            return cls.HIGH
        elif score >= 0.5:
            return cls.MEDIUM
        elif score >= 0.3:
            return cls.LOW
        else:
            return cls.SPECULATIVE


class EvidenceType(str, Enum):
    """Types of evidence that contribute to confidence"""
    # Definitive (high weight)
    EXPLOIT_SUCCESS = "exploit_success"      # SQLMap confirmed injection
    DATA_EXTRACTED = "data_extracted"        # Actual data leaked
    CODE_EXECUTION = "code_execution"        # RCE achieved
    
    # Strong (medium-high weight)
    ERROR_BASED = "error_based"              # SQL/XSS error in response
    TIME_BASED = "time_based"                # Timing attack confirmed
    BEHAVIORAL_CHANGE = "behavioral_change"  # Observable behavior difference
    
    # Moderate (medium weight)
    RESPONSE_DIFF = "response_diff"          # Different responses for payloads
    HEADER_INDICATOR = "header_indicator"    # Security headers missing
    PATTERN_MATCH = "pattern_match"          # Regex pattern found
    
    # Weak (low weight)
    HEURISTIC = "heuristic"                  # Heuristic detection
    BANNER_GRAB = "banner_grab"              # Version from banner
    DEFAULT_CONFIG = "default_config"        # Default configuration detected
    
    # Speculative (very low weight)
    INFERENCE = "inference"                  # Inferred from context
    CORRELATION = "correlation"              # Correlated from other findings


class ToolVerificationLevel(str, Enum):
    """Verification level based on tool used"""
    EXPLOIT_TOOL = "exploit_tool"            # SQLMap, Metasploit
    SPECIALIZED_SCANNER = "specialized"      # Dalfox, Nuclei
    GENERAL_SCANNER = "general"              # ZAP, Burp passive
    MANUAL_TEST = "manual"                   # Custom script
    INFERENCE = "inference"                  # LLM/heuristic


# Evidence weight mapping
EVIDENCE_WEIGHTS: Dict[EvidenceType, float] = {
    EvidenceType.EXPLOIT_SUCCESS: 0.95,
    EvidenceType.DATA_EXTRACTED: 0.95,
    EvidenceType.CODE_EXECUTION: 0.98,
    EvidenceType.ERROR_BASED: 0.75,
    EvidenceType.TIME_BASED: 0.70,
    EvidenceType.BEHAVIORAL_CHANGE: 0.65,
    EvidenceType.RESPONSE_DIFF: 0.55,
    EvidenceType.HEADER_INDICATOR: 0.50,
    EvidenceType.PATTERN_MATCH: 0.45,
    EvidenceType.HEURISTIC: 0.35,
    EvidenceType.BANNER_GRAB: 0.30,
    EvidenceType.DEFAULT_CONFIG: 0.25,
    EvidenceType.INFERENCE: 0.15,
    EvidenceType.CORRELATION: 0.10,
}

# Tool verification level weights
TOOL_WEIGHTS: Dict[ToolVerificationLevel, float] = {
    ToolVerificationLevel.EXPLOIT_TOOL: 1.0,
    ToolVerificationLevel.SPECIALIZED_SCANNER: 0.85,
    ToolVerificationLevel.GENERAL_SCANNER: 0.70,
    ToolVerificationLevel.MANUAL_TEST: 0.60,
    ToolVerificationLevel.INFERENCE: 0.30,
}

# Tool to verification level mapping
TOOL_VERIFICATION_MAP: Dict[str, ToolVerificationLevel] = {
    # Exploit tools
    "sqlmap": ToolVerificationLevel.EXPLOIT_TOOL,
    "run_sqlmap": ToolVerificationLevel.EXPLOIT_TOOL,
    "metasploit": ToolVerificationLevel.EXPLOIT_TOOL,
    
    # Specialized scanners
    "dalfox": ToolVerificationLevel.SPECIALIZED_SCANNER,
    "run_dalfox": ToolVerificationLevel.SPECIALIZED_SCANNER,
    "nuclei": ToolVerificationLevel.SPECIALIZED_SCANNER,
    "nikto": ToolVerificationLevel.SPECIALIZED_SCANNER,
    "wfuzz": ToolVerificationLevel.SPECIALIZED_SCANNER,
    "ffuf": ToolVerificationLevel.SPECIALIZED_SCANNER,
    
    # General scanners
    "zap": ToolVerificationLevel.GENERAL_SCANNER,
    "burp": ToolVerificationLevel.GENERAL_SCANNER,
    "nmap": ToolVerificationLevel.GENERAL_SCANNER,
    
    # Manual/custom
    "custom_script": ToolVerificationLevel.MANUAL_TEST,
    "manual_test": ToolVerificationLevel.MANUAL_TEST,
    
    # Inference
    "llm_analysis": ToolVerificationLevel.INFERENCE,
    "heuristic": ToolVerificationLevel.INFERENCE,
}


@dataclass
class Evidence:
    """A piece of evidence supporting a finding"""
    evidence_type: EvidenceType
    description: str
    raw_data: Optional[str] = None
    tool_used: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
    
    @property
    def weight(self) -> float:
        """Get the weight of this evidence"""
        return EVIDENCE_WEIGHTS.get(self.evidence_type, 0.3)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_type": self.evidence_type.value,
            "description": self.description,
            "raw_data": self.raw_data,
            "tool_used": self.tool_used,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "weight": self.weight,
        }


@dataclass
class ConfidenceScore:
    """
    Confidence score for a security finding.
    
    Combines multiple evidence types and tool verification
    to produce a final confidence score.
    """
    finding_id: str
    base_score: float = 0.5
    evidences: List[Evidence] = field(default_factory=list)
    tool_verification: ToolVerificationLevel = ToolVerificationLevel.INFERENCE
    false_positive_indicators: List[str] = field(default_factory=list)
    confirmed_by_agents: Set[str] = field(default_factory=set)
    
    @property
    def final_score(self) -> float:
        """
        Calculate final confidence score.
        
        Formula:
        score = base_score * tool_weight * evidence_boost * (1 - fp_penalty) * agent_boost
        """
        # Start with base score
        score = self.base_score
        
        # Apply tool verification weight
        tool_weight = TOOL_WEIGHTS.get(self.tool_verification, 0.5)
        score *= tool_weight
        
        # Boost from evidence (diminishing returns)
        if self.evidences:
            evidence_weights = sorted([e.weight for e in self.evidences], reverse=True)
            evidence_boost = 1.0
            for i, w in enumerate(evidence_weights[:5]):  # Max 5 evidence pieces
                # Diminishing returns: 100%, 50%, 25%, 12.5%, 6.25%
                evidence_boost += w * (0.5 ** i) * 0.3  # Max 30% boost per evidence
            score *= min(evidence_boost, 1.5)  # Cap at 50% boost
        
        # Penalty for false positive indicators
        fp_penalty = min(len(self.false_positive_indicators) * 0.15, 0.5)
        score *= (1 - fp_penalty)
        
        # Boost for multi-agent confirmation
        if len(self.confirmed_by_agents) > 1:
            agent_boost = 1 + (len(self.confirmed_by_agents) - 1) * 0.1
            score *= min(agent_boost, 1.3)  # Max 30% boost
        
        # Clamp to [0, 1]
        return max(0.0, min(1.0, score))
    
    @property
    def confidence_level(self) -> ConfidenceLevel:
        """Get confidence level from final score"""
        return ConfidenceLevel.from_score(self.final_score)
    
    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence and update tool verification if applicable"""
        self.evidences.append(evidence)
        
        # Update tool verification level if evidence has better tool
        if evidence.tool_used:
            tool_level = TOOL_VERIFICATION_MAP.get(
                evidence.tool_used.lower(),
                ToolVerificationLevel.INFERENCE
            )
            if TOOL_WEIGHTS.get(tool_level, 0) > TOOL_WEIGHTS.get(self.tool_verification, 0):
                self.tool_verification = tool_level
    
    def add_false_positive_indicator(self, indicator: str) -> None:
        """Add a false positive indicator"""
        if indicator not in self.false_positive_indicators:
            self.false_positive_indicators.append(indicator)
    
    def confirm_by_agent(self, agent_name: str) -> None:
        """Mark this finding as confirmed by an agent"""
        self.confirmed_by_agents.add(agent_name)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "final_score": self.final_score,
            "confidence_level": self.confidence_level.value,
            "base_score": self.base_score,
            "tool_verification": self.tool_verification.value,
            "evidences": [e.to_dict() for e in self.evidences],
            "false_positive_indicators": self.false_positive_indicators,
            "confirmed_by_agents": list(self.confirmed_by_agents),
        }


class ConfidenceScorer:
    """
    Confidence scoring system for findings.
    
    Usage:
        scorer = ConfidenceScorer()
        
        # Score a finding
        score = scorer.score_finding(
            finding_id="sqli-1",
            vulnerability_type="SQL_INJECTION",
            tool_used="sqlmap",
            tool_output={"injectable": True, "technique": "time-based blind"},
            agent_name="InputValidationAgent"
        )
        
        print(f"Confidence: {score.final_score} ({score.confidence_level.value})")
    """
    
    # Mapping vulnerability types to expected evidence types
    VULN_EVIDENCE_MAP: Dict[str, List[EvidenceType]] = {
        "SQL_INJECTION": [
            EvidenceType.EXPLOIT_SUCCESS,
            EvidenceType.ERROR_BASED,
            EvidenceType.TIME_BASED,
            EvidenceType.DATA_EXTRACTED,
        ],
        "XSS": [
            EvidenceType.EXPLOIT_SUCCESS,
            EvidenceType.BEHAVIORAL_CHANGE,
            EvidenceType.PATTERN_MATCH,
        ],
        "COMMAND_INJECTION": [
            EvidenceType.CODE_EXECUTION,
            EvidenceType.TIME_BASED,
            EvidenceType.BEHAVIORAL_CHANGE,
        ],
        "PATH_TRAVERSAL": [
            EvidenceType.DATA_EXTRACTED,
            EvidenceType.RESPONSE_DIFF,
            EvidenceType.PATTERN_MATCH,
        ],
        "IDOR": [
            EvidenceType.DATA_EXTRACTED,
            EvidenceType.BEHAVIORAL_CHANGE,
            EvidenceType.RESPONSE_DIFF,
        ],
        "AUTH_BYPASS": [
            EvidenceType.BEHAVIORAL_CHANGE,
            EvidenceType.DATA_EXTRACTED,
        ],
        "MISSING_HEADER": [
            EvidenceType.HEADER_INDICATOR,
        ],
        "INFORMATION_DISCLOSURE": [
            EvidenceType.PATTERN_MATCH,
            EvidenceType.BANNER_GRAB,
        ],
    }
    
    def __init__(self):
        self._scores: Dict[str, ConfidenceScore] = {}
    
    def score_finding(
        self,
        finding_id: str,
        vulnerability_type: str,
        tool_used: Optional[str] = None,
        tool_output: Optional[Dict[str, Any]] = None,
        agent_name: Optional[str] = None,
        manual_base_score: Optional[float] = None,
    ) -> ConfidenceScore:
        """
        Score a finding based on evidence.
        
        Args:
            finding_id: Unique identifier for the finding
            vulnerability_type: Type of vulnerability (e.g., SQL_INJECTION, XSS)
            tool_used: Name of the tool that found it
            tool_output: Raw output from the tool
            agent_name: Name of the agent that found it
            manual_base_score: Override base score if provided
        
        Returns:
            ConfidenceScore object with calculated confidence
        """
        # Get or create score object
        if finding_id in self._scores:
            score = self._scores[finding_id]
        else:
            # Determine base score from vulnerability type
            base_score = manual_base_score or self._get_base_score(vulnerability_type)
            score = ConfidenceScore(
                finding_id=finding_id,
                base_score=base_score,
            )
            self._scores[finding_id] = score
        
        # Set tool verification level
        if tool_used:
            tool_level = TOOL_VERIFICATION_MAP.get(
                tool_used.lower(),
                ToolVerificationLevel.INFERENCE
            )
            if TOOL_WEIGHTS.get(tool_level, 0) > TOOL_WEIGHTS.get(score.tool_verification, 0):
                score.tool_verification = tool_level
        
        # Extract evidence from tool output
        if tool_output:
            evidences = self._extract_evidence(
                vulnerability_type,
                tool_used or "unknown",
                tool_output
            )
            for evidence in evidences:
                score.add_evidence(evidence)
        
        # Confirm by agent
        if agent_name:
            score.confirm_by_agent(agent_name)
        
        return score
    
    def _get_base_score(self, vulnerability_type: str) -> float:
        """Get base score based on vulnerability type"""
        # Critical vulnerabilities start higher
        critical_vulns = {"SQL_INJECTION", "COMMAND_INJECTION", "RCE", "SSRF"}
        high_vulns = {"XSS", "AUTH_BYPASS", "PATH_TRAVERSAL", "IDOR"}
        medium_vulns = {"CSRF", "OPEN_REDIRECT", "INFORMATION_DISCLOSURE"}
        
        vuln_upper = vulnerability_type.upper()
        if vuln_upper in critical_vulns:
            return 0.6
        elif vuln_upper in high_vulns:
            return 0.5
        elif vuln_upper in medium_vulns:
            return 0.4
        else:
            return 0.35
    
    def _extract_evidence(
        self,
        vulnerability_type: str,
        tool_used: str,
        tool_output: Dict[str, Any]
    ) -> List[Evidence]:
        """Extract evidence from tool output"""
        evidences = []
        
        # SQLMap specific parsing
        if "sqlmap" in tool_used.lower():
            evidences.extend(self._parse_sqlmap_output(tool_output))
        
        # Dalfox specific parsing
        elif "dalfox" in tool_used.lower():
            evidences.extend(self._parse_dalfox_output(tool_output))
        
        # Generic parsing
        else:
            evidences.extend(self._parse_generic_output(tool_output, vulnerability_type))
        
        return evidences
    
    def _parse_sqlmap_output(self, output: Dict[str, Any]) -> List[Evidence]:
        """Parse SQLMap output for evidence"""
        evidences = []
        
        # Check for injectable parameter
        if output.get("injectable"):
            evidences.append(Evidence(
                evidence_type=EvidenceType.EXPLOIT_SUCCESS,
                description="SQLMap confirmed SQL injection",
                tool_used="sqlmap"
            ))
        
        # Check for specific techniques
        technique = output.get("technique", "")
        if "time-based" in str(technique).lower():
            evidences.append(Evidence(
                evidence_type=EvidenceType.TIME_BASED,
                description=f"Time-based blind SQL injection: {technique}",
                tool_used="sqlmap"
            ))
        if "error-based" in str(technique).lower():
            evidences.append(Evidence(
                evidence_type=EvidenceType.ERROR_BASED,
                description=f"Error-based SQL injection: {technique}",
                tool_used="sqlmap"
            ))
        if "union" in str(technique).lower():
            evidences.append(Evidence(
                evidence_type=EvidenceType.EXPLOIT_SUCCESS,
                description=f"UNION-based SQL injection: {technique}",
                tool_used="sqlmap"
            ))
        
        # Check for data extraction
        if output.get("data_extracted") or output.get("tables") or output.get("databases"):
            evidences.append(Evidence(
                evidence_type=EvidenceType.DATA_EXTRACTED,
                description="Database information extracted via SQL injection",
                raw_data=str(output.get("data_extracted") or output.get("tables") or output.get("databases")),
                tool_used="sqlmap"
            ))
        
        return evidences
    
    def _parse_dalfox_output(self, output: Dict[str, Any]) -> List[Evidence]:
        """Parse Dalfox output for evidence"""
        evidences = []
        
        # Check for confirmed XSS
        if output.get("verified") or output.get("poc"):
            evidences.append(Evidence(
                evidence_type=EvidenceType.EXPLOIT_SUCCESS,
                description="Dalfox confirmed XSS vulnerability",
                raw_data=output.get("poc"),
                tool_used="dalfox"
            ))
        
        # Check for reflected parameter
        if output.get("reflected"):
            evidences.append(Evidence(
                evidence_type=EvidenceType.PATTERN_MATCH,
                description="Reflected parameter detected",
                tool_used="dalfox"
            ))
        
        return evidences
    
    def _parse_generic_output(
        self,
        output: Dict[str, Any],
        vulnerability_type: str
    ) -> List[Evidence]:
        """Parse generic tool output"""
        evidences = []
        
        # Common indicators
        if output.get("vulnerable", False) or output.get("confirmed", False):
            evidences.append(Evidence(
                evidence_type=EvidenceType.PATTERN_MATCH,
                description=f"Tool confirmed {vulnerability_type}",
            ))
        
        if output.get("error_message"):
            evidences.append(Evidence(
                evidence_type=EvidenceType.ERROR_BASED,
                description=f"Error message observed: {output.get('error_message')[:200]}",
                raw_data=output.get("error_message"),
            ))
        
        if output.get("response_diff"):
            evidences.append(Evidence(
                evidence_type=EvidenceType.RESPONSE_DIFF,
                description="Different responses observed for test payloads",
            ))
        
        return evidences
    
    def get_score(self, finding_id: str) -> Optional[ConfidenceScore]:
        """Get score for a finding"""
        return self._scores.get(finding_id)
    
    def get_all_scores(self) -> Dict[str, ConfidenceScore]:
        """Get all scores"""
        return dict(self._scores)
    
    def get_high_confidence_findings(
        self,
        min_level: ConfidenceLevel = ConfidenceLevel.MEDIUM
    ) -> List[ConfidenceScore]:
        """Get findings at or above a confidence level"""
        level_order = [
            ConfidenceLevel.SPECULATIVE,
            ConfidenceLevel.LOW,
            ConfidenceLevel.MEDIUM,
            ConfidenceLevel.HIGH,
            ConfidenceLevel.CONFIRMED,
        ]
        min_idx = level_order.index(min_level)
        
        return [
            score for score in self._scores.values()
            if level_order.index(score.confidence_level) >= min_idx
        ]
    
    def get_false_positive_rate_estimate(self) -> float:
        """
        Estimate false positive rate based on confidence distribution.
        
        Low confidence findings are more likely to be false positives.
        """
        if not self._scores:
            return 0.0
        
        # Weight by inverse confidence
        fp_weights = {
            ConfidenceLevel.CONFIRMED: 0.05,
            ConfidenceLevel.HIGH: 0.10,
            ConfidenceLevel.MEDIUM: 0.25,
            ConfidenceLevel.LOW: 0.50,
            ConfidenceLevel.SPECULATIVE: 0.75,
        }
        
        total_fp_weight = sum(
            fp_weights.get(score.confidence_level, 0.5)
            for score in self._scores.values()
        )
        
        return total_fp_weight / len(self._scores)
    
    def to_summary_dict(self) -> Dict[str, Any]:
        """Get summary of all scores"""
        level_counts = {level.value: 0 for level in ConfidenceLevel}
        for score in self._scores.values():
            level_counts[score.confidence_level.value] += 1
        
        return {
            "total_findings": len(self._scores),
            "by_confidence_level": level_counts,
            "estimated_false_positive_rate": self.get_false_positive_rate_estimate(),
            "high_confidence_count": len(self.get_high_confidence_findings(ConfidenceLevel.HIGH)),
            "findings": [score.to_dict() for score in self._scores.values()],
        }


# Convenience function for quick scoring
def score_finding(
    finding_id: str,
    vulnerability_type: str,
    tool_used: Optional[str] = None,
    tool_output: Optional[Dict[str, Any]] = None,
    agent_name: Optional[str] = None,
) -> ConfidenceScore:
    """Quick function to score a single finding"""
    scorer = ConfidenceScorer()
    return scorer.score_finding(
        finding_id=finding_id,
        vulnerability_type=vulnerability_type,
        tool_used=tool_used,
        tool_output=tool_output,
        agent_name=agent_name,
    )
