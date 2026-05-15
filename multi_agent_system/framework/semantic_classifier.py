# multi_agent_system/framework/semantic_classifier.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class ClassificationMatch:
    challenge_id: str
    confidence: float
    rationale: str


class SemanticClassifier:
    """Map a finding to ground-truth challenges using deterministic taxonomy first,
    then LLM semantic similarity as tertiary tier.

    Target-agnostic: relies on WSTG / CWE which are public OWASP/MITRE standards.
    """

    def __init__(
        self,
        llm_client: Optional[Any] = None,
        similarity_threshold: float = 0.6,
        enabled: bool = True,
    ):
        self.llm_client = llm_client
        self.similarity_threshold = similarity_threshold
        self.enabled = enabled

    def _match_by_wstg(self, finding: dict, ground_truth: list[dict]) -> list[ClassificationMatch]:
        finding_wstg = self._normalize_wstg(finding.get("category"))
        if not finding_wstg:
            return []
        matches: list[ClassificationMatch] = []
        for gt in ground_truth:
            gt_wstg = self._normalize_wstg(gt.get("wstg") or gt.get("category"))
            if not gt_wstg:
                continue
            if finding_wstg == gt_wstg:
                matches.append(ClassificationMatch(
                    challenge_id=gt.get("id") or gt.get("challenge_id") or "<unknown>",
                    confidence=0.75,
                    rationale=f"WSTG exact match {finding_wstg}",
                ))
            elif ("-" in finding_wstg and "-" in gt_wstg and
                  finding_wstg.split("-")[1] == gt_wstg.split("-")[1]):
                matches.append(ClassificationMatch(
                    challenge_id=gt.get("id") or gt.get("challenge_id") or "<unknown>",
                    confidence=0.55,
                    rationale=f"WSTG prefix match {finding_wstg} ~ {gt_wstg}",
                ))
        return matches

    @staticmethod
    def _normalize_wstg(value: Any) -> Optional[str]:
        if not value:
            return None
        s = str(value).upper().strip()
        return s if s.startswith("WSTG-") else None

    def _match_by_cwe(self, finding: dict, ground_truth: list[dict]) -> list[ClassificationMatch]:
        evidence = finding.get("evidence") or {}
        finding_cwe = evidence.get("cwe_id") or finding.get("cwe_id")
        if not finding_cwe:
            return []
        finding_cwe = str(finding_cwe).upper().strip()
        matches: list[ClassificationMatch] = []
        for gt in ground_truth:
            gt_cwe = gt.get("cwe") or gt.get("cwe_id")
            if not gt_cwe:
                continue
            if str(gt_cwe).upper().strip() == finding_cwe:
                matches.append(ClassificationMatch(
                    challenge_id=gt.get("id") or gt.get("challenge_id") or "<unknown>",
                    confidence=0.85,
                    rationale=f"CWE exact match {finding_cwe}",
                ))
        return matches

    def classify(self, finding: dict, ground_truth: list[dict]) -> list[ClassificationMatch]:
        """Aggregate matches across tiers; return sorted by confidence descending."""
        if not self.enabled:
            return []
        wstg_matches = self._match_by_wstg(finding, ground_truth)
        cwe_matches = self._match_by_cwe(finding, ground_truth)

        # Merge: for same challenge_id, keep max confidence (CWE > WSTG normally)
        merged: dict[str, ClassificationMatch] = {}
        for m in wstg_matches + cwe_matches:
            existing = merged.get(m.challenge_id)
            if existing is None or m.confidence > existing.confidence:
                merged[m.challenge_id] = m

        # Filter by threshold and sort
        out = [m for m in merged.values() if m.confidence >= self.similarity_threshold]
        out.sort(key=lambda x: x.confidence, reverse=True)
        return out
