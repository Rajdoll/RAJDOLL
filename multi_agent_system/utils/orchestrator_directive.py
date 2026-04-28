from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List


NEVER_SKIP: frozenset = frozenset({"ReconnaissanceAgent", "ReportGenerationAgent"})


@dataclass
class OrchestratorDirective:
    skip_agents: List[str] = field(default_factory=list)
    focus_instructions: Dict[str, str] = field(default_factory=dict)
    inject_tools: Dict[str, List[dict]] = field(default_factory=dict)
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "skip_agents": self.skip_agents,
            "focus_instructions": self.focus_instructions,
            "inject_tools": self.inject_tools,
            "reasoning": self.reasoning,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "OrchestratorDirective":
        return cls(
            skip_agents=list(d.get("skip_agents") or []),
            focus_instructions=dict(d.get("focus_instructions") or {}),
            inject_tools=dict(d.get("inject_tools") or {}),
            reasoning=str(d.get("reasoning") or ""),
        )


def merge_directives(
    accumulated: OrchestratorDirective,
    new: OrchestratorDirective,
) -> OrchestratorDirective:
    """Merge new directive into accumulated. NEVER_SKIP agents are silently removed."""
    combined_skips = set(accumulated.skip_agents) | set(new.skip_agents)
    safe_skips = [a for a in combined_skips if a not in NEVER_SKIP]

    merged_inject: Dict[str, List[dict]] = {}
    for key in set(accumulated.inject_tools) | set(new.inject_tools):
        merged_inject[key] = (
            list(accumulated.inject_tools.get(key) or [])
            + list(new.inject_tools.get(key) or [])
        )

    return OrchestratorDirective(
        skip_agents=safe_skips,
        focus_instructions={**accumulated.focus_instructions, **new.focus_instructions},
        inject_tools=merged_inject,
        reasoning=new.reasoning,
    )
