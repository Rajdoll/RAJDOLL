from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class OrchestratorDirective:
    focus_instructions: Dict[str, str] = field(default_factory=dict)
    inject_tools: Dict[str, List[dict]] = field(default_factory=dict)
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "focus_instructions": self.focus_instructions,
            "inject_tools": self.inject_tools,
            "reasoning": self.reasoning,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "OrchestratorDirective":
        return cls(
            focus_instructions=dict(d.get("focus_instructions") or {}),
            inject_tools=dict(d.get("inject_tools") or {}),
            reasoning=str(d.get("reasoning") or ""),
        )


def merge_directives(
    accumulated: OrchestratorDirective,
    new: OrchestratorDirective,
) -> OrchestratorDirective:
    """Merge new directive into accumulated. Focus dict-merges (last wins),
    inject_tools list-concats per key, reasoning is replaced."""
    merged_inject: Dict[str, List[dict]] = {}
    for key in set(accumulated.inject_tools) | set(new.inject_tools):
        merged_inject[key] = (
            list(accumulated.inject_tools.get(key) or [])
            + list(new.inject_tools.get(key) or [])
        )

    return OrchestratorDirective(
        focus_instructions={**accumulated.focus_instructions, **new.focus_instructions},
        inject_tools=merged_inject,
        reasoning=new.reasoning,
    )
