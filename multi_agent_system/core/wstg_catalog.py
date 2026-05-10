from __future__ import annotations
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "wstg_v42_catalog.json"


@dataclass(frozen=True)
class SubTest:
    id: str
    title: str
    category: str
    owasp_agent: str
    high_risk: bool
    applicability: tuple


@lru_cache(maxsize=1)
def load_catalog() -> Dict[str, SubTest]:
    raw = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    return {
        k: SubTest(
            id=v["id"],
            title=v["title"],
            category=v["category"],
            owasp_agent=v["owasp_agent"],
            high_risk=bool(v.get("high_risk", False)),
            applicability=tuple(v.get("applicability", ["always"])),
        )
        for k, v in raw.items()
    }


def subtests_for_category(category: str) -> List[SubTest]:
    return [st for st in load_catalog().values() if st.category == category]


def subtests_for_agent(agent_name: str) -> List[SubTest]:
    return [st for st in load_catalog().values() if st.owasp_agent == agent_name]
