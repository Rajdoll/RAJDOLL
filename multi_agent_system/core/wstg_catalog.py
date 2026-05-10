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
            id=k,
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


TOOL_MAP_PATH = Path(__file__).resolve().parent.parent / "data" / "tool_wstg_map.json"


@lru_cache(maxsize=1)
def _load_tool_map() -> Dict[str, List[str]]:
    return json.loads(TOOL_MAP_PATH.read_text(encoding="utf-8"))


def subtests_for_tool(tool_name: str) -> List[SubTest]:
    cat = load_catalog()
    ids = _load_tool_map().get(tool_name, [])
    return [cat[i] for i in ids if i in cat]


def tools_for_subtest(subtest_id: str) -> List[str]:
    return [t for t, ids in _load_tool_map().items() if subtest_id in ids]


def all_mapped_tools() -> List[str]:
    return list(_load_tool_map().keys())
