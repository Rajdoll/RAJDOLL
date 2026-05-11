from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .wstg_catalog import SubTest


@dataclass
class TestSlot:
    id: str
    endpoint: str
    method: str
    wstg_id: str
    agent_owner: str
    high_risk: bool
    params: List[str]
    status: str = "pending"
    finding_count: int = 0

    @classmethod
    def make(cls, endpoint: str, method: str, wstg_id: str, catalog: Dict[str, SubTest]) -> "TestSlot":
        st = catalog[wstg_id]  # raises KeyError for unknown IDs
        raw = f"{endpoint}|{wstg_id}"
        slot_id = hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:12]
        return cls(
            id=slot_id,
            endpoint=endpoint,
            method=method,
            wstg_id=wstg_id,
            agent_owner=st.owasp_agent,
            high_risk=st.high_risk,
            params=[],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "endpoint": self.endpoint, "method": self.method,
            "wstg_id": self.wstg_id, "agent_owner": self.agent_owner,
            "high_risk": self.high_risk, "params": self.params,
            "status": self.status, "finding_count": self.finding_count,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TestSlot":
        return cls(
            id=d["id"], endpoint=d["endpoint"], method=d["method"],
            wstg_id=d["wstg_id"], agent_owner=d["agent_owner"],
            high_risk=bool(d["high_risk"]), params=list(d.get("params", [])),
            status=d.get("status", "pending"),
            finding_count=int(d.get("finding_count", 0)),
        )


class TestSlotRegistry:
    def __init__(self, slots: List[TestSlot]):
        self._slots = slots

    @classmethod
    def build(
        cls,
        endpoint_map: Dict[str, List[str]],
        endpoints_meta: List[Dict[str, Any]],
        catalog: Dict[str, SubTest],
    ) -> "TestSlotRegistry":
        meta_by_url = {e["url"]: e for e in endpoints_meta}
        slots: List[TestSlot] = []
        for url, wstg_ids in endpoint_map.items():
            meta = meta_by_url.get(url, {})
            method = meta.get("method", "GET")
            params = list(meta.get("params", []))
            for wstg_id in wstg_ids:
                if wstg_id not in catalog:
                    continue
                slot = TestSlot.make(url, method, wstg_id, catalog)
                slot.params = params
                slots.append(slot)
        # high_risk first within each agent group
        slots.sort(key=lambda s: (s.agent_owner, not s.high_risk))
        return cls(slots)

    def slots_for_agent(self, agent_name: str) -> List[TestSlot]:
        return [s for s in self._slots if s.agent_owner == agent_name]

    @property
    def total(self) -> int:
        return len(self._slots)

    def coverage_summary(self) -> Dict[str, Any]:
        total = len(self._slots)
        vulnerable = sum(1 for s in self._slots if s.status == "vulnerable")
        tested_clean = sum(1 for s in self._slots if s.status == "tested-clean")
        skipped = sum(1 for s in self._slots if s.status == "skipped")
        tested = vulnerable + tested_clean
        return {
            "total": total, "tested": tested, "vulnerable": vulnerable,
            "tested_clean": tested_clean, "skipped": skipped,
            "pct_tested": round(tested / total * 100, 1) if total else 0.0,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {"slots": [s.to_dict() for s in self._slots]}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TestSlotRegistry":
        return cls([TestSlot.from_dict(d) for d in data.get("slots", [])])
