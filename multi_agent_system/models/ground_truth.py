from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped

from ..core.db import Base


class GroundTruthEntry(Base):
    __tablename__ = "ground_truth_entries"

    id: Mapped[int] = Column(Integer, primary_key=True)
    target_profile: Mapped[str] = Column(String(100), nullable=False, index=True)
    vuln_name: Mapped[str] = Column(String(200), nullable=False)
    category: Mapped[str] = Column(String(50), nullable=False)
    severity: Mapped[str] = Column(String(20), nullable=False)
    cvss: Mapped[Optional[float]] = Column(Float, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime, default=datetime.utcnow, nullable=False)
