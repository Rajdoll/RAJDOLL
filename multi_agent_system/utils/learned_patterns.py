from __future__ import annotations
import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List


_LOCK = threading.Lock()  # serialises within-process; cross-process safety delegated to SQLite file locking


def target_signature(props: Dict[str, Any]) -> str:
    server = (props.get("server") or "").strip().lower()
    tech = props.get("tech") or props.get("technologies") or []
    if isinstance(tech, str):
        tech = [tech]
    tech_norm = ",".join(sorted({t.strip().lower() for t in tech if t}))
    raw = f"{server}|{tech_norm}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


class LearnedPatternStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _LOCK, sqlite3.connect(self.path) as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS patterns("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "signature TEXT NOT NULL,"
                "wstg_id TEXT NOT NULL,"
                "category TEXT NOT NULL,"
                "tool TEXT NOT NULL,"
                "args TEXT NOT NULL,"
                "success INTEGER NOT NULL,"
                "finding_count INTEGER NOT NULL,"
                "ts REAL NOT NULL"
                ")"
            )
            c.execute(
                "CREATE INDEX IF NOT EXISTS ix_sig_cat ON patterns(signature, category)"
            )

    def record(
        self,
        signature: str,
        wstg_id: str,
        tool: str,
        args: Dict[str, Any],
        success: bool,
        finding_count: int = 0,
    ) -> None:
        parts = wstg_id.rsplit("-", 1)
        category = parts[0] if (len(parts) == 2 and parts[1].isdigit()) else wstg_id
        with _LOCK, sqlite3.connect(self.path) as c:
            c.execute(
                "INSERT INTO patterns"
                "(signature, wstg_id, category, tool, args, success, finding_count, ts)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (
                    signature, wstg_id, category, tool,
                    json.dumps(args, default=str),
                    1 if success else 0, int(finding_count), time.time(),
                ),
            )

    def top_patterns_for(
        self,
        signature: str,
        category: str,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        with _LOCK, sqlite3.connect(self.path) as c:
            cur = c.execute(
                "SELECT wstg_id, tool, args, finding_count FROM patterns"
                " WHERE signature=? AND category=? AND success=1"
                " ORDER BY finding_count DESC, ts DESC LIMIT ?",
                (signature, category, limit),
            )
            return [
                {
                    "wstg_id": r[0],
                    "tool": r[1],
                    "args": json.loads(r[2]),
                    "finding_count": r[3],
                }
                for r in cur.fetchall()
            ]


_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "data" / "learned_patterns.db"


def get_default_store() -> LearnedPatternStore:
    return LearnedPatternStore(_DEFAULT_PATH)
