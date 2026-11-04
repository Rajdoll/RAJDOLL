"""CVSS v3.1 base score from a vector (FIRST CVSS v3.1 specification, section 7.1).

Scores are always computed from the vector (BSD 6.1), never typed in. CVSS v4.0 scoring arrives
with the finding templates (F9); until then a 4.0 vector is stored without a score.
"""

from __future__ import annotations

import math
import re

_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VECTOR = re.compile(r"^CVSS:3\.[01](/[A-Z]{1,3}:[A-Z])+$")


class CvssError(ValueError):
    """The vector is not a valid CVSS 3.x base vector."""


def _roundup(value: float) -> float:
    """Round up to one decimal, avoiding floating-point artefacts (spec Appendix A)."""
    integer = round(value * 100_000)
    if integer % 10_000 == 0:
        return integer / 100_000
    return (math.floor(integer / 10_000) + 1) / 10.0


def parse31(vector: str) -> dict[str, str]:
    if not _VECTOR.match(vector or ""):
        raise CvssError(f"bukan vektor CVSS 3.1: {vector!r}")
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        name, value = part.split(":")
        if name in metrics:
            raise CvssError(f"metrik {name} muncul dua kali")
        metrics[name] = value
    missing = [m for m in _REQUIRED if m not in metrics]
    if missing:
        raise CvssError(f"metrik dasar tidak lengkap: {', '.join(missing)}")
    for name in _REQUIRED:
        allowed = (
            _PR["U"] if name == "PR" else ({"U": 0, "C": 0} if name == "S" else _WEIGHTS[name])
        )
        if metrics[name] not in allowed:
            raise CvssError(f"nilai {name}:{metrics[name]} tidak valid")
    return metrics


def score31(vector: str) -> float:
    """Base score 0.0–10.0 of a CVSS 3.1 vector."""
    m = parse31(vector)
    changed = m["S"] == "C"
    iss = 1 - (
        (1 - _WEIGHTS["C"][m["C"]]) * (1 - _WEIGHTS["I"][m["I"]]) * (1 - _WEIGHTS["A"][m["A"]])
    )
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = (
        8.22
        * _WEIGHTS["AV"][m["AV"]]
        * _WEIGHTS["AC"][m["AC"]]
        * _PR["C" if changed else "U"][m["PR"]]
        * _WEIGHTS["UI"][m["UI"]]
    )
    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity(score: float) -> str:
    """BSD 6.1 mapping, the same for CVSS 3.1 and 4.0."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"
