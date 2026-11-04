from .artifact import Artifact


def guards_pass(verdict: dict, art: Artifact, min_confidence: float = 0.7) -> bool:
    if not isinstance(verdict, dict):
        return False
    if verdict.get("verdict") != "vulnerable":
        return False
    span = verdict.get("evidence_span") or ""
    if not span or span not in (art.body or ""):
        return False
    try:
        conf = float(verdict.get("confidence", 0))
    except (TypeError, ValueError):
        return False
    return conf >= min_confidence
