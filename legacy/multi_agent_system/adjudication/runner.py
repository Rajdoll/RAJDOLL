from ..core.config import settings
from .artifact import artifact_from_dict
from .gate import should_adjudicate
from .guards import guards_pass


async def run_adjudication(agent, artifacts: list) -> int:
    """Gate -> LLM adjudicate -> guard -> emit findings. Returns count emitted.
    No-op unless ENABLE_LLM_ADJUDICATION. Never raises; per-artifact failures are skipped."""
    if not getattr(settings, "enable_llm_adjudication", False):
        return 0
    client = getattr(agent, "_llm_client", None)
    if client is None or not artifacts:
        return 0
    cap = settings.adjudication_max_per_agent
    min_conf = settings.adjudication_min_confidence
    emitted = 0
    used = 0
    for raw in artifacts:
        if used >= cap:
            break
        art = artifact_from_dict(raw)
        if not should_adjudicate(art):
            continue
        used += 1
        try:
            verdict = await client.adjudicate_response(raw)
        except Exception as e:
            agent.log("warning", f"adjudicate_response raised: {e}")
            continue
        if guards_pass(verdict, art, min_conf):
            evidence = {"url": art.url, "role": art.role,
                        "evidence_span": verdict.get("evidence_span"),
                        "confidence": verdict.get("confidence"),
                        "source": "llm-adjudicated"}
            agent.add_finding(
                verdict.get("vuln_class") or art.wstg,
                f"LLM-adjudicated {verdict.get('vuln_class') or art.wstg}: {verdict.get('reason')}",
                severity="high",
                evidence=evidence,
                details=verdict.get("reason"),
            )
            emitted += 1
    return emitted
