"""EndpointTagger: maps discovered endpoints to applicable WSTG sub-test IDs via LLM."""
from __future__ import annotations
from typing import Any, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..utils.simple_llm_client import SimpleLLMClient
    from .wstg_catalog import SubTest

# Maps applicability hint -> callable(endpoint_dict) -> bool
_APPLICABILITY_CHECKS: Dict[str, Any] = {
    "has_query_params": lambda e: bool(e.get("params")),
    "has_post_body": lambda e: e.get("method", "GET").upper() in ("POST", "PUT", "PATCH"),
    "has_file_upload": lambda e: "multipart" in (e.get("content_type") or "").lower(),
    "has_xml_input": lambda e: "xml" in (e.get("content_type") or "").lower(),
    "uses_jwt":       lambda e: True,      # no jwt field in endpoint dict yet; LLM decides
    "has_graphql": lambda e: "graphql" in (e.get("url") or "").lower(),
    "has_db_backend": lambda e: True,      # no db_backend field in endpoint dict yet; LLM decides
    "always": lambda e: True,
}


def _candidates_for_endpoint(endpoint: Dict[str, Any], catalog: Dict[str, "SubTest"]) -> List[str]:
    results = []
    for st_id, st in catalog.items():
        hints = st.applicability
        if any(_APPLICABILITY_CHECKS.get(h, lambda e: True)(endpoint) for h in hints):
            results.append(st_id)
    return results


async def tag_endpoints(
    endpoints: List[Dict[str, Any]],
    catalog: Dict[str, "SubTest"],
    tech_stack: Dict[str, Any],
    llm_client: "SimpleLLMClient",
) -> Dict[str, List[str]]:
    if not endpoints:
        return {}
    if not catalog:
        return {}

    all_candidates: set = set()
    for ep in endpoints:
        all_candidates.update(_candidates_for_endpoint(ep, catalog))

    catalog_summary = [
        {"id": st_id, "title": catalog[st_id].title}
        for st_id in sorted(all_candidates)
    ]
    known_ids = set(catalog.keys())

    raw_result = await llm_client.tag_endpoints_with_subtests(
        endpoints=endpoints,
        catalog_summary=catalog_summary,
        tech_stack=tech_stack,
        known_ids=known_ids,
    )

    clean: Dict[str, List[str]] = {}
    for url, ids in raw_result.items():
        valid = [i for i in ids if i in catalog]
        if valid:
            clean[url] = valid
    return clean
