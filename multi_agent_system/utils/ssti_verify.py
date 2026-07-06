from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

_MATH_RE = re.compile(r"(\d+)\s*\*\s*(\d+)")

# One representative payload per common template-engine syntax family.
_ENGINE_TEMPLATES = ("{{%s}}", "${%s}", "<%%= %s %%>", "#{%s}", "*{%s}")


def _with_param(url: str, param: str, value: str) -> str:
    """Return url with param set to value, replacing any existing value for that key."""
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query))
    query[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def build_ssti_payloads(a: int, b: int) -> list[tuple[str, str, str]]:
    """Return (payload, product_str, raw_expr) for each engine syntax."""
    raw_expr = f"{a}*{b}"
    product = str(a * b)
    return [(tpl % raw_expr, product, raw_expr) for tpl in _ENGINE_TEMPLATES]


def product_from_payload(payload: str) -> tuple[str, str] | None:
    """Parse an 'N*M' expression out of a payload, returning (product, raw_expr)."""
    m = _MATH_RE.search(payload or "")
    if not m:
        return None
    a, b = int(m.group(1)), int(m.group(2))
    return str(a * b), f"{a}*{b}"


def ssti_candidates(endpoints: list[dict], cap: int = 15) -> list[tuple[str, str]]:
    """(url, param) pairs to probe. Skip wildcard URLs and endpoints with no real param."""
    out: list[tuple[str, str]] = []
    for ep in endpoints or []:
        url = ep.get("url") or ep.get("path")
        if not url or "*" in url:
            continue
        params = ep.get("params") or list((ep.get("query_parameters") or {}).keys())
        if not params:
            continue
        out.append((url, params[0]))
        if len(out) >= cap:
            break
    return out


def verify_ssti_evaluation(baseline_text: str, test_text: str, product: str, raw_expr: str) -> bool:
    """True only if the product appears in the test response, is absent from the
    baseline response, and the raw expression is not echoed (evaluation, not reflection)."""
    return (
        product in test_text
        and product not in baseline_text
        and raw_expr not in test_text
    )


async def run_ssti_probe(client, candidates, payloads, marker: str) -> list[dict]:
    """For each (url, param), take a benign baseline then test each payload.
    Return confirmed findings only."""
    confirmed: list[dict] = []
    for url, param in candidates:
        try:
            baseline = await client.get(_with_param(url, param, marker))
        except Exception:
            continue
        baseline_text = baseline.text
        for payload, product, raw_expr in payloads:
            try:
                resp = await client.get(_with_param(url, param, payload))
            except Exception:
                continue
            if verify_ssti_evaluation(baseline_text, resp.text, product, raw_expr):
                confirmed.append(
                    {"url": url, "parameter": param, "payload": payload, "product": product}
                )
                break
    return confirmed
