from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


def _with_param(url: str, param: str, value: str) -> str:
    """Return url with param set to value, replacing any existing value for that key."""
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query))
    query[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def verify_differential(baseline_text: str, test_text: str, signal: str, raw_payload: str | None = None) -> bool:
    """True only if signal appears in test_text, is absent from baseline_text,
    and (if raw_payload given) raw_payload is not echoed verbatim in test_text."""
    if signal not in test_text:
        return False
    if signal in baseline_text:
        return False
    if raw_payload and raw_payload in test_text:
        return False
    return True


async def run_differential_probe(client, candidates, payload_variants, marker: str) -> list[dict]:
    """For each (url, param) in candidates, take a baseline request with `marker`,
    then try each (payload, signal, raw_payload) in payload_variants. Return
    confirmed findings only."""
    confirmed: list[dict] = []
    for url, param in candidates:
        try:
            baseline = await client.get(_with_param(url, param, marker))
        except Exception:
            continue
        baseline_text = baseline.text
        for payload, signal, raw_payload in payload_variants:
            try:
                resp = await client.get(_with_param(url, param, payload))
            except Exception:
                continue
            if verify_differential(baseline_text, resp.text, signal, raw_payload):
                confirmed.append({"url": url, "parameter": param, "payload": payload, "signal": signal})
                break
    return confirmed
