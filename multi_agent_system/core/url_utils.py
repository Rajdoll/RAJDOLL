"""Generic URL helpers shared by agents (target-agnostic)."""
from urllib.parse import urljoin, urlparse, parse_qs


def absolutize_url(url: str, base: str | None) -> str:
    if not url or url.startswith(("http://", "https://")):
        return url
    if not base:
        return url
    return urljoin(base, url)


def prefer_query_params(url: str, defaults: list[str]) -> list[str]:
    q = list(parse_qs(urlparse(url).query).keys())
    if not q:
        return defaults
    return q + [p for p in defaults if p not in q]
