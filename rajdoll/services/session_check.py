"""Check whether a target account's session is still logged in (PRD F-07; AFD A2.3).

The request goes through the egress proxy like all target traffic, so it is scope-checked,
rate-limited, and written to the audit log. A session is valid when the session-check URL
answers 200 (after following redirects inside scope) and the page contains the login marker.
"""

from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

import httpx

TIMEOUT_SECONDS = 15.0
MAX_REDIRECTS = 5


@dataclass(frozen=True)
class CheckResult:
    checked: bool  # False when the check could not run (proxy or target unreachable)
    valid: bool
    message: str
    status_code: int | None = None


Prober = Callable[[str, str, dict[str, dict[str, str]], int], CheckResult]


def proxy_url(base: str, token: str, engagement_id: int, purpose: str) -> str:
    """Egress-proxy URL whose credentials identify this engagement and purpose."""
    parts = urlsplit(base)
    user = f"eng.{engagement_id}.{purpose}"
    return f"{parts.scheme}://{user}:{quote(token, safe='')}@{parts.netloc}"


def task_proxy_url(base: str, token: str, task_id: int, tool: str) -> str:
    """Egress-proxy URL whose credentials identify a pipeline task (`task.<id>.<tool>`)."""
    parts = urlsplit(base)
    return f"{parts.scheme}://task.{task_id}.{tool}:{quote(token, safe='')}@{parts.netloc}"


def request_headers(session: dict[str, dict[str, str]]) -> dict[str, str]:
    """A stored target session as request headers (cookies joined into one Cookie header)."""
    headers = dict(session.get("headers", {}))
    cookies = session.get("cookies", {})
    if cookies:
        # Sent as a plain header so cookies are not dropped by cookie-jar domain rules.
        headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
    return headers


def evaluate(response: httpx.Response, marker: str) -> CheckResult:
    blocked = response.headers.get("X-Rajdoll-Blocked")
    if blocked == "scope":
        return CheckResult(
            True, False, "Ditolak proxy: URL (atau redirect-nya) di luar scope.", 403
        )
    if blocked == "auth":
        return CheckResult(False, False, "Proxy menolak kredensial. Periksa TOOLS_TOKEN.", 407)
    if response.status_code != 200:
        return CheckResult(
            True,
            False,
            f"Halaman menjawab {response.status_code}, bukan 200.",
            response.status_code,
        )
    if marker.casefold() not in response.text.casefold():
        return CheckResult(True, False, "Penanda login tidak ditemukan di halaman.", 200)
    return CheckResult(True, True, "Sesi valid.", 200)


def make_prober(proxy_base: str, token: str) -> Prober:
    def probe(
        url: str, marker: str, session: dict[str, dict[str, str]], engagement_id: int
    ) -> CheckResult:
        proxy = proxy_url(proxy_base, token, engagement_id, "session_check")
        try:
            with httpx.Client(
                proxy=proxy,
                verify=False,  # noqa: S501 (targets are clones; TLS is intercepted by our proxy)
                timeout=TIMEOUT_SECONDS,
                follow_redirects=True,
                max_redirects=MAX_REDIRECTS,
            ) as client:
                response = client.get(url, headers=request_headers(session))
        except httpx.TooManyRedirects:
            return CheckResult(
                True, False, "Terlalu banyak redirect; kemungkinan sesi tidak valid."
            )
        except httpx.HTTPError as exc:
            return CheckResult(False, False, f"Tidak bisa menghubungi target lewat proxy: {exc}")
        return evaluate(response, marker)

    return probe
