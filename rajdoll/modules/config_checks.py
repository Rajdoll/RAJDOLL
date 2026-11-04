"""Configuration & Deployment checks (WSTG-CONF, WSTG-INFO-02).

All requests are GET without a session, except one TRACE: a misconfiguration or an exposed file
matters most when anyone can reach it.

- Security headers of the root page: Content-Security-Policy, X-Content-Type-Options: nosniff,
  X-Frame-Options (or CSP `frame-ancestors`), and Strict-Transport-Security on HTTPS.
- Versions in response headers (`Server`, `X-Powered-By`, ...).
- TRACE: a random header value echoed back in a 200 response.
- Backup copies of server-side files the inventory knows (`index.php` -> `index.php.bak`): a
  success that is neither the soft-404 page nor the original page, and that is not HTML or
  shows source code or secrets.
- nuclei templates for exposed files and debug pages (`templates/nuclei/config/<type>/`, plus
  RAJDOLL's own `rajdoll/exposure/`): the directory names the vulnerability type.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from rajdoll.modules import httpkit
from rajdoll.modules.authz_checks import similarity
from rajdoll.modules.base import Exchange

NUCLEI_TEMPLATES = ["config", "rajdoll/exposure"]
NUCLEI_TIMEOUT_S = 900
SAME_PAGE = 0.9
MAX_BACKUP_FILES = 30
BACKUP_SUFFIXES = (".bak", ".old", ".orig", ".save", "~", ".txt", ".backup", ".copy")
SOURCE_EXTENSIONS = {
    "php", "php3", "php4", "php5", "phtml", "inc", "asp", "aspx", "ascx", "jsp", "jspx", "do",
    "cfm", "pl", "py", "rb", "config", "conf", "ini", "yml", "yaml", "properties", "xml",
}  # fmt: skip
_SOURCE = re.compile(
    r"<\?php|<%[@=]?|^\s*(import|require|include|using|package)\b|passw|secret|db_|database",
    re.I | re.M,
)
_VERSION = re.compile(r"\d+\.\d+")
VERSION_HEADERS = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "X-AspNet-Version",
    "x-aspnetmvc-version": "X-AspNetMvc-Version",
    "x-generator": "X-Generator",
}


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


@dataclass
class Seen:
    response: httpx.Response
    exchange: Exchange

    @property
    def ok(self) -> bool:
        return 200 <= self.response.status_code < 300

    @property
    def text(self) -> str:
        return self.response.text[: httpkit.MAX_RESPONSE]


def fetch(
    client: httpx.Client,
    url: str,
    note: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> Seen:
    """One request without a session (cookies the client collected are dropped)."""
    client.cookies.clear()
    response = client.request(method, url, headers=headers or {}, follow_redirects=False)
    exchange = Exchange(
        httpkit.raw_request(response.request),
        httpkit.raw_response(response),
        response.status_code,
        note,
    )
    return Seen(response, exchange)


# -- headers ------------------------------------------------------------------------------------


def missing_headers(headers: httpx.Headers, https: bool) -> list[str]:
    """Security headers the response lacks."""
    csp = headers.get("content-security-policy", "")
    missing = []
    if not csp:
        missing.append("Content-Security-Policy")
    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        missing.append("X-Content-Type-Options")
    if not headers.get("x-frame-options") and "frame-ancestors" not in csp.lower():
        missing.append("X-Frame-Options")
    if https and not headers.get("strict-transport-security"):
        missing.append("Strict-Transport-Security")
    return missing


def version_headers(headers: httpx.Headers) -> dict[str, str]:
    """Response headers that name a software version: {display name: value}."""
    return {
        display: headers[name]
        for name, display in VERSION_HEADERS.items()
        if name in headers and _VERSION.search(headers[name])
    }


# -- TRACE --------------------------------------------------------------------------------------


def trace(client: httpx.Client, url: str) -> tuple[bool, Seen]:
    """Whether TRACE echoes the request: a random header value comes back in a 200 response."""
    marker = secrets.token_hex(8)
    seen = fetch(client, url, "TRACE dengan header acak", "TRACE", {"X-Rajdoll-Trace": marker})
    return seen.response.status_code == 200 and marker in seen.text, seen


# -- backup files -------------------------------------------------------------------------------


def backup_targets(endpoints: list[dict[str, Any]]) -> list[str]:
    """Inventory URLs of server-side files whose backup copies are worth trying."""
    urls = []
    for endpoint in endpoints:
        path = str(endpoint.get("path_template", ""))
        name = path.rsplit("/", 1)[-1]
        extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if (
            endpoint.get("method") == "GET"
            and not endpoint.get("excluded")
            and "{" not in path
            and extension in SOURCE_EXTENSIONS
        ):
            urls.append(str(endpoint["url"]))
    return list(dict.fromkeys(urls))[:MAX_BACKUP_FILES]


def soft_404(client: httpx.Client, url: str) -> str:
    """What the server answers for a backup name that cannot exist ("" for a real 404)."""
    origin = origin_of(url)
    seen = fetch(client, f"{origin}/rajdoll-{secrets.token_hex(6)}.php.bak", "nama acak")
    return seen.text if seen.ok else ""


def is_backup(seen: Seen, original: str, not_found: str) -> bool:
    if not seen.ok or not seen.text.strip():
        return False
    if similarity(seen.text, original) >= SAME_PAGE:
        return False  # the server ignores the suffix and serves the page itself
    if not_found and similarity(seen.text, not_found) >= SAME_PAGE:
        return False
    html = "text/html" in seen.response.headers.get("content-type", "").lower()
    return not html or bool(_SOURCE.search(seen.text))


@dataclass
class BackupHit:
    original: str
    url: str
    suffix: str
    seen: Seen
    original_seen: Seen


def find_backups(client: httpx.Client, url: str, not_found: str) -> BackupHit | None:
    """The first backup copy of `url` that the server serves."""
    original = fetch(client, url, "halaman asli")
    for suffix in BACKUP_SUFFIXES:
        candidate = url + suffix
        seen = fetch(client, candidate, f"salinan cadangan ({suffix})")
        if is_backup(seen, original.text if original.ok else "", not_found):
            return BackupHit(url, candidate, suffix, seen, original)
    return None


# -- nuclei ------------------------------------------------------------------------------------


def nuclei_vuln_type(template_path: str | None) -> str | None:
    """The vulnerability type a template's directory names."""
    parts = (template_path or "").split("/")
    if len(parts) >= 3 and parts[0] == "config":
        return parts[1]
    if parts[:2] == ["rajdoll", "exposure"]:
        return "sensitive_file"
    return None


def nuclei_status(raw_response: str | None) -> int | None:
    try:
        return int((raw_response or "").split(" ", 2)[1])
    except (IndexError, ValueError):
        return None


def nuclei_exchange(hit: dict[str, Any]) -> Exchange:
    # Extracted values (credentials, keys) stay in the encrypted response, never in the note.
    note = f"nuclei {hit.get('template_id')}: {hit.get('name') or ''}".strip()
    return Exchange(
        httpkit.mask_raw(hit.get("request") or ""),
        httpkit.mask_raw(hit.get("response") or "") or None,
        nuclei_status(hit.get("response")),
        note,
    )
