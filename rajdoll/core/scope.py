"""Scope patterns and host matching (PRD F-02, AFD 6, TRD P5).

A pattern is a host, never a URL:

    app.instansi.test     exactly this host
    *.instansi.test       any subdomain of instansi.test (not instansi.test itself)
    10.20.30.40           exactly this IPv4 address

Matching ignores scheme and port. Everything that does not match is out of scope (deny by
default). This module has no dependencies outside the standard library so the egress proxy in
the tools container can reuse it unchanged.
"""

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlsplit

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
MAX_HOST_LENGTH = 253


class ScopeError(ValueError):
    """A scope pattern or URL is not acceptable. The message is safe to show the user."""


def _valid_hostname(host: str) -> bool:
    if not host or len(host) > MAX_HOST_LENGTH:
        return False
    return all(_LABEL.match(label) for label in host.split("."))


def _is_ipv4(host: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
    except ValueError:
        return False


def normalize_pattern(raw: str) -> str:
    """Return the canonical pattern for user input, or raise ScopeError.

    A full URL is accepted and reduced to its host, and a port is dropped, because people
    often paste the target URL. Paths are rejected rather than silently discarded.
    """
    value = raw.strip().lower().rstrip(".")
    if not value:
        raise ScopeError("Pola scope tidak boleh kosong.")
    if "://" in value:
        parts = urlsplit(value)
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ScopeError("Isi host saja, tanpa path. Contoh: app.instansi.test")
        value = parts.hostname or ""
    elif "/" in value:
        raise ScopeError("Isi host saja, tanpa path. Contoh: app.instansi.test")
    if value.count(":") == 1:
        host, port = value.split(":")
        if not port.isdigit():
            raise ScopeError(f"Port tidak valid: {port}")
        value = host

    if value == "*":
        raise ScopeError(
            "Pola * akan mengizinkan semua host. Gunakan host tertentu atau *.instansi.test"
        )
    if value.startswith("*."):
        base = value[2:]
        if "*" in base or not _valid_hostname(base):
            raise ScopeError("Wildcard hanya boleh di awal, misalnya *.instansi.test")
        if base.count(".") < 1:
            raise ScopeError(
                "Wildcard terlalu luas. Gunakan minimal dua label, misalnya *.instansi.test"
            )
        return value
    if "*" in value:
        raise ScopeError("Wildcard hanya boleh di awal, misalnya *.instansi.test")
    if _is_ipv4(value) or _valid_hostname(value):
        return value
    raise ScopeError(f"Host tidak valid: {raw.strip()}")


def host_matches(pattern: str, host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    if not host:
        return False
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    return host == pattern


def in_scope(patterns: Iterable[str], host: str | None) -> bool:
    """True if `host` matches at least one pattern. An empty scope allows nothing."""
    if not host:
        return False
    return any(host_matches(pattern, host) for pattern in patterns)


def url_host(url: str) -> str:
    """Host of an http(s) URL, or raise ScopeError."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ScopeError("URL harus diawali http:// atau https:// dan berisi host.")
    return parts.hostname.lower()


def url_in_scope(patterns: Iterable[str], url: str) -> bool:
    try:
        return in_scope(patterns, url_host(url))
    except ScopeError:
        return False
