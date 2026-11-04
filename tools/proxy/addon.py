"""RAJDOLL egress proxy: a mitmproxy addon (TRD 4.2, P5).

Every HTTP(S) request from a tool, validator, or session check passes through here. The addon

* authenticates the caller and identifies its context from the proxy credentials,
* enforces the engagement scope (deny by default) before any upstream connection is made,
* applies a per-engagement token-bucket rate limit,
* adds the engagement's identity header when configured,
* writes one `request_log` row per request (forwarded, blocked, or failed).

Proxy credentials carry the context, so tools that cannot add custom headers still work:

    http://task.<task_id>.<tool>:<token>@tools:8081       a pipeline task
    http://eng.<engagement_id>.<purpose>:<token>@tools:8081   a direct request (session check)

Started by tools/entrypoint.py through tools/proxy/mitm_script.py.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from mitmproxy import http, tls

from rajdoll.core.scope import in_scope

log = logging.getLogger("rajdoll.proxy")

CACHE_SECONDS = 5.0
DIRECT_DEFAULT_RPS = 5.0
MAX_URL_LENGTH = 2048
_USERNAME = re.compile(r"^(task|eng)\.(\d{1,18})\.([a-z0-9_-]{1,40})$")
# TLS scanners must see the target's own TLS, not the proxy's interception certificate: their
# tunnels are relayed unmodified after the scope check at CONNECT, and each tunnel is audited and
# rate-limited as one request. No other tool's traffic is ever passed through undecrypted.
PASSTHROUGH_TOOLS = frozenset({"sslyze"})
_CONTEXT_KEY = "rajdoll_context"
_LOGGED_KEY = "rajdoll_logged"
_STARTED_KEY = "rajdoll_started"


# --------------------------------------------------------------------------------------
# Context
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Credentials:
    kind: str  # "task" or "eng"
    ident: int
    label: str  # tool name for tasks, purpose for direct requests


@dataclass
class Context:
    engagement_id: int
    scan_id: int | None
    task_id: int | None
    tool: str
    scope: list[str]
    rate_limit_rps: float
    identity_header: tuple[str, str] | None = None
    loaded_at: float = field(default_factory=time.monotonic)


class Store(Protocol):
    """Database access the addon needs; see tools/proxy/store.py."""

    def task(self, task_id: int) -> tuple[int, int, dict[str, Any]] | None:
        """(engagement_id, scan_id, settings_snapshot) for a task."""

    def engagement_settings(self, engagement_id: int) -> dict[str, Any] | None: ...

    def scope(self, engagement_id: int) -> list[str]: ...

    def write(self, row: dict[str, Any]) -> None: ...


def parse_credentials(header_value: str | None, token: str) -> Credentials | None:
    """Decode `Proxy-Authorization: Basic ...` and check the shared token in constant time."""
    if not header_value or not header_value.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(header_value[6:].strip(), validate=True).decode()
    except (ValueError, UnicodeDecodeError):
        return None
    username, sep, password = decoded.partition(":")
    if not sep or not secrets.compare_digest(password.encode(), token.encode()):
        return None
    match = _USERNAME.match(username)
    if not match:
        return None
    return Credentials(match.group(1), int(match.group(2)), match.group(3))


def _identity(settings: dict[str, Any] | None) -> tuple[str, str] | None:
    header = (settings or {}).get("identity_header")
    if isinstance(header, dict) and header.get("name") and header.get("value") is not None:
        return str(header["name"]), str(header["value"])
    return None


def _rate(value: Any, fallback: float) -> float:
    try:
        rate = float(value)
    except (TypeError, ValueError):
        return fallback
    return rate if rate > 0 else fallback


def build_context(store: Store, creds: Credentials) -> Context | None:
    if creds.kind == "task":
        found = store.task(creds.ident)
        if found is None:
            return None
        engagement_id, scan_id, snapshot = found
        own = store.engagement_settings(engagement_id) or {}
        return Context(
            engagement_id=engagement_id,
            scan_id=scan_id,
            task_id=creds.ident,
            tool=creds.label,
            scope=store.scope(engagement_id),
            rate_limit_rps=_rate(snapshot.get("rate_limit_rps"), DIRECT_DEFAULT_RPS),
            identity_header=_identity(snapshot) or _identity(own),
        )
    own = store.engagement_settings(creds.ident)
    if own is None:
        return None
    return Context(
        engagement_id=creds.ident,
        scan_id=None,
        task_id=None,
        tool=creds.label,
        scope=store.scope(creds.ident),
        rate_limit_rps=_rate(own.get("rate_limit_rps"), DIRECT_DEFAULT_RPS),
        identity_header=_identity(own),
    )


# --------------------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------------------


class TokenBucket:
    """Allows `rate` requests per second on average, with a burst of at most max(1, rate)."""

    def __init__(self, rate: float, clock: Any = time.monotonic) -> None:
        self._clock = clock
        self.rate = rate
        self._tokens = self.capacity
        self._updated = clock()
        self._lock = asyncio.Lock()

    @property
    def capacity(self) -> float:
        return max(1.0, self.rate)

    def set_rate(self, rate: float) -> None:
        self.rate = rate
        self._tokens = min(self._tokens, self.capacity)

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
        self._updated = now

    async def acquire(self) -> None:
        async with self._lock:
            self._refill()
            if self._tokens < 1:
                await asyncio.sleep((1 - self._tokens) / self.rate)
                self._refill()
            self._tokens -= 1


# --------------------------------------------------------------------------------------
# Addon
# --------------------------------------------------------------------------------------


def _deny(flow: http.HTTPFlow, status: int, reason: str, message: str) -> None:
    headers = {"Content-Type": "text/plain; charset=utf-8", "X-Rajdoll-Blocked": reason}
    if status == 407:
        headers["Proxy-Authenticate"] = 'Basic realm="rajdoll"'
    flow.response = http.Response.make(status, message.encode(), headers)


class EgressProxy:
    def __init__(self, store: Store, token: str) -> None:
        if not token:
            raise ValueError("RAJDOLL_TOOLS_TOKEN must be set")
        self._store = store
        self._token = token
        self._contexts: dict[str, Context] = {}
        self._tunnels: dict[str, Context] = {}
        self._buckets: dict[int, TokenBucket] = {}

    # Context lookup -------------------------------------------------------------------

    async def _context_for(self, flow: http.HTTPFlow) -> Context | None:
        header = flow.request.headers.get("Proxy-Authorization")
        if header is None:
            return self._tunnels.get(flow.client_conn.id)
        creds = parse_credentials(header, self._token)
        if creds is None:
            return None
        cache_key = f"{creds.kind}.{creds.ident}.{creds.label}"
        cached = self._contexts.get(cache_key)
        if cached is not None and time.monotonic() - cached.loaded_at < CACHE_SECONDS:
            return cached
        context = await asyncio.to_thread(build_context, self._store, creds)
        if context is not None:
            self._contexts[cache_key] = context
        return context

    def _bucket(self, context: Context) -> TokenBucket:
        bucket = self._buckets.get(context.engagement_id)
        if bucket is None:
            bucket = self._buckets[context.engagement_id] = TokenBucket(context.rate_limit_rps)
        elif bucket.rate != context.rate_limit_rps:
            bucket.set_rate(context.rate_limit_rps)
        return bucket

    # Audit ----------------------------------------------------------------------------

    def _log(
        self,
        flow: http.HTTPFlow,
        context: Context | None,
        outcome: str,
        status: int | None = None,
        response_bytes: int | None = None,
    ) -> None:
        flow.metadata[_LOGGED_KEY] = True
        if context is None:
            # Unauthenticated callers have no engagement to attribute the row to.
            log.warning("rejected unauthenticated proxy request to %s", flow.request.pretty_host)
            return
        started = flow.metadata.get(_STARTED_KEY)
        duration = int((time.monotonic() - started) * 1000) if started else None
        is_connect = flow.request.method == "CONNECT"
        url = f"{flow.request.host}:{flow.request.port}" if is_connect else flow.request.pretty_url
        self._store.write(
            {
                "engagement_id": context.engagement_id,
                "scan_id": context.scan_id,
                "task_id": context.task_id,
                "kind": "http",
                "tool": context.tool,
                "method": flow.request.method,
                "url": url[:MAX_URL_LENGTH],
                "host": flow.request.pretty_host.lower(),
                "status": status,
                "response_bytes": response_bytes,
                "duration_ms": duration,
                "outcome": outcome,
            }
        )

    # mitmproxy hooks ------------------------------------------------------------------

    async def http_connect(self, flow: http.HTTPFlow) -> None:
        flow.metadata[_STARTED_KEY] = time.monotonic()
        context = await self._context_for(flow)
        if context is None:
            _deny(flow, 407, "auth", "RAJDOLL: proxy credentials required\n")
            self._log(flow, None, "error")
            return
        if not in_scope(context.scope, flow.request.host):
            _deny(flow, 403, "scope", f"RAJDOLL: {flow.request.host} is outside the scope\n")
            self._log(flow, context, "blocked_scope", status=403)
            return
        self._tunnels[flow.client_conn.id] = context
        del flow.request.headers["Proxy-Authorization"]
        if context.tool in PASSTHROUGH_TOOLS:
            await self._bucket(context).acquire()
            self._log(flow, context, "forwarded", status=200)

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        context = self._tunnels.get(data.context.client.id)
        if context is not None and context.tool in PASSTHROUGH_TOOLS:
            data.ignore_connection = True

    async def request(self, flow: http.HTTPFlow) -> None:
        flow.metadata[_STARTED_KEY] = time.monotonic()
        context = await self._context_for(flow)
        if context is None:
            _deny(flow, 407, "auth", "RAJDOLL: proxy credentials required\n")
            self._log(flow, None, "error")
            return
        flow.metadata[_CONTEXT_KEY] = context
        # Check both the connection target and the Host header; they can differ.
        hosts = {flow.request.host, flow.request.pretty_host}
        if not all(in_scope(context.scope, host) for host in hosts):
            _deny(flow, 403, "scope", f"RAJDOLL: {flow.request.pretty_host} is outside the scope\n")
            self._log(flow, context, "blocked_scope", status=403)
            return
        flow.request.headers.pop("Proxy-Authorization", None)
        if context.identity_header is not None:
            name, value = context.identity_header
            flow.request.headers[name] = value
        await self._bucket(context).acquire()

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get(_LOGGED_KEY) or flow.request.method == "CONNECT":
            return
        context = flow.metadata.get(_CONTEXT_KEY)
        size = len(flow.response.raw_content or b"") if flow.response else None
        status = flow.response.status_code if flow.response else None
        self._log(flow, context, "forwarded", status=status, response_bytes=size)

    def error(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get(_LOGGED_KEY):
            return
        self._log(flow, flow.metadata.get(_CONTEXT_KEY), "error")

    def client_disconnected(self, client: Any) -> None:
        self._tunnels.pop(client.id, None)


def create_addons() -> list[EgressProxy]:
    """Build the addon from the environment; called by tools/proxy/mitm_script.py."""
    from tools.proxy.store import PostgresStore

    store = PostgresStore(os.environ["RAJDOLL_PROXY_DATABASE_URL"])
    return [EgressProxy(store, os.environ.get("RAJDOLL_TOOLS_TOKEN", ""))]
