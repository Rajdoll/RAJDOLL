"""Client for the tools container's runner (TRD 4.1).

The worker never runs a security tool itself: it asks the runner, which checks scope again and
sends the tool's traffic through the egress proxy.
"""

from typing import Any

import httpx

from rajdoll.modules.base import TransientTaskError

# The runner answers when the tool ends, so the read timeout is the tool's own limit plus slack.
_SLACK_SECONDS = 60.0


class ToolsClient:
    def __init__(self, base_url: str, token: str, transport: httpx.BaseTransport | None = None):
        self._client = httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            # The runner is on the internal network; never route it through an inherited proxy.
            trust_env=False,
            transport=transport,
            timeout=httpx.Timeout(30.0),
        )

    def close(self) -> None:
        self._client.close()

    def run(
        self,
        run_id: str,
        *,
        task_id: int,
        scan_id: int,
        tool: str,
        params: dict[str, Any],
        scope: list[str],
        timeout_s: int,
    ) -> dict[str, Any]:
        """Run a tool and return the runner's answer (status, normalized, raw_output, ...)."""
        body = {
            "run_id": run_id,
            "task_id": task_id,
            "scan_id": scan_id,
            "tool": tool,
            "params": params,
            "scope": scope,
            "timeout_s": timeout_s,
        }
        try:
            response = self._client.post(
                "/run", json=body, timeout=httpx.Timeout(30.0, read=timeout_s + _SLACK_SECONDS)
            )
        except httpx.TransportError as exc:
            raise TransientTaskError(f"runner tidak bisa dihubungi: {exc}") from exc
        if response.status_code >= 500:
            raise TransientTaskError(f"runner menjawab {response.status_code}")
        if response.status_code != 200:
            # 4xx: a bug in the module's parameters, not worth a retry.
            raise RuntimeError(f"runner menolak {tool}: {response.status_code} {response.text}")
        return response.json()

    def cancel(self, run_id: str) -> bool:
        """Stop a running tool. False when the runner no longer knows the run."""
        try:
            response = self._client.post(f"/run/{run_id}/cancel")
        except httpx.TransportError:
            return False
        return response.status_code == 200
