"""SSLyze: the TLS configuration of one host and port (WSTG-CRYP-01; TRD 6.2, decision F8b-3).

SSLyze tunnels every connection through the egress proxy with HTTP CONNECT and the task's proxy
credentials (`--https_tunnel`). The proxy relays these tunnels without intercepting TLS
(`tools/proxy/addon.py`, PASSTHROUGH_TOOLS), so SSLyze sees the target's own certificate and
protocols; scope is checked at CONNECT and every tunnel is audited. testssl.sh could not be used:
its proxy support has no authentication.

SSLyze runs from its own virtual environment (`tools/sslyze-requirements.txt`): its pinned
`cryptography` conflicts with the main package's.
"""

import json
import re
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator

from tools.runner.adapters.base import Adapter, BaseParams, RunContext

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
SCANS = (
    "--certinfo", "--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3",
    "--heartbleed", "--openssl_ccs", "--robot", "--reneg", "--compression", "--fallback",
)  # fmt: skip
PROTOCOLS = {
    "ssl_2_0_cipher_suites": "SSL 2.0",
    "ssl_3_0_cipher_suites": "SSL 3.0",
    "tls_1_0_cipher_suites": "TLS 1.0",
    "tls_1_1_cipher_suites": "TLS 1.1",
    "tls_1_2_cipher_suites": "TLS 1.2",
    "tls_1_3_cipher_suites": "TLS 1.3",
}
_WEAK_CIPHER = re.compile(r"NULL|EXPORT|anon|RC4|_DES_|DES40|3DES|_MD5$", re.I)


class SslyzeParams(BaseParams):
    host: str
    port: int = Field(default=443, ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        try:
            ip_address(value)
        except ValueError:
            if not _HOSTNAME.match(value):
                raise ValueError("must be a hostname or an IP address") from None
        return value


def _result(scan: dict[str, Any], name: str) -> dict[str, Any]:
    item = scan.get(name) or {}
    return item.get("result") or {} if item.get("status") == "COMPLETED" else {}


def _matches(host: str, alt_names: dict[str, Any], common_name: str | None) -> bool:
    names = list(alt_names.get("dns_names") or []) + list(alt_names.get("ip_addresses") or [])
    if not names and common_name:
        names = [common_name]
    host = host.lower()
    for name in (n.lower() for n in names):
        if name == host or (name.startswith("*.") and host.split(".", 1)[-1] == name[2:]):
            return True
    return False


def _certificate(scan: dict[str, Any], host: str) -> dict[str, Any] | None:
    info = _result(scan, "certificate_info")
    deployments = info.get("certificate_deployments") or []
    if not deployments:
        return None
    deployment = deployments[0]
    chain = deployment.get("received_certificate_chain") or []
    if not chain:
        return None
    leaf = chain[0]
    validations = deployment.get("path_validation_results") or []
    subject = (leaf.get("subject") or {}).get("rfc4514_string")
    issuer = (leaf.get("issuer") or {}).get("rfc4514_string")
    common_name = next(
        (
            a.get("value")
            for a in (leaf.get("subject") or {}).get("attributes") or []
            if (a.get("oid") or {}).get("name") == "commonName"
        ),
        None,
    )
    not_after = leaf.get("not_valid_after")
    now = datetime.now(UTC)
    expired = bool(not_after) and datetime.fromisoformat(not_after.replace("Z", "+00:00")) < now
    return {
        "subject": subject,
        "issuer": issuer,
        "not_valid_after": not_after,
        "trusted": any(v.get("was_validation_successful") for v in validations),
        "validation_error": next(
            (v.get("validation_error") for v in validations if v.get("validation_error")), None
        ),
        "self_signed": bool(subject) and subject == issuer,
        "expired": expired,
        "hostname_matches": _matches(host, leaf.get("subject_alternative_name") or {}, common_name),
        "key_algorithm": (leaf.get("public_key") or {}).get("algorithm"),
        "key_size": (leaf.get("public_key") or {}).get("key_size"),
        "sha1_signature": bool(deployment.get("verified_chain_has_sha1_signature")),
    }


def normalize(report: dict[str, Any], host: str) -> dict[str, Any]:
    results = report.get("server_scan_results") or []
    if not results:
        return {"connected": False, "error": "no scan result"}
    server = results[0]
    if server.get("scan_status") != "COMPLETED":
        trace = str(server.get("connectivity_error_trace") or server.get("scan_status"))
        return {"connected": False, "error": trace.strip().splitlines()[-1][:300]}
    scan = server.get("scan_result") or {}
    protocols: dict[str, list[str]] = {}
    for key, label in PROTOCOLS.items():
        accepted = _result(scan, key).get("accepted_cipher_suites") or []
        names = [c["cipher_suite"]["name"] for c in accepted if c.get("cipher_suite")]
        if names:
            protocols[label] = names
    weak = sorted({n for names in protocols.values() for n in names if _WEAK_CIPHER.search(n)})
    reneg = _result(scan, "session_renegotiation")
    robot = str(_result(scan, "robot").get("robot_result") or "")
    fallback = _result(scan, "tls_fallback_scsv")
    return {
        "connected": True,
        "sslyze_version": report.get("sslyze_version"),
        "protocols": protocols,
        "legacy_protocols": [
            p for p in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1") if p in protocols
        ],
        "weak_ciphers": weak,
        "certificate": _certificate(scan, host),
        "vulnerabilities": {
            "heartbleed": bool(_result(scan, "heartbleed").get("is_vulnerable_to_heartbleed")),
            "ccs_injection": bool(
                _result(scan, "openssl_ccs_injection").get("is_vulnerable_to_ccs_injection")
            ),
            "robot": robot.startswith("VULNERABLE"),
            "insecure_renegotiation": bool(reneg)
            and (
                not reneg.get("supports_secure_renegotiation", True)
                or bool(reneg.get("is_vulnerable_to_client_renegotiation_dos"))
            ),
            "compression": bool(_result(scan, "tls_compression").get("supports_compression")),
        },
        "fallback_scsv": fallback.get("supports_fallback_scsv") if fallback else None,
    }


class SslyzeAdapter(Adapter):
    name = "sslyze"
    binary = "sslyze"
    Params = SslyzeParams
    version_pattern = re.compile(r"SSLyze version (\d+\.\d+\.\d+)")

    def targets(self, params: SslyzeParams) -> list[str]:  # type: ignore[override]
        return [f"https://{params.host}:{params.port}/"]

    def command(self, params: SslyzeParams, ctx: RunContext) -> list[str]:  # type: ignore[override]
        return [
            str(ctx.bin_dir / self.binary),
            "--json_out", str(ctx.workdir / "out.json"),
            "--https_tunnel", ctx.proxy_url.rstrip("/") + "/",
            "--mozilla_config", "disable",
            "--quiet",
            *SCANS,
            f"{params.host}:{params.port}",
        ]  # fmt: skip

    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:  # type: ignore[override]
        path = Path(ctx.workdir) / "out.json"
        if not path.exists():
            return {"connected": False, "error": "no report"}
        report = json.loads(path.read_text(encoding="utf-8"))
        host = ((report.get("server_scan_results") or [{}])[0].get("server_location") or {}).get(
            "hostname", ""
        )
        return normalize(report, host)

    def version_command(self, bin_dir: Path) -> list[str]:
        return [str(bin_dir / self.binary), "--help"]
