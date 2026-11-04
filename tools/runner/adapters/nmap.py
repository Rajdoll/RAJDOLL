"""nmap: TCP connect port scan and light service detection (TRD 4.3).

nmap is not an HTTP tool, so it cannot use the egress proxy (TRD 4.2): the runner checks the host
against the scope before it runs and writes one `tool_exec` audit row per run. The scan uses TCP
connect (`-sT`, no raw sockets, so the tools container needs no extra capabilities).
"""

import re
import xml.etree.ElementTree as ET  # noqa: S405 (our own nmap's output, not untrusted input)
from pathlib import Path
from typing import Any, ClassVar

from pydantic import Field, field_validator

from tools.runner.adapters.base import Adapter, BaseParams, RunContext

_HOST = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9-]{1,63})*$"
)
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class NmapParams(BaseParams):
    host: str
    ports: list[int] = Field(default=[], max_length=1000)
    top_ports: int = Field(default=1000, ge=1, le=5000)
    service_detection: bool = True
    max_rate: int = Field(default=50, ge=1, le=1000)
    host_timeout_s: int = Field(default=900, ge=30, le=3600)

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        if value.startswith("-") or not (_HOST.match(value) or _IPV4.match(value)):
            raise ValueError("must be a host name or IPv4 address")
        return value.lower()

    @field_validator("ports")
    @classmethod
    def _ports(cls, value: list[int]) -> list[int]:
        if any(not 1 <= port <= 65535 for port in value):
            raise ValueError("ports must be between 1 and 65535")
        return sorted(set(value))


class NmapAdapter(Adapter):
    name = "nmap"
    binary = "nmap"
    Params = NmapParams
    # Non-HTTP: the runner records the execution itself (TRD 4.2).
    audit_exec: ClassVar[bool] = True
    # "Nmap version 7.95"; later lines list library versions such as liblua-5.4.6.
    version_pattern = re.compile(r"Nmap version (\d+\.\d+)")

    def targets(self, params: NmapParams) -> list[str]:
        return [f"nmap://{params.host}"]

    def audit_summary(self, params: NmapParams) -> str:
        ports = ",".join(map(str, params.ports)) if params.ports else f"top {params.top_ports}"
        return f"nmap -sT {params.host} ports={ports}"

    def command(self, params: NmapParams, ctx: RunContext) -> list[str]:
        argv = [
            str(ctx.bin_dir / self.binary),
            "-sT", "-Pn", "--unprivileged",
            "-T3",
            "--max-rate", str(params.max_rate),
            "--host-timeout", f"{params.host_timeout_s}s",
            "-oX", str(ctx.workdir / "out.xml"),
        ]  # fmt: skip
        if params.ports:
            argv += ["-p", ",".join(map(str, params.ports))]
        else:
            argv += ["--top-ports", str(params.top_ports)]
        if params.service_detection:
            argv += ["-sV", "--version-light"]
        return [*argv, "--", params.host]

    def parse(self, ctx: RunContext, stdout: str) -> dict[str, Any]:
        path: Path = ctx.workdir / "out.xml"
        if not path.exists():
            return {"ports": []}
        try:
            root = ET.parse(path).getroot()  # noqa: S314 (see the import)
        except ET.ParseError:
            return {"ports": []}
        ports = []
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            ports.append(
                {
                    "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol"),
                    "service": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                }
            )
        return {"ports": ports}

    def version_command(self, bin_dir: Path) -> list[str]:
        return [str(bin_dir / self.binary), "--version"]
