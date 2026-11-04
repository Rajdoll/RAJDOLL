"""Tool adapters available to the runner."""

from tools.runner.adapters.base import Adapter, AdapterError, RunContext
from tools.runner.adapters.browser import BrowserAdapter, XssCheckAdapter
from tools.runner.adapters.commix import CommixAdapter
from tools.runner.adapters.dalfox import DalfoxAdapter
from tools.runner.adapters.ffuf import FfufAdapter
from tools.runner.adapters.httpx import HttpxAdapter
from tools.runner.adapters.katana import KatanaAdapter
from tools.runner.adapters.nmap import NmapAdapter
from tools.runner.adapters.nuclei import NucleiAdapter
from tools.runner.adapters.sqlmap import SqlmapAdapter
from tools.runner.adapters.sslyze import SslyzeAdapter


def default_adapters() -> dict[str, Adapter]:
    adapters: list[Adapter] = [
        HttpxAdapter(),
        NucleiAdapter(),
        KatanaAdapter(),
        FfufAdapter(),
        NmapAdapter(),
        BrowserAdapter(),
        XssCheckAdapter(),
        SqlmapAdapter(),
        CommixAdapter(),
        DalfoxAdapter(),
        SslyzeAdapter(),
    ]
    return {adapter.name: adapter for adapter in adapters}


__all__ = ["Adapter", "AdapterError", "RunContext", "default_adapters"]
