"""Tool adapters available to the runner."""

from tools.runner.adapters.base import Adapter, AdapterError, RunContext
from tools.runner.adapters.httpx import HttpxAdapter
from tools.runner.adapters.nuclei import NucleiAdapter


def default_adapters() -> dict[str, Adapter]:
    adapters: list[Adapter] = [HttpxAdapter(), NucleiAdapter()]
    return {adapter.name: adapter for adapter in adapters}


__all__ = ["Adapter", "AdapterError", "RunContext", "default_adapters"]
