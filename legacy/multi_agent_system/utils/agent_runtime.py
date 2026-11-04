from __future__ import annotations

"""Runtime helpers shared between agents and infrastructure layers."""

import contextvars
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover
	from ..agents.base_agent import BaseAgent

# Context variable used by MCPClient (and other utilities) to figure out which
# agent is currently executing. BaseAgent sets this value before calling
# ``run()`` so downstream helpers can attach metadata or enforce policies
# without every agent needing to be modified individually.
CURRENT_AGENT: contextvars.ContextVar[Optional["BaseAgent"]] = contextvars.ContextVar(
	"rajdoll_current_agent",
	default=None,
)
