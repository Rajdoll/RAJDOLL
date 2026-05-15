from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EndpointSpec:
    """Target endpoint description passed to framework components.

    Generic across all targets; sourced from endpoint_inventory at runtime.
    """
    url: str
    method: str
    params: list[str] = field(default_factory=list)
    content_type: Optional[str] = None


@dataclass
class Payload:
    """Single payload candidate emitted by PayloadSynthesizer.

    `expected_signal` is required so callers can validate response without
    relying on HTTP status alone (reduces false positives).
    """
    value: str
    encoding: str               # raw|url|base64|json|xml
    expected_signal: str
    category: str
    engine_hypothesis: Optional[str] = None
