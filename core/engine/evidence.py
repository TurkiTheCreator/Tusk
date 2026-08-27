"""Evidence: the common currency between scan modules and the rule engine.

Every analyzer (banner grabber, HTTP header analyzer, future TLS/DNS
analyzers, ...) observes raw facts about a target. Instead of each analyzer
inventing its own ad-hoc shape, they all emit `Evidence` objects, which the
rule engine can then evaluate uniformly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class Evidence:
    """A single observed fact from a scan.

    Attributes:
        type: Category of the observation, e.g. "banner", "header", "cert", "dns".
        value: The raw observed string (e.g. the banner text, a header value).
        source: Name of the module/analyzer that produced this evidence.
        port: Port the evidence was observed on, if applicable.
        timestamp: UTC time the evidence was captured.
    """

    type: str
    value: str
    source: str
    port: Optional[int] = None
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "value": self.value,
            "source": self.source,
            "port": self.port,
            "timestamp": self.timestamp.isoformat(),
        }
