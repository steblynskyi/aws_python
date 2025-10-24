"""Data models for AWS security audit findings."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Finding:
    """Represents a potential security issue for a single AWS resource."""

    service: str
    resource_id: str
    severity: str
    message: str

    def key(self) -> str:
        """Stable identifier used to de-duplicate findings."""

        return f"{self.severity}:{self.service}:{self.resource_id}:{self.message}"


__all__ = ["Finding"]
