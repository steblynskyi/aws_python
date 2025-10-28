"""Data models for AWS security audit findings."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


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


@dataclass
class InventoryItem:
    """Represents the compliance state of an audited AWS resource."""

    service: str
    resource_id: str
    status: Literal["COMPLIANT", "NON_COMPLIANT", "ERROR"]
    details: str


__all__ = ["Finding", "InventoryItem"]
