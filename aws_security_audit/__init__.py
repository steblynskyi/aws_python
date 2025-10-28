"""AWS security auditing toolkit."""

from __future__ import annotations

from typing import Any

from .core import collect_audit_results, collect_findings, print_findings
from .findings import Finding, InventoryItem

try:  # Network diagram generation is an optional feature
    from .diagram import generate_network_diagram
except ModuleNotFoundError as exc:  # pragma: no cover - exercised only when optional extras missing
    if exc.name in {"aws_security_audit.diagram", "aws_security_audit.diagram.main"}:

        def generate_network_diagram(*args: Any, **kwargs: Any) -> None:
            """Placeholder that explains how to enable diagram generation."""

            raise ModuleNotFoundError(
                "Network diagram support is unavailable. Ensure the optional "
                "diagram modules are present and optional dependencies are installed."
            ) from exc

    else:
        raise

__all__ = [
    "Finding",
    "InventoryItem",
    "collect_audit_results",
    "collect_findings",
    "generate_network_diagram",
    "print_findings",
]
