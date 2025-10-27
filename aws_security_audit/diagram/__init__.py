"""Network diagram package with service-specific helpers."""

from __future__ import annotations

from typing import Any

try:
    from .main import generate_network_diagram
except ModuleNotFoundError as exc:  # pragma: no cover - triggered when optional files missing
    if exc.name == "aws_security_audit.diagram.main":

        def generate_network_diagram(*args: Any, **kwargs: Any) -> None:
            """Placeholder that explains how to enable diagram generation."""

            raise ModuleNotFoundError(
                "Network diagram support is unavailable. Ensure the optional "
                "diagram modules are present and optional dependencies are installed."
            ) from exc

    else:
        raise

__all__ = ["generate_network_diagram"]
