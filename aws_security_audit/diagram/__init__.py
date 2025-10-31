"""Network diagram package with service-specific helpers."""

from __future__ import annotations

from typing import Any

try:
    from .main import generate_network_diagram
except ModuleNotFoundError as exc:  # pragma: no cover - triggered when optional files missing
    if exc.name == "aws_security_audit.diagram.main":
        _import_error = exc

        def generate_network_diagram(
            *args: Any, _exc: ModuleNotFoundError = _import_error, **kwargs: Any
        ) -> None:
            """Placeholder that explains how to enable diagram generation."""

            raise ModuleNotFoundError(
                "Network diagram support is unavailable. Ensure the optional "
                "diagram modules are present and optional dependencies are installed."
            ) from _exc

    else:
        raise

from .registry import (
    GLOBAL_SERVICE_BUILDERS,
    GLOBAL_SERVICE_REGISTRY,
    GlobalServiceBuilder,
    build_global_service_summaries,
    get_global_service_builders,
    iter_global_service_summaries,
    register_global_service,
)

__all__ = [
    "generate_network_diagram",
    "GLOBAL_SERVICE_BUILDERS",
    "GLOBAL_SERVICE_REGISTRY",
    "GlobalServiceBuilder",
    "build_global_service_summaries",
    "get_global_service_builders",
    "iter_global_service_summaries",
    "register_global_service",
]
