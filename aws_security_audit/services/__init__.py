"""Service-specific audit entry points and registry helpers."""
from __future__ import annotations

from dataclasses import dataclass
import importlib
import pkgutil
from types import MappingProxyType
from typing import Callable, Dict, Iterable, Iterator, List, Mapping

import boto3

from ..findings import Finding, InventoryItem


@dataclass
class ServiceReport:
    """Aggregated findings and inventory emitted by a service audit."""

    findings: List[Finding]
    inventory: List[InventoryItem]


ServiceChecker = Callable[[boto3.session.Session], ServiceReport]


def inventory_item_from_findings(
    service: str,
    resource_id: str,
    resource_findings: Iterable[Finding],
    *,
    compliant_details: str = "All checks passed.",
    extra_details: Iterable[str] | None = None,
) -> InventoryItem:
    """Build an :class:`InventoryItem` summarising ``resource_findings``.

    ``extra_details`` allows callers to append contextual information regardless of
    whether the resource is compliant, ensuring the details surface alongside any
    findings.
    """

    messages = [finding.message for finding in resource_findings]
    extra_parts = [detail for detail in (extra_details or []) if detail]
    if messages:
        if extra_parts:
            messages.extend(extra_parts)
        return InventoryItem(
            service=service,
            resource_id=resource_id,
            status="NON_COMPLIANT",
            details="; ".join(messages),
        )

    details_parts = [compliant_details] if compliant_details else []
    details_parts.extend(extra_parts)
    return InventoryItem(
        service=service,
        resource_id=resource_id,
        status="COMPLIANT",
        details="; ".join(details_parts),
    )


class ServiceRegistry:
    """Registry that stores available service audit callables."""

    def __init__(self) -> None:
        self._checks: Dict[str, ServiceChecker] = {}

    @staticmethod
    def _normalize(name: str) -> str:
        if not name:
            raise ValueError("Service name must be a non-empty string")
        return name.strip().lower()

    def register(self, name: str) -> Callable[[ServiceChecker], ServiceChecker]:
        """Return a decorator that registers *name* for the wrapped checker."""

        normalized = self._normalize(name)

        def decorator(func: ServiceChecker) -> ServiceChecker:
            if normalized in self._checks and self._checks[normalized] is not func:
                raise ValueError(f"Service '{name}' is already registered")
            self._checks[normalized] = func
            return func

        return decorator

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        return self._normalize(name) in self._checks

    def __getitem__(self, name: str) -> ServiceChecker:
        return self._checks[self._normalize(name)]

    def keys(self) -> Iterator[str]:
        return iter(self._checks)

    def items(self) -> Iterator[tuple[str, ServiceChecker]]:
        return iter(self._checks.items())

    def as_mapping(self) -> Mapping[str, ServiceChecker]:
        return MappingProxyType(self._checks)


SERVICE_REGISTRY = ServiceRegistry()
register_service = SERVICE_REGISTRY.register


def get_service_checks() -> Mapping[str, ServiceChecker]:
    """Return a read-only mapping of registered service checks."""

    return SERVICE_REGISTRY.as_mapping()


def _import_service_modules() -> None:
    """Import modules that register service checks via decorators."""

    package_name = __name__
    package_paths = getattr(__spec__, "submodule_search_locations", None)
    if not package_paths:
        return

    for module_info in pkgutil.iter_modules(package_paths):
        module_name = module_info.name
        if module_name.startswith("_"):
            continue
        importlib.import_module(f"{package_name}.{module_name}")


_import_service_modules()

SERVICE_CHECKS: Mapping[str, ServiceChecker] = get_service_checks()

__all__ = [
    "SERVICE_CHECKS",
    "SERVICE_REGISTRY",
    "ServiceChecker",
    "ServiceReport",
    "get_service_checks",
    "inventory_item_from_findings",
    "register_service",
]
