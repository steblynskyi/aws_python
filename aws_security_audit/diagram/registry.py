"""Registries and helpers for diagram service summaries."""

from __future__ import annotations

from types import MappingProxyType
from typing import Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from .models import GlobalServiceSummary


GlobalServiceBuilder = Callable[
    [boto3.session.Session, int], Optional[GlobalServiceSummary]
]
"""Callable used to construct a :class:`GlobalServiceSummary`."""


class GlobalServiceRegistry:
    """Registry storing builders for diagram global service summaries."""

    def __init__(self) -> None:
        self._builders: Dict[str, GlobalServiceBuilder] = {}

    @staticmethod
    def _normalize(name: str) -> str:
        if not name:
            raise ValueError("Service name must be a non-empty string")
        return name.strip().lower()

    def register(self, name: str) -> Callable[[GlobalServiceBuilder], GlobalServiceBuilder]:
        normalized = self._normalize(name)

        def decorator(func: GlobalServiceBuilder) -> GlobalServiceBuilder:
            if normalized in self._builders and self._builders[normalized] is not func:
                raise ValueError(f"Diagram service '{name}' is already registered")
            self._builders[normalized] = func
            return func

        return decorator

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        return self._normalize(name) in self._builders

    def __getitem__(self, name: str) -> GlobalServiceBuilder:
        return self._builders[self._normalize(name)]

    def items(self) -> Iterator[Tuple[str, GlobalServiceBuilder]]:
        return iter(self._builders.items())

    def as_mapping(self) -> Mapping[str, GlobalServiceBuilder]:
        return MappingProxyType(self._builders)


GLOBAL_SERVICE_REGISTRY = GlobalServiceRegistry()
register_global_service = GLOBAL_SERVICE_REGISTRY.register


def get_global_service_builders() -> Mapping[str, GlobalServiceBuilder]:
    """Return a read-only mapping of registered diagram builders."""

    return GLOBAL_SERVICE_REGISTRY.as_mapping()


def _import_service_modules() -> None:
    """Import modules whose side effects register global service builders."""

    from . import acm, ecs, eks, iam, kms, route53, s3, ssm  # noqa: F401


_import_service_modules()

GLOBAL_SERVICE_BUILDERS: Mapping[str, GlobalServiceBuilder] = (
    get_global_service_builders()
)


def _call_builder(
    builder: GlobalServiceBuilder,
    session: boto3.session.Session,
    max_items: int,
) -> Optional[GlobalServiceSummary]:
    try:
        return builder(session, max_items)
    except (ClientError, EndpointConnectionError):
        return None


def iter_global_service_summaries(
    session: boto3.session.Session,
    max_items: int,
    *,
    builders: Mapping[str, GlobalServiceBuilder] | Iterable[Tuple[str, GlobalServiceBuilder]] = GLOBAL_SERVICE_BUILDERS,
) -> Iterator[Tuple[str, GlobalServiceSummary]]:
    """Yield pairs of service identifiers and their summaries."""

    items: Iterable[Tuple[str, GlobalServiceBuilder]]
    if isinstance(builders, Mapping):
        items = builders.items()
    else:
        items = builders

    for service, builder in items:
        summary = _call_builder(builder, session, max_items)
        if summary:
            yield service, summary


def build_global_service_summaries(
    session: boto3.session.Session,
    max_items: int,
    *,
    builders: Mapping[str, GlobalServiceBuilder] | Iterable[Tuple[str, GlobalServiceBuilder]] = GLOBAL_SERVICE_BUILDERS,
) -> List[GlobalServiceSummary]:
    """Return a list of global service summaries using ``builders``."""

    return [
        summary
        for _, summary in iter_global_service_summaries(
            session, max_items, builders=builders
        )
    ]


__all__ = [
    "GLOBAL_SERVICE_BUILDERS",
    "GLOBAL_SERVICE_REGISTRY",
    "GlobalServiceBuilder",
    "build_global_service_summaries",
    "get_global_service_builders",
    "iter_global_service_summaries",
    "register_global_service",
]

