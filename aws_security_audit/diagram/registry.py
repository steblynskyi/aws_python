"""Registries and helpers for diagram service summaries."""

from __future__ import annotations

from typing import Callable, Dict, Iterator, List, Mapping, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from .acm import build_acm_summary
from .ecs import build_ecs_summary
from .eks import build_eks_summary
from .iam import build_iam_summary
from .kms import build_kms_summary
from .models import GlobalServiceSummary
from .route53 import build_route53_summary
from .s3 import build_s3_summary
from .ssm import build_ssm_summary


GlobalServiceBuilder = Callable[
    [boto3.session.Session, int], Optional[GlobalServiceSummary]
]
"""Callable used to construct a :class:`GlobalServiceSummary`."""


GLOBAL_SERVICE_BUILDERS: Dict[str, GlobalServiceBuilder] = {
    "kms": build_kms_summary,
    "s3": build_s3_summary,
    "acm": build_acm_summary,
    "route53": build_route53_summary,
    "iam": build_iam_summary,
    "ssm": build_ssm_summary,
    "eks": build_eks_summary,
    "ecs": build_ecs_summary,
}
"""Default mapping of global service identifiers to summary builders."""


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
    builders: Mapping[str, GlobalServiceBuilder] = GLOBAL_SERVICE_BUILDERS,
) -> Iterator[Tuple[str, GlobalServiceSummary]]:
    """Yield pairs of service identifiers and their summaries."""

    for service, builder in builders.items():
        summary = _call_builder(builder, session, max_items)
        if summary:
            yield service, summary


def build_global_service_summaries(
    session: boto3.session.Session,
    max_items: int,
    *,
    builders: Mapping[str, GlobalServiceBuilder] = GLOBAL_SERVICE_BUILDERS,
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
    "GlobalServiceBuilder",
    "build_global_service_summaries",
    "iter_global_service_summaries",
]

