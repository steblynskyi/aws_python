"""Helpers for summarising Amazon ECS clusters in the network diagram."""
from __future__ import annotations

from typing import List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..utils import safe_paginate
from .models import GlobalServiceSummary, summarize_global_service_lines
from .registry import register_global_service


def _cluster_label_from_arn(arn: str) -> str:
    """Return a human friendly identifier for an ECS cluster ARN."""

    if not arn:
        return "Cluster"
    if "/" in arn:
        candidate = arn.split("/")[-1]
        if candidate:
            return candidate
    if ":" in arn:
        candidate = arn.split(":")[-1]
        if candidate:
            return candidate
    return arn


@register_global_service("ecs")
def build_ecs_summary(
    session: boto3.session.Session, max_items: int
) -> Optional[GlobalServiceSummary]:
    """Collect ECS cluster information for the global services panel."""

    try:
        ecs = session.client("ecs")
    except (ClientError, EndpointConnectionError):
        return None

    cluster_labels: List[str] = []
    try:
        for arn in safe_paginate(ecs, "list_clusters", "clusterArns"):
            if not isinstance(arn, str):
                continue
            label = _cluster_label_from_arn(arn)
            if label:
                cluster_labels.append(label)
    except (ClientError, EndpointConnectionError):
        cluster_labels = []

    if not cluster_labels:
        return None

    cluster_labels.sort()
    return GlobalServiceSummary(
        title="Amazon ECS",
        lines=summarize_global_service_lines(cluster_labels, max_items),
        fillcolor="#fed7aa",
        fontcolor="#7c2d12",
    )


__all__ = ["build_ecs_summary"]
