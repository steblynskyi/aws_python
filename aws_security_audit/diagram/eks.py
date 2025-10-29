"""Helpers for summarising Amazon EKS clusters in the network diagram."""
from __future__ import annotations

from typing import List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..utils import safe_paginate
from .models import GlobalServiceSummary, summarize_global_service_lines


def build_eks_summary(
    session: boto3.session.Session, max_items: int
) -> Optional[GlobalServiceSummary]:
    """Collect EKS cluster information for the global services panel."""

    try:
        eks = session.client("eks")
    except (ClientError, EndpointConnectionError):
        return None

    cluster_names: List[str] = []
    try:
        for name in safe_paginate(eks, "list_clusters", "clusters"):
            if isinstance(name, str) and name:
                cluster_names.append(name)
    except (ClientError, EndpointConnectionError):
        cluster_names = []

    if not cluster_names:
        return None

    cluster_names.sort()
    return GlobalServiceSummary(
        title="Amazon EKS",
        lines=summarize_global_service_lines(cluster_names, max_items),
        fillcolor="#bfdbfe",
        fontcolor="#1e3a8a",
    )


__all__ = ["build_eks_summary"]
