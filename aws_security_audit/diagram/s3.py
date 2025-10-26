"""Helpers for summarising Amazon S3 resources in the network diagram."""
from __future__ import annotations

from typing import List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..utils import safe_paginate
from .models import GlobalServiceSummary, summarize_global_service_lines


def build_s3_summary(
    session: boto3.session.Session, max_items: int
) -> Optional[GlobalServiceSummary]:
    """Collect S3 bucket information for the global services panel."""

    try:
        s3 = session.client("s3")
    except (ClientError, EndpointConnectionError):
        return None

    bucket_names: List[str] = []
    try:
        for bucket in safe_paginate(s3, "list_buckets", "Buckets"):
            name = bucket.get("Name")
            if name:
                bucket_names.append(name)
    except (ClientError, EndpointConnectionError):
        bucket_names = []

    if not bucket_names:
        return None

    bucket_names.sort()
    return GlobalServiceSummary(
        title="Amazon S3",
        lines=summarize_global_service_lines(bucket_names, max_items),
        fillcolor="#fefcbf",
        fontcolor="#744210",
    )


__all__ = ["build_s3_summary"]

