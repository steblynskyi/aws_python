"""Helpers for summarising Amazon Route 53 resources."""
from __future__ import annotations

from typing import List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..utils import safe_paginate
from .models import GlobalServiceSummary, summarize_global_service_lines


def build_route53_summary(
    session: boto3.session.Session, max_items: int
) -> Optional[GlobalServiceSummary]:
    """Collect Route 53 hosted zone details for the global services panel."""

    try:
        route53 = session.client("route53")
    except (ClientError, EndpointConnectionError):
        return None

    hosted_zone_labels: List[str] = []
    try:
        for zone in safe_paginate(route53, "list_hosted_zones", "HostedZones"):
            zone_name = (zone.get("Name") or "").rstrip(".")
            zone_id = zone.get("Id", "").split("/")[-1]
            if zone_name and zone_id:
                hosted_zone_labels.append(f"{zone_name} ({zone_id})")
            elif zone_name:
                hosted_zone_labels.append(zone_name)
            elif zone_id:
                hosted_zone_labels.append(zone_id)
    except (ClientError, EndpointConnectionError):
        hosted_zone_labels = []

    if not hosted_zone_labels:
        return None

    hosted_zone_labels.sort()
    return GlobalServiceSummary(
        title="Amazon Route 53",
        lines=summarize_global_service_lines(hosted_zone_labels, max_items),
        fillcolor="#e9d8fd",
        fontcolor="#44337a",
    )


__all__ = ["build_route53_summary"]

