"""Helpers for summarising AWS Systems Manager managed instances."""
from __future__ import annotations

from typing import List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..utils import safe_paginate
from .models import GlobalServiceSummary, summarize_global_service_lines


def _format_instance_label(instance: dict) -> Optional[str]:
    instance_id = instance.get("InstanceId") or instance.get("ManagedInstanceId")
    if not instance_id:
        return None
    ping_status = instance.get("PingStatus")
    platform = instance.get("PlatformType")

    details: List[str] = []
    if ping_status:
        details.append(f"Ping: {ping_status}")
    if platform:
        details.append(str(platform))

    if details:
        return f"{instance_id} ({'; '.join(details)})"
    return instance_id


def build_ssm_summary(
    session: boto3.session.Session, max_items: int
) -> Optional[GlobalServiceSummary]:
    """Collect SSM managed instance details for the global services panel."""

    try:
        ssm = session.client("ssm")
    except (ClientError, EndpointConnectionError):
        return None

    instance_labels: List[str] = []
    try:
        for instance in safe_paginate(
            ssm, "describe_instance_information", "InstanceInformationList"
        ):
            label = _format_instance_label(instance)
            if label:
                instance_labels.append(label)
    except EndpointConnectionError:
        return None
    except ClientError:
        instance_labels = []

    if not instance_labels:
        return None

    instance_labels.sort()
    return GlobalServiceSummary(
        title="AWS Systems Manager",
        lines=summarize_global_service_lines(instance_labels, max_items),
        fillcolor="#dcfce7",
        fontcolor="#166534",
    )


__all__ = ["build_ssm_summary"]
