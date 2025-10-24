"""Audit helpers for Amazon ECS clusters."""
from __future__ import annotations

from typing import Iterable, List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding
from ..utils import batch_iterable, safe_paginate


def audit_ecs_clusters(session: boto3.session.Session) -> List[Finding]:
    """Inspect ECS clusters for observability and exec support."""

    findings: List[Finding] = []
    ecs = session.client("ecs")
    try:
        cluster_arns = list(safe_paginate(ecs, "list_clusters", "clusterArns"))
        for batch in batch_iterable(cluster_arns, 10):
            if not batch:
                continue
            try:
                response = ecs.describe_clusters(clusters=list(batch), include=["SETTINGS", "CONFIGURATIONS"])
            except ClientError as exc:
                for arn in batch:
                    findings.append(
                        Finding(
                            service="ECS",
                            resource_id=arn,
                            severity="ERROR",
                            message=f"Failed to describe cluster: {exc}",
                        )
                    )
                continue
            for cluster in response.get("clusters", []):
                arn = cluster.get("clusterArn", "unknown")
                insights = {setting.get("name"): setting.get("value") for setting in cluster.get("settings", [])}
                if insights.get("containerInsights") != "enabled":
                    findings.append(
                        Finding(
                            service="ECS",
                            resource_id=arn,
                            severity="LOW",
                            message="CloudWatch Container Insights is not enabled.",
                        )
                    )
                if not cluster.get("configuration", {}).get("executeCommandConfiguration"):
                    findings.append(
                        Finding(
                            service="ECS",
                            resource_id=arn,
                            severity="LOW",
                            message="ECS Exec is not configured.",
                        )
                    )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            Finding(
                service="ECS",
                resource_id="*",
                severity="ERROR",
                message=f"Failed to list ECS clusters: {exc}",
            )
        )
    return findings


__all__ = ["audit_ecs_clusters"]
