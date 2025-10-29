"""Audit helpers for Amazon ECS clusters."""
from __future__ import annotations

from typing import Iterable, List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import batch_iterable, finding_from_exception, safe_paginate
from . import ServiceReport, inventory_item_from_findings


def audit_ecs_clusters(session: boto3.session.Session) -> ServiceReport:
    """Inspect ECS clusters for observability and exec support."""

    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    ecs = session.client("ecs")
    try:
        cluster_arns = list(safe_paginate(ecs, "list_clusters", "clusterArns"))
        for batch in batch_iterable(cluster_arns, 10):
            if not batch:
                continue
            try:
                response = ecs.describe_clusters(clusters=list(batch), include=["SETTINGS", "CONFIGURATIONS"])
            except (ClientError, EndpointConnectionError) as exc:
                for arn in batch:
                    findings.append(
                        finding_from_exception(
                            "ECS",
                            "Failed to describe cluster",
                            exc,
                            resource_id=arn,
                        )
                    )
                    inventory.append(
                        InventoryItem(
                            service="ECS",
                            resource_id=arn,
                            status="ERROR",
                            details=f"Failed to describe cluster: {exc}",
                        )
                    )
                continue
            for cluster in response.get("clusters", []):
                arn = cluster.get("clusterArn", "unknown")
                cluster_findings: List[Finding] = []
                insights = {setting.get("name"): setting.get("value") for setting in cluster.get("settings", [])}
                if insights.get("containerInsights") != "enabled":
                    cluster_findings.append(
                        Finding(
                            service="ECS",
                            resource_id=arn,
                            severity="LOW",
                            message="CloudWatch Container Insights is not enabled.",
                        )
                    )
                if not cluster.get("configuration", {}).get("executeCommandConfiguration"):
                    cluster_findings.append(
                        Finding(
                            service="ECS",
                            resource_id=arn,
                            severity="LOW",
                            message="ECS Exec is not configured.",
                        )
                    )
                findings.extend(cluster_findings)
                inventory.append(
                    inventory_item_from_findings("ECS", arn, cluster_findings)
                )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("ECS", "Failed to list ECS clusters", exc)
        )
        inventory.append(
            InventoryItem(
                service="ECS",
                resource_id="*",
                status="ERROR",
                details=f"Failed to list ECS clusters: {exc}",
            )
        )
    return ServiceReport(findings=findings, inventory=inventory)


__all__ = ["audit_ecs_clusters"]
