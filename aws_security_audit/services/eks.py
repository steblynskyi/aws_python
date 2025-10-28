"""Audit helpers for Amazon EKS clusters."""
from __future__ import annotations

from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import finding_from_exception, safe_paginate
from . import ServiceReport


def audit_eks_clusters(session: boto3.session.Session) -> ServiceReport:
    """Assess EKS clusters for logging and encryption coverage."""

    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    eks = session.client("eks")
    try:
        clusters = list(safe_paginate(eks, "list_clusters", "clusters"))
        for name in clusters:
            try:
                cluster = eks.describe_cluster(name=name)["cluster"]
            except ClientError as exc:
                finding = finding_from_exception(
                    "EKS",
                    "Failed to describe cluster",
                    exc,
                    resource_id=name,
                )
                findings.append(finding)
                inventory.append(
                    InventoryItem(
                        service="EKS",
                        resource_id=name,
                        status="ERROR",
                        details=f"Failed to describe cluster: {exc}",
                    )
                )
                continue
            cluster_findings: List[Finding] = []
            logging = cluster.get("logging", {}).get("clusterLogging", [])
            if not logging:
                cluster_findings.append(
                    Finding(
                        service="EKS",
                        resource_id=name,
                        severity="MEDIUM",
                        message="Control plane logging is disabled.",
                    )
                )
            else:
                for entry in logging:
                    if not entry.get("enabled"):
                        cluster_findings.append(
                            Finding(
                                service="EKS",
                                resource_id=name,
                                severity="MEDIUM",
                                message=f"Control plane logging for {entry.get('types')} is disabled.",
                            )
                        )
            if not cluster.get("encryptionConfig"):
                cluster_findings.append(
                    Finding(
                        service="EKS",
                        resource_id=name,
                        severity="MEDIUM",
                        message="Secret encryption is not configured for the cluster.",
                    )
                )
            findings.extend(cluster_findings)
            if cluster_findings:
                details = "; ".join(f.message for f in cluster_findings)
                status = "NON_COMPLIANT"
            else:
                details = "All checks passed."
                status = "COMPLIANT"
            inventory.append(
                InventoryItem(
                    service="EKS",
                    resource_id=name,
                    status=status,
                    details=details,
                )
            )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("EKS", "Failed to list clusters", exc)
        )
        inventory.append(
            InventoryItem(
                service="EKS",
                resource_id="*",
                status="ERROR",
                details=f"Failed to list clusters: {exc}",
            )
        )
    return ServiceReport(findings=findings, inventory=inventory)


__all__ = ["audit_eks_clusters"]
