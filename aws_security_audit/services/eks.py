"""Audit helpers for Amazon EKS clusters."""
from __future__ import annotations

from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding
from ..utils import finding_from_exception, safe_paginate


def audit_eks_clusters(session: boto3.session.Session) -> List[Finding]:
    """Assess EKS clusters for logging and encryption coverage."""

    findings: List[Finding] = []
    eks = session.client("eks")
    try:
        clusters = list(safe_paginate(eks, "list_clusters", "clusters"))
        for name in clusters:
            try:
                cluster = eks.describe_cluster(name=name)["cluster"]
            except ClientError as exc:
                findings.append(
                    finding_from_exception(
                        "EKS",
                        "Failed to describe cluster",
                        exc,
                        resource_id=name,
                    )
                )
                continue
            logging = cluster.get("logging", {}).get("clusterLogging", [])
            if not logging:
                findings.append(
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
                        findings.append(
                            Finding(
                                service="EKS",
                                resource_id=name,
                                severity="MEDIUM",
                                message=f"Control plane logging for {entry.get('types')} is disabled.",
                            )
                        )
            if not cluster.get("encryptionConfig"):
                findings.append(
                    Finding(
                        service="EKS",
                        resource_id=name,
                        severity="MEDIUM",
                        message="Secret encryption is not configured for the cluster.",
                    )
                )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("EKS", "Failed to list clusters", exc)
        )
    return findings


__all__ = ["audit_eks_clusters"]
