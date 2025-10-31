"""Audit helpers for Amazon S3 buckets."""
from __future__ import annotations

from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import finding_from_exception
from . import ServiceReport, inventory_item_from_findings, register_service


@register_service("s3")
def audit_s3_buckets(session: boto3.session.Session) -> ServiceReport:
    """Check buckets for public access and encryption gaps."""

    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except (ClientError, EndpointConnectionError) as exc:
        message = "Failed to list buckets"
        finding = finding_from_exception("S3", message, exc)
        return ServiceReport(
            findings=[finding],
            inventory=[
                InventoryItem(
                    service="S3",
                    resource_id="*",
                    status="ERROR",
                    details=f"{message}: {exc}",
                )
            ],
        )

    for bucket in buckets:
        name = bucket["Name"]
        bucket_findings: List[Finding] = []
        bucket_findings.extend(_check_bucket_acl(s3, name))
        bucket_findings.extend(_check_public_access_block(s3, name))
        bucket_findings.extend(_check_bucket_encryption(s3, name))
        findings.extend(bucket_findings)

        inventory.append(
            inventory_item_from_findings("S3", name, bucket_findings)
        )
    return ServiceReport(findings=findings, inventory=inventory)


def _check_bucket_acl(s3: boto3.client, name: str) -> List[Finding]:
    """Return findings related to an S3 bucket ACL."""

    findings: List[Finding] = []

    try:
        acl = s3.get_bucket_acl(Bucket=name)
    except (ClientError, EndpointConnectionError) as exc:
        code = _error_code(exc)
        if code == "AccessDenied":
            findings.append(
                Finding(
                    service="S3",
                    resource_id=name,
                    severity="WARNING",
                    message="Access denied while retrieving bucket ACL.",
                )
            )
        else:
            findings.append(
                finding_from_exception(
                    "S3", "Failed to retrieve bucket ACL", exc, resource_id=name
                )
            )
        return findings

    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        if not uri:
            continue

        if uri.endswith("AllUsers"):
            severity = "HIGH"
            audience = "the internet"
        elif uri.endswith("AuthenticatedUsers"):
            severity = "MEDIUM"
            audience = "all AWS accounts"
        else:
            continue

        findings.append(
            Finding(
                service="S3",
                resource_id=name,
                severity=severity,
                message=f"Bucket ACL allows access for {audience}.",
            )
        )
    return findings


def _check_public_access_block(s3: boto3.client, name: str) -> List[Finding]:
    """Return findings for bucket-level public access block configuration."""

    findings: List[Finding] = []

    try:
        pab = s3.get_public_access_block(Bucket=name)
    except (ClientError, EndpointConnectionError) as exc:
        code = _error_code(exc)
        if code == "NoSuchPublicAccessBlockConfiguration":
            findings.append(
                Finding(
                    service="S3",
                    resource_id=name,
                    severity="LOW",
                    message="Public access block configuration is missing.",
                )
            )
        elif code == "AccessDenied":
            findings.append(
                Finding(
                    service="S3",
                    resource_id=name,
                    severity="WARNING",
                    message="Access denied while checking public access block configuration.",
                )
            )
        else:
            findings.append(
                finding_from_exception(
                    "S3",
                    "Failed to retrieve public access block configuration",
                    exc,
                    resource_id=name,
                )
            )
        return findings

    config = pab.get("PublicAccessBlockConfiguration", {})
    required_flags = (
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    )
    if not all(config.get(key, False) for key in required_flags):
        findings.append(
            Finding(
                service="S3",
                resource_id=name,
                severity="MEDIUM",
                message="Public access block is not fully enabled.",
            )
        )
    return findings


def _check_bucket_encryption(s3: boto3.client, name: str) -> List[Finding]:
    """Return findings about default encryption for an S3 bucket."""

    findings: List[Finding] = []

    try:
        s3.get_bucket_encryption(Bucket=name)
    except (ClientError, EndpointConnectionError) as exc:
        code = _error_code(exc)
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append(
                Finding(
                    service="S3",
                    resource_id=name,
                    severity="HIGH",
                    message="Bucket encryption is not enabled.",
                )
            )
        elif code == "AccessDenied":
            findings.append(
                Finding(
                    service="S3",
                    resource_id=name,
                    severity="WARNING",
                    message="Access denied while checking default encryption.",
                )
            )
        else:
            findings.append(
                finding_from_exception(
                    "S3", "Failed to check bucket encryption", exc, resource_id=name
                )
            )
    return findings


def _error_code(exc: Exception) -> str:
    """Return the AWS error code from a botocore exception, if present."""

    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "")
    return ""


__all__ = ["audit_s3_buckets"]
