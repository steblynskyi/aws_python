"""Audit helpers for Amazon S3 buckets."""
from __future__ import annotations

from typing import Iterable, List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding


def audit_s3_buckets(session: boto3.session.Session) -> List[Finding]:
    """Check buckets for public access and encryption gaps."""

    findings: List[Finding] = []
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except (ClientError, EndpointConnectionError) as exc:
        return [
            Finding(
                service="S3",
                resource_id="*",
                severity="ERROR",
                message=f"Failed to list buckets: {exc}",
            )
        ]

    for bucket in buckets:
        name = bucket["Name"]
        findings.extend(_check_bucket_acl(s3, name))
        findings.extend(_check_public_access_block(s3, name))
        findings.extend(_check_bucket_encryption(s3, name))
    return findings


def _check_bucket_acl(s3: boto3.client, name: str) -> Iterable[Finding]:
    """Yield findings related to an S3 bucket ACL."""

    try:
        acl = s3.get_bucket_acl(Bucket=name)
    except (ClientError, EndpointConnectionError) as exc:
        code = _error_code(exc)
        severity = "WARNING" if code == "AccessDenied" else "ERROR"
        message = (
            "Access denied while retrieving bucket ACL." if severity == "WARNING" else f"Failed to retrieve bucket ACL: {exc}"
        )
        yield Finding(service="S3", resource_id=name, severity=severity, message=message)
        return

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

        yield Finding(
            service="S3",
            resource_id=name,
            severity=severity,
            message=f"Bucket ACL allows access for {audience}.",
        )


def _check_public_access_block(s3: boto3.client, name: str) -> Iterable[Finding]:
    """Yield findings for bucket-level public access block configuration."""

    try:
        pab = s3.get_public_access_block(Bucket=name)
    except (ClientError, EndpointConnectionError) as exc:
        code = _error_code(exc)
        if code == "NoSuchPublicAccessBlockConfiguration":
            severity = "LOW"
            message = "Public access block configuration is missing."
        elif code == "AccessDenied":
            severity = "WARNING"
            message = "Access denied while checking public access block configuration."
        else:
            severity = "ERROR"
            message = f"Failed to retrieve public access block configuration: {exc}"
        yield Finding(service="S3", resource_id=name, severity=severity, message=message)
        return

    config = pab.get("PublicAccessBlockConfiguration", {})
    required_flags = (
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    )
    if not all(config.get(key, False) for key in required_flags):
        yield Finding(
            service="S3",
            resource_id=name,
            severity="MEDIUM",
            message="Public access block is not fully enabled.",
        )


def _check_bucket_encryption(s3: boto3.client, name: str) -> Iterable[Finding]:
    """Yield findings about default encryption for an S3 bucket."""

    try:
        s3.get_bucket_encryption(Bucket=name)
    except (ClientError, EndpointConnectionError) as exc:
        code = _error_code(exc)
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            severity = "HIGH"
            message = "Bucket encryption is not enabled."
        elif code == "AccessDenied":
            severity = "WARNING"
            message = "Access denied while checking default encryption."
        else:
            severity = "ERROR"
            message = f"Failed to check bucket encryption: {exc}"
        yield Finding(service="S3", resource_id=name, severity=severity, message=message)


def _error_code(exc: Exception) -> str:
    """Return the AWS error code from a botocore exception, if present."""

    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "")
    return ""


__all__ = ["audit_s3_buckets"]
