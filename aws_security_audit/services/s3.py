"""Audit helpers for Amazon S3 buckets."""
from __future__ import annotations

from typing import List

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
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    findings.append(
                        Finding(
                            service="S3",
                            resource_id=name,
                            severity="HIGH",
                            message="Bucket ACL allows public access.",
                        )
                    )
        except ClientError:
            pass

        try:
            pab = s3.get_public_access_block(Bucket=name)
            config = pab.get("PublicAccessBlockConfiguration", {})
            if not all(
                config.get(key, False)
                for key in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            ):
                findings.append(
                    Finding(
                        service="S3",
                        resource_id=name,
                        severity="MEDIUM",
                        message="Public access block is not fully enabled.",
                    )
                )
        except ClientError:
            findings.append(
                Finding(
                    service="S3",
                    resource_id=name,
                    severity="LOW",
                    message="Public access block configuration is missing.",
                )
            )

        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            findings.append(
                Finding(
                    service="S3",
                    resource_id=name,
                    severity="HIGH",
                    message="Bucket encryption is not enabled.",
                )
            )
    return findings


__all__ = ["audit_s3_buckets"]
