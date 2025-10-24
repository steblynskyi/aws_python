"""Audit helpers for AWS IAM users."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding
from ..utils import safe_paginate


def audit_iam_users(session: boto3.session.Session) -> List[Finding]:
    """Ensure IAM users enforce MFA and rotate long-lived access keys."""

    findings: List[Finding] = []
    iam = session.client("iam")
    now = datetime.now(timezone.utc)
    try:
        for user in safe_paginate(iam, "list_users", "Users"):
            user_name = user["UserName"]
            mfas = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
            if not mfas:
                findings.append(
                    Finding(
                        service="IAM",
                        resource_id=user_name,
                        severity="HIGH",
                        message="IAM user does not have MFA enabled.",
                    )
                )
            for key in iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
                create_date = key["CreateDate"]
                if now - create_date > timedelta(days=90):
                    findings.append(
                        Finding(
                            service="IAM",
                            resource_id=f"{user_name}:{key['AccessKeyId']}",
                            severity="MEDIUM",
                            message="Access key is older than 90 days.",
                        )
                    )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            Finding(
                service="IAM",
                resource_id="*",
                severity="ERROR",
                message=f"Failed to audit IAM users: {exc}",
            )
        )
    return findings


__all__ = ["audit_iam_users"]
