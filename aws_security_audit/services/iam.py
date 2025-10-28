"""Audit helpers for AWS IAM users."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import finding_from_exception, safe_paginate
from . import ServiceReport


def audit_iam_users(session: boto3.session.Session) -> ServiceReport:
    """Ensure IAM users enforce MFA and rotate long-lived access keys."""

    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    iam = session.client("iam")
    now = datetime.now(timezone.utc)
    try:
        for user in safe_paginate(iam, "list_users", "Users"):
            user_name = user["UserName"]
            user_findings: List[Finding] = []
            key_inventory: List[InventoryItem] = []
            mfas = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
            if not mfas:
                user_findings.append(
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
                    user_findings.append(
                        Finding(
                            service="IAM",
                            resource_id=f"{user_name}:{key['AccessKeyId']}",
                            severity="MEDIUM",
                            message="Access key is older than 90 days.",
                        )
                    )
                    key_inventory.append(
                        InventoryItem(
                            service="IAM",
                            resource_id=f"{user_name}:{key['AccessKeyId']}",
                            status="NON_COMPLIANT",
                            details="Access key is older than 90 days.",
                        )
                    )
                else:
                    key_inventory.append(
                        InventoryItem(
                            service="IAM",
                            resource_id=f"{user_name}:{key['AccessKeyId']}",
                            status="COMPLIANT",
                            details="Access key rotation within 90 days.",
                        )
                    )
            findings.extend(user_findings)
            if user_findings:
                details = "; ".join(f.message for f in user_findings)
                status = "NON_COMPLIANT"
            else:
                details = "All checks passed."
                status = "COMPLIANT"
            inventory.append(
                InventoryItem(
                    service="IAM",
                    resource_id=user_name,
                    status=status,
                    details=details,
                )
            )
            inventory.extend(key_inventory)
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("IAM", "Failed to audit IAM users", exc)
        )
        inventory.append(
            InventoryItem(
                service="IAM",
                resource_id="*",
                status="ERROR",
                details=f"Failed to audit IAM users: {exc}",
            )
        )
    return ServiceReport(findings=findings, inventory=inventory)


__all__ = ["audit_iam_users"]
