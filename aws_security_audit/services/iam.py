"""Audit helpers for AWS IAM users."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import finding_from_exception, safe_paginate
from . import ServiceReport, inventory_item_from_findings


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
            try:
                mfas = list(
                    safe_paginate(
                        iam,
                        "list_mfa_devices",
                        "MFADevices",
                        UserName=user_name,
                    )
                )
            except (ClientError, EndpointConnectionError) as exc:
                user_findings.append(
                    finding_from_exception(
                        "IAM",
                        "Failed to list MFA devices",
                        exc,
                        resource_id=user_name,
                        severity="WARNING",
                    )
                )
                mfas = None
            if mfas is not None and not mfas:
                user_findings.append(
                    Finding(
                        service="IAM",
                        resource_id=user_name,
                        severity="HIGH",
                        message="IAM user does not have MFA enabled.",
                    )
                )
            try:
                access_keys = list(
                    safe_paginate(
                        iam,
                        "list_access_keys",
                        "AccessKeyMetadata",
                        UserName=user_name,
                    )
                )
            except (ClientError, EndpointConnectionError) as exc:
                user_findings.append(
                    finding_from_exception(
                        "IAM",
                        "Failed to list access keys",
                        exc,
                        resource_id=user_name,
                        severity="WARNING",
                    )
                )
                access_keys = []
            for key in access_keys:
                create_date = key["CreateDate"]
                resource_id = f"{user_name}:{key['AccessKeyId']}"
                if now - create_date > timedelta(days=90):
                    message = "Access key is older than 90 days."
                    user_findings.append(
                        Finding(
                            service="IAM",
                            resource_id=resource_id,
                            severity="MEDIUM",
                            message=message,
                        )
                    )
                    key_inventory.append(
                        InventoryItem(
                            service="IAM",
                            resource_id=resource_id,
                            status="NON_COMPLIANT",
                            details=message,
                        )
                    )
                else:
                    key_inventory.append(
                        InventoryItem(
                            service="IAM",
                            resource_id=resource_id,
                            status="COMPLIANT",
                            details="Access key rotation within 90 days.",
                        )
                    )
            findings.extend(user_findings)
            inventory.append(
                inventory_item_from_findings("IAM", user_name, user_findings)
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
