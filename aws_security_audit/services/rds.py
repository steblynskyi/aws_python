"""Audit helpers for Amazon RDS instances."""
from __future__ import annotations

from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import finding_from_exception, safe_paginate
from . import ServiceReport, inventory_item_from_findings


def audit_rds_instances(session: boto3.session.Session) -> ServiceReport:
    """Check RDS instances for encryption and public exposure."""

    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    rds = session.client("rds")
    try:
        for db in safe_paginate(rds, "describe_db_instances", "DBInstances"):
            db_id = db["DBInstanceIdentifier"]
            db_findings: List[Finding] = []
            if db.get("PubliclyAccessible"):
                db_findings.append(
                    Finding(
                        service="RDS",
                        resource_id=db_id,
                        severity="HIGH",
                        message="RDS instance is publicly accessible.",
                    )
                )
            if not db.get("StorageEncrypted", False):
                db_findings.append(
                    Finding(
                        service="RDS",
                        resource_id=db_id,
                        severity="HIGH",
                        message="RDS storage is not encrypted.",
                    )
                )
            findings.extend(db_findings)
            inventory.append(
                inventory_item_from_findings("RDS", db_id, db_findings)
            )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("RDS", "Failed to describe RDS instances", exc)
        )
        inventory.append(
            InventoryItem(
                service="RDS",
                resource_id="*",
                status="ERROR",
                details=f"Failed to describe RDS instances: {exc}",
            )
        )
    return ServiceReport(findings=findings, inventory=inventory)


__all__ = ["audit_rds_instances"]
