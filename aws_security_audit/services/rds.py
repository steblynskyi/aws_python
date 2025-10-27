"""Audit helpers for Amazon RDS instances."""
from __future__ import annotations

from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding
from ..utils import finding_from_exception, safe_paginate


def audit_rds_instances(session: boto3.session.Session) -> List[Finding]:
    """Check RDS instances for encryption and public exposure."""

    findings: List[Finding] = []
    rds = session.client("rds")
    try:
        for db in safe_paginate(rds, "describe_db_instances", "DBInstances"):
            db_id = db["DBInstanceIdentifier"]
            if db.get("PubliclyAccessible"):
                findings.append(
                    Finding(
                        service="RDS",
                        resource_id=db_id,
                        severity="HIGH",
                        message="RDS instance is publicly accessible.",
                    )
                )
            if not db.get("StorageEncrypted", False):
                findings.append(
                    Finding(
                        service="RDS",
                        resource_id=db_id,
                        severity="HIGH",
                        message="RDS storage is not encrypted.",
                    )
                )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("RDS", "Failed to describe RDS instances", exc)
        )
    return findings


__all__ = ["audit_rds_instances"]
