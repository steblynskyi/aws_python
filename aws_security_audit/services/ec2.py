"""Audit helpers for Amazon EC2 resources."""
from __future__ import annotations

from typing import Dict, List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import finding_from_exception, safe_paginate
from . import ServiceReport


def audit_ec2_instances(session: boto3.session.Session) -> ServiceReport:
    """Check EC2 instances for IAM profile coverage and encrypted volumes."""

    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    ec2 = session.client("ec2")
    try:
        reservations = safe_paginate(ec2, "describe_instances", "Reservations")
        volume_cache: Dict[str, bool] = {}
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]
                instance_findings: List[Finding] = []
                if "IamInstanceProfile" not in instance:
                    instance_findings.append(
                        Finding(
                            service="EC2",
                            resource_id=instance_id,
                            severity="MEDIUM",
                            message="Instance is not associated with an IAM instance profile.",
                        )
                    )
                for mapping in instance.get("BlockDeviceMappings", []):
                    ebs = mapping.get("Ebs")
                    if not ebs:
                        continue
                    volume_id = ebs["VolumeId"]
                    if volume_id not in volume_cache:
                        try:
                            volume = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
                            volume_cache[volume_id] = volume.get("Encrypted", False)
                        except (ClientError, EndpointConnectionError) as exc:
                            instance_findings.append(
                                finding_from_exception(
                                    "EC2",
                                    "Failed to describe EBS volume",
                                    exc,
                                    resource_id=volume_id,
                                )
                            )
                            volume_cache[volume_id] = True
                            continue
                    if not volume_cache[volume_id]:
                        instance_findings.append(
                            Finding(
                                service="EC2",
                                resource_id=f"{instance_id}:{volume_id}",
                                severity="HIGH",
                                message="EBS volume is not encrypted.",
                            )
                        )
                findings.extend(instance_findings)
                if instance_findings:
                    details = "; ".join(f.message for f in instance_findings)
                    status = "NON_COMPLIANT"
                else:
                    details = "All checks passed."
                    status = "COMPLIANT"
                inventory.append(
                    InventoryItem(
                        service="EC2",
                        resource_id=instance_id,
                        status=status,
                        details=details,
                    )
                )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("EC2", "Failed to describe EC2 instances", exc)
        )
        inventory.append(
            InventoryItem(
                service="EC2",
                resource_id="*",
                status="ERROR",
                details=f"Failed to describe EC2 instances: {exc}",
            )
        )
    return ServiceReport(findings=findings, inventory=inventory)


__all__ = ["audit_ec2_instances"]
