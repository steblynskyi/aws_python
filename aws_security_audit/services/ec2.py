"""Audit helpers for Amazon EC2 resources."""
from __future__ import annotations

from typing import Dict, List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import batch_iterable, finding_from_exception, safe_paginate
from . import ServiceReport, inventory_item_from_findings


VOLUME_BATCH_SIZE = 200  # describe_volumes allows up to 500 IDs


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

                volume_ids = []
                for mapping in instance.get("BlockDeviceMappings", []):
                    ebs = mapping.get("Ebs")
                    if not ebs:
                        continue
                    volume_id = ebs.get("VolumeId")
                    if volume_id:
                        volume_ids.append(volume_id)

                unique_volume_ids = list(dict.fromkeys(volume_ids))
                if unique_volume_ids:
                    _ensure_volume_details(
                        ec2, unique_volume_ids, volume_cache, instance_findings
                    )
                    for volume_id in unique_volume_ids:
                        if not volume_cache.get(volume_id, True):
                            instance_findings.append(
                                Finding(
                                    service="EC2",
                                    resource_id=f"{instance_id}:{volume_id}",
                                    severity="HIGH",
                                    message="EBS volume is not encrypted.",
                                )
                            )

                findings.extend(instance_findings)
                inventory.append(
                    inventory_item_from_findings("EC2", instance_id, instance_findings)
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


def _ensure_volume_details(
    ec2: boto3.client,
    volume_ids: List[str],
    volume_cache: Dict[str, bool],
    instance_findings: List[Finding],
) -> None:
    """Populate ``volume_cache`` with encryption status for ``volume_ids``."""

    missing_ids = [volume_id for volume_id in volume_ids if volume_id not in volume_cache]
    if not missing_ids:
        return

    for batch in batch_iterable(missing_ids, VOLUME_BATCH_SIZE):
        try:
            response = ec2.describe_volumes(VolumeIds=list(batch))
        except (ClientError, EndpointConnectionError) as exc:
            for volume_id in batch:
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

        volumes = response.get("Volumes", [])
        retrieved_ids = set()
        for volume in volumes:
            volume_id = volume.get("VolumeId")
            if not volume_id:
                continue
            retrieved_ids.add(volume_id)
            volume_cache[volume_id] = volume.get("Encrypted", False)

        for volume_id in batch:
            if volume_id not in retrieved_ids:
                volume_cache.setdefault(volume_id, True)


__all__ = ["audit_ec2_instances"]
