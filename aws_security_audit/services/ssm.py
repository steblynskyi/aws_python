"""Audit helpers for AWS Systems Manager."""
from __future__ import annotations

from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import finding_from_exception, safe_paginate
from . import ServiceReport, inventory_item_from_findings, register_service


@register_service("ssm")
def audit_ssm_managed_instances(session: boto3.session.Session) -> ServiceReport:
    """Inspect Systems Manager managed instances for connectivity and patches."""

    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    ssm = session.client("ssm")
    try:
        for instance in safe_paginate(ssm, "describe_instance_information", "InstanceInformationList"):
            instance_id = instance.get("InstanceId")
            instance_findings: List[Finding] = []
            if instance.get("PingStatus") != "Online":
                instance_findings.append(
                    Finding(
                        service="SSM",
                        resource_id=instance_id or "unknown",
                        severity="MEDIUM",
                        message="SSM managed instance is not online.",
                    )
                )
            patch_state = instance.get("PatchStatus")
            if patch_state and patch_state.get("PatchState") not in {"INSTALLED", "INSTALLED_OTHER"}:
                instance_findings.append(
                    Finding(
                        service="SSM",
                        resource_id=instance_id or "unknown",
                        severity="MEDIUM",
                        message=f"Patch compliance state is {patch_state.get('PatchState')}.",
                    )
                )
            findings.extend(instance_findings)
            inventory.append(
                inventory_item_from_findings(
                    "SSM", instance_id or "unknown", instance_findings
                )
            )
    except ClientError as exc:
        findings.append(
            finding_from_exception("SSM", "Failed to describe SSM instances", exc)
        )
        inventory.append(
            InventoryItem(
                service="SSM",
                resource_id="*",
                status="ERROR",
                details=f"Failed to describe SSM instances: {exc}",
            )
        )
    except EndpointConnectionError:
        # Systems Manager is not available in every region.
        findings.append(
            Finding(
                service="SSM",
                resource_id="*",
                severity="WARNING",
                message="SSM endpoint is not available in the selected region.",
            )
        )
        inventory.append(
            InventoryItem(
                service="SSM",
                resource_id="*",
                status="ERROR",
                details="SSM endpoint is not available in the selected region.",
            )
        )
    return ServiceReport(findings=findings, inventory=inventory)


__all__ = ["audit_ssm_managed_instances"]
