"""Audit helpers for AWS Systems Manager."""
from __future__ import annotations

from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding
from ..utils import safe_paginate


def audit_ssm_managed_instances(session: boto3.session.Session) -> List[Finding]:
    """Inspect Systems Manager managed instances for connectivity and patches."""

    findings: List[Finding] = []
    ssm = session.client("ssm")
    try:
        for instance in safe_paginate(ssm, "describe_instance_information", "InstanceInformationList"):
            instance_id = instance.get("InstanceId")
            if instance.get("PingStatus") != "Online":
                findings.append(
                    Finding(
                        service="SSM",
                        resource_id=instance_id or "unknown",
                        severity="MEDIUM",
                        message="SSM managed instance is not online.",
                    )
                )
            patch_state = instance.get("PatchStatus")
            if patch_state and patch_state.get("PatchState") not in {"INSTALLED", "INSTALLED_OTHER"}:
                findings.append(
                    Finding(
                        service="SSM",
                        resource_id=instance_id or "unknown",
                        severity="MEDIUM",
                        message=f"Patch compliance state is {patch_state.get('PatchState')}.",
                    )
                )
    except ClientError as exc:
        findings.append(
            Finding(
                service="SSM",
                resource_id="*",
                severity="ERROR",
                message=f"Failed to describe SSM instances: {exc}",
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
    return findings


__all__ = ["audit_ssm_managed_instances"]
