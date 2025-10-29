"""Audit helpers for AWS Key Management Service (KMS) keys."""
from __future__ import annotations

from typing import Dict, List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import finding_from_exception
from . import ServiceReport, inventory_item_from_findings


def audit_kms_keys(session: boto3.session.Session) -> ServiceReport:
    """Inspect customer-managed KMS keys for common misconfigurations."""

    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    kms = session.client("kms")

    try:
        paginator = kms.get_paginator("list_keys")
        keys = [key for page in paginator.paginate() for key in page.get("Keys", [])]
    except (ClientError, EndpointConnectionError) as exc:
        finding = finding_from_exception("KMS", "Failed to list KMS keys", exc)
        return ServiceReport(
            findings=[finding],
            inventory=[
                InventoryItem(
                    service="KMS",
                    resource_id="*",
                    status="ERROR",
                    details=f"Failed to list KMS keys: {exc}",
                )
            ],
        )

    alias_map = _build_alias_map(kms)

    if not keys:
        inventory.append(
            InventoryItem(
                service="KMS",
                resource_id="(none)",
                status="COMPLIANT",
                details="No customer-managed KMS keys were discovered.",
            )
        )
        return ServiceReport(findings=findings, inventory=inventory)

    for key in keys:
        key_id = key.get("KeyId", "")
        if not key_id:
            continue
        resource_id = alias_map.get(key_id, key_id)

        try:
            metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
        except (ClientError, EndpointConnectionError) as exc:
            code = _error_code(exc)
            severity = "WARNING" if code == "AccessDeniedException" else "ERROR"
            if severity == "WARNING":
                message = "Access denied while describing KMS key."
                finding = Finding(
                    service="KMS",
                    resource_id=resource_id,
                    severity=severity,
                    message=message,
                )
                findings.append(finding)
                inventory.append(
                    InventoryItem(
                        service="KMS",
                        resource_id=resource_id,
                        status="ERROR",
                        details=message,
                    )
                )
            else:
                finding = finding_from_exception(
                    "KMS",
                    "Failed to describe KMS key",
                    exc,
                    resource_id=resource_id,
                )
                findings.append(finding)
                inventory.append(
                    InventoryItem(
                        service="KMS",
                        resource_id=resource_id,
                        status="ERROR",
                        details=f"Failed to describe KMS key: {exc}",
                    )
                )
            continue

        key_findings: List[Finding] = []
        key_state = metadata.get("KeyState")
        if key_state not in {"Enabled", None}:
            key_findings.append(
                Finding(
                    service="KMS",
                    resource_id=resource_id,
                    severity="MEDIUM",
                    message=f"Key state is '{key_state}'.",
                )
            )

        if _supports_rotation_check(metadata):
            key_findings.extend(_check_rotation(kms, key_id, resource_id))

        findings.extend(key_findings)
        inventory.append(
            inventory_item_from_findings("KMS", resource_id, key_findings)
        )

    return ServiceReport(findings=findings, inventory=inventory)


def _build_alias_map(kms: boto3.client) -> Dict[str, str]:
    """Return a mapping of key IDs to human-readable alias labels."""

    alias_map: Dict[str, str] = {}
    try:
        paginator = kms.get_paginator("list_aliases")
        for page in paginator.paginate():
            for alias in page.get("Aliases", []):
                key_id = alias.get("TargetKeyId")
                alias_name = alias.get("AliasName")
                if key_id and alias_name:
                    alias_map[key_id] = f"{alias_name} ({key_id})"
    except (ClientError, EndpointConnectionError):
        # Alias lookups are best-effort. Failures should not block auditing.
        return alias_map
    return alias_map


def _supports_rotation_check(metadata: Dict[str, object]) -> bool:
    """Return ``True`` when ``metadata`` represents a key that supports rotation checks."""

    if metadata.get("KeyManager") != "CUSTOMER":
        return False
    if metadata.get("Origin") != "AWS_KMS":
        return False
    if metadata.get("KeyState") != "Enabled":
        return False
    key_spec = metadata.get("KeySpec", "")
    # Automatic rotation is only available for symmetric encryption keys.
    return isinstance(key_spec, str) and key_spec.startswith("SYMMETRIC")


def _check_rotation(kms: boto3.client, key_id: str, resource_id: str) -> List[Finding]:
    """Return findings related to KMS key rotation."""

    findings: List[Finding] = []

    try:
        status = kms.get_key_rotation_status(KeyId=key_id)
    except (ClientError, EndpointConnectionError) as exc:
        code = _error_code(exc)
        if code == "AccessDeniedException":
            findings.append(
                Finding(
                    service="KMS",
                    resource_id=resource_id,
                    severity="WARNING",
                    message="Access denied while checking rotation status.",
                )
            )
        elif code == "UnsupportedOperationException":
            # Some key types do not support rotation; skip without raising noise.
            return findings
        else:
            findings.append(
                finding_from_exception(
                    "KMS", "Failed to check rotation status", exc, resource_id=resource_id
                )
            )
        return findings

    if not status.get("KeyRotationEnabled", False):
        findings.append(
            Finding(
                service="KMS",
                resource_id=resource_id,
                severity="MEDIUM",
                message="Automatic key rotation is disabled.",
            )
        )

    return findings


def _error_code(exc: Exception) -> str:
    """Return the AWS error code from a botocore exception, if present."""

    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "")
    return ""


__all__ = ["audit_kms_keys"]
