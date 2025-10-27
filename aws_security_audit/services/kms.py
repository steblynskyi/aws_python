"""Audit helpers for AWS Key Management Service (KMS) keys."""
from __future__ import annotations

from typing import Dict, Iterable, List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding
from ..utils import finding_from_exception


def audit_kms_keys(session: boto3.session.Session) -> List[Finding]:
    """Inspect customer-managed KMS keys for common misconfigurations."""

    findings: List[Finding] = []
    kms = session.client("kms")

    try:
        paginator = kms.get_paginator("list_keys")
        keys = [key for page in paginator.paginate() for key in page.get("Keys", [])]
    except (ClientError, EndpointConnectionError) as exc:
        return [finding_from_exception("KMS", "Failed to list KMS keys", exc)]

    alias_map = _build_alias_map(kms)

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
                findings.append(
                    Finding(
                        service="KMS",
                        resource_id=resource_id,
                        severity=severity,
                        message=message,
                    )
                )
            else:
                findings.append(
                    finding_from_exception(
                        "KMS",
                        "Failed to describe KMS key",
                        exc,
                        resource_id=resource_id,
                    )
                )
            continue

        key_state = metadata.get("KeyState")
        if key_state not in {"Enabled", None}:
            findings.append(
                Finding(
                    service="KMS",
                    resource_id=resource_id,
                    severity="MEDIUM",
                    message=f"Key state is '{key_state}'.",
                )
            )

        if _supports_rotation_check(metadata):
            findings.extend(
                _check_rotation(kms, key_id, resource_id)
            )

    return findings


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


def _check_rotation(kms: boto3.client, key_id: str, resource_id: str) -> Iterable[Finding]:
    """Yield findings related to KMS key rotation."""

    try:
        status = kms.get_key_rotation_status(KeyId=key_id)
    except (ClientError, EndpointConnectionError) as exc:
        code = _error_code(exc)
        if code == "AccessDeniedException":
            yield Finding(
                service="KMS",
                resource_id=resource_id,
                severity="WARNING",
                message="Access denied while checking rotation status.",
            )
        elif code == "UnsupportedOperationException":
            # Some key types do not support rotation; skip without raising noise.
            return
        else:
            yield finding_from_exception(
                "KMS", "Failed to check rotation status", exc, resource_id=resource_id
            )
        return

    if not status.get("KeyRotationEnabled", False):
        yield Finding(
            service="KMS",
            resource_id=resource_id,
            severity="MEDIUM",
            message="Automatic key rotation is disabled.",
        )


def _error_code(exc: Exception) -> str:
    """Return the AWS error code from a botocore exception, if present."""

    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "")
    return ""


__all__ = ["audit_kms_keys"]
