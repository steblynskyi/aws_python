"""Audit helpers for AWS Certificate Manager."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import finding_from_exception, safe_paginate
from . import ServiceReport


def audit_acm_certificates(session: boto3.session.Session) -> ServiceReport:
    """Check ACM certificates for expiration and resource usage."""

    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    acm = session.client("acm")
    now = datetime.now(timezone.utc)
    try:
        for summary in safe_paginate(acm, "list_certificates", "CertificateSummaryList"):
            arn = summary["CertificateArn"]
            try:
                certificate_findings: List[Finding] = []
                cert = acm.describe_certificate(CertificateArn=arn)["Certificate"]
                not_after = cert.get("NotAfter")
                if not_after and not_after - now < timedelta(days=30):
                    certificate_findings.append(
                        Finding(
                            service="ACM",
                            resource_id=arn,
                            severity="MEDIUM",
                            message="Certificate expires in less than 30 days.",
                        )
                    )
                if cert.get("InUseBy") is None or len(cert.get("InUseBy", [])) == 0:
                    certificate_findings.append(
                        Finding(
                            service="ACM",
                            resource_id=arn,
                            severity="LOW",
                            message="Certificate is not associated with any resources.",
                        )
                    )
                findings.extend(certificate_findings)
                if certificate_findings:
                    details = "; ".join(f.message for f in certificate_findings)
                    status = "NON_COMPLIANT"
                else:
                    details = "All checks passed."
                    status = "COMPLIANT"
                inventory.append(
                    InventoryItem(
                        service="ACM",
                        resource_id=arn,
                        status=status,
                        details=details,
                    )
                )
            except ClientError as exc:
                findings.append(
                    finding_from_exception(
                        "ACM",
                        "Failed to describe certificate",
                        exc,
                        resource_id=arn,
                    )
                )
                inventory.append(
                    InventoryItem(
                        service="ACM",
                        resource_id=arn,
                        status="ERROR",
                        details=f"Failed to describe certificate: {exc}",
                    )
                )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("ACM", "Failed to list certificates", exc)
        )
        inventory.append(
            InventoryItem(
                service="ACM",
                resource_id="*",
                status="ERROR",
                details=f"Failed to list certificates: {exc}",
            )
        )
    return ServiceReport(findings=findings, inventory=inventory)


__all__ = ["audit_acm_certificates"]
