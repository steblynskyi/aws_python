"""Audit helpers for AWS Certificate Manager."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding
from ..utils import finding_from_exception, safe_paginate


def audit_acm_certificates(session: boto3.session.Session) -> List[Finding]:
    """Check ACM certificates for expiration and resource usage."""

    findings: List[Finding] = []
    acm = session.client("acm")
    now = datetime.now(timezone.utc)
    try:
        for summary in safe_paginate(acm, "list_certificates", "CertificateSummaryList"):
            arn = summary["CertificateArn"]
            try:
                cert = acm.describe_certificate(CertificateArn=arn)["Certificate"]
                not_after = cert.get("NotAfter")
                if not_after and not_after - now < timedelta(days=30):
                    findings.append(
                        Finding(
                            service="ACM",
                            resource_id=arn,
                            severity="MEDIUM",
                            message="Certificate expires in less than 30 days.",
                        )
                    )
                if cert.get("InUseBy") is None or len(cert.get("InUseBy", [])) == 0:
                    findings.append(
                        Finding(
                            service="ACM",
                            resource_id=arn,
                            severity="LOW",
                            message="Certificate is not associated with any resources.",
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
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("ACM", "Failed to list certificates", exc)
        )
    return findings


__all__ = ["audit_acm_certificates"]
