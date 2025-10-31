"""Helpers for summarising AWS Certificate Manager resources."""
from __future__ import annotations

from typing import List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..utils import safe_paginate
from .models import GlobalServiceSummary, summarize_global_service_lines
from .registry import register_global_service


@register_global_service("acm")
def build_acm_summary(
    session: boto3.session.Session, max_items: int
) -> Optional[GlobalServiceSummary]:
    """Collect ACM certificate details for the global services panel."""

    try:
        acm = session.client("acm")
    except (ClientError, EndpointConnectionError):
        return None

    certificate_labels: List[str] = []
    try:
        for cert in safe_paginate(
            acm, "list_certificates", "CertificateSummaryList"
        ):
            domain = cert.get("DomainName")
            status = cert.get("Status")
            arn = cert.get("CertificateArn")
            base_label = domain or (arn.split(":")[-1] if arn else "Certificate")
            if status:
                certificate_labels.append(f"{base_label} [{status}]")
            else:
                certificate_labels.append(base_label)
    except (ClientError, EndpointConnectionError):
        certificate_labels = []

    if not certificate_labels:
        return None

    certificate_labels.sort()
    return GlobalServiceSummary(
        title="AWS Certificate Manager",
        lines=summarize_global_service_lines(certificate_labels, max_items),
        fillcolor="#e6fffa",
        fontcolor="#285e61",
    )


__all__ = ["build_acm_summary"]

