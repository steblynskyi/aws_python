"""Audit helpers for Amazon Route53 hosted zones."""
from __future__ import annotations

from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding
from ..utils import finding_from_exception, safe_paginate


def audit_route53_zones(session: boto3.session.Session) -> List[Finding]:
    """Check public hosted zones for DNSSEC coverage."""

    findings: List[Finding] = []
    route53 = session.client("route53")
    try:
        for zone in safe_paginate(route53, "list_hosted_zones", "HostedZones"):
            zone_id = zone["Id"].split("/")[-1]
            config = zone.get("Config", {})
            if not config.get("PrivateZone"):
                try:
                    dnssec = route53.get_dnssec(HostedZoneId=zone_id)
                    if not dnssec.get("KeySigningKeys"):
                        findings.append(
                            Finding(
                                service="Route53",
                                resource_id=zone_id,
                                severity="LOW",
                                message="DNSSEC is not configured for public hosted zone.",
                            )
                        )
                except ClientError:
                    findings.append(
                        Finding(
                            service="Route53",
                            resource_id=zone_id,
                            severity="LOW",
                            message="Unable to determine DNSSEC status for hosted zone.",
                        )
                    )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("Route53", "Failed to describe hosted zones", exc)
        )
    return findings


__all__ = ["audit_route53_zones"]
