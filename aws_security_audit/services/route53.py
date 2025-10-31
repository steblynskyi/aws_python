"""Audit helpers for Amazon Route53 hosted zones."""
from __future__ import annotations

from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import finding_from_exception, safe_paginate
from . import ServiceReport, inventory_item_from_findings, register_service


@register_service("route53")
def audit_route53_zones(session: boto3.session.Session) -> ServiceReport:
    """Check public hosted zones for DNSSEC coverage."""

    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    route53 = session.client("route53")
    try:
        for zone in safe_paginate(route53, "list_hosted_zones", "HostedZones"):
            zone_id = zone["Id"].split("/")[-1]
            config = zone.get("Config", {})
            if config.get("PrivateZone"):
                inventory.append(
                    InventoryItem(
                        service="Route53",
                        resource_id=zone_id,
                        status="COMPLIANT",
                        details="Private hosted zone (DNSSEC not required).",
                    )
                )
                continue
            zone_findings: List[Finding] = []
            try:
                dnssec = route53.get_dnssec(HostedZoneId=zone_id)
                if not dnssec.get("KeySigningKeys"):
                    zone_findings.append(
                        Finding(
                            service="Route53",
                            resource_id=zone_id,
                            severity="LOW",
                            message="DNSSEC is not configured for public hosted zone.",
                        )
                    )
            except (ClientError, EndpointConnectionError) as exc:
                zone_findings.append(
                    Finding(
                        service="Route53",
                        resource_id=zone_id,
                        severity="LOW",
                        message="Unable to determine DNSSEC status for hosted zone.",
                    )
                )
                inventory.append(
                    InventoryItem(
                        service="Route53",
                        resource_id=zone_id,
                        status="ERROR",
                        details=f"Failed to retrieve DNSSEC status: {exc}",
                    )
                )
                findings.extend(zone_findings)
                continue
            findings.extend(zone_findings)
            inventory.append(
                inventory_item_from_findings("Route53", zone_id, zone_findings)
            )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("Route53", "Failed to describe hosted zones", exc)
        )
        inventory.append(
            InventoryItem(
                service="Route53",
                resource_id="*",
                status="ERROR",
                details=f"Failed to describe hosted zones: {exc}",
            )
        )
    return ServiceReport(findings=findings, inventory=inventory)


__all__ = ["audit_route53_zones"]
