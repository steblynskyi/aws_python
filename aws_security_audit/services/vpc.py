"""Audit helpers for Amazon VPC resources."""
from __future__ import annotations

from typing import List, Optional

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding
from ..utils import finding_from_exception, safe_paginate


def audit_vpcs(session: boto3.session.Session) -> List[Finding]:
    """Inspect VPC networking constructs for common security gaps."""

    findings: List[Finding] = []
    ec2 = session.client("ec2")

    findings.extend(_audit_security_groups(ec2))
    findings.extend(_audit_network_acls(ec2))
    findings.extend(_audit_vpc_peering(ec2))
    findings.extend(_audit_vpn_connections(ec2))

    return findings


def _audit_security_groups(ec2: BaseClient) -> List[Finding]:
    findings: List[Finding] = []
    try:
        for sg in safe_paginate(ec2, "describe_security_groups", "SecurityGroups"):
            group_id = sg["GroupId"]
            for permission in sg.get("IpPermissions", []):
                findings.extend(
                    _build_open_security_group_findings(group_id, permission, inbound=True)
                )
            for permission in sg.get("IpPermissionsEgress", []):
                findings.extend(
                    _build_open_security_group_findings(group_id, permission, inbound=False)
                )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("VPC", "Failed to describe security groups", exc)
        )
    return findings


def _build_open_security_group_findings(
    group_id: str, permission: dict, *, inbound: bool
) -> List[Finding]:
    findings: List[Finding] = []
    proto = permission.get("IpProtocol", "all")
    from_port = permission.get("FromPort", "*")
    to_port = permission.get("ToPort", "*")
    direction = "inbound" if inbound else "outbound"

    for ip_range in permission.get("IpRanges", []):
        cidr = ip_range.get("CidrIp")
        if cidr == "0.0.0.0/0":
            findings.append(
                Finding(
                    service="VPC",
                    resource_id=group_id,
                    severity="HIGH",
                    message=(
                        "Security group allows {} access from the entire internet "
                        "(protocol={}, ports={}-{})."
                    ).format(direction, proto, from_port, to_port),
                )
            )
    for ip_range in permission.get("Ipv6Ranges", []):
        cidr = ip_range.get("CidrIpv6")
        if cidr == "::/0":
            findings.append(
                Finding(
                    service="VPC",
                    resource_id=group_id,
                    severity="HIGH",
                    message=(
                        "Security group allows {} IPv6 access from the entire internet "
                        "(protocol={}, ports={}-{})."
                    ).format(direction, proto, from_port, to_port),
                )
            )
    return findings


def _audit_network_acls(ec2: BaseClient) -> List[Finding]:
    findings: List[Finding] = []
    try:
        for acl in safe_paginate(ec2, "describe_network_acls", "NetworkAcls"):
            acl_id = acl["NetworkAclId"]
            for entry in acl.get("Entries", []):
                cidr = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")
                if cidr not in {"0.0.0.0/0", "::/0"}:
                    continue
                if entry.get("RuleAction") != "allow":
                    continue
                direction = "egress" if entry.get("Egress") else "ingress"
                port_range = _format_port_range(entry.get("PortRange"))
                findings.append(
                    Finding(
                        service="VPC",
                        resource_id=acl_id,
                        severity="HIGH",
                        message=(
                            f"Network ACL allows {direction} from the entire internet {port_range}."
                        ),
                    )
                )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("VPC", "Failed to describe network ACLs", exc)
        )
    return findings


def _audit_vpc_peering(ec2: BaseClient) -> List[Finding]:
    findings: List[Finding] = []
    try:
        for connection in safe_paginate(
            ec2, "describe_vpc_peering_connections", "VpcPeeringConnections"
        ):
            status = connection.get("Status", {}).get("Code")
            if status and status != "active":
                conn_id = connection.get("VpcPeeringConnectionId", "unknown")
                findings.append(
                    Finding(
                        service="VPC",
                        resource_id=conn_id,
                        severity="MEDIUM",
                        message=f"VPC peering connection not active (status={status}).",
                    )
                )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception(
                "VPC", "Failed to describe VPC peering connections", exc
            )
        )
    return findings


def _audit_vpn_connections(ec2: BaseClient) -> List[Finding]:
    findings: List[Finding] = []
    try:
        for vpn in safe_paginate(ec2, "describe_vpn_connections", "VpnConnections"):
            vpn_id = vpn.get("VpnConnectionId", "unknown")
            state = vpn.get("State")
            if state and state != "available":
                findings.append(
                    Finding(
                        service="VPC",
                        resource_id=vpn_id,
                        severity="MEDIUM",
                        message=f"Site-to-site VPN connection not in available state (state={state}).",
                    )
                )
            for telemetry in vpn.get("VgwTelemetry", []):
                status = telemetry.get("Status")
                outside_ip = telemetry.get("OutsideIpAddress")
                if status and status != "UP":
                    findings.append(
                        Finding(
                            service="VPC",
                            resource_id=vpn_id,
                            severity="HIGH",
                            message=(
                                "VPN tunnel endpoint %s is reporting status %s."
                                % (outside_ip or "unknown", status)
                            ),
                        )
                    )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("VPC", "Failed to describe VPN connections", exc)
        )
    return findings


def _format_port_range(port_range: Optional[dict]) -> str:
    if not port_range:
        return "on all ports"
    from_port = port_range.get("From")
    to_port = port_range.get("To")
    if from_port == to_port:
        return f"on port {from_port}"
    return f"on ports {from_port}-{to_port}"


__all__ = ["audit_vpcs"]
