"""Audit helpers for Amazon VPC resources."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError, EndpointConnectionError

from ..findings import Finding, InventoryItem
from ..utils import finding_from_exception, safe_paginate
from . import ServiceReport, inventory_item_from_findings


def audit_vpcs(session: boto3.session.Session) -> ServiceReport:
    """Inspect VPC networking constructs for common security gaps."""

    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    ec2 = session.client("ec2")

    sg_findings, sg_inventory = _audit_security_groups(ec2)
    findings.extend(sg_findings)
    inventory.extend(sg_inventory)

    acl_findings, acl_inventory = _audit_network_acls(ec2)
    findings.extend(acl_findings)
    inventory.extend(acl_inventory)

    peering_findings, peering_inventory = _audit_vpc_peering(ec2)
    findings.extend(peering_findings)
    inventory.extend(peering_inventory)

    vpn_findings, vpn_inventory = _audit_vpn_connections(ec2)
    findings.extend(vpn_findings)
    inventory.extend(vpn_inventory)

    return ServiceReport(findings=findings, inventory=inventory)


def _audit_security_groups(ec2: BaseClient) -> Tuple[List[Finding], List[InventoryItem]]:
    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    try:
        for sg in safe_paginate(ec2, "describe_security_groups", "SecurityGroups"):
            group_id = sg["GroupId"]
            group_findings: List[Finding] = []
            for permission in sg.get("IpPermissions", []):
                group_findings.extend(
                    _build_open_security_group_findings(group_id, permission, inbound=True)
                )
            for permission in sg.get("IpPermissionsEgress", []):
                group_findings.extend(
                    _build_open_security_group_findings(group_id, permission, inbound=False)
                )
            findings.extend(group_findings)
            inventory.append(
                inventory_item_from_findings("VPC", group_id, group_findings)
            )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("VPC", "Failed to describe security groups", exc)
        )
        inventory.append(
            InventoryItem(
                service="VPC",
                resource_id="*",
                status="ERROR",
                details=f"Failed to describe security groups: {exc}",
            )
        )
    return findings, inventory


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


def _audit_network_acls(ec2: BaseClient) -> Tuple[List[Finding], List[InventoryItem]]:
    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    try:
        for acl in safe_paginate(ec2, "describe_network_acls", "NetworkAcls"):
            acl_id = acl["NetworkAclId"]
            acl_findings: List[Finding] = []
            for entry in acl.get("Entries", []):
                cidr = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")
                if cidr not in {"0.0.0.0/0", "::/0"}:
                    continue
                if entry.get("RuleAction") != "allow":
                    continue
                direction = "egress" if entry.get("Egress") else "ingress"
                port_range = _format_port_range(entry.get("PortRange"))
                acl_findings.append(
                    Finding(
                        service="VPC",
                        resource_id=acl_id,
                        severity="HIGH",
                        message=(
                            f"Network ACL allows {direction} from the entire internet {port_range}."
                        ),
                    )
                )
            findings.extend(acl_findings)
            inventory.append(
                inventory_item_from_findings("VPC", acl_id, acl_findings)
            )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("VPC", "Failed to describe network ACLs", exc)
        )
        inventory.append(
            InventoryItem(
                service="VPC",
                resource_id="*",
                status="ERROR",
                details=f"Failed to describe network ACLs: {exc}",
            )
        )
    return findings, inventory


def _audit_vpc_peering(ec2: BaseClient) -> Tuple[List[Finding], List[InventoryItem]]:
    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    try:
        for connection in safe_paginate(
            ec2, "describe_vpc_peering_connections", "VpcPeeringConnections"
        ):
            status = connection.get("Status", {}).get("Code")
            conn_id = connection.get("VpcPeeringConnectionId", "unknown")
            conn_findings: List[Finding] = []
            if status and status != "active":
                conn_findings.append(
                    Finding(
                        service="VPC",
                        resource_id=conn_id,
                        severity="MEDIUM",
                        message=f"VPC peering connection not active (status={status}).",
                    )
                )
            if conn_findings:
                findings.extend(conn_findings)
            inventory.append(
                inventory_item_from_findings(
                    "VPC",
                    conn_id,
                    conn_findings,
                    compliant_details="Peering connection is active.",
                )
            )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception(
                "VPC", "Failed to describe VPC peering connections", exc
            )
        )
        inventory.append(
            InventoryItem(
                service="VPC",
                resource_id="*",
                status="ERROR",
                details=f"Failed to describe VPC peering connections: {exc}",
            )
        )
    return findings, inventory


def _audit_vpn_connections(ec2: BaseClient) -> Tuple[List[Finding], List[InventoryItem]]:
    findings: List[Finding] = []
    inventory: List[InventoryItem] = []
    try:
        vpn_connections = list(
            safe_paginate(ec2, "describe_vpn_connections", "VpnConnections")
        )
    except (ClientError, EndpointConnectionError) as exc:
        findings.append(
            finding_from_exception("VPC", "Failed to describe VPN connections", exc)
        )
        inventory.append(
            InventoryItem(
                service="VPC",
                resource_id="*",
                status="ERROR",
                details=f"Failed to describe VPN connections: {exc}",
            )
        )
        return findings, inventory

    customer_gateway_addresses: Dict[str, str] = {}
    customer_gateway_ids = sorted(
        {
            vpn.get("CustomerGatewayId")
            for vpn in vpn_connections
            if vpn.get("CustomerGatewayId")
        }
    )
    if customer_gateway_ids:
        try:
            for gateway in safe_paginate(
                ec2,
                "describe_customer_gateways",
                "CustomerGateways",
                CustomerGatewayIds=customer_gateway_ids,
            ):
                gateway_id = gateway.get("CustomerGatewayId")
                address = gateway.get("IpAddress")
                if gateway_id and address:
                    customer_gateway_addresses[gateway_id] = address
        except (ClientError, EndpointConnectionError) as exc:
            findings.append(
                finding_from_exception("VPC", "Failed to describe customer gateways", exc)
            )
            inventory.append(
                InventoryItem(
                    service="VPC",
                    resource_id="*",
                    status="ERROR",
                    details=f"Failed to describe customer gateways: {exc}",
                )
            )

    for vpn in vpn_connections:
        vpn_id = vpn.get("VpnConnectionId", "unknown")
        vpn_findings: List[Finding] = []
        state = vpn.get("State")
        if state and state != "available":
            vpn_findings.append(
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
                vpn_findings.append(
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

        extra_details: List[str] = []
        vpn_name = next(
            (tag.get("Value") for tag in vpn.get("Tags", []) if tag.get("Key") == "Name"),
            None,
        )
        if vpn_name:
            extra_details.append(f"Name: {vpn_name}")

        customer_gateway_id = vpn.get("CustomerGatewayId")
        if customer_gateway_id:
            customer_gateway_address = customer_gateway_addresses.get(customer_gateway_id)
            if customer_gateway_address:
                extra_details.append(
                    f"Customer gateway address: {customer_gateway_address}"
                )

        findings.extend(vpn_findings)
        inventory.append(
            inventory_item_from_findings(
                "VPC",
                vpn_id,
                vpn_findings,
                compliant_details="VPN connection is available.",
                extra_details=extra_details,
            )
        )

    return findings, inventory


def _format_port_range(port_range: Optional[dict]) -> str:
    if not port_range:
        return "on all ports"
    from_port = port_range.get("From")
    to_port = port_range.get("To")
    if from_port == to_port:
        return f"on port {from_port}"
    return f"on ports {from_port}-{to_port}"


__all__ = ["audit_vpcs"]
