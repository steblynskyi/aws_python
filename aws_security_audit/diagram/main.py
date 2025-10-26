"""Network diagram generation utilities."""
from __future__ import annotations

from html import escape
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..utils import safe_paginate

try:  # Optional dependency used for diagram generation
    from graphviz import Digraph  # type: ignore
except Exception:  # pragma: no cover - library is optional
    Digraph = None  # type: ignore

from .acm import build_acm_summary
from .ec2 import group_instances_by_subnet
from .iam import build_iam_summary
from .kms import build_kms_summary
from .models import GlobalServiceSummary, InstanceSummary, RouteSummary, SubnetCell
from .route53 import build_route53_summary
from .rds import group_rds_instances_by_vpc
from .s3 import build_s3_summary
from .vpc import (
    build_route_table_indexes,
    build_subnet_cell,
    classify_subnet,
    format_subnet_cell_label,
    group_subnets_by_vpc,
    identify_route_target,
    summarize_route_table,
)


TIER_ORDER = [
    ("ingress", "Ingress (IGW / NAT)"),
    ("public", "Public Subnets"),
    ("private_app", "Private App Subnets"),
    ("private_data", "Private Data Subnets"),
    ("shared", "Shared / Directories"),
]


def generate_network_diagram(session: boto3.session.Session, output_path: str) -> Optional[str]:
    """Render a VPC-centric network diagram if ``graphviz`` is available."""

    if Digraph is None:
        return None

    ec2 = session.client("ec2")
    rds = session.client("rds")
    graph = Digraph("aws_network", format="png")
    graph.attr(rankdir="TB", bgcolor="white", fontname="Helvetica")
    graph.node_attr.update(fontname="Helvetica", fontsize="11")
    graph.edge_attr.update(fontname="Helvetica", fontsize="10")

    try:
        vpcs = list(safe_paginate(ec2, "describe_vpcs", "Vpcs"))
        subnets = list(safe_paginate(ec2, "describe_subnets", "Subnets"))
        route_tables = list(safe_paginate(ec2, "describe_route_tables", "RouteTables"))
        nat_gateways = list(safe_paginate(ec2, "describe_nat_gateways", "NatGateways"))
        internet_gateways = list(
            safe_paginate(ec2, "describe_internet_gateways", "InternetGateways")
        )
        vpc_endpoints = list(
            safe_paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints")
        )
        reservations = list(
            safe_paginate(
                ec2,
                "describe_instances",
                "Reservations",
                Filters=[
                    {
                        "Name": "instance-state-name",
                        "Values": [
                            "pending",
                            "running",
                            "stopping",
                            "stopped",
                            "shutting-down",
                        ],
                    }
                ],
            )
        )
    except (ClientError, EndpointConnectionError) as exc:
        raise RuntimeError(f"Unable to generate diagram: {exc}") from exc

    try:
        db_instances = list(safe_paginate(rds, "describe_db_instances", "DBInstances"))
    except (ClientError, EndpointConnectionError):
        db_instances = []

    max_service_items = 8

    service_builders = (
        build_kms_summary,
        build_s3_summary,
        build_acm_summary,
        build_route53_summary,
        build_iam_summary,
    )

    global_services: List[GlobalServiceSummary] = []
    for builder in service_builders:
        try:
            summary = builder(session, max_service_items)
        except (ClientError, EndpointConnectionError):
            summary = None
        if summary:
            global_services.append(summary)

    has_global_services = bool(global_services)

    def build_global_service_label(summary: GlobalServiceSummary) -> str:
        label = "<<TABLE BORDER='0' CELLBORDER='1' CELLSPACING='0'>"
        label += (
            "<TR><TD BGCOLOR='{}'><FONT COLOR='{}'><B>{}</B></FONT></TD></TR>".format(
                summary.fillcolor, summary.fontcolor, escape(summary.title)
            )
        )
        if summary.lines:
            for line in summary.lines:
                label += f"<TR><TD ALIGN='LEFT'>{line}</TD></TR>"
        else:
            label += "<TR><TD ALIGN='LEFT'>No resources found</TD></TR>"
        label += "</TABLE>>"
        return label

    subnet_by_vpc = group_subnets_by_vpc(subnets)
    (
        route_tables_by_vpc,
        subnet_route_table,
        main_route_table_by_vpc,
    ) = build_route_table_indexes(route_tables)

    instances_by_subnet = group_instances_by_subnet(reservations)
    rds_instances_by_vpc = group_rds_instances_by_vpc(db_instances)

    def tier_placeholder(tier_key: str, az: str) -> str:
        return f"placeholder_{tier_key}_{az}"

    igw_nodes: Dict[str, dict] = {}
    for igw in internet_gateways:
        igw_id = igw["InternetGatewayId"]
        igw_nodes[igw_id] = igw

    endpoint_by_vpc: Dict[str, List[dict]] = {}
    for endpoint in vpc_endpoints:
        endpoint_by_vpc.setdefault(endpoint.get("VpcId", ""), []).append(endpoint)

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        vpc_title = f"VPC {vpc_id}"
        vpc_label_lines = [f"<B>{vpc_title}</B>"]
        cidr_block = vpc.get("CidrBlock")
        if cidr_block:
            vpc_label_lines.append(cidr_block)
        dhcp_options_id = vpc.get("DhcpOptionsId")
        if dhcp_options_id and dhcp_options_id != "default":
            vpc_label_lines.append(f"DHCP Options: {dhcp_options_id}")
        vpc_label = "<" + "<BR ALIGN='LEFT'/>".join(vpc_label_lines) + ">"

        with graph.subgraph(name=f"cluster_{vpc_id}") as vpc_graph:
            vpc_graph.attr(
                label=vpc_label,
                style="rounded",
                color="#4a5568",
                fontsize="13",
                fontname="Helvetica",
            )

            subnets_in_vpc = [subnet for subnet in subnets if subnet["VpcId"] == vpc_id]
            azs = sorted({subnet.get("AvailabilityZone", "") for subnet in subnets_in_vpc if subnet.get("AvailabilityZone")})
            if not azs:
                azs = [""]

            route_tables_in_vpc = route_tables_by_vpc.get(vpc_id, [])
            main_route_table_id = main_route_table_by_vpc.get(vpc_id)
            route_table_by_id = {rt["RouteTableId"]: rt for rt in route_tables_in_vpc}

            igw_in_vpc = [
                igw_id
                for igw_id, igw in igw_nodes.items()
                if any(att.get("VpcId") == vpc_id for att in igw.get("Attachments", []))
            ]

            nat_in_vpc = [
                nat
                for nat in nat_gateways
                if nat.get("VpcId") == vpc_id and nat.get("State") not in {"deleted", "failed"}
            ]

            endpoints_in_vpc = endpoint_by_vpc.get(vpc_id, [])

            vpc_graph.node(
                f"{vpc_id}_internet",
                "<<B>Internet</B>>",
                shape="box",
                style="rounded,filled,dashed",
                color="#4a5568",
                fillcolor="white",
                fontsize="12",
                group="internet",
            )

            subnet_ids_in_vpc = {subnet["SubnetId"] for subnet in subnets_in_vpc}

            tier_nodes: Dict[str, Dict[str, List[str]]] = {
                tier_key: {az: [] for az in azs} for tier_key, _ in TIER_ORDER
            }

            cells: Dict[str, List[SubnetCell]] = {az: [] for az in azs}
            for subnet in sorted(subnets_in_vpc, key=lambda s: s.get("AvailabilityZone", "")):
                subnet_id = subnet["SubnetId"]
                associated_route_table = subnet_route_table.get(subnet_id) or main_route_table_id
                route_table = route_table_by_id.get(associated_route_table) if associated_route_table else None
                tier_key, isolated = classify_subnet(subnet, route_table)
                route_summary = summarize_route_table(route_table)
                cell = build_subnet_cell(
                    subnet,
                    tier_key,
                    tier_key if tier_key != "public" else "public",
                    isolated,
                    route_summary,
                    instances_by_subnet.get(subnet_id, []),
                )
                az = cell.az or ""
                if az not in cells:
                    cells[az] = []
                    for tier, _ in TIER_ORDER:
                        tier_nodes[tier][az] = []
                cells[az].append(cell)

            external_nodes: Dict[str, str] = {}
            nat_node_names: List[str] = []
            nat_node_lookup: Dict[str, str] = {}
            for nat in nat_in_vpc:
                nat_id = nat["NatGatewayId"]
                subnet_id = nat.get("SubnetId", "")
                az = next(
                    (
                        subnet.get("AvailabilityZone")
                        for subnet in subnets_in_vpc
                        if subnet["SubnetId"] == subnet_id
                    ),
                    nat.get("AvailabilityZone", ""),
                )
                eip = next(
                    (
                        addr.get("PublicIp")
                        for addr in nat.get("NatGatewayAddresses", [])
                        if addr.get("PublicIp")
                    ),
                    None,
                )
                nat_lines = [f"<B>{nat_id}</B>"]
                if az:
                    nat_lines.append(escape(az))
                if eip:
                    nat_lines.append(f"EIP: {escape(eip)}")
                if subnet_id:
                    nat_lines.append(f"Subnet: {escape(subnet_id)}")
                nat_label = "<<TABLE BORDER='0' CELLBORDER='1' CELLSPACING='0'>" "<TR><TD BGCOLOR='#fff2cc'><FONT COLOR='#8a6d3b'>"
                nat_label += "<BR/>".join(nat_lines)
                nat_label += "</FONT></TD></TR></TABLE>>"
                node_name = f"{nat_id}_node"
                az_key = az or (azs[len(azs) // 2] if azs else "")
                if az_key not in tier_nodes["ingress"]:
                    tier_nodes["ingress"][az_key] = []
                vpc_graph.node(
                    node_name,
                    nat_label,
                    shape="plaintext",
                    style="dashed",
                    group=az_key or nat_id,
                )
                tier_nodes["ingress"].setdefault(az_key, []).append(node_name)
                nat_node_names.append(node_name)
                nat_node_lookup[nat_id] = node_name
                external_nodes[nat_id] = node_name

            center_az = azs[len(azs) // 2] if azs else ""
            igw_node_names: List[str] = []
            igw_node_lookup: Dict[str, str] = {}
            for igw_id in igw_in_vpc:
                node_name = f"{igw_id}_node"
                vpc_graph.node(
                    node_name,
                    f"<<B>{igw_id}</B><BR/>Internet Gateway>",
                    shape="box",
                    style="rounded,filled,dashed",
                    color="#4a5568",
                    fillcolor="white",
                    fontsize="11",
                    group=center_az or "internet",
                )
                vpc_graph.edge(f"{vpc_id}_internet", node_name, color="#4a5568", style="dashed")
                tier_nodes["ingress"].setdefault(center_az, []).append(node_name)
                igw_node_names.append(node_name)
                igw_node_lookup[igw_id] = node_name
                external_nodes[igw_id] = node_name

            for nat_node in nat_node_names:
                for igw_node in igw_node_names:
                    vpc_graph.edge(nat_node, igw_node, style="dashed", color="#b7791f")

            for az, cell_list in cells.items():
                for cell in cell_list:
                    node_label = format_subnet_cell_label(cell)
                    node_name = cell.subnet_id
                    vpc_graph.node(
                        node_name,
                        node_label,
                        shape="plaintext",
                        group=az,
                    )
                    tier_nodes[cell.tier][az].append(node_name)

                    if cell.route_summary:
                        def ensure_external_node(node_id: str, node_type: str) -> Optional[str]:
                            if not node_id or node_id in external_nodes:
                                return external_nodes.get(node_id)

                            label_map = {
                                "egress_only_internet_gateway": (
                                    f"<<B>{escape(node_id)}</B><BR/>Egress-Only IGW>>",
                                    "box",
                                    "rounded,filled,dashed",
                                    "#4a5568",
                                    "white",
                                ),
                                "transit_gateway": (
                                    f"<<B>{escape(node_id)}</B><BR/>Transit Gateway>>",
                                    "box",
                                    "rounded,filled,dashed",
                                    "#2c5282",
                                    "#ebf8ff",
                                ),
                                "vpc_peering_connection": (
                                    f"<<B>{escape(node_id)}</B><BR/>VPC Peering>>",
                                    "box",
                                    "rounded,dashed",
                                    "#2c5282",
                                    "white",
                                ),
                                "virtual_private_gateway": (
                                    f"<<B>{escape(node_id)}</B><BR/>Virtual Private Gateway>>",
                                    "box",
                                    "rounded,filled,dashed",
                                    "#2c5282",
                                    "#edf2f7",
                                ),
                                "carrier_gateway": (
                                    f"<<B>{escape(node_id)}</B><BR/>Carrier Gateway>>",
                                    "box",
                                    "rounded,dashed",
                                    "#2c5282",
                                    "white",
                                ),
                                "local_gateway": (
                                    f"<<B>{escape(node_id)}</B><BR/>Local Gateway>>",
                                    "box",
                                    "rounded,dashed",
                                    "#2c5282",
                                    "white",
                                ),
                            }

                            if node_type not in label_map:
                                return None

                            label, shape, style, color, fillcolor = label_map[node_type]
                            node_name = f"{node_id}_node"
                            vpc_graph.node(
                                node_name,
                                label,
                                shape=shape,
                                style=style,
                                color=color,
                                fillcolor=fillcolor,
                                fontsize="10",
                            )
                            external_nodes[node_id] = node_name
                            return node_name

                        for route in cell.route_summary.routes:
                            target_id = route.target
                            target_type = route.target_type or ""
                            if not target_id:
                                continue

                            if target_type == "nat_gateway":
                                target_node = nat_node_lookup.get(target_id)
                                edge_color = "#b7791f"
                            elif target_type in {"internet_gateway", "egress_only_internet_gateway"}:
                                target_node = igw_node_lookup.get(target_id)
                                if not target_node:
                                    target_node = ensure_external_node(target_id, target_type)
                                edge_color = "#2f855a"
                            elif target_type == "vpc_endpoint":
                                target_node = external_nodes.get(target_id)
                                edge_color = "#4c51bf"
                            else:
                                target_node = ensure_external_node(target_id, target_type)
                                edge_color = "#2c5282"

                            if not target_node:
                                continue

                            vpc_graph.edge(
                                f"{node_name}:routes",
                                target_node,
                                color=edge_color,
                                arrowhead="normal",
                            )

            subnet_az_map = {
                subnet["SubnetId"]: subnet.get("AvailabilityZone", "") for subnet in subnets_in_vpc
            }

            for endpoint in endpoints_in_vpc:
                endpoint_id = endpoint.get("VpcEndpointId", "")
                endpoint_type = endpoint.get("VpcEndpointType", "")
                services = ", ".join(endpoint.get("ServiceName", "").split(".")[-2:])
                node_name = f"{endpoint_id}_node"
                endpoint_az = center_az
                if endpoint_type.lower() == "interface":
                    subnet_ids = endpoint.get("SubnetIds", [])
                    if subnet_ids:
                        endpoint_az = subnet_az_map.get(subnet_ids[0], center_az)
                vpc_graph.node(
                    node_name,
                    f"<<B>{endpoint_id}</B><BR/>{escape(endpoint_type)}<BR/>{escape(services)}>",
                    shape="box",
                    style="rounded,filled",
                    fillcolor="#e8e8ff",
                    color="#4c51bf",
                    fontsize="10",
                )
                tier_nodes["shared"].setdefault(endpoint_az, []).append(node_name)
                external_nodes[endpoint_id] = node_name

                for subnet_id in endpoint.get("SubnetIds", []):
                    if subnet_id in subnet_route_table:
                        vpc_graph.edge(
                            node_name,
                            subnet_id,
                            color="#4c51bf",
                            style="dotted",
                        )

            for db_instance in rds_instances_by_vpc.get(vpc_id, []):
                identifier = db_instance.get("DBInstanceIdentifier", "")
                engine = db_instance.get("Engine") or ""
                status = db_instance.get("DBInstanceStatus") or ""
                instance_class = db_instance.get("DBInstanceClass") or ""
                label_lines = []
                if identifier:
                    label_lines.append(f"<B>{escape(identifier)}</B>")
                if engine:
                    label_lines.append(escape(engine))
                if instance_class:
                    label_lines.append(escape(instance_class))
                if status:
                    label_lines.append(f"Status: {escape(status)}")

                label_html = "<<TABLE BORDER='0' CELLBORDER='1' CELLSPACING='0'>"
                label_html += "<TR><TD BGCOLOR='#fdebd0'><FONT COLOR='#7b341e'>"
                label_html += "<BR/>".join(label_lines) if label_lines else "RDS Instance"
                label_html += "</FONT></TD></TR></TABLE>>"

                node_name = f"rds_{identifier or 'instance'}"
                node_name = node_name.replace("-", "_")

                subnet_group = db_instance.get("DBSubnetGroup") or {}
                subnets_for_instance = subnet_group.get("Subnets", [])
                az_from_subnet = next(
                    (
                        subnet.get("SubnetAvailabilityZone", {}).get("Name")
                        for subnet in subnets_for_instance
                        if subnet.get("SubnetAvailabilityZone", {}).get("Name")
                    ),
                    center_az,
                )
                az_key = az_from_subnet or center_az or ""
                if az_key not in tier_nodes["private_data"]:
                    tier_nodes["private_data"][az_key] = []

                vpc_graph.node(
                    node_name,
                    label_html,
                    shape="plaintext",
                    group=az_key,
                )
                tier_nodes["private_data"].setdefault(az_key, []).append(node_name)

                for subnet in subnets_for_instance:
                    subnet_id = subnet.get("SubnetIdentifier")
                    if subnet_id and subnet_id in subnet_ids_in_vpc:
                        vpc_graph.edge(
                            subnet_id,
                            node_name,
                            color="#d97706",
                            style="dashed",
                        )

            for tier_key, tier_label in TIER_ORDER:
                with vpc_graph.subgraph(name=f"cluster_{vpc_id}_{tier_key}") as tier_graph:
                    tier_graph.attr(rank="same")
                    tier_graph.attr(label=f"<<B>{escape(tier_label)}</B>>", color="gray", style="dashed")
                    for az in azs:
                        if not tier_nodes[tier_key].get(az):
                            placeholder = tier_placeholder(tier_key, az)
                            tier_graph.node(
                                placeholder,
                                "",
                                shape="point",
                                width="0.01",
                                height="0.01",
                                style="invis",
                                group=az,
                            )
                            tier_nodes[tier_key][az] = [placeholder]
                    for az in azs:
                        for node in tier_nodes[tier_key][az]:
                            tier_graph.node(node)

            for az in azs:
                column_nodes = []
                for tier_key, _ in TIER_ORDER:
                    column_nodes.extend(tier_nodes[tier_key].get(az, []))
                for idx in range(len(column_nodes) - 1):
                    vpc_graph.edge(
                        column_nodes[idx],
                        column_nodes[idx + 1],
                        style="invis",
                        weight="10",
                    )

            with vpc_graph.subgraph(name=f"legend_{vpc_id}") as legend:
                legend.attr(
                    label="<<B>Legend</B>>",
                    color="#b7b7b7",
                    style="rounded",
                    bgcolor="#f7f7f7",
                    fontsize="11",
                )
                legend.node(
                    f"legend_public_{vpc_id}",
                    "<<TABLE BORDER='0' CELLBORDER='1' CELLSPACING='0'><TR><TD BGCOLOR='#ccebd4'>Public subnet</TD></TR></TABLE>>",
                    shape="plaintext",
                )
                legend.node(
                    f"legend_private_{vpc_id}",
                    "<<TABLE BORDER='0' CELLBORDER='1' CELLSPACING='0'><TR><TD BGCOLOR='#cfe3ff'>Private subnet</TD></TR></TABLE>>",
                    shape="plaintext",
                )
                legend.node(
                    f"legend_isolated_{vpc_id}",
                    "<<TABLE BORDER='0' CELLBORDER='1' CELLSPACING='0'><TR><TD BGCOLOR='#e2e2e2'>Isolated subnet</TD></TR></TABLE>>",
                    shape="plaintext",
                )
                legend.node(
                    f"legend_nat_{vpc_id}",
                    "<<TABLE BORDER='0' CELLBORDER='1' CELLSPACING='0'><TR><TD BGCOLOR='#fff2cc'>NAT Gateway</TD></TR></TABLE>>",
                    shape="plaintext",
                )
                legend.node(
                    f"legend_vpce_{vpc_id}",
                    "<<TABLE BORDER='0' CELLBORDER='1' CELLSPACING='0'><TR><TD BGCOLOR='#e8e8ff'>VPC Endpoint</TD></TR></TABLE>>",
                    shape="plaintext",
                )
                legend.node(
                    f"legend_instances_{vpc_id}",
                    "<<TABLE BORDER='0' CELLBORDER='1' CELLSPACING='0'><TR><TD BGCOLOR='#eef2ff'>Instances</TD></TR></TABLE>>",
                    shape="plaintext",
                )
                legend.node(
                    f"legend_rds_{vpc_id}",
                    "<<TABLE BORDER='0' CELLBORDER='1' CELLSPACING='0'><TR><TD BGCOLOR='#fdebd0'>RDS Instance</TD></TR></TABLE>>",
                    shape="plaintext",
                )
                legend.node(
                    f"legend_igw_{vpc_id}",
                    "<<B>Internet Gateway / Internet</B>>",
                    shape="plaintext",
                )
                if has_global_services:
                    legend.node(
                        f"legend_global_service_{vpc_id}",
                        "<<TABLE BORDER='0' CELLBORDER='1' CELLSPACING='0'><TR><TD BGCOLOR='#f7fafc'>Global service summary</TD></TR></TABLE>>",
                        shape="plaintext",
                    )
                legend.edge(f"legend_public_{vpc_id}", f"legend_private_{vpc_id}", style="invis")
                legend.edge(f"legend_private_{vpc_id}", f"legend_isolated_{vpc_id}", style="invis")
                legend.edge(f"legend_isolated_{vpc_id}", f"legend_nat_{vpc_id}", style="invis")
                legend.edge(f"legend_nat_{vpc_id}", f"legend_vpce_{vpc_id}", style="invis")
                legend.edge(f"legend_vpce_{vpc_id}", f"legend_instances_{vpc_id}", style="invis")
                legend.edge(f"legend_instances_{vpc_id}", f"legend_rds_{vpc_id}", style="invis")
                legend.edge(f"legend_rds_{vpc_id}", f"legend_igw_{vpc_id}", style="invis")
                if has_global_services:
                    legend.edge(
                        f"legend_igw_{vpc_id}",
                        f"legend_global_service_{vpc_id}",
                        style="invis",
                    )

    if has_global_services:
        with graph.subgraph(name="cluster_global_services") as global_graph:
            global_graph.attr(
                label="<<B>Global / Regional Services</B>>",
                style="rounded",
                color="#4a5568",
                bgcolor="#f7fafc",
                fontsize="12",
                fontname="Helvetica",
            )
            previous_node: Optional[str] = None
            for index, summary in enumerate(global_services):
                node_id = f"global_service_{index}"
                global_graph.node(
                    node_id,
                    build_global_service_label(summary),
                    shape="plaintext",
                )
                if previous_node is not None:
                    global_graph.edge(previous_node, node_id, style="invis")
                previous_node = node_id

    rendered_path = graph.render(output_path, cleanup=True)
    return rendered_path


__all__ = ["generate_network_diagram"]
