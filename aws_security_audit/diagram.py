"""Network diagram generation utilities."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from .utils import safe_paginate

try:  # Optional dependency used for diagram generation
    from graphviz import Digraph  # type: ignore
except Exception:  # pragma: no cover - library is optional
    Digraph = None  # type: ignore

from html import escape


@dataclass
class RouteDetail:
    """Structured information about a single route table entry."""

    destination: str
    target: Optional[str]
    target_type: Optional[str]
    state: Optional[str] = None
    description: Optional[str] = None

    def display_text(self) -> str:
        """Return a human readable representation of the route."""

        target_text = self.description or self.target
        if target_text:
            base = f"{self.destination} → {target_text}"
        else:
            base = self.destination
        if self.state and self.state.lower() != "active":
            base += f" [{self.state}]"
        return base


@dataclass
class RouteSummary:
    """Compact representation of a route table for display."""

    route_table_id: str
    name: Optional[str]
    routes: List[RouteDetail]


@dataclass
class SubnetCell:
    """Information required to render a subnet + route table cell."""

    subnet_id: str
    name: Optional[str]
    cidr: Optional[str]
    az: Optional[str]
    classification: str
    tier: str
    color: str
    font_color: str
    route_summary: Optional[RouteSummary]
    is_isolated: bool


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
    except (ClientError, EndpointConnectionError) as exc:
        raise RuntimeError(f"Unable to generate diagram: {exc}") from exc

    subnet_by_vpc: Dict[str, List[dict]] = {}
    for subnet in subnets:
        subnet_by_vpc.setdefault(subnet["VpcId"], []).append(subnet)

    route_tables_by_vpc: Dict[str, List[dict]] = {}
    subnet_route_table: Dict[str, str] = {}
    main_route_table_by_vpc: Dict[str, str] = {}
    for route_table in route_tables:
        vpc_id = route_table["VpcId"]
        route_tables_by_vpc.setdefault(vpc_id, []).append(route_table)
        for association in route_table.get("Associations", []):
            if association.get("Main"):
                main_route_table_by_vpc[vpc_id] = route_table["RouteTableId"]
            subnet_id = association.get("SubnetId")
            if subnet_id:
                subnet_route_table[subnet_id] = route_table["RouteTableId"]

    def classify_subnet(subnet: dict, route_table: Optional[dict]) -> Tuple[str, bool]:
        """Determine subnet tier key and isolation."""

        public = False
        isolated = True
        routes = route_table.get("Routes", []) if route_table else []

        for route in routes:
            destination = route.get("DestinationCidrBlock") or route.get(
                "DestinationIpv6CidrBlock"
            )
            if destination in {"0.0.0.0/0", "::/0"}:
                isolated = False
                if (route.get("GatewayId") or "").startswith("igw-"):
                    public = True
                if route.get("NatGatewayId"):
                    public = False
        if not routes:
            isolated = True

        if subnet.get("MapPublicIpOnLaunch"):
            public = True
            isolated = False

        if public:
            return "public", False

        name = next(
            (
                tag["Value"]
                for tag in subnet.get("Tags", [])
                if tag.get("Key") == "Name" and tag.get("Value")
            ),
            "",
        ).lower()

        if any(keyword in name for keyword in {"data", "db", "database"}):
            return "private_data", isolated

        if any(keyword in name for keyword in {"directory", "shared", "ad", "ds"}):
            return "shared", isolated

        return "private_app", isolated

    def identify_route_target(route: dict) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Return the target identifier, type and optional description."""

        nat_gateway_id = route.get("NatGatewayId")
        if nat_gateway_id:
            return nat_gateway_id, "nat_gateway", None

        transit_gateway_id = route.get("TransitGatewayId")
        if transit_gateway_id:
            return transit_gateway_id, "transit_gateway", None

        vpc_peering_id = route.get("VpcPeeringConnectionId")
        if vpc_peering_id:
            return vpc_peering_id, "vpc_peering_connection", None

        vpc_endpoint_id = route.get("VpcEndpointId")
        if vpc_endpoint_id:
            return vpc_endpoint_id, "vpc_endpoint", None

        egress_only_id = route.get("EgressOnlyInternetGatewayId")
        if egress_only_id:
            return egress_only_id, "egress_only_internet_gateway", None

        gateway_id = route.get("GatewayId")
        if gateway_id:
            if gateway_id.lower() == "local":
                return None, None, None
            if gateway_id.startswith("igw-"):
                return gateway_id, "internet_gateway", None
            if gateway_id.startswith("eigw-"):
                return gateway_id, "egress_only_internet_gateway", None
            if gateway_id.startswith("vgw-"):
                return gateway_id, "virtual_private_gateway", None
            if gateway_id.startswith("tgw-"):
                return gateway_id, "transit_gateway", None
            if gateway_id.startswith("pcx-"):
                return gateway_id, "vpc_peering_connection", None
            if gateway_id.startswith("vpce-"):
                return gateway_id, "vpc_endpoint", None
            return gateway_id, "gateway", None

        instance_id = route.get("InstanceId")
        if instance_id:
            return instance_id, "instance", None

        network_interface_id = route.get("NetworkInterfaceId")
        if network_interface_id:
            return network_interface_id, "network_interface", None

        carrier_gateway_id = route.get("CarrierGatewayId")
        if carrier_gateway_id:
            return carrier_gateway_id, "carrier_gateway", None

        local_gateway_id = route.get("LocalGatewayId")
        if local_gateway_id:
            return local_gateway_id, "local_gateway", None

        return None, None, None

    def route_summaries(route_table: Optional[dict]) -> Optional[RouteSummary]:
        if not route_table:
            return None

        name = next(
            (
                tag["Value"]
                for tag in route_table.get("Tags", [])
                if tag.get("Key") == "Name" and tag.get("Value")
            ),
            None,
        )

        summaries: List[RouteDetail] = []
        for route in route_table.get("Routes", []):
            destination = route.get("DestinationCidrBlock") or route.get(
                "DestinationIpv6CidrBlock"
            )
            if not destination:
                continue
            target, target_type, description = identify_route_target(route)
            state = route.get("State")
            if not target and not description:
                if state and state.lower() != "active":
                    description = state
                else:
                    continue

            if description is None and target_type in {
                "transit_gateway",
                "vpc_peering_connection",
                "virtual_private_gateway",
                "carrier_gateway",
                "local_gateway",
            }:
                pretty_name = {
                    "transit_gateway": "Transit Gateway",
                    "vpc_peering_connection": "VPC Peering",
                    "virtual_private_gateway": "Virtual Private Gateway",
                    "carrier_gateway": "Carrier Gateway",
                    "local_gateway": "Local Gateway",
                }[target_type]
                description = f"{pretty_name} ({target})"

            summaries.append(
                RouteDetail(
                    destination=destination,
                    target=target,
                    target_type=target_type,
                    state=state,
                    description=description,
                )
            )

        return RouteSummary(route_table_id=route_table["RouteTableId"], name=name, routes=summaries)

    def subnet_cell(subnet: dict, tier: str, classification: str, isolated: bool, route_summary: Optional[RouteSummary]) -> SubnetCell:
        color_map = {
            "public": ("#ccebd4", "#1f3f2e"),
            "private_app": ("#cfe3ff", "#1a365d"),
            "private_data": ("#c0d7ff", "#102a56"),
            "shared": ("#e2e2e2", "#2d3748"),
        }

        fillcolor, fontcolor = color_map.get(classification, ("#cfe3ff", "#1a365d"))
        if isolated:
            fillcolor = "#e2e2e2"
            fontcolor = "#2d3748"

        name = next(
            (
                tag["Value"]
                for tag in subnet.get("Tags", [])
                if tag.get("Key") == "Name" and tag.get("Value")
            ),
            None,
        )
        cidr = subnet.get("CidrBlock")
        az = subnet.get("AvailabilityZone")

        return SubnetCell(
            subnet_id=subnet["SubnetId"],
            name=name,
            cidr=cidr,
            az=az,
            classification=classification,
            tier=tier,
            color=fillcolor,
            font_color=fontcolor,
            route_summary=route_summary,
            is_isolated=isolated,
        )

    def format_cell_label(cell: SubnetCell) -> str:
        subnet_lines = []
        if cell.name:
            subnet_lines.append(f"<B>{escape(cell.name)}</B>")
        subnet_lines.append(f"<FONT POINT-SIZE='10'>{escape(cell.subnet_id)}</FONT>")
        if cell.cidr:
            subnet_lines.append(escape(cell.cidr))
        if cell.az:
            subnet_lines.append(escape(cell.az))
        if cell.route_summary:
            subnet_lines.append(
                f"<FONT POINT-SIZE='9' COLOR='#2d3748'><B>rt:</B> {escape(cell.route_summary.route_table_id)}</FONT>"
            )

        subnet_html = "<BR/>".join(subnet_lines)

        route_html = "<FONT POINT-SIZE='9' COLOR='#2d3748'><I>No non-local routes</I></FONT>"
        if cell.route_summary:
            route_lines = []
            if cell.route_summary.name:
                route_lines.append(f"<B>{escape(cell.route_summary.name)}</B>")
            route_lines.append(escape(cell.route_summary.route_table_id))
            if cell.route_summary.routes:
                for route in cell.route_summary.routes:
                    route_lines.append(escape(route.display_text()))
            else:
                route_lines.append("No non-local routes")
            route_html = "<BR ALIGN='LEFT'/>".join(route_lines)

        return (
            "<<TABLE BORDER='0' CELLBORDER='1' CELLSPACING='0'>"
            f"<TR><TD BGCOLOR='{cell.color}' COLOR='{cell.font_color}'><FONT COLOR='{cell.font_color}'>{subnet_html}</FONT></TD></TR>"
            f"<TR><TD PORT='routes' BGCOLOR='#fff6d1'><FONT COLOR='#5c3d0c'>{route_html}</FONT></TD></TR>"
            "</TABLE>>"
        )

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

            tier_nodes: Dict[str, Dict[str, List[str]]] = {
                tier_key: {az: [] for az in azs} for tier_key, _ in TIER_ORDER
            }

            cells: Dict[str, List[SubnetCell]] = {az: [] for az in azs}
            for subnet in sorted(subnets_in_vpc, key=lambda s: s.get("AvailabilityZone", "")):
                subnet_id = subnet["SubnetId"]
                associated_route_table = subnet_route_table.get(subnet_id) or main_route_table_id
                route_table = route_table_by_id.get(associated_route_table) if associated_route_table else None
                tier_key, isolated = classify_subnet(subnet, route_table)
                route_summary = route_summaries(route_table)
                cell = subnet_cell(subnet, tier_key, tier_key if tier_key != "public" else "public", isolated, route_summary)
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
                    node_label = format_cell_label(cell)
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
                    f"legend_igw_{vpc_id}",
                    "<<B>Internet Gateway / Internet</B>>",
                    shape="plaintext",
                )
                legend.edge(f"legend_public_{vpc_id}", f"legend_private_{vpc_id}", style="invis")
                legend.edge(f"legend_private_{vpc_id}", f"legend_isolated_{vpc_id}", style="invis")
                legend.edge(f"legend_isolated_{vpc_id}", f"legend_nat_{vpc_id}", style="invis")
                legend.edge(f"legend_nat_{vpc_id}", f"legend_vpce_{vpc_id}", style="invis")
                legend.edge(f"legend_vpce_{vpc_id}", f"legend_igw_{vpc_id}", style="invis")

    rendered_path = graph.render(output_path, cleanup=True)
    return rendered_path


__all__ = ["generate_network_diagram"]
