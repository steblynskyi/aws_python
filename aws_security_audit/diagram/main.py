"""Network diagram generation utilities."""
from __future__ import annotations

from functools import partial
from subprocess import CalledProcessError
from typing import Dict, List, Optional, Set

from .html_utils import (
    build_icon_label,
    build_panel_label,
    build_panel_text_rows,
    escape_label,
)

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..utils import safe_paginate

try:  # Optional dependency used for diagram generation
    from graphviz import Digraph  # type: ignore
    from graphviz.backend import ExecutableNotFound  # type: ignore
except Exception:  # pragma: no cover - library is optional
    Digraph = None  # type: ignore
    ExecutableNotFound = None  # type: ignore

from .ec2 import group_instances_by_subnet
from .models import (
    DiagramContext,
    Ec2Resources,
    GlobalServiceSummary,
    InstanceSummary,
    SubnetCell,
)
from .rds import group_rds_instances_by_vpc
from .registry import (
    GLOBAL_SERVICE_REGISTRY,
    build_global_service_summaries,
)
from .vpc import (
    build_route_table_indexes,
    build_subnet_cell,
    classify_subnet,
    format_subnet_cell_label,
    format_vpc_peering_connection_label,
    format_virtual_private_gateway_label,
    INTERNET_GATEWAY_PANEL_COLORS,
    NAT_GATEWAY_PANEL_COLORS,
    PEERING_PANEL_COLORS,
    RDS_PANEL_COLORS,
    VPC_PANEL_COLORS,
    group_subnets_by_vpc,
    identify_route_target,
    summarize_route_table,
    wrap_label_text,
)


TIER_ORDER = [
    ("ingress", "Ingress (IGW / NAT)"),
    ("public", "Public Subnets"),
    ("private_app", "Private App Subnets"),
    ("private_data", "Private Data Subnets"),
    ("shared", "Shared / Directories"),
]

def build_rds_panel_label(
    *,
    identifier: Optional[str] = None,
    engine: Optional[str] = None,
    instance_class: Optional[str] = None,
    status: Optional[str] = None,
) -> str:
    """Return a panel-style label for an RDS instance."""

    palette = RDS_PANEL_COLORS
    wrap32 = partial(wrap_label_text, width=32)
    panel_rows: List[str] = []

    panel_rows.extend(
        build_panel_text_rows(
            "RDS Instance",
            background=palette.header_bg,
            text_color=palette.header_color,
            bold=True,
        )
    )
    panel_rows.extend(
        build_panel_text_rows(
            identifier,
            label="Identifier",
            background=palette.meta_bg,
            text_color=palette.meta_text,
            wrap_lines=wrap32,
        )
    )
    panel_rows.extend(
        build_panel_text_rows(
            engine,
            label="Engine",
            background=palette.info_bg,
            text_color=palette.info_text,
            wrap_lines=wrap32,
        )
    )
    panel_rows.extend(
        build_panel_text_rows(
            instance_class,
            label="Instance Class",
            background=palette.info_bg,
            text_color=palette.info_text,
            wrap_lines=wrap32,
        )
    )
    panel_rows.extend(
        build_panel_text_rows(
            status,
            label="Status",
            background=palette.info_bg,
            text_color=palette.info_text,
            wrap_lines=wrap32,
        )
    )

    return build_panel_label(panel_rows, border_color="#c05621")


def build_global_service_label(summary: GlobalServiceSummary) -> str:
    """Render the HTML label used for the global services cluster."""

    label = '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">'
    label += '<TR><TD BGCOLOR="{}"><FONT COLOR="{}"><B>{}</B></FONT></TD></TR>'.format(
        summary.fillcolor, summary.fontcolor, escape_label(summary.title)
    )
    if summary.lines:
        for line in summary.lines:
            label += f'<TR><TD ALIGN="LEFT">{escape_label(line)}</TD></TR>'
    else:
        label += '<TR><TD ALIGN="LEFT">No resources found</TD></TR>'
    label += '</TABLE>>'
    return label


def tier_placeholder(tier_key: str, az: str) -> str:
    return f"placeholder_{tier_key}_{az}"


def _create_graph() -> "Digraph":
    graph = Digraph("aws_network", format="png")
    graph.attr(rankdir="TB")
    graph.attr(bgcolor="white")
    graph.attr(fontname="Helvetica")
    graph.node_attr.update(fontname="Helvetica", fontsize="12")
    graph.edge_attr.update(fontname="Helvetica", fontsize="11")
    return graph


def _collect_ec2_resources(session: boto3.session.Session) -> Ec2Resources:
    ec2 = session.client("ec2")
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
        vpc_peering_connections = list(
            safe_paginate(
                ec2, "describe_vpc_peering_connections", "VpcPeeringConnections"
            )
        )
        vpn_connections = list(
            safe_paginate(ec2, "describe_vpn_connections", "VpnConnections")
        )
        customer_gateways = list(
            safe_paginate(ec2, "describe_customer_gateways", "CustomerGateways")
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

    return Ec2Resources(
        vpcs=vpcs,
        subnets=subnets,
        route_tables=route_tables,
        nat_gateways=nat_gateways,
        internet_gateways=internet_gateways,
        vpc_endpoints=vpc_endpoints,
        vpc_peering_connections=vpc_peering_connections,
        vpn_connections=vpn_connections,
        customer_gateways=customer_gateways,
        reservations=reservations,
    )


def _collect_rds_instances(session: boto3.session.Session) -> List[dict]:
    rds = session.client("rds")
    try:
        return list(safe_paginate(rds, "describe_db_instances", "DBInstances"))
    except (ClientError, EndpointConnectionError):
        return []


def _prepare_context(
    resources: Ec2Resources, db_instances: List[dict]
) -> DiagramContext:
    subnets_by_vpc = group_subnets_by_vpc(resources.subnets)
    (
        route_tables_by_vpc,
        subnet_route_table,
        main_route_table_by_vpc,
    ) = build_route_table_indexes(resources.route_tables)

    instances_by_subnet = group_instances_by_subnet(resources.reservations)
    rds_instances_by_vpc = group_rds_instances_by_vpc(db_instances)

    internet_gateways = {
        gateway["InternetGatewayId"]: gateway for gateway in resources.internet_gateways
    }

    vpc_endpoints_by_vpc: Dict[str, List[dict]] = {}
    for endpoint in resources.vpc_endpoints:
        vpc_endpoints_by_vpc.setdefault(endpoint.get("VpcId", ""), []).append(endpoint)

    vpc_peering_connections = {
        connection.get("VpcPeeringConnectionId", ""): connection
        for connection in resources.vpc_peering_connections
        if connection.get("VpcPeeringConnectionId")
    }

    vpn_connections_by_vgw: Dict[str, List[dict]] = {}
    for connection in resources.vpn_connections:
        vgw_id = connection.get("VpnGatewayId")
        if vgw_id:
            vpn_connections_by_vgw.setdefault(vgw_id, []).append(connection)

    customer_gateways = {
        gateway.get("CustomerGatewayId", ""): gateway
        for gateway in resources.customer_gateways
        if gateway.get("CustomerGatewayId")
    }

    return DiagramContext(
        resources=resources,
        subnets_by_vpc=subnets_by_vpc,
        route_tables_by_vpc=route_tables_by_vpc,
        subnet_route_table=subnet_route_table,
        main_route_table_by_vpc=main_route_table_by_vpc,
        instances_by_subnet=instances_by_subnet,
        rds_instances_by_vpc=rds_instances_by_vpc,
        internet_gateways=internet_gateways,
        vpc_endpoints_by_vpc=vpc_endpoints_by_vpc,
        vpc_peering_connections=vpc_peering_connections,
        vpn_connections_by_vgw=vpn_connections_by_vgw,
        customer_gateways=customer_gateways,
    )


def generate_network_diagram(
    session: boto3.session.Session,
    output_path: str,
    services: Optional[List[str]] = None,
) -> Optional[str]:
    """Render a VPC-centric network diagram if ``graphviz`` is available."""

    if Digraph is None:
        return None

    requested_services: Optional[Set[str]] = None
    if services is not None:
        requested_services = {service.lower() for service in services}

    include_network = (
        requested_services is None
        or bool(requested_services & {"ec2", "vpc", "rds"})
    )

    builders = list(GLOBAL_SERVICE_REGISTRY.items())
    if requested_services is not None:
        requested = set(requested_services)
        builders = [(name, builder) for name, builder in builders if name in requested]

    global_services = build_global_service_summaries(
        session, max_items=8, builders=builders
    )
    has_global_services = bool(global_services)

    if not include_network and not has_global_services:
        raise RuntimeError(
            "Unable to generate diagram: none of the requested services provide "
            "diagram data."
        )

    graph = _create_graph()
    alignment_nodes: List[str] = []

    if include_network:
        resources = _collect_ec2_resources(session)
        db_instances = _collect_rds_instances(session)
        context = _prepare_context(resources, db_instances)

        for vpc in resources.vpcs:
            top_node = _render_vpc_cluster(graph, vpc, context, has_global_services)
            if has_global_services:
                alignment_nodes.append(top_node)

    if has_global_services:
        _render_global_services_cluster(
            graph, global_services, alignment_nodes=alignment_nodes
        )

    return _render_graph(graph, output_path)


def _build_vpc_label(vpc: dict) -> str:
    vpc_id = vpc["VpcId"]
    palette = VPC_PANEL_COLORS
    wrap32 = partial(wrap_label_text, width=32)

    panel_rows = build_panel_text_rows(
        f"VPC {vpc_id}",
        background=palette.header_bg,
        text_color=palette.header_color,
        bold=True,
    )

    panel_rows.extend(
        build_panel_text_rows(
            vpc.get("CidrBlock"),
            label="CIDR",
            background=palette.info_bg,
            text_color=palette.info_text,
            wrap_lines=wrap32,
        )
    )

    dhcp_options_id = vpc.get("DhcpOptionsId")
    if dhcp_options_id == "default":
        dhcp_options_id = None

    panel_rows.extend(
        build_panel_text_rows(
            dhcp_options_id,
            label="DHCP Options",
            background=palette.meta_bg,
            text_color=palette.meta_text,
            wrap_lines=wrap32,
        )
    )

    return build_panel_label(panel_rows, border_color=palette.header_bg)


def _render_vpc_cluster(
    graph: "Digraph", vpc: dict, context: DiagramContext, has_global_services: bool
) -> str:
    vpc_id = vpc["VpcId"]
    subnets_in_vpc = list(context.subnets_by_vpc.get(vpc_id, []))
    azs = sorted(
        {
            subnet.get("AvailabilityZone", "")
            for subnet in subnets_in_vpc
            if subnet.get("AvailabilityZone")
        }
    )
    if not azs:
        azs = [""]

    resources = context.resources
    route_tables_in_vpc = context.route_tables_by_vpc.get(vpc_id, [])
    main_route_table_id = context.main_route_table_by_vpc.get(vpc_id)
    route_table_by_id = {rt["RouteTableId"]: rt for rt in route_tables_in_vpc}

    igw_in_vpc = [
        igw_id
        for igw_id, igw in context.internet_gateways.items()
        if any(att.get("VpcId") == vpc_id for att in igw.get("Attachments", []))
    ]

    nat_in_vpc = [
        nat
        for nat in resources.nat_gateways
        if nat.get("VpcId") == vpc_id and nat.get("State") not in {"deleted", "failed"}
    ]

    endpoints_in_vpc = context.vpc_endpoints_by_vpc.get(vpc_id, [])

    with graph.subgraph(name=f"cluster_{vpc_id}") as vpc_graph:
        vpc_graph.attr(label=_build_vpc_label(vpc))
        vpc_graph.attr(style="rounded")
        vpc_graph.attr(color="#4a5568")
        vpc_graph.attr(fontsize="13")
        vpc_graph.attr(fontname="Helvetica")
        vpc_graph.attr(bgcolor="#f8fafc")

        palette = INTERNET_GATEWAY_PANEL_COLORS
        wrap32 = partial(wrap_label_text, width=32)
        internet_rows: List[str] = []
        internet_rows.extend(
            build_panel_text_rows(
                "Internet",
                background=palette.header_bg,
                text_color=palette.header_color,
                bold=True,
            )
        )
        internet_rows.extend(
            build_panel_text_rows(
                vpc_id,
                label="VPC",
                background=palette.meta_bg,
                text_color=palette.meta_text,
                wrap_lines=wrap32,
            )
        )

        internet_label = build_panel_label(
            internet_rows,
            border_color=palette.header_bg,
        )
        vpc_graph.node(
            f"{vpc_id}_internet",
            internet_label,
            shape="plaintext",
            group="internet",
        )

        subnet_ids_in_vpc = {subnet["SubnetId"] for subnet in subnets_in_vpc}
        tier_nodes: Dict[str, Dict[str, List[str]]] = {
            tier_key: {az: [] for az in azs} for tier_key, _ in TIER_ORDER
        }

        cells: Dict[str, List[SubnetCell]] = {az: [] for az in azs}
        for subnet in sorted(subnets_in_vpc, key=lambda s: s.get("AvailabilityZone", "")):
            subnet_id = subnet["SubnetId"]
            associated_route_table = (
                context.subnet_route_table.get(subnet_id) or main_route_table_id
            )
            route_table = (
                route_table_by_id.get(associated_route_table) if associated_route_table else None
            )
            tier_key, isolated = classify_subnet(subnet, route_table)
            route_summary = summarize_route_table(route_table)
            cell = build_subnet_cell(
                subnet,
                tier_key,
                tier_key if tier_key != "public" else "public",
                isolated,
                route_summary,
                context.instances_by_subnet.get(subnet_id, []),
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
        center_az = azs[len(azs) // 2] if azs else ""
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
            palette = NAT_GATEWAY_PANEL_COLORS
            wrap32 = partial(wrap_label_text, width=32)
            panel_rows: List[str] = []

            panel_rows.extend(
                build_panel_text_rows(
                    "NAT Gateway",
                    background=palette.header_bg,
                    text_color=palette.header_color,
                    bold=True,
                )
            )
            panel_rows.extend(
                build_panel_text_rows(
                    nat_id,
                    label="Gateway ID",
                    background=palette.meta_bg,
                    text_color=palette.meta_text,
                    wrap_lines=wrap32,
                )
            )
            panel_rows.extend(
                build_panel_text_rows(
                    az,
                    label="Availability Zone",
                    background=palette.info_bg,
                    text_color=palette.info_text,
                    wrap_lines=wrap32,
                )
            )
            panel_rows.extend(
                build_panel_text_rows(
                    eip,
                    label="Elastic IP",
                    background=palette.info_bg,
                    text_color=palette.info_text,
                    wrap_lines=wrap32,
                )
            )
            panel_rows.extend(
                build_panel_text_rows(
                    subnet_id,
                    label="Subnet",
                    background=palette.info_bg,
                    text_color=palette.info_text,
                    wrap_lines=wrap32,
                )
            )

            nat_label = build_panel_label(
                panel_rows,
                border_color=palette.header_bg,
            )
            node_name = f"{nat_id}_node"
            az_key = az or center_az
            if az_key not in tier_nodes["ingress"]:
                tier_nodes["ingress"][az_key] = []
            vpc_graph.node(
                node_name,
                nat_label,
                shape="plaintext",
                group=az_key or nat_id,
            )
            tier_nodes["ingress"].setdefault(az_key, []).append(node_name)
            nat_node_names.append(node_name)
            nat_node_lookup[nat_id] = node_name
            external_nodes[nat_id] = node_name

        igw_node_names: List[str] = []
        igw_node_lookup: Dict[str, str] = {}
        for igw_id in igw_in_vpc:
            node_name = f"{igw_id}_node"
            igw_details = context.internet_gateways.get(igw_id, {})
            palette = INTERNET_GATEWAY_PANEL_COLORS
            wrap32 = partial(wrap_label_text, width=32)
            panel_rows: List[str] = []

            panel_rows.extend(
                build_panel_text_rows(
                    "Internet Gateway",
                    background=palette.header_bg,
                    text_color=palette.header_color,
                    bold=True,
                )
            )

            panel_rows.extend(
                build_panel_text_rows(
                    igw_id,
                    label="Gateway ID",
                    background=palette.meta_bg,
                    text_color=palette.meta_text,
                    wrap_lines=wrap32,
                )
            )

            igw_name = next(
                (
                    tag.get("Value")
                    for tag in igw_details.get("Tags", [])
                    if tag.get("Key") == "Name" and tag.get("Value")
                ),
                None,
            )

            panel_rows.extend(
                build_panel_text_rows(
                    igw_name,
                    label="Name",
                    background=palette.meta_bg,
                    text_color=palette.meta_text,
                    wrap_lines=wrap32,
                )
            )

            attachments: List[str] = []
            for attachment in igw_details.get("Attachments", []):
                vpc_attachment = attachment.get("VpcId")
                state = attachment.get("State")
                if vpc_attachment and state:
                    attachments.append(f"{vpc_attachment} ({state})")
                elif vpc_attachment:
                    attachments.append(vpc_attachment)
                elif state:
                    attachments.append(state)

            panel_rows.extend(
                build_panel_text_rows(
                    attachments,
                    label="Attachments",
                    background=palette.info_bg,
                    text_color=palette.info_text,
                    wrap_lines=wrap32,
                )
            )

            igw_label = build_panel_label(
                panel_rows,
                border_color=palette.header_bg,
            )
            vpc_graph.node(
                node_name,
                igw_label,
                shape="plaintext",
                group=center_az or "internet",
            )
            vpc_graph.edge(f"{vpc_id}_internet", node_name, color="#4a5568", style="dashed")
            tier_nodes["ingress"].setdefault(center_az, []).append(node_name)
            igw_node_names.append(node_name)
            igw_node_lookup[igw_id] = node_name
            external_nodes[igw_id] = node_name

        for nat_node in nat_node_names:
            for igw_node in igw_node_names:
                vpc_graph.edge(
                    nat_node,
                    igw_node,
                    style="dashed",
                    color=PEERING_PANEL_COLORS.header_bg,
                )

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

                if not cell.route_summary:
                    continue

                def ensure_external_node(node_id: str, node_type: str) -> Optional[str]:
                    if not node_id or node_id in external_nodes:
                        return external_nodes.get(node_id)

                    label = None
                    if node_type == "vpc_peering_connection":
                        connection = context.vpc_peering_connections.get(node_id)
                        label = format_vpc_peering_connection_label(node_id, connection)
                    elif node_type == "virtual_private_gateway":
                        label = format_virtual_private_gateway_label(
                            node_id,
                            context.vpn_connections_by_vgw.get(node_id, []),
                            context.customer_gateways,
                        )
                    else:
                        label_map = {
                            "egress_only_internet_gateway": build_icon_label(
                                node_id,
                                ["Egress-only IGW"],
                                icon_text="EIGW",
                                icon_bgcolor="#2d3748",
                                body_bgcolor="#f7fafc",
                                body_color="#2d3748",
                                border_color="#2d3748",
                            ),
                            "transit_gateway": build_icon_label(
                                node_id,
                                ["Transit Gateway"],
                                icon_text="TGW",
                                icon_bgcolor="#2c5282",
                                body_bgcolor="#ebf8ff",
                                body_color="#1a365d",
                                border_color="#2c5282",
                            ),
                            "carrier_gateway": build_icon_label(
                                node_id,
                                ["Carrier Gateway"],
                                icon_text="CGW",
                                icon_bgcolor="#2c5282",
                                body_bgcolor="#f7fafc",
                                body_color="#1a365d",
                                border_color="#2c5282",
                            ),
                            "local_gateway": build_icon_label(
                                node_id,
                                ["Local Gateway"],
                                icon_text="LGW",
                                icon_bgcolor="#2c5282",
                                body_bgcolor="#f7fafc",
                                body_color="#1a365d",
                                border_color="#2c5282",
                            ),
                        }

                        label = label_map.get(node_type)

                    if not label:
                        return None

                    external_node_name = f"{node_id}_node"
                    vpc_graph.node(
                        external_node_name,
                        label,
                        shape="plaintext",
                    )
                    external_nodes[node_id] = external_node_name
                    return external_node_name

                for route in cell.route_summary.routes:
                    target_id = route.target
                    target_type = route.target_type or ""
                    if not target_id:
                        continue

                    if target_type == "nat_gateway":
                        target_node = nat_node_lookup.get(target_id)
                        edge_color = PEERING_PANEL_COLORS.header_bg
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
            endpoint_lines = []
            if endpoint_type:
                endpoint_lines.append(endpoint_type.title())
            if services:
                endpoint_lines.append(services)
            endpoint_label = build_icon_label(
                endpoint_id or "VPC Endpoint",
                endpoint_lines,
                icon_text="VPCE",
                icon_bgcolor="#4c51bf",
                body_bgcolor="#e8e8ff",
                body_color="#2c5282",
                border_color="#4c51bf",
            )
            vpc_graph.node(
                node_name,
                endpoint_label,
                shape="plaintext",
            )
            tier_nodes["shared"].setdefault(endpoint_az, []).append(node_name)
            external_nodes[endpoint_id] = node_name

            for subnet_id in endpoint.get("SubnetIds", []):
                if subnet_id in context.subnet_route_table:
                    vpc_graph.edge(
                        node_name,
                        subnet_id,
                        color="#4c51bf",
                        style="dotted",
                    )

        for db_instance in context.rds_instances_by_vpc.get(vpc_id, []):
            identifier = db_instance.get("DBInstanceIdentifier", "")
            engine = db_instance.get("Engine") or ""
            status = db_instance.get("DBInstanceStatus") or ""
            instance_class = db_instance.get("DBInstanceClass") or ""

            label_html = build_rds_panel_label(
                identifier=identifier or None,
                engine=engine or None,
                instance_class=instance_class or None,
                status=status or None,
            )

            node_name = f"rds_{identifier or 'instance'}".replace("-", "_")

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
                tier_graph.attr(label=f"<<B>{escape_label(tier_label)}</B>>")
                tier_graph.attr(color="gray")
                tier_graph.attr(style="dashed")
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

    return f"{vpc_id}_internet"


def _render_global_services_cluster(
    graph: "Digraph",
    global_services: List[GlobalServiceSummary],
    *,
    alignment_nodes: Optional[List[str]] = None,
) -> None:
    with graph.subgraph(name="cluster_global_services") as global_graph:
        global_graph.attr(label="<<B>Global / Regional Services</B>>")
        global_graph.attr(style="rounded")
        global_graph.attr(color="#4a5568")
        global_graph.attr(bgcolor="#f7fafc")
        global_graph.attr(fontsize="12")
        global_graph.attr(fontname="Helvetica")
        global_graph.attr(rank="min")
        global_graph.attr(labelloc="t")
        global_graph.attr(labeljust="r")
        previous_node: Optional[str] = None
        first_node_id: Optional[str] = None
        for index, summary in enumerate(global_services):
            node_id = f"global_service_{index}"
            global_graph.node(
                node_id,
                build_global_service_label(summary),
                shape="plaintext",
            )
            if first_node_id is None:
                first_node_id = node_id
            if previous_node is not None:
                global_graph.edge(previous_node, node_id, style="invis")
            previous_node = node_id

    if alignment_nodes and first_node_id:
        # ``rank`` statements cannot be injected directly into the root graph body
        # when the referenced nodes already belong to other ranksets (for example,
        # nodes inside tier clusters). Doing so causes Graphviz to emit warnings
        # similar to ``node ... was already in a rankset`` which are treated as
        # errors by our renderer. Instead, create a dedicated non-cluster
        # subgraph to hold the alignment directive so that Graphviz can merge the
        # rank requirements without complaint.
        rank_nodes = list(dict.fromkeys(list(alignment_nodes) + [first_node_id]))

        with graph.subgraph() as alignment_graph:
            alignment_graph.attr(rank="same")
            for node_id in rank_nodes:
                alignment_graph.node(node_id)

        graph.edge(
            alignment_nodes[-1],
            first_node_id,
            style="invis",
            weight="2",
            minlen="2",
            constraint="false",
        )


def _render_graph(graph: "Digraph", output_path: str) -> Optional[str]:
    try:
        return graph.render(output_path, cleanup=True)
    except Exception as exc:
        if ExecutableNotFound is not None and isinstance(exc, ExecutableNotFound):
            return None
        if isinstance(exc, CalledProcessError):
            stderr = (
                exc.stderr.decode("utf-8", "replace")
                if isinstance(exc.stderr, bytes)
                else exc.stderr
            )
            message = stderr.strip() or str(exc)
            raise RuntimeError(
                f"graphviz failed to render the network diagram: {message}"
            ) from exc
        raise



__all__ = ["generate_network_diagram"]
