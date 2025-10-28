"""Network diagram generation utilities."""
from __future__ import annotations

from subprocess import CalledProcessError
from typing import Dict, List, Optional

from .html_utils import escape_label, format_vertical_label

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..utils import safe_paginate

try:  # Optional dependency used for diagram generation
    from graphviz import Digraph  # type: ignore
    from graphviz.backend import ExecutableNotFound  # type: ignore
except Exception:  # pragma: no cover - library is optional
    Digraph = None  # type: ignore
    ExecutableNotFound = None  # type: ignore

from .acm import build_acm_summary
from .ec2 import group_instances_by_subnet
from .iam import build_iam_summary
from .kms import build_kms_summary
from .models import (
    DiagramContext,
    Ec2Resources,
    GlobalServiceSummary,
    InstanceSummary,
    SubnetCell,
)
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
        reservations=reservations,
    )


def _collect_rds_instances(session: boto3.session.Session) -> List[dict]:
    rds = session.client("rds")
    try:
        return list(safe_paginate(rds, "describe_db_instances", "DBInstances"))
    except (ClientError, EndpointConnectionError):
        return []


def _build_global_services(
    session: boto3.session.Session, max_items: int
) -> List[GlobalServiceSummary]:
    service_builders = (
        build_kms_summary,
        build_s3_summary,
        build_acm_summary,
        build_route53_summary,
        build_iam_summary,
    )

    services: List[GlobalServiceSummary] = []
    for builder in service_builders:
        try:
            summary = builder(session, max_items)
        except (ClientError, EndpointConnectionError):
            summary = None
        if summary:
            services.append(summary)
    return services


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
    )


def generate_network_diagram(session: boto3.session.Session, output_path: str) -> Optional[str]:
    """Render a VPC-centric network diagram if ``graphviz`` is available."""

    if Digraph is None:
        return None

    graph = _create_graph()
    resources = _collect_ec2_resources(session)
    db_instances = _collect_rds_instances(session)
    global_services = _build_global_services(session, max_items=8)
    has_global_services = bool(global_services)

    context = _prepare_context(resources, db_instances)

    for vpc in resources.vpcs:
        _render_vpc_cluster(graph, vpc, context, has_global_services)

    if has_global_services:
        _render_global_services_cluster(graph, global_services)

    return _render_graph(graph, output_path)


def _build_vpc_label(vpc: dict) -> str:
    vpc_id = vpc["VpcId"]
    vpc_title = f"VPC {vpc_id}"
    rows = [f'<TR><TD ALIGN="LEFT"><B>{escape_label(vpc_title)}</B></TD></TR>']
    cidr_block = vpc.get("CidrBlock")
    if cidr_block:
        rows.append(f'<TR><TD ALIGN="LEFT">{escape_label(cidr_block)}</TD></TR>')
    dhcp_options_id = vpc.get("DhcpOptionsId")
    if dhcp_options_id and dhcp_options_id != "default":
        rows.append(
            '<TR><TD ALIGN="LEFT">DHCP Options: '
            f'{escape_label(dhcp_options_id)}</TD></TR>'
        )
    return (
        '<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0">' + "".join(rows) + "</TABLE>>"
    )


def _render_vpc_cluster(
    graph: "Digraph", vpc: dict, context: DiagramContext, has_global_services: bool
) -> None:
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
            nat_lines = [f"<B>{nat_id}</B>"]
            if az:
                nat_lines.append(escape_label(az))
            if eip:
                nat_lines.append(f"EIP: {escape_label(eip)}")
            if subnet_id:
                nat_lines.append(f"Subnet: {escape_label(subnet_id)}")
            nat_label = (
                '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">'
                '<TR><TD BGCOLOR="#fff2cc"><FONT COLOR="#8a6d3b">'
            )
            nat_label += "<BR/>".join(nat_lines)
            nat_label += "</FONT></TD></TR></TABLE>>"
            node_name = f"{nat_id}_node"
            az_key = az or center_az
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

        igw_node_names: List[str] = []
        igw_node_lookup: Dict[str, str] = {}
        for igw_id in igw_in_vpc:
            node_name = f"{igw_id}_node"
            vpc_graph.node(
                node_name,
                (
                    f'<<B>{escape_label(igw_id)}</B>'
                    '<BR/><FONT POINT-SIZE="10">Internet Gateway</FONT>>'
                ),
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

                if not cell.route_summary:
                    continue

                def ensure_external_node(node_id: str, node_type: str) -> Optional[str]:
                    if not node_id or node_id in external_nodes:
                        return external_nodes.get(node_id)

                    label_map = {
                        "egress_only_internet_gateway": (
                            format_vertical_label(
                                [node_id, "Egress-Only IGW"], bold_first=True
                            ),
                            "box",
                            "rounded,filled,dashed",
                            "#4a5568",
                            "white",
                        ),
                        "transit_gateway": (
                            format_vertical_label(
                                [node_id, "Transit Gateway"], bold_first=True
                            ),
                            "box",
                            "rounded,filled,dashed",
                            "#2c5282",
                            "#ebf8ff",
                        ),
                        "vpc_peering_connection": (
                            format_vertical_label(
                                [node_id, "VPC Peering"], bold_first=True
                            ),
                            "box",
                            "rounded,dashed",
                            "#2c5282",
                            "white",
                        ),
                        "virtual_private_gateway": (
                            format_vertical_label(
                                [node_id, "Virtual Private Gateway"], bold_first=True
                            ),
                            "box",
                            "rounded,filled,dashed",
                            "#2c5282",
                            "#edf2f7",
                        ),
                        "carrier_gateway": (
                            format_vertical_label(
                                [node_id, "Carrier Gateway"], bold_first=True
                            ),
                            "box",
                            "rounded,dashed",
                            "#2c5282",
                            "white",
                        ),
                        "local_gateway": (
                            format_vertical_label(
                                [node_id, "Local Gateway"], bold_first=True
                            ),
                            "box",
                            "rounded,dashed",
                            "#2c5282",
                            "white",
                        ),
                    }

                    if node_type not in label_map:
                        return None

                    label, shape, style, color, fillcolor = label_map[node_type]
                    external_node_name = f"{node_id}_node"
                    vpc_graph.node(
                        external_node_name,
                        label,
                        shape=shape,
                        style=style,
                        color=color,
                        fillcolor=fillcolor,
                        fontsize="10",
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
                f"<<B>{escape_label(endpoint_id)}</B><BR/>{escape_label(endpoint_type)}<BR/>{escape_label(services)}>>",
                shape="box",
                style="rounded,filled",
                fillcolor="#e8e8ff",
                color="#4c51bf",
                fontsize="10",
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
            label_lines = []
            if identifier:
                label_lines.append(f"<B>{escape_label(identifier)}</B>")
            if engine:
                label_lines.append(escape_label(engine))
            if instance_class:
                label_lines.append(escape_label(instance_class))
            if status:
                label_lines.append(f"Status: {escape_label(status)}")

            label_html = '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">'
            label_html += '<TR><TD BGCOLOR="#fdebd0"><FONT COLOR="#7b341e">'
            label_html += "<BR/>".join(label_lines) if label_lines else "RDS Instance"
            label_html += "</FONT></TD></TR></TABLE>>"

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

        with vpc_graph.subgraph(name=f"legend_{vpc_id}") as legend:
            legend.attr(label="<<B>Legend</B>>")
            legend.attr(color="#b7b7b7")
            legend.attr(style="rounded")
            legend.attr(bgcolor="#f7f7f7")
            legend.attr(fontsize="11")
            legend_entries = [
                ("public", "#ccebd4", "Public subnet"),
                ("private", "#cfe3ff", "Private subnet"),
                ("isolated", "#e2e2e2", "Isolated subnet"),
                ("nat", "#fff2cc", "NAT Gateway"),
                ("vpce", "#e8e8ff", "VPC Endpoint"),
                ("instances", "#eef2ff", "Instances"),
                ("rds", "#fdebd0", "RDS Instance"),
            ]
            if has_global_services:
                legend_entries.append(("global_service", "#f7fafc", "Global service summary"))

            for key, color, text in legend_entries:
                legend.node(
                    f"legend_{key}_{vpc_id}",
                    (
                        '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">'
                        f'<TR><TD BGCOLOR="{color}">{text}</TD></TR></TABLE>>'
                    ),
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
            legend.edge(f"legend_vpce_{vpc_id}", f"legend_instances_{vpc_id}", style="invis")
            legend.edge(f"legend_instances_{vpc_id}", f"legend_rds_{vpc_id}", style="invis")
            legend.edge(f"legend_rds_{vpc_id}", f"legend_igw_{vpc_id}", style="invis")
            if has_global_services:
                legend.edge(
                    f"legend_igw_{vpc_id}",
                    f"legend_global_service_{vpc_id}",
                    style="invis",
                )


def _render_global_services_cluster(
    graph: "Digraph", global_services: List[GlobalServiceSummary]
) -> None:
    with graph.subgraph(name="cluster_global_services") as global_graph:
        global_graph.attr(label="<<B>Global / Regional Services</B>>")
        global_graph.attr(style="rounded")
        global_graph.attr(color="#4a5568")
        global_graph.attr(bgcolor="#f7fafc")
        global_graph.attr(fontsize="12")
        global_graph.attr(fontname="Helvetica")
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
