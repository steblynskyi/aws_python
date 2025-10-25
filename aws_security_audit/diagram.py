"""Network diagram generation utilities."""
from __future__ import annotations

import html
from typing import Dict, Iterable, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from .utils import safe_paginate

try:  # Optional dependency used for diagram generation
    from graphviz import Digraph  # type: ignore
except Exception:  # pragma: no cover - library is optional
    Digraph = None  # type: ignore


def generate_network_diagram(session: boto3.session.Session, output_path: str) -> Optional[str]:
    """Render a VPC-centric network diagram if ``graphviz`` is available."""

    if Digraph is None:
        return None

    ec2 = session.client("ec2")
    palette = {
        "background": "#f8fafc",
        "text": "#1f2933",
        "muted_text": "#52606d",
        "outline": "#cbd2d9",
        "accent_public": "#0d9488",
        "accent_private": "#1d4ed8",
        "accent_main": "#b7791f",
        "fill_public": "#e6fffa",
        "fill_private": "#e0ecff",
        "fill_main": "#fff4db",
        "fill_vpc_public": "#f3fbfb",
        "fill_vpc_private": "#f4f7ff",
        "fill_edge": "#eef2ff",
    }

    graph = Digraph("aws_network", format="png")
    graph.attr(
        rankdir="TB",
        bgcolor=palette["background"],
        fontname="Helvetica",
        fontsize="12",
        fontcolor=palette["text"],
        labelloc="t",
        pad="0.4",
        nodesep="0.5",
        ranksep="1.0 equally",
        splines="ortho",
    )
    graph.node_attr.update(
        fontname="Helvetica",
        fontsize="10",
        color=palette["outline"],
        style="filled",
        fillcolor="white",
        fontcolor=palette["text"],
    )
    graph.edge_attr.update(
        fontname="Helvetica",
        fontsize="9",
        color=palette["outline"],
        arrowsize="0.7",
        penwidth="1.2",
    )

    def html_panel_label(
        title: str,
        *,
        subtitle: Optional[str] = None,
        metadata: Optional[Iterable[str]] = None,
        accent: Optional[str] = None,
    ) -> str:
        """Create a neatly formatted HTML-like label for nodes."""

        parts: List[str] = ["<", "<TABLE BORDER='0' CELLBORDER='0' CELLSPACING='0'>"]
        if title:
            safe_title = html.escape(title)
            if accent:
                parts.append(
                    "<TR><TD ALIGN='LEFT'><FONT FACE='Helvetica' COLOR='{accent}'><B>{title}</B></FONT></TD></TR>".format(
                        accent=accent, title=safe_title
                    )
                )
            else:
                parts.append(
                    "<TR><TD ALIGN='LEFT'><FONT FACE='Helvetica'><B>{}</B></FONT></TD></TR>".format(
                        safe_title
                    )
                )

        if subtitle:
            parts.append(
                "<TR><TD ALIGN='LEFT'><FONT FACE='Helvetica' COLOR='{color}'>{subtitle}</FONT></TD></TR>".format(
                    color=palette["text"], subtitle=html.escape(subtitle)
                )
            )

        for line in metadata or []:
            parts.append(
                "<TR><TD ALIGN='LEFT'><FONT FACE='Helvetica' POINT-SIZE='9' COLOR='{color}'>{line}</FONT></TD></TR>".format(
                    color=palette["muted_text"], line=html.escape(line)
                )
            )

        parts.append("</TABLE>")
        parts.append(">")
        return "".join(parts)

    def extract_name_tag(resource: dict) -> str:
        return next(
            (
                tag["Value"]
                for tag in resource.get("Tags", [])
                if tag.get("Key") == "Name" and tag.get("Value")
            ),
            "",
        )

    try:
        vpcs = list(safe_paginate(ec2, "describe_vpcs", "Vpcs"))
        subnets = list(safe_paginate(ec2, "describe_subnets", "Subnets"))
        reservations = list(safe_paginate(ec2, "describe_instances", "Reservations"))
        route_tables = list(safe_paginate(ec2, "describe_route_tables", "RouteTables"))
    except (ClientError, EndpointConnectionError) as exc:
        raise RuntimeError(f"Unable to generate diagram: {exc}") from exc

    subnet_by_vpc: Dict[str, List[dict]] = {}
    for subnet in subnets:
        subnet_by_vpc.setdefault(subnet["VpcId"], []).append(subnet)

    for subnet_list in subnet_by_vpc.values():
        subnet_list.sort(
            key=lambda item: (
                item.get("AvailabilityZone") or "",
                extract_name_tag(item),
                item.get("SubnetId", ""),
            )
        )

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

    for route_table_list in route_tables_by_vpc.values():
        route_table_list.sort(
            key=lambda item: (extract_name_tag(item), item.get("RouteTableId", ""))
        )

    instances_by_subnet: Dict[str, List[dict]] = {}
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            subnet_id = instance.get("SubnetId")
            if subnet_id:
                instances_by_subnet.setdefault(subnet_id, []).append(instance)

    for instance_list in instances_by_subnet.values():
        instance_list.sort(
            key=lambda item: (extract_name_tag(item) or item.get("InstanceId", ""))
        )

    graph.node(
        "internet",
        html_panel_label("Internet"),
        shape="oval",
        color=palette["accent_public"],
        penwidth="1.6",
        fillcolor="#ecfeff",
    )

    gateway_nodes: Dict[str, Tuple[str, Dict[str, str], str]] = {}

    # Create a dedicated area where shared gateway-style nodes live. This avoids
    # sprinkling them across VPC clusters and keeps the diagram easier to scan.
    edge_graph = Digraph(name="cluster_edge")
    edge_graph.attr(
        label="Edge & Shared Connectivity",
        color=palette["outline"],
        style="rounded",
        bgcolor=palette["fill_edge"],
        fontname="Helvetica",
        fontcolor=palette["text"],
    )
    edge_graph.node_attr.update(
        fontname="Helvetica",
        fontsize="10",
        fontcolor=palette["text"],
        color=palette["outline"],
        style="filled",
        fillcolor="white",
    )

    def ensure_gateway_node(
        node_id: str, label: str, attrs: Dict[str, str], owner_vpc: str
    ) -> None:
        if node_id in gateway_nodes:
            return

        node_attrs = {
            "shape": "box",
            "style": "filled",
            "fillcolor": "white",
            "fontcolor": palette["text"],
            "color": palette["outline"],
        }
        node_attrs.update(attrs)
        edge_graph.node(node_id, label, **node_attrs)
        gateway_nodes[node_id] = (label, node_attrs, owner_vpc)

    def route_target(route: dict) -> Optional[Tuple[str, str, Dict[str, str]]]:
        destination = route.get("DestinationCidrBlock") or route.get(
            "DestinationIpv6CidrBlock"
        )
        if not destination:
            return None

        if destination not in {"0.0.0.0/0", "::/0"} and not route.get("NatGatewayId"):
            # Focus on default or NAT routes to keep the diagram readable.
            return None

        target_mappings: Iterable[Tuple[str, str, str, Dict[str, str], str]] = (
            (
                "GatewayId",
                "igw-",
                "Internet Gateway",
                {"shape": "Msquare"},
                palette["accent_public"],
            ),
            (
                "EgressOnlyInternetGatewayId",
                "eigw-",
                "Egress-Only Internet Gateway",
                {"shape": "Msquare"},
                palette["accent_public"],
            ),
            (
                "NatGatewayId",
                "nat-",
                "NAT Gateway",
                {"shape": "box", "style": "rounded"},
                palette["accent_main"],
            ),
            (
                "TransitGatewayId",
                "tgw-",
                "Transit Gateway",
                {"shape": "hexagon"},
                palette["accent_private"],
            ),
            (
                "VpcPeeringConnectionId",
                "pcx-",
                "VPC Peering",
                {"shape": "doublecircle"},
                palette["accent_private"],
            ),
        )

        for key, prefix, label, attrs, accent in target_mappings:
            value = route.get(key)
            if value and value.startswith(prefix):
                return (
                    value,
                    html_panel_label(
                        value,
                        metadata=[label, f"Destination: {destination}"],
                        accent=accent,
                    ),
                    attrs,
                )

        instance_id = route.get("InstanceId")
        if instance_id:
            return (
                instance_id,
                html_panel_label(
                    instance_id,
                    metadata=["Instance target", f"Destination: {destination}"],
                    accent=palette["accent_private"],
                ),
                {"shape": "oval"},
            )

        eni_id = route.get("NetworkInterfaceId")
        if eni_id:
            return (
                eni_id,
                html_panel_label(
                    eni_id,
                    metadata=["ENI target", f"Destination: {destination}"],
                    accent=palette["accent_private"],
                ),
                {"shape": "component"},
            )

        return None

    def is_public_route_table(route_table: dict) -> bool:
        for route in route_table.get("Routes", []):
            destination = route.get("DestinationCidrBlock") or route.get(
                "DestinationIpv6CidrBlock"
            )
            if destination not in {"0.0.0.0/0", "::/0"}:
                continue

            gateway_id = route.get("GatewayId") or ""
            if gateway_id.startswith("igw-"):
                return True

            if route.get("EgressOnlyInternetGatewayId"):
                return True

        return False

    def is_public_subnet(subnet: dict) -> bool:
        route_table_id = subnet_route_table.get(subnet["SubnetId"]) or main_route_table_by_vpc.get(
            subnet["VpcId"], ""
        )
        if route_table_id:
            route_table = next(
                (rt for rt in route_tables_by_vpc.get(subnet["VpcId"], []) if rt["RouteTableId"] == route_table_id),
                None,
            )
            if route_table and is_public_route_table(route_table):
                return True

        return bool(subnet.get("MapPublicIpOnLaunch"))

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        vpc_label = f"VPC {vpc_id}"
        if vpc.get("CidrBlock"):
            vpc_label += f"\n{vpc['CidrBlock']}"

        with graph.subgraph(name=f"cluster_{vpc_id}") as vpc_graph:
            vpc_graph.attr(
                label=vpc_label,
                style="rounded",
                color=palette["outline"],
                fontcolor=palette["text"],
                bgcolor="white",
            )

            public_subgraph_name = f"cluster_{vpc_id}_public"
            private_subgraph_name = f"cluster_{vpc_id}_private"

            public_group = f"{vpc_id}_public_column"
            private_group = f"{vpc_id}_private_column"

            with vpc_graph.subgraph(name=public_subgraph_name) as public_graph:
                public_graph.attr(
                    label="Public Routes & Subnets",
                    color=palette["accent_public"],
                    style="rounded",
                    bgcolor=palette["fill_vpc_public"],
                    fontcolor=palette["accent_public"],
                )
                public_graph.node_attr.update(
                    style="filled",
                    fillcolor=palette["fill_public"],
                    color=palette["accent_public"],
                )
                public_anchor = f"{vpc_id}_public_anchor"
                public_graph.node(
                    public_anchor,
                    "",
                    shape="point",
                    width="0",
                    height="0",
                    style="invis",
                    group=public_group,
                )

            with vpc_graph.subgraph(name=private_subgraph_name) as private_graph:
                private_graph.attr(
                    label="Private Routes & Subnets",
                    color=palette["accent_private"],
                    style="rounded",
                    bgcolor=palette["fill_vpc_private"],
                    fontcolor=palette["accent_private"],
                )
                private_graph.node_attr.update(
                    style="filled",
                    fillcolor=palette["fill_private"],
                    color=palette["accent_private"],
                )
                private_anchor = f"{vpc_id}_private_anchor"
                private_graph.node(
                    private_anchor,
                    "",
                    shape="point",
                    width="0",
                    height="0",
                    style="invis",
                    group=private_group,
                )

            route_tables_in_vpc = route_tables_by_vpc.get(vpc_id, [])
            main_route_table_id = main_route_table_by_vpc.get(vpc_id)
            private_column_nodes: List[str] = []
            public_column_nodes: List[str] = []

            def append_column_node(column_nodes: List[str], node_id: str) -> None:
                if node_id not in column_nodes:
                    column_nodes.append(node_id)

            for route_table in route_tables_in_vpc:
                route_table_id = route_table["RouteTableId"]
                name_tag = extract_name_tag(route_table) or None

                classification = "main"
                if route_table_id != main_route_table_id:
                    classification = (
                        "public" if is_public_route_table(route_table) else "private"
                    )

                metadata: List[str] = [f"ID: {route_table_id}"]
                display_routes: List[Tuple[dict, Tuple[str, str, Dict[str, str]]]] = []
                for route in route_table.get("Routes", []):
                    target = route_target(route)
                    if not target:
                        continue
                    display_routes.append((route, target))

                for route, target in display_routes:
                    destination = route.get("DestinationCidrBlock") or route.get(
                        "DestinationIpv6CidrBlock"
                    )
                    if destination:
                        metadata.append(f"Route: {destination} → {target[0]}")
                subtitle_text: Optional[str] = None

                if classification == "main":
                    if name_tag:
                        subtitle_text = "Main Route Table"
                    is_public_main = is_public_route_table(route_table)
                    metadata.append("Role: Main")
                    metadata.append(
                        "Visibility: Public" if is_public_main else "Visibility: Private"
                    )
                    target_graph = public_graph if is_public_main else private_graph
                    anchor = public_anchor if is_public_main else private_anchor
                    group = public_group if is_public_main else private_group
                    target_graph.node(
                        route_table_id,
                        html_panel_label(
                            name_tag or "Main Route Table",
                            subtitle=subtitle_text,
                            metadata=metadata,
                            accent=palette["accent_main"],
                        ),
                        shape="folder",
                        style="rounded,filled",
                        fillcolor=palette["fill_main"],
                        color=palette["accent_main"],
                        group=group,
                    )
                    graph.edge(anchor, route_table_id, style="invis", weight="6")
                    append_column_node(
                        public_column_nodes if is_public_main else private_column_nodes,
                        route_table_id,
                    )
                else:
                    is_public = classification == "public"
                    target_graph = public_graph if is_public else private_graph
                    group = public_group if is_public else private_group
                    fillcolor = (
                        palette["fill_public"] if is_public else palette["fill_private"]
                    )
                    border_color = (
                        palette["accent_public"] if is_public else palette["accent_private"]
                    )
                    if name_tag:
                        subtitle_text = "Public Route Table" if is_public else "Private Route Table"
                    metadata.append("Role: Public" if is_public else "Role: Private")
                    target_graph.node(
                        route_table_id,
                        html_panel_label(
                            name_tag
                            or ("Public Route Table" if is_public else "Private Route Table"),
                            subtitle=subtitle_text,
                            metadata=metadata,
                            accent=palette["accent_public"]
                            if is_public
                            else palette["accent_private"],
                        ),
                        shape="folder",
                        style="rounded,filled",
                        fillcolor=fillcolor,
                        color=border_color,
                        group=group,
                    )
                    anchor = public_anchor if is_public else private_anchor
                    graph.edge(anchor, route_table_id, style="invis", weight="5")
                    append_column_node(
                        public_column_nodes if is_public else private_column_nodes,
                        route_table_id,
                    )

                for route, target in display_routes:
                    target_id, target_label, attrs = target
                    ensure_gateway_node(target_id, target_label, attrs, vpc_id)
                    graph.edge(
                        route_table_id,
                        target_id,
                        label=route.get("DestinationCidrBlock")
                        or route.get("DestinationIpv6CidrBlock", ""),
                    )

            graph.edge(private_anchor, public_anchor, style="invis", weight="4")

            for subnet in subnet_by_vpc.get(vpc_id, []):
                subnet_id = subnet["SubnetId"]
                cidr = subnet.get("CidrBlock", "")
                public = is_public_subnet(subnet)
                visibility_label = "Public" if public else "Private"
                subnet_label_lines: List[str] = []
                name_tag = extract_name_tag(subnet)
                if cidr:
                    subnet_label_lines.append(f"CIDR: {cidr}")
                az = subnet.get("AvailabilityZone")
                if az:
                    subnet_label_lines.append(f"AZ: {az}")
                subnet_label_lines.append(f"Visibility: {visibility_label}")
                subnet_label_lines.append(f"ID: {subnet_id}")
                subnet_label = html_panel_label(
                    name_tag or ("Public Subnet" if public else "Private Subnet"),
                    metadata=subnet_label_lines,
                    accent=palette["accent_public"] if public else palette["accent_private"],
                )
                target_graph = public_graph if public else private_graph
                node_color = (
                    palette["fill_public"] if public else palette["fill_private"]
                )
                group = public_group if public else private_group
                target_graph.node(
                    subnet_id,
                    subnet_label,
                    shape="box",
                    style="rounded,filled",
                    fillcolor=node_color,
                    color=palette["accent_public"]
                    if public
                    else palette["accent_private"],
                    group=group,
                )

                append_column_node(
                    public_column_nodes if public else private_column_nodes, subnet_id
                )

                associated_route_table = subnet_route_table.get(subnet_id) or main_route_table_by_vpc.get(
                    vpc_id
                )
                anchor = public_anchor if public else private_anchor
                graph.edge(anchor, subnet_id, style="invis", weight="3")

                if associated_route_table:
                    graph.edge(associated_route_table, subnet_id)

                for instance in instances_by_subnet.get(subnet_id, []):
                    name = extract_name_tag(instance)
                    label = (
                        f"{name}\n{instance['InstanceId']}" if name else instance["InstanceId"]
                    )
                    instance_metadata = [f"ID: {instance['InstanceId']}"]
                    instance_type = instance.get("InstanceType")
                    if instance_type:
                        instance_metadata.append(f"Type: {instance_type}")
                    graph.node(
                        instance["InstanceId"],
                        html_panel_label(
                            name or "EC2 Instance",
                            metadata=instance_metadata,
                            accent=palette["accent_public"]
                            if public
                            else palette["accent_private"],
                        ),
                        shape="oval",
                        style="filled",
                        fillcolor="white",
                    )
                    graph.edge(subnet_id, instance["InstanceId"])

            def connect_column(anchor: str, nodes: List[str]) -> None:
                previous = anchor
                for node_id in nodes:
                    graph.edge(previous, node_id, style="invis", weight="2")
                    previous = node_id

            if private_column_nodes:
                connect_column(private_anchor, private_column_nodes)
            if public_column_nodes:
                connect_column(public_anchor, public_column_nodes)

    graph.subgraph(edge_graph)

    for node_id, (_, attrs, _) in gateway_nodes.items():
        if node_id.startswith("igw-") or node_id.startswith("eigw-"):
            graph.edge("internet", node_id, style="dashed")

    if subnet_by_vpc:
        with graph.subgraph(name="cluster_legend") as legend:
            legend.attr(
                label="Legend",
                color=palette["outline"],
                fontcolor=palette["text"],
                style="rounded",
                bgcolor="white",
            )
            legend.node(
                "legend_public_subnet",
                html_panel_label(
                    "Public Subnet",
                    metadata=["Visibility: Public", "Color: Teal"],
                    accent=palette["accent_public"],
                ),
                shape="box",
                style="rounded,filled",
                fillcolor=palette["fill_public"],
                color=palette["accent_public"],
            )
            legend.node(
                "legend_private_subnet",
                html_panel_label(
                    "Private Subnet",
                    metadata=["Visibility: Private", "Color: Indigo"],
                    accent=palette["accent_private"],
                ),
                shape="box",
                style="rounded,filled",
                fillcolor=palette["fill_private"],
                color=palette["accent_private"],
            )
            legend.edge(
                "legend_public_subnet",
                "legend_private_subnet",
                style="invis",
            )
            legend.node(
                "legend_main_rt",
                html_panel_label(
                    "Main Route Table",
                    metadata=["Color: Amber"],
                    accent=palette["accent_main"],
                ),
                shape="folder",
                style="rounded,filled",
                fillcolor=palette["fill_main"],
                color=palette["accent_main"],
            )
            legend.node(
                "legend_public_rt",
                html_panel_label(
                    "Public Route Table",
                    metadata=["Color: Teal"],
                    accent=palette["accent_public"],
                ),
                shape="folder",
                style="rounded,filled",
                fillcolor=palette["fill_public"],
                color=palette["accent_public"],
            )
            legend.node(
                "legend_private_rt",
                html_panel_label(
                    "Private Route Table",
                    metadata=["Color: Indigo"],
                    accent=palette["accent_private"],
                ),
                shape="folder",
                style="rounded,filled",
                fillcolor=palette["fill_private"],
                color=palette["accent_private"],
            )
            legend.edge("legend_main_rt", "legend_public_rt", style="invis")
            legend.edge("legend_public_rt", "legend_private_rt", style="invis")
            legend.node(
                "legend_nat_gateway",
                html_panel_label("NAT Gateway", metadata=["Shared connectivity"]),
                shape="box",
                style="rounded,filled",
                fillcolor="white",
            )
            legend.node(
                "legend_igw",
                html_panel_label("Internet Gateway", metadata=["Public egress"]),
                shape="Msquare",
                style="filled",
                fillcolor="white",
            )
            legend.node(
                "legend_instance",
                html_panel_label("EC2 Instance", metadata=["Instance node"]),
                shape="oval",
                style="filled",
                fillcolor="white",
            )
            legend.edge("legend_nat_gateway", "legend_igw", style="invis")
            legend.edge("legend_igw", "legend_instance", style="invis")

    rendered_path = graph.render(output_path, cleanup=True)
    return rendered_path


__all__ = ["generate_network_diagram"]
