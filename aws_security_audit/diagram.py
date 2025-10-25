"""Network diagram generation utilities."""
from __future__ import annotations

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
    graph = Digraph("aws_network", format="png")
    graph.attr(
        rankdir="TB",
        bgcolor="white",
        fontname="Helvetica",
        fontsize="12",
        labelloc="t",
        pad="0.5",
        nodesep="0.6",
        ranksep="1.0 equally",
        splines="ortho",
    )
    graph.node_attr.update(
        fontname="Helvetica",
        fontsize="10",
        color="#4a5568",
        style="filled",
        fillcolor="white",
    )
    graph.edge_attr.update(
        fontname="Helvetica",
        fontsize="9",
        color="#4a5568",
        arrowsize="0.8",
    )

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
        "Internet",
        shape="oval",
        color="lightblue",
        style="filled",
        fillcolor="aliceblue",
        penwidth="2",
    )

    gateway_nodes: Dict[str, Tuple[str, Dict[str, str], str]] = {}

    # Create a dedicated area where shared gateway-style nodes live. This avoids
    # sprinkling them across VPC clusters and keeps the diagram easier to scan.
    edge_graph = Digraph(name="cluster_edge")
    edge_graph.attr(
        label="Edge & Shared Connectivity",
        color="#cbd5f5",
        style="rounded,dashed",
        bgcolor="#f8fbff",
        fontname="Helvetica",
    )
    edge_graph.node_attr.update(fontname="Helvetica", fontsize="10")

    def ensure_gateway_node(
        node_id: str, label: str, attrs: Dict[str, str], owner_vpc: str
    ) -> None:
        if node_id in gateway_nodes:
            return

        node_attrs = {
            "shape": "box",
            "style": "filled",
            "fillcolor": "white",
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

        target_mappings: Iterable[Tuple[str, str, str, Dict[str, str]]] = (
            ("GatewayId", "igw-", "Internet Gateway", {"shape": "Msquare"}),
            (
                "EgressOnlyInternetGatewayId",
                "eigw-",
                "Egress-Only Internet Gateway",
                {"shape": "Msquare"},
            ),
            ("NatGatewayId", "nat-", "NAT Gateway", {"shape": "box", "style": "rounded"}),
            ("TransitGatewayId", "tgw-", "Transit Gateway", {"shape": "hexagon"}),
            ("VpcPeeringConnectionId", "pcx-", "VPC Peering", {"shape": "doublecircle"}),
        )

        for key, prefix, label, attrs in target_mappings:
            value = route.get(key)
            if value and value.startswith(prefix):
                return value, f"{value}\n{label}", attrs

        instance_id = route.get("InstanceId")
        if instance_id:
            return instance_id, f"{instance_id}\nInstance", {"shape": "oval"}

        eni_id = route.get("NetworkInterfaceId")
        if eni_id:
            return eni_id, f"{eni_id}\nENI", {"shape": "component"}

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
            vpc_graph.attr(label=vpc_label, style="rounded", color="gray")

            public_subgraph_name = f"cluster_{vpc_id}_public"
            private_subgraph_name = f"cluster_{vpc_id}_private"

            public_group = f"{vpc_id}_public_column"
            private_group = f"{vpc_id}_private_column"

            with vpc_graph.subgraph(name=public_subgraph_name) as public_graph:
                public_graph.attr(
                    label="Public Routes & Subnets",
                    color="darkseagreen",
                    style="rounded",
                    bgcolor="mintcream",
                )
                public_graph.node_attr.update(style="filled", fillcolor="honeydew")
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
                    color="lightsteelblue",
                    style="rounded",
                    bgcolor="ghostwhite",
                )
                private_graph.node_attr.update(style="filled", fillcolor="azure")
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

                label_lines: List[str] = []
                if name_tag:
                    label_lines.append(name_tag)
                label_lines.append(route_table_id)
                if classification == "main":
                    label_lines.append("(Main)")

                if classification == "main":
                    vpc_graph.node(
                        route_table_id,
                        "\n".join(label_lines),
                        shape="folder",
                        style="rounded,filled",
                        fillcolor="#fff1cc",
                        color="goldenrod",
                        group=f"{vpc_id}_main",
                    )
                    graph.edge(
                        route_table_id,
                        private_anchor,
                        style="invis",
                        weight="8",
                    )
                    graph.edge(
                        route_table_id,
                        public_anchor,
                        style="invis",
                        weight="8",
                    )
                else:
                    is_public = classification == "public"
                    target_graph = public_graph if is_public else private_graph
                    group = public_group if is_public else private_group
                    fillcolor = "#e6ffed" if is_public else "#e6f0ff"
                    border_color = "darkseagreen" if is_public else "steelblue"
                    target_graph.node(
                        route_table_id,
                        "\n".join(label_lines),
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

                for route in route_table.get("Routes", []):
                    target = route_target(route)
                    if not target:
                        continue
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
                if name_tag:
                    subnet_label_lines.append(name_tag)
                subnet_label_lines.append(subnet_id)
                if cidr:
                    subnet_label_lines.append(cidr)
                az = subnet.get("AvailabilityZone")
                if az:
                    subnet_label_lines.append(az)
                subnet_label_lines.append(f"({visibility_label})")
                subnet_label = "\n".join(subnet_label_lines)
                target_graph = public_graph if public else private_graph
                node_color = "#b6f2b6" if public else "#d2dcff"
                group = public_group if public else private_group
                target_graph.node(
                    subnet_id,
                    subnet_label,
                    shape="box",
                    style="rounded,filled",
                    fillcolor=node_color,
                    color="darkseagreen" if public else "steelblue",
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
                    graph.node(
                        instance["InstanceId"],
                        label,
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
            legend.attr(label="Legend", color="gray", style="dashed")
            legend.node(
                "legend_public_subnet",
                "Public Subnet",
                shape="box",
                style="rounded,filled",
                fillcolor="#b6f2b6",
                color="darkseagreen",
            )
            legend.node(
                "legend_private_subnet",
                "Private Subnet",
                shape="box",
                style="rounded,filled",
                fillcolor="#d2dcff",
                color="steelblue",
            )
            legend.edge(
                "legend_public_subnet",
                "legend_private_subnet",
                style="invis",
            )
            legend.node(
                "legend_main_rt",
                "Main Route Table",
                shape="folder",
                style="rounded,filled",
                fillcolor="#fff1cc",
                color="goldenrod",
            )
            legend.node(
                "legend_public_rt",
                "Public Route Table",
                shape="folder",
                style="rounded,filled",
                fillcolor="#e6ffed",
                color="darkseagreen",
            )
            legend.node(
                "legend_private_rt",
                "Private Route Table",
                shape="folder",
                style="rounded,filled",
                fillcolor="#e6f0ff",
                color="steelblue",
            )
            legend.edge("legend_main_rt", "legend_public_rt", style="invis")
            legend.edge("legend_public_rt", "legend_private_rt", style="invis")
            legend.node(
                "legend_nat_gateway",
                "NAT Gateway",
                shape="box",
                style="rounded,filled",
                fillcolor="white",
            )
            legend.node(
                "legend_igw",
                "Internet Gateway",
                shape="Msquare",
                style="filled",
                fillcolor="white",
            )
            legend.node(
                "legend_instance",
                "EC2 Instance",
                shape="oval",
                style="filled",
                fillcolor="white",
            )
            legend.edge("legend_nat_gateway", "legend_igw", style="invis")
            legend.edge("legend_igw", "legend_instance", style="invis")

    rendered_path = graph.render(output_path, cleanup=True)
    return rendered_path


__all__ = ["generate_network_diagram"]
