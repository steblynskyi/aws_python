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
        nodesep="0.6",
        ranksep="1.0",
    )
    graph.node_attr.update(fontname="Helvetica", fontsize="11")
    graph.edge_attr.update(fontname="Helvetica", fontsize="10")

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

    instances_by_subnet: Dict[str, List[dict]] = {}
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            subnet_id = instance.get("SubnetId")
            if subnet_id:
                instances_by_subnet.setdefault(subnet_id, []).append(instance)

    graph.node(
        "internet",
        label="<<B>Internet</B>>",
        shape="oval",
        color="#9faab5",
        style="dashed",
        fillcolor="white",
        penwidth="2",
    )
    with graph.subgraph() as internet_rank:
        internet_rank.attr(rank="source")
        internet_rank.node("internet")

    gateway_nodes: Dict[str, Tuple[str, Dict[str, str], str]] = {}

    def formatted_label(title: str, identifier: str) -> str:
        return f"<<B>{title}</B><BR/>{identifier}>>"

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
                return value, formatted_label(label, value), attrs

        instance_id = route.get("InstanceId")
        if instance_id:
            return instance_id, formatted_label("Instance", instance_id), {"shape": "component"}

        eni_id = route.get("NetworkInterfaceId")
        if eni_id:
            return eni_id, formatted_label("ENI", eni_id), {"shape": "component"}

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
        vpc_label_lines = [f"<B>VPC {vpc_id}</B>"]
        if vpc.get("CidrBlock"):
            vpc_label_lines.append(vpc["CidrBlock"])
        vpc_label = f"<<{'<BR/>'.join(vpc_label_lines)}>>"

        with graph.subgraph(name=f"cluster_{vpc_id}") as vpc_graph:
            vpc_graph.attr(
                label=vpc_label,
                style="rounded",
                color="#7d8996",
                fontname="Helvetica",
                fontsize="12",
            )

            public_subgraph_name = f"cluster_{vpc_id}_public"
            private_subgraph_name = f"cluster_{vpc_id}_private"

            with vpc_graph.subgraph(name=public_subgraph_name) as public_graph:
                public_graph.attr(
                    label="<<B>Public Subnets</B>>",
                    color="#4b8b3b",
                    style="rounded",
                    bgcolor="#e8f5ed",
                    rank="same",
                )
                public_graph.node_attr.update(style="filled", fillcolor="#B7E1CD")

            with vpc_graph.subgraph(name=private_subgraph_name) as private_graph:
                private_graph.attr(
                    label="<<B>Private Subnets</B>>",
                    color="#4461a7",
                    style="rounded",
                    bgcolor="#eef3fc",
                    rank="same",
                )
                private_graph.node_attr.update(style="filled", fillcolor="#C9DAF8")

            route_tables_in_vpc = route_tables_by_vpc.get(vpc_id, [])
            main_route_table_id = main_route_table_by_vpc.get(vpc_id)
            with vpc_graph.subgraph(name=f"cluster_{vpc_id}_route_tables") as route_table_graph:
                route_table_graph.attr(
                    label="<<B>Route Tables</B>>",
                    color="#7d8996",
                    style="rounded",
                    bgcolor="#fdfdfd",
                    rank="same",
                )
                route_table_graph.node_attr.update(
                    shape="folder", style="rounded,filled", fillcolor="white"
                )

                private_route_tables: List[str] = []
                public_route_tables: List[str] = []

                def route_table_group(classification: str) -> str:
                    return f"{vpc_id}_rt_{classification}_group"

                for route_table in route_tables_in_vpc:
                    route_table_id = route_table["RouteTableId"]
                    name_tag = next(
                        (
                            tag["Value"]
                            for tag in route_table.get("Tags", [])
                            if tag.get("Key") == "Name" and tag.get("Value")
                        ),
                        None,
                    )

                    classification = "main"
                    if route_table_id != main_route_table_id:
                        classification = (
                            "public" if is_public_route_table(route_table) else "private"
                        )

                    if classification == "public":
                        public_route_tables.append(route_table_id)
                    elif classification == "private":
                        private_route_tables.append(route_table_id)

                    label_lines: List[str] = []
                    if name_tag:
                        label_lines.append(name_tag)
                    label_lines.append(route_table_id)
                    if classification == "main":
                        label_lines.append("(Main)")

                    fillcolor = {
                        "main": "#ffe8bf",
                        "public": "#dbf2e3",
                        "private": "#dde7fb",
                    }[classification]
                    penwidth = "2" if classification == "main" else "1"

                    route_table_graph.node(
                        route_table_id,
                        "\n".join(label_lines),
                        fillcolor=fillcolor,
                        color="#7d8996",
                        penwidth=penwidth,
                        group=route_table_group(classification),
                    )

                    for route in route_table.get("Routes", []):
                        target = route_target(route)
                        if not target:
                            continue
                        target_id, target_label, attrs = target
                        if target_id not in gateway_nodes:
                            node_attrs = {
                                "shape": "box",
                                "style": "filled",
                                "fillcolor": "white",
                            }
                            node_attrs.update(attrs)
                            vpc_graph.node(target_id, target_label, **node_attrs)
                            gateway_nodes[target_id] = (target_label, node_attrs, vpc_id)
                        graph.edge(
                            route_table_id,
                            target_id,
                            label=route.get("DestinationCidrBlock")
                            or route.get("DestinationIpv6CidrBlock", ""),
                            color="#7d8996",
                        )

                private_anchor = None
                public_anchor = None
                if private_route_tables:
                    private_anchor = f"{vpc_id}_rt_private_anchor"
                    route_table_graph.node(
                        private_anchor,
                        "",
                        shape="point",
                        width="0",
                        height="0",
                        style="invis",
                        group=route_table_group("private"),
                    )
                if public_route_tables:
                    public_anchor = f"{vpc_id}_rt_public_anchor"
                    route_table_graph.node(
                        public_anchor,
                        "",
                        shape="point",
                        width="0",
                        height="0",
                        style="invis",
                        group=route_table_group("public"),
                    )

                if private_anchor and public_anchor:
                    route_table_graph.edge(private_anchor, public_anchor, style="invis", weight="5")

                if main_route_table_id:
                    if private_anchor:
                        route_table_graph.edge(
                            main_route_table_id, private_anchor, style="invis", weight="5"
                        )
                    if public_anchor:
                        route_table_graph.edge(
                            main_route_table_id, public_anchor, style="invis", weight="5"
                        )

                for idx, route_table_id in enumerate(private_route_tables):
                    predecessor = private_anchor if idx == 0 else private_route_tables[idx - 1]
                    route_table_graph.edge(predecessor, route_table_id, style="invis", weight="2")

                for idx, route_table_id in enumerate(public_route_tables):
                    predecessor = public_anchor if idx == 0 else public_route_tables[idx - 1]
                    route_table_graph.edge(predecessor, route_table_id, style="invis", weight="2")

            for subnet in subnet_by_vpc.get(vpc_id, []):
                subnet_id = subnet["SubnetId"]
                cidr = subnet.get("CidrBlock", "")
                public = is_public_subnet(subnet)
                visibility_label = "Public" if public else "Private"
                az = subnet.get("AvailabilityZone", "")
                subnet_label = f"{subnet_id}\n{cidr}\n{visibility_label}\n{az}"
                target_graph = public_graph if public else private_graph
                node_color = "#B7E1CD" if public else "#C9DAF8"
                target_graph.node(
                    subnet_id,
                    subnet_label,
                    shape="box",
                    style="rounded,filled",
                    fillcolor=node_color,
                    color="#4b8b3b" if public else "#4461a7",
                )

                associated_route_table = subnet_route_table.get(subnet_id) or main_route_table_by_vpc.get(
                    vpc_id
                )
                if associated_route_table:
                    association_label = visibility_label
                    if az:
                        association_label = f"{visibility_label} ({az})"
                    graph.edge(
                        associated_route_table,
                        subnet_id,
                        label=association_label,
                        color="#7d8996",
                        arrowsize="0.7",
                    )

                for instance in instances_by_subnet.get(subnet_id, []):
                    name = next(
                        (
                            tag["Value"]
                            for tag in instance.get("Tags", [])
                            if tag.get("Key") == "Name"
                        ),
                        instance["InstanceId"],
                    )
                    graph.node(
                        instance["InstanceId"],
                        name,
                        shape="component",
                        style="filled",
                        fillcolor="white",
                        color="#7d8996",
                    )
                    graph.edge(subnet_id, instance["InstanceId"], color="#7d8996")

    gateway_rank_nodes: List[str] = []
    for node_id, (_, attrs, _) in gateway_nodes.items():
        if node_id.startswith("igw-") or node_id.startswith("eigw-"):
            graph.edge("internet", node_id, style="dashed", color="#7d8996")
        if attrs.get("shape") in {"Msquare", "box"}:
            gateway_rank_nodes.append(node_id)

    if gateway_rank_nodes:
        sink_anchor = "gateway_rank_anchor"
        graph.node(sink_anchor, "", shape="point", width="0", height="0", style="invis")
        with graph.subgraph() as gateway_rank:
            gateway_rank.attr(rank="sink")
            gateway_rank.node(sink_anchor)
            for gateway_node in gateway_rank_nodes:
                gateway_rank.edge(gateway_node, sink_anchor, style="invis")

    if subnet_by_vpc:
        with graph.subgraph(name="cluster_legend") as legend:
            legend.attr(
                label="<<B>Legend</B>>",
                color="#9faab5",
                style="rounded",
                bgcolor="#f7f9fb",
                fontsize="10",
            )
            legend.node(
                "legend_public_subnet",
                "Public Subnet",
                shape="box",
                style="rounded,filled",
                fillcolor="#B7E1CD",
                color="#4b8b3b",
                fontsize="9",
            )
            legend.node(
                "legend_private_subnet",
                "Private Subnet",
                shape="box",
                style="rounded,filled",
                fillcolor="#C9DAF8",
                color="#4461a7",
                fontsize="9",
            )
            legend.edge(
                "legend_public_subnet",
                "legend_private_subnet",
                style="invis",
            )

    rendered_path = graph.render(output_path, cleanup=True)
    return rendered_path


__all__ = ["generate_network_diagram"]
