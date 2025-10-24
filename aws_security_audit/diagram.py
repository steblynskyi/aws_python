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
    graph.attr(rankdir="LR", bgcolor="white")

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
        "Internet",
        shape="cloud",
        color="lightblue",
        style="filled",
        fillcolor="aliceblue",
    )

    gateway_nodes: Dict[str, Tuple[str, Dict[str, str], str]] = {}

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

    def is_public_subnet(subnet: dict) -> bool:
        route_table_id = subnet_route_table.get(subnet["SubnetId"]) or main_route_table_by_vpc.get(
            subnet["VpcId"], ""
        )
        if route_table_id:
            route_table = next(
                (rt for rt in route_tables_by_vpc.get(subnet["VpcId"], []) if rt["RouteTableId"] == route_table_id),
                None,
            )
            if route_table and any(
                (route.get("GatewayId") or "").startswith("igw-")
                and (route.get("DestinationCidrBlock") == "0.0.0.0/0"
                or route.get("DestinationIpv6CidrBlock") == "::/0")
                for route in route_table.get("Routes", [])
            ):
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

            with vpc_graph.subgraph(name=public_subgraph_name) as public_graph:
                public_graph.attr(
                    label="Public Subnets",
                    color="darkseagreen",
                    style="rounded",
                    bgcolor="mintcream",
                )
                public_graph.node_attr.update(style="filled", fillcolor="honeydew")

            with vpc_graph.subgraph(name=private_subgraph_name) as private_graph:
                private_graph.attr(
                    label="Private Subnets",
                    color="lightsteelblue",
                    style="rounded",
                    bgcolor="ghostwhite",
                )
                private_graph.node_attr.update(style="filled", fillcolor="azure")

            route_tables_in_vpc = route_tables_by_vpc.get(vpc_id, [])
            for route_table in route_tables_in_vpc:
                route_table_id = route_table["RouteTableId"]
                label_lines = [route_table_id]
                if route_table_id == main_route_table_by_vpc.get(vpc_id):
                    label_lines.append("(Main)")
                vpc_graph.node(
                    route_table_id,
                    "\n".join(label_lines),
                    shape="folder",
                    style="rounded,filled",
                    fillcolor="white",
                )

                for route in route_table.get("Routes", []):
                    target = route_target(route)
                    if not target:
                        continue
                    target_id, target_label, attrs = target
                    if target_id not in gateway_nodes:
                        node_attrs = {"shape": "box", "style": "filled", "fillcolor": "white"}
                        node_attrs.update(attrs)
                        vpc_graph.node(target_id, target_label, **node_attrs)
                        gateway_nodes[target_id] = (target_label, node_attrs, vpc_id)
                    graph.edge(route_table_id, target_id, label=route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock", ""))

            for subnet in subnet_by_vpc.get(vpc_id, []):
                subnet_id = subnet["SubnetId"]
                cidr = subnet.get("CidrBlock", "")
                public = is_public_subnet(subnet)
                visibility_label = "Public" if public else "Private"
                subnet_label = f"{subnet_id}\n{cidr}\n({visibility_label})"
                target_graph = public_graph if public else private_graph
                node_color = "#b6f2b6" if public else "#d2dcff"
                target_graph.node(
                    subnet_id,
                    subnet_label,
                    shape="box",
                    style="rounded,filled",
                    fillcolor=node_color,
                    color="darkseagreen" if public else "steelblue",
                )

                associated_route_table = subnet_route_table.get(subnet_id) or main_route_table_by_vpc.get(
                    vpc_id
                )
                if associated_route_table:
                    graph.edge(associated_route_table, subnet_id)

                for instance in instances_by_subnet.get(subnet_id, []):
                    name = next(
                        (
                            tag["Value"]
                            for tag in instance.get("Tags", [])
                            if tag.get("Key") == "Name"
                        ),
                        instance["InstanceId"],
                    )
                    graph.node(instance["InstanceId"], name, shape="oval", style="filled", fillcolor="white")
                    graph.edge(subnet_id, instance["InstanceId"])

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

    rendered_path = graph.render(output_path, cleanup=True)
    return rendered_path


__all__ = ["generate_network_diagram"]
