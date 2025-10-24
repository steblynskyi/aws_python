"""Network diagram generation utilities."""
from __future__ import annotations

from typing import Dict, List, Optional

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
    except (ClientError, EndpointConnectionError) as exc:
        raise RuntimeError(f"Unable to generate diagram: {exc}") from exc

    subnet_by_vpc: Dict[str, List[dict]] = {}
    for subnet in subnets:
        subnet_by_vpc.setdefault(subnet["VpcId"], []).append(subnet)

    instances_by_subnet: Dict[str, List[dict]] = {}
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            subnet_id = instance.get("SubnetId")
            if subnet_id:
                instances_by_subnet.setdefault(subnet_id, []).append(instance)

    graph.node("internet", "Internet", shape="cloud", color="lightblue")

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        with graph.subgraph(name=f"cluster_{vpc_id}") as vpc_graph:
            vpc_graph.attr(label=f"VPC {vpc_id}")
            for subnet in subnet_by_vpc.get(vpc_id, []):
                subnet_id = subnet["SubnetId"]
                cidr = subnet.get("CidrBlock", "")
                subnet_label = f"{subnet_id}\n{cidr}"
                vpc_graph.node(subnet_id, subnet_label, shape="box", style="rounded")
                for instance in instances_by_subnet.get(subnet_id, []):
                    name = next(
                        (
                            tag["Value"]
                            for tag in instance.get("Tags", [])
                            if tag.get("Key") == "Name"
                        ),
                        instance["InstanceId"],
                    )
                    graph.node(instance["InstanceId"], name, shape="oval")
                    graph.edge(subnet_id, instance["InstanceId"])
                if subnet.get("MapPublicIpOnLaunch"):
                    graph.edge("internet", subnet_id, style="dashed")

    rendered_path = graph.render(output_path, cleanup=True)
    return rendered_path


__all__ = ["generate_network_diagram"]
