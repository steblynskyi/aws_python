"""Shared dataclasses and helpers for network diagram rendering."""
from __future__ import annotations

from dataclasses import dataclass
from .html_utils import escape_label
from typing import Dict, Iterable, List, Optional


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
            # Graphviz's HTML-like labels safely accept Unicode characters so
            # long as they are encoded as XML character references (see
            # https://graphviz.org/doc/info/shapes.html#html).  Our
            # ``escape_label`` helper performs that conversion, which means we
            # can use the human friendly right arrow here without upsetting the
            # ``dot`` parser.
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
class InstanceSummary:
    """Compact details about an EC2 instance for display within a subnet."""

    instance_id: str
    name: Optional[str]
    state: Optional[str]
    private_ip: Optional[str]

    def display_text(self) -> str:
        """Return a formatted label for the instance."""

        name_part = f"{self.name} ({self.instance_id})" if self.name else self.instance_id
        state_part = f"[{self.state}]" if self.state else ""
        ip_part = self.private_ip or ""
        parts = [segment for segment in [name_part, state_part, ip_part] if segment]
        return " ".join(parts)


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
    instances: List[InstanceSummary]


@dataclass
class GlobalServiceSummary:
    """Aggregated information for services that do not live within a VPC."""

    title: str
    lines: List[str]
    fillcolor: str
    fontcolor: str


@dataclass
class Ec2Resources:
    """Raw EC2 resources required for the diagram."""

    vpcs: List[dict]
    subnets: List[dict]
    route_tables: List[dict]
    nat_gateways: List[dict]
    internet_gateways: List[dict]
    virtual_private_gateways: List[dict]
    vpc_endpoints: List[dict]
    vpc_peering_connections: List[dict]
    reservations: List[dict]


@dataclass
class DiagramContext:
    """Prepared context for rendering the VPC diagram."""

    resources: Ec2Resources
    subnets_by_vpc: Dict[str, List[dict]]
    route_tables_by_vpc: Dict[str, List[dict]]
    subnet_route_table: Dict[str, str]
    main_route_table_by_vpc: Dict[str, str]
    instances_by_subnet: Dict[str, List[InstanceSummary]]
    rds_instances_by_vpc: Dict[str, List[dict]]
    internet_gateways: Dict[str, dict]
    virtual_private_gateways: Dict[str, dict]
    vpc_endpoints_by_vpc: Dict[str, List[dict]]
    vpc_peering_connections: Dict[str, dict]


def summarize_global_service_lines(
    items: Iterable[str], max_items: int
) -> List[str]:
    """Return HTML-safe lines truncated for compact global service panels."""

    sanitized = [escape_label(item) for item in items]
    limited = sanitized[:max_items]
    if len(sanitized) > max_items:
        limited.append(escape_label(f"… (+{len(sanitized) - max_items} more)"))
    return limited


__all__ = [
    "InstanceSummary",
    "Ec2Resources",
    "RouteDetail",
    "RouteSummary",
    "SubnetCell",
    "GlobalServiceSummary",
    "DiagramContext",
    "summarize_global_service_lines",
]
