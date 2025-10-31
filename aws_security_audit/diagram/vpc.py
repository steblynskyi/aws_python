"""VPC-related helpers for network diagram generation."""
from __future__ import annotations

from textwrap import wrap
from typing import Dict, Iterable, List, Optional, Tuple

from .html_utils import build_icon_cell, escape_label

from .models import InstanceSummary, RouteDetail, RouteSummary, SubnetCell


def group_subnets_by_vpc(subnets: Iterable[dict]) -> Dict[str, List[dict]]:
    """Return mapping of VPC identifiers to their subnets."""

    subnet_by_vpc: Dict[str, List[dict]] = {}
    for subnet in subnets:
        subnet_by_vpc.setdefault(subnet["VpcId"], []).append(subnet)
    return subnet_by_vpc


def build_route_table_indexes(route_tables: Iterable[dict]) -> Tuple[
    Dict[str, List[dict]],
    Dict[str, str],
    Dict[str, str],
]:
    """Return indexes for route tables keyed by VPC and subnet."""

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

    return route_tables_by_vpc, subnet_route_table, main_route_table_by_vpc


def classify_subnet(subnet: dict, route_table: Optional[dict]) -> Tuple[str, bool]:
    """Determine subnet tier key and isolation."""

    public = False
    isolated = True
    routes = route_table.get("Routes", []) if route_table else []

    for route in routes:
        destination = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
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


def summarize_route_table(route_table: Optional[dict]) -> Optional[RouteSummary]:
    """Return a :class:`RouteSummary` for the provided route table."""

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
        destination = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
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


def build_subnet_cell(
    subnet: dict,
    tier: str,
    classification: str,
    isolated: bool,
    route_summary: Optional[RouteSummary],
    instances: List[InstanceSummary],
) -> SubnetCell:
    """Return :class:`SubnetCell` representation for the subnet."""

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
        instances=instances,
    )


def wrap_label_text(value: str, width: int = 26) -> List[str]:
    """Return the label split into shorter lines for improved readability."""

    if not value:
        return []

    def _split_with_delimiter(text: str, delimiter: str) -> List[str]:
        parts = text.split(delimiter)
        lines: List[str] = []
        current = ""

        for part in parts:
            part = part.strip()
            if not part:
                continue

            candidate = f"{current}{delimiter}{part}" if current else part
            if len(candidate) <= width or not current:
                current = candidate
            else:
                lines.append(current)
                current = part

        if current:
            lines.append(current)

        return lines or [text]

    lines = _split_with_delimiter(value, "-")
    refined: List[str] = []

    for line in lines:
        working_line = line
        if len(working_line) > width and "_" in working_line:
            refined.extend(_split_with_delimiter(working_line, "_"))
            continue

        if len(working_line) > width and " " in working_line:
            refined.extend(wrap(working_line, width=width, break_long_words=False, break_on_hyphens=False))
            continue

        if len(working_line) > width:
            refined.extend(wrap(working_line, width=width, break_long_words=False, break_on_hyphens=False) or [working_line])
            continue

        refined.append(working_line)

    return refined or [value]


def format_subnet_cell_label(cell: SubnetCell) -> str:
    """Return the HTML label used for subnet cells."""

    icon_map = {
        "public": ("PUB", "#047857"),
        "private_app": ("APP", "#1d4ed8"),
        "private_data": ("DB", "#1e3a8a"),
        "shared": ("SHR", "#4a5568"),
    }
    icon_text, icon_bgcolor = icon_map.get(cell.classification, ("SUB", "#2d3748"))
    if cell.is_isolated:
        icon_text = "ISO"
        icon_bgcolor = "#4a5568"

    subnet_lines = []
    if cell.name:
        for line in wrap_label_text(cell.name):
            subnet_lines.append(f"<B>{escape_label(line)}</B>")
    subnet_lines.append(f'<FONT POINT-SIZE="11">{escape_label(cell.subnet_id)}</FONT>')
    if cell.cidr:
        subnet_lines.append(escape_label(cell.cidr))
    if cell.az:
        subnet_lines.append(escape_label(cell.az))
    if cell.route_summary:
        subnet_lines.append(
            f'<FONT POINT-SIZE="11" COLOR="#2d3748"><B>rt:</B> {escape_label(cell.route_summary.route_table_id)}</FONT>'
        )

    subnet_html = '<BR ALIGN="LEFT"/>'.join(subnet_lines)

    def build_route_table_panel(summary: Optional[RouteSummary]) -> str:
        """Return a styled HTML table describing the subnet's route table."""

        header_bg = "#fb923c"
        header_color = "#ffffff"
        info_bg = "#ffedd5"
        info_text = "#7c2d12"
        routes_bg = "#fff7ed"

        rows = [
            (
                f'<TR><TD ALIGN="LEFT" BGCOLOR="{header_bg}">'
                f'<FONT COLOR="{header_color}"><B>Route Table</B></FONT></TD></TR>'
            )
        ]

        if not summary:
            rows.append(
                f'<TR><TD ALIGN="LEFT" BGCOLOR="{routes_bg}">'
                f'<FONT POINT-SIZE="10" COLOR="{info_text}"><I>No non-local routes</I></FONT>'
                "</TD></TR>"
            )
            return (
                '<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" '
                'CELLPADDING="4" COLOR="#fb923c">' + "".join(rows) + "</TABLE>"
            )

        if summary.name:
            name_lines = wrap_label_text(summary.name, width=30)
            for line in name_lines:
                rows.append(
                    f'<TR><TD ALIGN="LEFT" BGCOLOR="{info_bg}">'
                    f'<FONT COLOR="{info_text}"><B>{escape_label(line)}</B></FONT></TD></TR>'
                )

        route_table_lines = wrap_label_text(summary.route_table_id, width=30)
        for line in route_table_lines:
            rows.append(
                f'<TR><TD ALIGN="LEFT" BGCOLOR="{info_bg}">'
                f'<FONT COLOR="{info_text}">{escape_label(line)}</FONT></TD></TR>'
            )

        if summary.routes:
            for route in summary.routes:
                rows.append(
                    f'<TR><TD ALIGN="LEFT" BGCOLOR="{routes_bg}">'
                    f'<FONT POINT-SIZE="10" COLOR="{info_text}">&#8226; '
                    f"{escape_label(route.display_text())}</FONT></TD></TR>"
                )
        else:
            rows.append(
                f'<TR><TD ALIGN="LEFT" BGCOLOR="{routes_bg}">'
                f'<FONT POINT-SIZE="10" COLOR="{info_text}"><I>No non-local routes</I></FONT>'
                "</TD></TR>"
            )

        return (
            '<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4" '
            'COLOR="#fb923c">' + "".join(rows) + "</TABLE>"
        )

    route_html = build_route_table_panel(cell.route_summary)

    instance_row = ""
    if cell.instances:
        instance_lines = ['<FONT POINT-SIZE="11"><B>Instances</B></FONT>']
        for instance in cell.instances:
            instance_lines.append(f'<FONT POINT-SIZE="11">{escape_label(instance.display_text())}</FONT>')
        instance_html = '<BR ALIGN="LEFT"/>'.join(instance_lines)
        instance_row = (
            '<TR><TD BGCOLOR="#eef2ff"><FONT COLOR="#1a365d">'
            f"{instance_html}"
            '</FONT></TD></TR>'
        )

    row_count = 2 + (1 if cell.instances else 0)
    icon_cell = build_icon_cell(
        icon_text,
        icon_bgcolor=icon_bgcolor,
        icon_color="#ffffff",
        rowspan=row_count,
    )

    return (
        '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">'
        f'<TR>{icon_cell}'
        f'<TD BGCOLOR="{cell.color}" COLOR="{cell.font_color}"><FONT COLOR="{cell.font_color}">{subnet_html}</FONT></TD></TR>'
        f'<TR><TD PORT="routes" BGCOLOR="#fff7ed" ALIGN="LEFT">{route_html}</TD></TR>'
        f"{instance_row}"
        '</TABLE>>'
    )


__all__ = [
    "build_route_table_indexes",
    "build_subnet_cell",
    "classify_subnet",
    "format_subnet_cell_label",
    "group_subnets_by_vpc",
    "identify_route_target",
    "summarize_route_table",
]
