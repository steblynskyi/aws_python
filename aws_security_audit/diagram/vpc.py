"""VPC-related helpers for network diagram generation."""
from __future__ import annotations

from dataclasses import dataclass
from textwrap import wrap
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .html_utils import build_panel_label, build_panel_table, escape_label

from .models import InstanceSummary, RouteDetail, RouteSummary, SubnetCell


@dataclass(frozen=True)
class PanelColors:
    """Color palette configuration for diagram detail panels."""

    header_bg: str
    header_color: str
    info_bg: str
    info_text: str
    meta_bg: str
    meta_text: str
    section_bg: str


PEERING_PANEL_COLORS = PanelColors(
    header_bg="#6b21a8",
    header_color="#ffffff",
    info_bg="#f3e8ff",
    info_text="#581c87",
    meta_bg="#e9d5ff",
    meta_text="#5b21b6",
    section_bg="#ddd6fe",
)


ROUTE_TABLE_PANEL_COLORS = PanelColors(
    header_bg="#1e3a8a",
    header_color="#ffffff",
    info_bg="#eff6ff",
    info_text="#1e3a8a",
    meta_bg="#dbeafe",
    meta_text="#1e3a8a",
    section_bg="#bfdbfe",
)


NAT_GATEWAY_PANEL_COLORS = PanelColors(
    header_bg="#f97316",
    header_color="#ffffff",
    info_bg="#fff7ed",
    info_text="#9a3412",
    meta_bg="#ffedd5",
    meta_text="#c2410c",
    section_bg="#fed7aa",
)


RDS_PANEL_COLORS = PanelColors(
    header_bg="#9b2c2c",
    header_color="#ffffff",
    info_bg="#fdebd0",
    info_text="#7b341e",
    meta_bg="#fdebd0",
    meta_text="#7b341e",
    section_bg="#fdebd0",
)


VPC_PANEL_COLORS = PanelColors(
    header_bg="#1d4ed8",
    header_color="#ffffff",
    info_bg="#eff6ff",
    info_text="#1e40af",
    meta_bg="#dbeafe",
    meta_text="#1e3a8a",
    section_bg="#bfdbfe",
)


INTERNET_GATEWAY_PANEL_COLORS = PanelColors(
    header_bg="#1f2937",
    header_color="#ffffff",
    info_bg="#f8fafc",
    info_text="#1a202c",
    meta_bg="#e2e8f0",
    meta_text="#1a202c",
    section_bg="#cbd5f5",
)


VIRTUAL_PRIVATE_GATEWAY_PANEL_COLORS = PanelColors(
    header_bg="#047857",
    header_color="#ffffff",
    info_bg="#ecfdf5",
    info_text="#064e3b",
    meta_bg="#d1fae5",
    meta_text="#065f46",
    section_bg="#bbf7d0",
)


PUBLIC_SUBNET_PANEL_COLORS = PanelColors(
    header_bg="#d9f99d",
    header_color="#365314",
    info_bg="#f7fee7",
    info_text="#3f6212",
    meta_bg="#ecfccb",
    meta_text="#3f6212",
    section_bg="#bef264",
)


PRIVATE_SUBNET_PANEL_COLORS = PanelColors(
    header_bg="#dcfce7",
    header_color="#14532d",
    info_bg="#f0fdf4",
    info_text="#166534",
    meta_bg="#d1fae5",
    meta_text="#166534",
    section_bg="#bbf7d0",
)


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
        "public": (
            PUBLIC_SUBNET_PANEL_COLORS.header_bg,
            PUBLIC_SUBNET_PANEL_COLORS.header_color,
        ),
        "private_app": (
            PRIVATE_SUBNET_PANEL_COLORS.header_bg,
            PRIVATE_SUBNET_PANEL_COLORS.header_color,
        ),
        "private_data": (
            PRIVATE_SUBNET_PANEL_COLORS.header_bg,
            PRIVATE_SUBNET_PANEL_COLORS.header_color,
        ),
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


def _collect_vpc_cidrs(vpc_info: dict) -> List[str]:
    """Return a list of IPv4/IPv6 CIDRs associated with a VPC attachment."""

    cidrs: List[str] = []
    seen: Set[str] = set()

    def _add_cidr(value: Optional[str]) -> None:
        if value and value not in seen:
            seen.add(value)
            cidrs.append(value)

    _add_cidr(vpc_info.get("CidrBlock"))

    for block in vpc_info.get("CidrBlockSet", []) or []:
        _add_cidr(block.get("CidrBlock"))

    for block in vpc_info.get("Ipv6CidrBlockSet", []) or []:
        _add_cidr(block.get("Ipv6CidrBlock"))

    return cidrs


def format_vpc_peering_connection_label(
    connection_id: str,
    connection: Optional[dict],
) -> str:
    """Return a richly formatted label for a VPC peering connection."""

    connection = connection or {}
    requester = connection.get("RequesterVpcInfo", {}) or {}
    accepter = connection.get("AccepterVpcInfo", {}) or {}

    palette = PEERING_PANEL_COLORS
    header_bg = palette.header_bg
    header_color = palette.header_color
    info_bg = palette.info_bg
    info_text = palette.info_text
    meta_bg = palette.meta_bg
    meta_text = palette.meta_text
    section_bg = palette.section_bg

    rows: List[str] = [
        (
            f'<TR><TD ALIGN="LEFT" BGCOLOR="{header_bg}">'
            f'<FONT COLOR="{header_color}"><B>VPC Peering</B></FONT></TD></TR>'
        )
    ]

    name = next(
        (
            tag.get("Value")
            for tag in connection.get("Tags", [])
            if tag.get("Key") == "Name" and tag.get("Value")
        ),
        None,
    )

    def append_plain(
        value: Optional[str],
        *,
        background: str = info_bg,
        text_color: str = info_text,
        bold: bool = False,
    ) -> None:
        if not value:
            return

        for line in wrap_label_text(value, width=32):
            content = escape_label(line)
            if bold:
                content = f"<B>{content}</B>"
            rows.append(
                f'<TR><TD ALIGN="LEFT" BGCOLOR="{background}">'  # Value row
                f'<FONT COLOR="{text_color}">{content}</FONT></TD></TR>'
            )

    def append_info(
        label: str,
        value: Optional[str],
        *,
        background: str = info_bg,
        text_color: str = info_text,
    ) -> None:
        if not value:
            return

        label_added = False
        for line in wrap_label_text(value, width=32):
            prefix = ""
            if label and not label_added:
                prefix = f"<B>{escape_label(label)}:</B> "
                label_added = True
            rows.append(
                f'<TR><TD ALIGN="LEFT" BGCOLOR="{background}">'
                f'<FONT COLOR="{text_color}">{prefix}{escape_label(line)}</FONT></TD></TR>'
            )

    if name:
        append_plain(name, bold=True)

    append_info("Peering Connection ID", connection_id, background=meta_bg, text_color=meta_text)

    status = connection.get("Status", {}) or {}
    status_text = status.get("Message") or status.get("Code")
    append_info("Status", status_text)

    def append_vpc_section(title: str, info: dict) -> None:
        append_plain(title, background=section_bg, text_color=info_text, bold=True)
        append_info("VPC ID", info.get("VpcId") or "Unknown VPC")
        append_info("Account", info.get("OwnerId"))
        append_info("Region", info.get("Region"))
        cidrs = _collect_vpc_cidrs(info)
        if cidrs:
            append_info("CIDRs", ", ".join(cidrs))

    append_vpc_section("Requester", requester)
    append_vpc_section("Accepter", accepter)

    return build_panel_label(rows, border_color=header_bg)


def format_virtual_private_gateway_label(
    gateway_id: str,
    connections: Optional[List[dict]],
    customer_gateways: Dict[str, dict],
) -> str:
    """Return a richly formatted label for a virtual private gateway."""

    colors = VIRTUAL_PRIVATE_GATEWAY_PANEL_COLORS
    header_bg = colors.header_bg
    header_color = colors.header_color
    info_bg = colors.info_bg
    info_text = colors.info_text
    meta_bg = colors.meta_bg
    meta_text = colors.meta_text
    connection_bg = "#dcfce7"
    section_bg = colors.section_bg
    section_text = info_text

    rows: List[str] = [
        (
            f'<TR><TD ALIGN="LEFT" BGCOLOR="{header_bg}">'
            f'<FONT COLOR="{header_color}"><B>Virtual Private Gateway</B></FONT></TD></TR>'
        )
    ]

    def append_plain(
        value: Optional[str],
        *,
        background: str = info_bg,
        text_color: str = info_text,
        italic: bool = False,
        bold: bool = False,
    ) -> None:
        if value is None:
            return

        for line in wrap_label_text(value, width=32):
            content = escape_label(line)
            if bold:
                content = f"<B>{content}</B>"
            if italic:
                content = f"<I>{content}</I>"
            rows.append(
                f'<TR><TD ALIGN="LEFT" BGCOLOR="{background}">'
                f'<FONT COLOR="{text_color}">{content}</FONT></TD></TR>'
            )

    def append_info(
        label: str,
        value: Optional[str],
        *,
        background: str = info_bg,
        text_color: str = info_text,
    ) -> None:
        if value is None:
            return

        label_added = False
        for line in wrap_label_text(value, width=32):
            prefix = ""
            if label and not label_added:
                prefix = f"<B>{escape_label(label)}:</B> "
                label_added = True
            rows.append(
                f'<TR><TD ALIGN="LEFT" BGCOLOR="{background}">'
                f'<FONT COLOR="{text_color}">{prefix}{escape_label(line)}</FONT></TD></TR>'
            )

    append_info("Gateway ID", gateway_id, background=meta_bg, text_color=meta_text)

    connection_list = sorted(connections or [], key=lambda item: item.get("VpnConnectionId", ""))

    append_plain(
        f"Connections: {len(connection_list)}",
        background=info_bg,
        text_color=info_text,
        bold=True,
    )

    append_plain(
        "Site-to-Site VPN connections",
        background=section_bg,
        text_color=section_text,
        bold=True,
    )

    if not connection_list:
        append_plain(
            "No Site-to-Site VPN connections found",
            background=connection_bg,
            text_color=info_text,
            italic=True,
        )
    else:
        for index, connection in enumerate(connection_list):
            vpn_id = connection.get("VpnConnectionId", "unknown")
            vpn_name = next(
                (
                    tag.get("Value")
                    for tag in connection.get("Tags", [])
                    if tag.get("Key") == "Name" and tag.get("Value")
                ),
                None,
            )
            connection_type = connection.get("Type")
            state = connection.get("State") or connection.get("Status", {}).get("Message")
            customer_gateway_id = connection.get("CustomerGatewayId") or ""
            customer_gateway = customer_gateways.get(customer_gateway_id, {})
            customer_address = (
                customer_gateway.get("IpAddress")
                or customer_gateway_id
                or "unknown"
            )

            telemetry_ips = sorted(
                {
                    telemetry.get("OutsideIpAddress")
                    for telemetry in connection.get("VgwTelemetry", []) or []
                    if telemetry.get("OutsideIpAddress")
                }
            )

            title = vpn_name or vpn_id
            append_plain(
                title,
                background=connection_bg,
                text_color=info_text,
                bold=True,
            )
            append_info(
                "VPN ID",
                vpn_id,
                background=meta_bg,
                text_color=meta_text,
            )
            append_info(
                "Type",
                connection_type,
                background=connection_bg,
                text_color=info_text,
            )
            append_info(
                "Status",
                state,
                background=connection_bg,
                text_color=info_text,
            )
            append_info(
                "Customer gateway",
                customer_address,
                background=connection_bg,
                text_color=info_text,
            )
            if customer_gateway_id and customer_gateway_id != customer_address:
                append_info(
                    "Customer gateway ID",
                    customer_gateway_id,
                    background=connection_bg,
                    text_color=info_text,
                )
            if telemetry_ips:
                append_info(
                    "Outside IPs",
                    ", ".join(telemetry_ips),
                    background=connection_bg,
                    text_color=info_text,
                )

            if index != len(connection_list) - 1:
                append_plain(
                    "",
                    background="#ffffff",
                    text_color=info_text,
                )

    return build_panel_label(rows, border_color=header_bg)


def format_subnet_cell_label(cell: SubnetCell) -> str:
    """Return the HTML label used for subnet cells."""

    def build_subnet_panel(cell: SubnetCell) -> str:
        """Return a styled HTML table describing subnet attributes."""

        if cell.classification == "public":
            palette = PUBLIC_SUBNET_PANEL_COLORS
            header_bg = palette.header_bg
            header_color = palette.header_color
            border_color = palette.header_bg
            info_bg = palette.info_bg
            info_text = palette.info_text
            meta_bg = palette.meta_bg
            meta_text = palette.meta_text
        elif cell.classification in {"private_app", "private_data"} and not cell.is_isolated:
            palette = PRIVATE_SUBNET_PANEL_COLORS
            header_bg = palette.header_bg
            header_color = palette.header_color
            border_color = palette.header_bg
            info_bg = palette.info_bg
            info_text = palette.info_text
            meta_bg = palette.meta_bg
            meta_text = palette.meta_text
        else:
            header_bg = cell.color
            header_color = cell.font_color
            border_color = cell.color
            info_bg = "#f8fafc"
            info_text = "#1a202c"
            meta_bg = "#edf2f7"
            meta_text = "#1a202c"

        rows = [
            (
                f'<TR><TD ALIGN="LEFT" BGCOLOR="{header_bg}">'  # Header row
                f'<FONT COLOR="{header_color}"><B>Subnet</B></FONT></TD></TR>'
            )
        ]

        if cell.name:
            for line in wrap_label_text(cell.name, width=32):
                rows.append(
                    f'<TR><TD ALIGN="LEFT" BGCOLOR="{info_bg}">'  # Subnet name rows
                    f'<FONT COLOR="{info_text}"><B>{escape_label(line)}</B></FONT></TD></TR>'
                )

        subnet_id_lines = wrap_label_text(cell.subnet_id, width=32)
        for line in subnet_id_lines:
            rows.append(
                f'<TR><TD ALIGN="LEFT" BGCOLOR="{meta_bg}">'  # Subnet ID rows
                f'<FONT POINT-SIZE="11" COLOR="{meta_text}">{escape_label(line)}</FONT></TD></TR>'
            )

        def append_info(label: str, value: Optional[str]) -> None:
            if not value:
                return

            value_lines = wrap_label_text(value, width=32)
            for index, line in enumerate(value_lines):
                prefix = f'<B>{escape_label(label)}:</B> ' if index == 0 else ""
                rows.append(
                    f'<TR><TD ALIGN="LEFT" BGCOLOR="{info_bg}">'  # Attribute rows
                    f'<FONT COLOR="{info_text}">{prefix}{escape_label(line)}</FONT></TD></TR>'
                )

        append_info("CIDR", cell.cidr)
        append_info("Availability Zone", cell.az)

        return build_panel_table(rows, border_color=border_color)

    def build_route_table_panel(summary: Optional[RouteSummary]) -> str:
        """Return a styled HTML table describing the subnet's route table."""

        palette = ROUTE_TABLE_PANEL_COLORS
        header_bg = palette.header_bg
        header_color = palette.header_color
        info_bg = palette.info_bg
        info_text = palette.info_text
        meta_bg = palette.meta_bg
        meta_text = palette.meta_text
        routes_bg = palette.section_bg

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
            return build_panel_table(rows, border_color=header_bg)

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
                f'<TR><TD ALIGN="LEFT" BGCOLOR="{meta_bg}">' 
                f'<FONT COLOR="{meta_text}">{escape_label(line)}</FONT></TD></TR>'
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

        return build_panel_table(rows, border_color=header_bg)

    subnet_html = build_subnet_panel(cell)
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

    rows = [
        f'<TR><TD ALIGN="LEFT" BGCOLOR="#ffffff">{subnet_html}</TD></TR>',
        f'<TR><TD PORT="routes" BGCOLOR="#ffffff" ALIGN="LEFT">{route_html}</TD></TR>',
    ]

    if instance_row:
        rows.append(instance_row)

    return (
        '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">'
        + "".join(rows)
        + '</TABLE>>'
    )


__all__ = [
    "build_route_table_indexes",
    "build_subnet_cell",
    "classify_subnet",
    "format_subnet_cell_label",
    "format_vpc_peering_connection_label",
    "format_virtual_private_gateway_label",
    "group_subnets_by_vpc",
    "identify_route_target",
    "summarize_route_table",
    "PanelColors",
    "PEERING_PANEL_COLORS",
    "ROUTE_TABLE_PANEL_COLORS",
    "NAT_GATEWAY_PANEL_COLORS",
    "RDS_PANEL_COLORS",
    "INTERNET_GATEWAY_PANEL_COLORS",
    "VPC_PANEL_COLORS",
    "PUBLIC_SUBNET_PANEL_COLORS",
    "PRIVATE_SUBNET_PANEL_COLORS",
    "wrap_label_text",
]
