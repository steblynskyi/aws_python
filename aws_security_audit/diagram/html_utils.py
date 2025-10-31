"""Helpers for preparing HTML-like Graphviz labels."""

from __future__ import annotations

from html import escape as html_escape
from typing import Iterable, List, Optional


def escape_label(value: str) -> str:
    """Return ``value`` escaped for use inside Graphviz HTML labels.

    Graphviz is fairly strict about the characters it accepts within HTML-like
    labels (see https://graphviz.org/doc/info/shapes.html#html).  In particular,
    hex character references such as ``&#x27;`` are not universally supported across
    the versions that users may have installed.
    Additionally, certain non-ASCII characters (for example the Unicode arrow
    used in route descriptions) can trigger syntax errors when ``dot`` parses
    the generated diagram source.

    To maximise compatibility we combine the standard HTML escaping from
    :func:`html.escape` with ``xmlcharrefreplace`` so that every non-ASCII
    character is converted into a decimal entity (e.g. ``&#8594;``).  We also
    normalise the single quote escape sequence to ``&#39;`` because older
    Graphviz releases only understand the decimal form.  The end result is a
    string that is safe to embed directly inside Graphviz HTML labels while
    remaining readable in the rendered diagram.
    """

    escaped = html_escape(value, quote=True).replace("&#x27;", "&#39;")
    return escaped.encode("ascii", "xmlcharrefreplace").decode("ascii")


def format_vertical_label(lines: Iterable[str], *, bold_first: bool = False, align: str = "CENTER") -> str:
    """Return an HTML-like table label with one line per table row.

    Graphviz's HTML labels expect a single root element, and emitting a table is
    the most broadly compatible option across Graphviz versions.  This helper
    wraps each ``line`` in its own ``<TR><TD>`` and optionally renders the first
    entry in bold.  All text is escaped via :func:`escape_label` to avoid
    ``dot`` syntax errors.
    """

    rows = []
    for index, raw_line in enumerate(lines):
        content = escape_label(raw_line)
        if bold_first and index == 0:
            content = f"<B>{content}</B>"
        rows.append(f'<TR><TD ALIGN="{align}">{content}</TD></TR>')
    body = "".join(rows) or '<TR><TD ALIGN="CENTER"></TD></TR>'
    return f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0">{body}</TABLE>>'


def build_icon_cell(
    icon_text: str,
    *,
    icon_bgcolor: str = "#1f2937",
    icon_color: str = "#ffffff",
    align: str = "CENTER",
    valign: str = "TOP",
    rowspan: Optional[int] = None,
) -> str:
    """Return a formatted ``<TD>`` element for icon-style columns.

    The route table panels define the visual baseline for icon columns within
    the network diagram.  Reusing this helper ensures that every icon-based
    label shares consistent alignment, colouring, and minimum sizing.
    """

    icon_cell_attributes = []
    if rowspan and rowspan > 1:
        icon_cell_attributes.append(f'ROWSPAN="{rowspan}"')
    # Maintain a consistent minimum size while still allowing Graphviz to
    # expand the icon column when the label content requires additional space.
    icon_cell_attributes.extend(
        [
            f'BGCOLOR="{icon_bgcolor}"',
            f'ALIGN="{align}"',
            f'VALIGN="{valign}"',
            'WIDTH="32"',
            'HEIGHT="32"',
        ]
    )
    attribute_str = " ".join(icon_cell_attributes)
    return (
        f'<TD {attribute_str}><FONT COLOR="{icon_color}"><B>'
        f"{escape_label(icon_text)}</B></FONT></TD>"
    )


def build_panel_table(rows: Iterable[str], *, border_color: str) -> str:
    """Return a HTML table wrapper for detail panels."""

    return (
        '<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4" '
        f'COLOR="{border_color}">' + "".join(rows) + "</TABLE>"
    )


def build_icon_label(
    title: str,
    lines: Iterable[str],
    *,
    icon_text: str,
    icon_bgcolor: str = "#1f2937",
    icon_color: str = "#ffffff",
    body_bgcolor: str = "#ffffff",
    body_color: str = "#1a202c",
    border_color: str = "#1a202c",
    align: str = "LEFT",
) -> str:
    """Return an HTML label featuring an icon-style column beside text content."""

    safe_title = escape_label(title)
    safe_lines: List[str] = [escape_label(line) for line in lines]

    body_rows = [
        f'<TR><TD ALIGN="{align}"><FONT COLOR="{body_color}"><B>{safe_title}</B></FONT></TD></TR>'
    ]
    for line in safe_lines:
        body_rows.append(
            f'<TR><TD ALIGN="{align}"><FONT COLOR="{body_color}">{line}</FONT></TD></TR>'
        )
    body_table = (
        '<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0">' + "".join(body_rows) + "</TABLE>"
    )

    icon_cell = build_icon_cell(
        icon_text,
        icon_bgcolor=icon_bgcolor,
        icon_color=icon_color,
    )

    label = (
        '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" '
        f'COLOR="{border_color}"><TR>'
        f"{icon_cell}"
        f'<TD BGCOLOR="{body_bgcolor}" ALIGN="{align}" VALIGN="TOP">{body_table}</TD>'
        "</TR></TABLE>>"
    )
    return label


__all__ = [
    "escape_label",
    "format_vertical_label",
    "build_icon_cell",
    "build_panel_table",
    "build_icon_label",
]

