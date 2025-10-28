"""Helpers for preparing HTML-like Graphviz labels."""

from __future__ import annotations

from html import escape as html_escape
from typing import Iterable, List


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

    icon_cell_attributes = [
        f'BGCOLOR="{icon_bgcolor}"',
        'ALIGN="CENTER"',
        'VALIGN="MIDDLE"',
        'WIDTH="32"',
        'HEIGHT="32"',
    ]
    # Allow Graphviz to expand the icon cell when the text would otherwise
    # overflow the fixed 32px square.  This avoids ``cell size too small``
    # warnings while keeping the minimum size consistent for short labels.
    icon_cell_attribute_str = " ".join(icon_cell_attributes)
    icon_cell = (
        f'<TD {icon_cell_attribute_str}><FONT COLOR="{icon_color}"><B>'
        f"{escape_label(icon_text)}</B></FONT></TD>"
    )

    label = (
        '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" '
        f'COLOR="{border_color}"><TR>'
        f"{icon_cell}"
        f'<TD BGCOLOR="{body_bgcolor}" ALIGN="{align}">{body_table}</TD>'
        "</TR></TABLE>>"
    )
    return label


__all__ = ["escape_label", "format_vertical_label", "build_icon_label"]

