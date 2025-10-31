"""Helpers for preparing HTML-like Graphviz labels."""

from __future__ import annotations

from html import escape as html_escape
from typing import Callable, Iterable, List, Optional, Union


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
        '<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="10" '
        f'COLOR="{border_color}">' + "".join(rows) + "</TABLE>"
    )


def build_panel_label(rows: Iterable[str], *, border_color: str) -> str:
    """Return a bordered panel label without an icon column."""

    panel = build_panel_table(rows, border_color=border_color)
    return f"<{panel}>"


def build_panel_text_rows(
    value: Optional[Union[str, Iterable[str]]],
    *,
    background: str,
    text_color: str,
    bold: bool = False,
    label: Optional[str] = None,
    wrap_lines: Optional[Callable[[str], Iterable[str]]] = None,
    align: str = "LEFT",
) -> List[str]:
    """Return table row strings formatted for panel-style labels.

    ``value`` can be a single string or an iterable of pre-split strings.  The
    content is first normalised into a list of ``lines`` via the optional
    ``wrap_lines`` callable before being escaped and wrapped in ``<TR>``
    elements.  The first line can be emphasised via ``bold`` or by supplying a
    ``label`` that will be rendered in bold followed by the associated value.
    Subsequent lines omit the label to match the styling of NAT gateway panels.
    """

    if value is None:
        return []

    wrapper: Callable[[str], Iterable[str]] = wrap_lines or (lambda text: [text])

    line_values: List[str] = []

    def _append_lines(text: str) -> None:
        if not text:
            return
        for raw_line in wrapper(text):
            if raw_line:
                line_values.append(raw_line)

    if isinstance(value, str):
        if not value:
            return []
        _append_lines(value)
    else:
        try:
            iterator = iter(value)
        except TypeError:
            return []
        added = False
        for item in iterator:
            if not item:
                continue
            added = True
            _append_lines(str(item))
        if not added and not line_values:
            return []

    if not line_values:
        return []

    rows: List[str] = []
    label_rendered = False

    for raw_line in line_values:
        content = escape_label(raw_line)
        prefix = ""
        if label and not label_rendered:
            prefix = f"<B>{escape_label(label)}:</B> "
            label_rendered = True
        if bold:
            content = f"<B>{content}</B>"
        rows.append(
            f'<TR><TD ALIGN="{align}" BGCOLOR="{background}">'  # Panel row
            f'<FONT COLOR="{text_color}">{prefix}{content}</FONT></TD></TR>'
        )

    return rows


def build_icon_panel_label(
    icon_text: str,
    panel_rows: Iterable[str],
    *,
    border_color: str,
    icon_bgcolor: str = "#1f2937",
    icon_color: str = "#ffffff",
    body_bgcolor: str = "#ffffff",
    align: str = "LEFT",
    icon_align: str = "CENTER",
) -> str:
    """Return a bordered panel label for panel style content.

    The function signature is retained for backwards compatibility even
    though icon-specific arguments are now ignored.  This allows callers to
    continue passing styling values while rendering a single column layout.
    """

    _ = icon_text, icon_bgcolor, icon_color, icon_align

    panel = build_panel_table(panel_rows, border_color=border_color)

    return (
        '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" '
        f'COLOR="{border_color}"><TR>'
        f'<TD ALIGN="{align}" VALIGN="TOP" BGCOLOR="{body_bgcolor}">{panel}</TD>'
        "</TR></TABLE>>"
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
    """Return an HTML label containing the supplied ``lines``.

    The ``icon_*`` arguments are ignored but preserved in the signature so that
    callers do not need to change.  Labels now render without an icon column,
    showing only the textual content.
    """

    _ = icon_text, icon_bgcolor, icon_color

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

    label = (
        '<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" '
        f'COLOR="{border_color}"><TR>'
        f'<TD BGCOLOR="{body_bgcolor}" ALIGN="{align}" VALIGN="TOP">{body_table}</TD>'
        "</TR></TABLE>>"
    )
    return label


__all__ = [
    "escape_label",
    "format_vertical_label",
    "build_icon_cell",
    "build_panel_table",
    "build_panel_label",
    "build_panel_text_rows",
    "build_icon_panel_label",
    "build_icon_label",
]

