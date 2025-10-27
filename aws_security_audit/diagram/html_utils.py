"""Helpers for preparing HTML-like Graphviz labels."""

from __future__ import annotations

from html import escape as html_escape
from typing import Iterable


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


__all__ = ["escape_label", "format_vertical_label"]

