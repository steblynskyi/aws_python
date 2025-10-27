"""Helpers for preparing HTML-like Graphviz labels."""

from __future__ import annotations

from html import escape as html_escape


def escape_label(value: str) -> str:
    """Return ``value`` escaped for use inside Graphviz HTML labels.

    Graphviz is fairly strict about the characters it accepts within HTML-like
    labels.  In particular, hex character references such as ``&#x27;`` are not
    universally supported across the versions that users may have installed.
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


__all__ = ["escape_label"]

