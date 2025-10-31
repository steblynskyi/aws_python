"""Tests for HTML helper utilities."""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from aws_security_audit.diagram.html_utils import build_panel_text_rows


def test_build_panel_text_rows_collapses_whitespace() -> None:
    """Panel rows collapse redundant whitespace for clearer text."""

    rows = build_panel_text_rows(
        "  Example\t   text  ", background="#ffffff", text_color="#000000"
    )

    assert rows
    assert "Example text" in rows[0]


def test_build_panel_text_rows_normalises_unicode_and_newlines() -> None:
    """Panel rows normalise unicode spacing and newline styles."""

    rows = build_panel_text_rows(
        "Primary\u00a0Value\r\nSecondary\u2003Value",
        background="#ffffff",
        text_color="#000000",
        wrap_lines=lambda text: text.split("\n"),
    )

    assert len(rows) == 2
    assert "Primary Value" in rows[0]
    assert "Secondary Value" in rows[1]
