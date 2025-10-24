"""Module entry-point for ``python -m aws_security_audit``."""
from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
