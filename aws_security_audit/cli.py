"""Command line interface for the AWS security audit tool."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import List, Optional

import boto3

from .core import collect_findings, print_findings
from .diagram import generate_network_diagram
from .services import SERVICE_CHECKS


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Return parsed command line arguments."""

    parser = argparse.ArgumentParser(description="Audit AWS resources for common security issues.")
    parser.add_argument("--profile", help="AWS CLI profile to use", default=None)
    parser.add_argument("--region", help="AWS region for regional checks", default=None)
    parser.add_argument(
        "--services",
        nargs="*",
        default=None,
        help="Subset of services to audit (default: all)",
    )
    parser.add_argument("--json", dest="json_path", help="Optional path to export findings as JSON")
    parser.add_argument(
        "--diagram",
        dest="diagram_path",
        help="Generate a Graphviz network diagram at the given path (requires graphviz)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point used by ``python -m aws_security_audit``."""

    args = parse_args(argv)
    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    selected_services = args.services if args.services else list(SERVICE_CHECKS)

    try:
        findings = collect_findings(session, selected_services)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print_findings(findings)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump([asdict(f) for f in findings], fh, indent=2, default=str)
        print(f"Findings exported to {args.json_path}")

    if args.diagram_path:
        try:
            path = generate_network_diagram(session, args.diagram_path)
            if path:
                print(f"Network diagram written to {path}")
            else:
                print("graphviz is not installed; diagram was not generated.")
        except RuntimeError as exc:
            print(f"Failed to generate network diagram: {exc}", file=sys.stderr)

    return 0


__all__ = ["main", "parse_args"]
