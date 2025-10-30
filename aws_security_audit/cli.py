"""Command line interface for the AWS security audit tool."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import List, Optional

import boto3

from .compliance import COMPLIANCE_SERVICE_MAP, expand_compliance_frameworks
from .core import (
    collect_audit_results,
    export_findings_to_excel,
    export_inventory_to_excel,
    print_findings,
)
from .diagram import generate_network_diagram


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Return parsed command line arguments."""

    parser = argparse.ArgumentParser(description="Audit AWS resources for common security issues.")
    parser.add_argument("--profile", help="AWS CLI profile to use", default=None)
    parser.add_argument("--region", help="AWS region for regional checks", default=None)
    parser.add_argument(
        "--services",
        nargs="*",
        default=None,
        help="Subset of services to audit (required unless --compliance is provided)",
    )
    parser.add_argument(
        "--compliance",
        nargs="*",
        choices=sorted(COMPLIANCE_SERVICE_MAP),
        default=None,
        help="Limit checks to service sets aligned with compliance frameworks (e.g., hipaa)",
    )
    parser.add_argument("--json", dest="json_path", help="Optional path to export findings as JSON")
    parser.add_argument(
        "--excel",
        dest="excel_path",
        help="Optional path to export findings as an Excel workbook (.xlsx)",
    )
    parser.add_argument(
        "--inventory-excel",
        dest="inventory_excel_path",
        help="Optional path to export the full inventory as an Excel workbook (.xlsx)",
    )
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

    selected_services = list(args.services) if args.services else []
    if args.compliance:
        try:
            compliance_services = expand_compliance_frameworks(args.compliance)
        except (RuntimeError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        if args.services:
            filtered_services = []
            excluded_services = []
            for service in args.services:
                key = service.lower()
                if key in compliance_services:
                    filtered_services.append(service)
                else:
                    excluded_services.append(service)

            if excluded_services:
                print(
                    "Warning: Ignoring services not covered by the selected compliance "
                    f"frameworks: {', '.join(sorted(set(excluded_services)))}",
                    file=sys.stderr,
                )

            if not filtered_services:
                print(
                    "Error: None of the requested services are part of the selected compliance frameworks.",
                    file=sys.stderr,
                )
                return 1

            selected_services = filtered_services
        else:
            selected_services = sorted(compliance_services)

    if not selected_services:
        print(
            "Error: No services selected. Specify services with --services or choose a "
            "compliance framework with --compliance.",
            file=sys.stderr,
        )
        return 1

    try:
        results = collect_audit_results(session, selected_services)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    findings = results.findings
    print_findings(findings)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump([asdict(f) for f in findings], fh, indent=2, default=str)
        print(f"Findings exported to {args.json_path}")

    if args.excel_path:
        try:
            path = export_findings_to_excel(findings, args.excel_path)
        except RuntimeError as exc:
            print(f"Failed to export Excel report: {exc}", file=sys.stderr)
        else:
            print(f"Excel report written to {path}")

    if args.inventory_excel_path:
        try:
            path = export_inventory_to_excel(results.inventory, args.inventory_excel_path)
        except RuntimeError as exc:
            print(f"Failed to export inventory Excel report: {exc}", file=sys.stderr)
        else:
            print(f"Inventory Excel report written to {path}")

    if args.diagram_path:
        try:
            path = generate_network_diagram(
                session, args.diagram_path, services=selected_services
            )
            if path:
                print(f"Network diagram written to {path}")
            else:
                print("graphviz is not installed; diagram was not generated.")
        except RuntimeError as exc:
            print(f"Failed to generate network diagram: {exc}", file=sys.stderr)

    return 0


__all__ = ["main", "parse_args"]
