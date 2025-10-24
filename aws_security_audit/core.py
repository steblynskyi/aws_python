"""Core orchestration utilities for the AWS security audit."""
from __future__ import annotations

from typing import Iterable, List

import boto3

from .findings import Finding
from .services import SERVICE_CHECKS


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "ERROR": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "WARNING": 5,
    "INFO": 6,
}


def _finding_sort_key(finding: Finding) -> tuple[int, str, str, str]:
    """Return a tuple used to order findings consistently."""

    severity_rank = SEVERITY_ORDER.get(finding.severity.upper(), len(SEVERITY_ORDER))
    return (severity_rank, finding.service, finding.resource_id, finding.message)


def collect_findings(session: boto3.session.Session, services: Iterable[str]) -> List[Finding]:
    """Run all requested service checks and return de-duplicated findings."""

    findings: dict[str, Finding] = {}
    normalized_services: List[str] = []
    for service in services:
        key = service.lower()
        if key not in SERVICE_CHECKS:
            valid = ", ".join(sorted(SERVICE_CHECKS))
            raise ValueError(f"Unknown service '{service}'. Valid services: {valid}")
        normalized_services.append(key)

    for service in dict.fromkeys(normalized_services):
        checker = SERVICE_CHECKS[service]
        for finding in checker(session):
            findings[finding.key()] = finding

    return sorted(findings.values(), key=_finding_sort_key)


def print_findings(findings: Iterable[Finding]) -> None:
    """Pretty-print findings to stdout."""

    findings = list(findings)
    if not findings:
        print("No findings detected.")
        return

    header = f"{'Service':<10} {'Severity':<8} {'Resource':<40} Message"
    print(header)
    print("-" * len(header))
    for finding in findings:
        resource = (finding.resource_id[:37] + "...") if len(finding.resource_id) > 40 else finding.resource_id
        print(f"{finding.service:<10} {finding.severity:<8} {resource:<40} {finding.message}")


__all__ = ["collect_findings", "print_findings"]
