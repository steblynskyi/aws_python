"""Compliance framework presets for the AWS security audit toolkit."""

from __future__ import annotations

from typing import Dict, Iterable, Set, Tuple

from .services import SERVICE_CHECKS

# Mapping of compliance framework identifiers to the service checks that
# contribute evidence for that framework. Keys are normalized to lowercase so
# callers can perform case-insensitive lookups.
COMPLIANCE_SERVICE_MAP: Dict[str, Tuple[str, ...]] = {
    "hipaa": (
        "vpc",
        "ec2",
        "s3",
        "iam",
        "rds",
        "kms",
        "acm",
        "ssm",
        "eks",
        "ecs",
    ),
}


def expand_compliance_frameworks(frameworks: Iterable[str]) -> Set[str]:
    """Return the normalized set of services for *frameworks*.

    Raises a :class:`ValueError` when an unknown framework is requested and a
    :class:`RuntimeError` if the static mapping references a service that is not
    registered in :data:`aws_security_audit.services.SERVICE_CHECKS`.
    """

    normalized = {framework.lower() for framework in frameworks}
    valid_frameworks = set(COMPLIANCE_SERVICE_MAP)
    missing = sorted(normalized - valid_frameworks)
    if missing:
        valid = ", ".join(sorted(valid_frameworks))
        raise ValueError(
            f"Unknown compliance framework(s): {', '.join(missing)}. Valid options: {valid}"
        )

    services: Set[str] = set()
    for framework in normalized:
        services.update(COMPLIANCE_SERVICE_MAP[framework])

    unknown_services = sorted(services - set(SERVICE_CHECKS))
    if unknown_services:
        raise RuntimeError(
            "Compliance service map references unknown service(s): "
            + ", ".join(unknown_services)
        )

    return services


__all__ = ["COMPLIANCE_SERVICE_MAP", "expand_compliance_frameworks"]
