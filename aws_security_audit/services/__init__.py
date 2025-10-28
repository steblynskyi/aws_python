"""Service-specific audit entry points."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List

import boto3

from ..findings import Finding, InventoryItem
from .acm import audit_acm_certificates
from .ec2 import audit_ec2_instances
from .ecs import audit_ecs_clusters
from .eks import audit_eks_clusters
from .iam import audit_iam_users
from .kms import audit_kms_keys
from .rds import audit_rds_instances
from .route53 import audit_route53_zones
from .s3 import audit_s3_buckets
from .ssm import audit_ssm_managed_instances
from .vpc import audit_vpcs

@dataclass
class ServiceReport:
    """Aggregated findings and inventory emitted by a service audit."""

    findings: List[Finding]
    inventory: List[InventoryItem]


ServiceChecker = Callable[[boto3.session.Session], ServiceReport]

SERVICE_CHECKS: Dict[str, ServiceChecker] = {
    "vpc": audit_vpcs,
    "ec2": audit_ec2_instances,
    "s3": audit_s3_buckets,
    "iam": audit_iam_users,
    "rds": audit_rds_instances,
    "kms": audit_kms_keys,
    "route53": audit_route53_zones,
    "acm": audit_acm_certificates,
    "ssm": audit_ssm_managed_instances,
    "eks": audit_eks_clusters,
    "ecs": audit_ecs_clusters,
}

__all__ = ["SERVICE_CHECKS", "ServiceChecker", "ServiceReport"]
