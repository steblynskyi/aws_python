"""RDS helpers for network diagram generation."""
from __future__ import annotations

from typing import Dict, Iterable, List


def group_rds_instances_by_vpc(db_instances: Iterable[dict]) -> Dict[str, List[dict]]:
    """Return RDS DB instances keyed by their associated VPC."""

    rds_instances_by_vpc: Dict[str, List[dict]] = {}
    for db_instance in db_instances:
        subnet_group = db_instance.get("DBSubnetGroup") or {}
        vpc_id = subnet_group.get("VpcId")
        if not vpc_id:
            continue
        rds_instances_by_vpc.setdefault(vpc_id, []).append(db_instance)
    return rds_instances_by_vpc


__all__ = ["group_rds_instances_by_vpc"]
