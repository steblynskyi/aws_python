"""Helpers for gathering EC2 data for network diagrams."""
from __future__ import annotations

from typing import Dict, List

from .models import InstanceSummary


def group_instances_by_subnet(reservations: List[dict]) -> Dict[str, List[InstanceSummary]]:
    """Return EC2 instances grouped by subnet identifier."""

    instances_by_subnet: Dict[str, List[InstanceSummary]] = {}
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            state = (instance.get("State") or {}).get("Name")
            if state == "terminated":
                continue
            subnet_id = instance.get("SubnetId")
            if not subnet_id:
                continue
            name = next(
                (
                    tag.get("Value")
                    for tag in instance.get("Tags", [])
                    if tag.get("Key") == "Name" and tag.get("Value")
                ),
                None,
            )
            summary = InstanceSummary(
                instance_id=instance.get("InstanceId", ""),
                name=name,
                state=state,
                private_ip=instance.get("PrivateIpAddress"),
            )
            instances_by_subnet.setdefault(subnet_id, []).append(summary)

    for summaries in instances_by_subnet.values():
        summaries.sort(key=lambda inst: ((inst.name or inst.instance_id) or ""))

    return instances_by_subnet


__all__ = ["group_instances_by_subnet"]
