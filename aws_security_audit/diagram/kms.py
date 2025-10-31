"""Helpers for summarising AWS KMS resources in the network diagram."""
from __future__ import annotations

from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..utils import safe_paginate
from .models import GlobalServiceSummary, summarize_global_service_lines
from .registry import register_global_service


@register_global_service("kms")
def build_kms_summary(
    session: boto3.session.Session, max_items: int
) -> Optional[GlobalServiceSummary]:
    """Collect AWS KMS details for the global services panel."""

    try:
        kms = session.client("kms")
    except (ClientError, EndpointConnectionError):
        return None

    key_alias_map: Dict[str, str] = {}
    try:
        for alias in safe_paginate(kms, "list_aliases", "Aliases"):
            target_key = alias.get("TargetKeyId")
            alias_name = alias.get("AliasName")
            if target_key and alias_name:
                key_alias_map[target_key] = alias_name
    except (ClientError, EndpointConnectionError):
        key_alias_map = {}

    kms_keys: List[str] = []
    try:
        for key in safe_paginate(kms, "list_keys", "Keys"):
            key_id = key.get("KeyId")
            if not key_id:
                continue
            alias_name = key_alias_map.get(key_id)
            if alias_name:
                kms_keys.append(f"{alias_name} ({key_id})")
            else:
                kms_keys.append(key_id)
    except (ClientError, EndpointConnectionError):
        kms_keys = []

    if not kms_keys:
        return None

    kms_keys.sort()
    return GlobalServiceSummary(
        title="AWS KMS",
        lines=summarize_global_service_lines(kms_keys, max_items),
        fillcolor="#faf5ff",
        fontcolor="#553c9a",
    )


__all__ = ["build_kms_summary"]

