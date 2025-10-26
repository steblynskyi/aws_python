"""Helpers for summarising IAM resources for the network diagram."""
from __future__ import annotations

from typing import List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from ..utils import safe_paginate
from .models import GlobalServiceSummary, summarize_global_service_lines


def build_iam_summary(
    session: boto3.session.Session, max_items: int
) -> Optional[GlobalServiceSummary]:
    """Collect IAM resource counts for the global services panel."""

    try:
        iam = session.client("iam")
    except (ClientError, EndpointConnectionError):
        return None

    iam_lines: List[str] = []

    try:
        role_count = sum(1 for _ in safe_paginate(iam, "list_roles", "Roles"))
        if role_count:
            iam_lines.append(f"Roles: {role_count}")
    except (ClientError, EndpointConnectionError):
        pass

    try:
        user_count = sum(1 for _ in safe_paginate(iam, "list_users", "Users"))
        if user_count:
            iam_lines.append(f"Users: {user_count}")
    except (ClientError, EndpointConnectionError):
        pass

    try:
        group_count = sum(1 for _ in safe_paginate(iam, "list_groups", "Groups"))
        if group_count:
            iam_lines.append(f"Groups: {group_count}")
    except (ClientError, EndpointConnectionError):
        pass

    try:
        policy_count = sum(
            1 for _ in safe_paginate(iam, "list_policies", "Policies", Scope="Local")
        )
        if policy_count:
            iam_lines.append(f"Customer Policies: {policy_count}")
    except (ClientError, EndpointConnectionError):
        pass

    if not iam_lines:
        return None

    return GlobalServiceSummary(
        title="AWS IAM",
        lines=summarize_global_service_lines(iam_lines, max_items),
        fillcolor="#fef7f5",
        fontcolor="#9b2c2c",
    )


__all__ = ["build_iam_summary"]

