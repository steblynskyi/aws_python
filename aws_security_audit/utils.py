"""Shared helpers for AWS service audits."""
from __future__ import annotations

from typing import Iterable, Iterator, Sequence, TypeVar

import boto3
from botocore.exceptions import OperationNotPageableError

T = TypeVar("T")


def safe_paginate(client: boto3.client, method_name: str, result_key: str, **kwargs) -> Iterator[dict]:
    """Iterate through paginated boto3 results while handling pagination gaps."""

    try:
        paginator = client.get_paginator(method_name)
    except OperationNotPageableError:
        response = getattr(client, method_name)(**kwargs)
        for item in response.get(result_key, []):
            yield item
        return

    for page in paginator.paginate(**kwargs):
        for item in page.get(result_key, []):
            yield item


def batch_iterable(items: Sequence[T], size: int) -> Iterable[Sequence[T]]:
    """Yield slices of *items* with at most ``size`` members."""

    for i in range(0, len(items), size):
        yield items[i : i + size]


__all__ = ["safe_paginate", "batch_iterable"]
