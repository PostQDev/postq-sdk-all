"""Official PostQ SDK for Python.

Submit quantum-risk scans and read results from the PostQ API
(https://api.postq.dev).

Example::

    from postq import PostQ

    pq = PostQ(api_key="pq_live_...")

    result = pq.scans.submit(
        type="url",
        target="example.com",
        risk_score=85,
        risk_level="High",
    )
    print(result.url)

    for scan in pq.scans.list(limit=10):
        print(scan.target, scan.risk_level)
"""
from __future__ import annotations

__version__ = "0.2.0"

from .client import PostQ, ScansResource
from .errors import (
    PostQAuthError,
    PostQConfigError,
    PostQError,
    PostQNetworkError,
    PostQNotFoundError,
    PostQRateLimitError,
    PostQServerError,
)
from .models import Finding, ScanListItem, ScanSubmitResult

__all__ = [
    "__version__",
    "PostQ",
    "ScansResource",
    "PostQError",
    "PostQConfigError",
    "PostQAuthError",
    "PostQNotFoundError",
    "PostQRateLimitError",
    "PostQServerError",
    "PostQNetworkError",
    "Finding",
    "ScanListItem",
    "ScanSubmitResult",
]
