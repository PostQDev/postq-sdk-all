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

__version__ = "0.4.0"

from .client import AssetsResource, HybridKeysResource, KeysResource, PostQ, ScansResource
from .errors import (
    PostQAuthError,
    PostQConfigError,
    PostQError,
    PostQNetworkError,
    PostQNotFoundError,
    PostQRateLimitError,
    PostQServerError,
)
from .models import (
    Asset,
    Finding,
    HybridAlgorithm,
    HybridKey,
    HybridKeyWithPublic,
    HybridSignResult,
    HybridVerifyResult,
    Key,
    ScanListItem,
    ScanSubmitResult,
)

__all__ = [
    "__version__",
    "PostQ",
    "ScansResource",
    "AssetsResource",
    "KeysResource",
    "HybridKeysResource",
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
    "Asset",
    "Key",
    "HybridAlgorithm",
    "HybridKey",
    "HybridKeyWithPublic",
    "HybridSignResult",
    "HybridVerifyResult",
]
