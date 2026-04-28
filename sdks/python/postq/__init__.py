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

__version__ = "0.5.0"

from .client import (
    AssetsResource,
    HybridKeysResource,
    KeysResource,
    LedgerResource,
    PoliciesResource,
    PostQ,
    ScansResource,
    VaultResource,
)
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
    CertificateInfo,
    Finding,
    HndlAssessment,
    HybridAlgorithm,
    HybridKey,
    HybridKeyAuditEntry,
    HybridKeyWithPublic,
    HybridSignResult,
    HybridVerifyResult,
    Key,
    LedgerBundle,
    LedgerCheckpoint,
    LedgerEntry,
    LedgerInclusionProof,
    LedgerSealResult,
    Policy,
    PolicyAction,
    PolicyOperation,
    PolicyRule,
    ScanDetail,
    ScanFindingRow,
    ScanListItem,
    ScanSubmitResult,
    TlsInfo,
    VaultSettings,
)

__all__ = [
    "__version__",
    "PostQ",
    "ScansResource",
    "AssetsResource",
    "KeysResource",
    "HybridKeysResource",
    "PoliciesResource",
    "LedgerResource",
    "VaultResource",
    "PostQError",
    "PostQConfigError",
    "PostQAuthError",
    "PostQNotFoundError",
    "PostQRateLimitError",
    "PostQServerError",
    "PostQNetworkError",
    "Finding",
    "ScanListItem",
    "ScanDetail",
    "ScanFindingRow",
    "ScanSubmitResult",
    "HndlAssessment",
    "CertificateInfo",
    "TlsInfo",
    "Asset",
    "Key",
    "HybridAlgorithm",
    "HybridKey",
    "HybridKeyWithPublic",
    "HybridKeyAuditEntry",
    "HybridSignResult",
    "HybridVerifyResult",
    "Policy",
    "PolicyAction",
    "PolicyOperation",
    "PolicyRule",
    "LedgerEntry",
    "LedgerCheckpoint",
    "LedgerInclusionProof",
    "LedgerSealResult",
    "LedgerBundle",
    "VaultSettings",
]
