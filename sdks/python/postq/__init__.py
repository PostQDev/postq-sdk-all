"""
PostQ SDK for Python
~~~~~~~~~~~~~~~~~~~~

Official Python SDK for PostQ – quantum-safe cryptography for your applications.

Basic usage::

    from postq import PostQ

    pq = PostQ(api_key="pq_live_sk_...")

    signature = pq.sign(
        payload=b"Hello Quantum World",
        algorithm="dilithium3+ed25519",
        key_id="vault://signing/production",
    )

    is_valid = pq.verify(
        payload=b"Hello Quantum World",
        signature=signature["signature"],
        key_id="vault://signing/production",
    )
"""

from .client import PostQ
from .errors import PostQError, PostQConfigError
from .models import (
    Algorithm,
    SignResponse,
    VerifyResponse,
    Key,
    ListKeysResponse,
    ScanSummary,
    ScanResponse,
)

__all__ = [
    "PostQ",
    "PostQError",
    "PostQConfigError",
    "Algorithm",
    "SignResponse",
    "VerifyResponse",
    "Key",
    "ListKeysResponse",
    "ScanSummary",
    "ScanResponse",
]
