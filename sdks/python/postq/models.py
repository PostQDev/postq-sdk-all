"""Typed data classes for SDK inputs and responses."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# Type aliases — kept as plain strings for 3.9 compatibility.
Severity = str  # "critical" | "high" | "medium" | "low" | "info"
RiskLevel = str  # "Critical" | "High" | "Medium" | "Low" | "Safe"
ScanType = str  # "url" | "github" | "aws" | "azure" | "kubernetes" | "bulk"
ScanSource = str  # "cli" | "helm" | "lambda" | "bicep" | "web" | "sdk"
Provider = str  # "aws" | "azure" | "gcp" | "kubernetes" | "github" | "vault" | "url" | "other"
AssetType = str  # "ENDPOINT" | "CERTIFICATE" | "KEY" | "DATA_STORE"
ResourceRisk = str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"


@dataclass
class Finding:
    """A single quantum-vulnerability finding attached to a scan submission."""

    severity: Severity
    title: str
    description: str = ""
    location: str = ""
    algorithm: Optional[str] = None
    remediation: str = ""
    vulnerable: bool = True


@dataclass
class ScanSubmitResult:
    """Returned by :meth:`PostQ.scans.submit`."""

    id: str
    created_at: str
    url: str


@dataclass
class ScanListItem:
    """A single row returned by :meth:`PostQ.scans.list`."""

    id: str
    type: str
    target: str
    source: str
    risk_score: int
    risk_level: str
    findings_count: int
    created_at: str
    url: str


@dataclass
class Asset:
    """A discovered cryptographic asset returned by :meth:`PostQ.assets.list`."""

    id: str
    name: str
    type: AssetType
    algorithm: str
    risk: ResourceRisk
    environment: str
    pq_ready: bool
    created_at: str
    updated_at: str
    provider: Optional[Provider] = None
    external_id: Optional[str] = None
    region: Optional[str] = None
    last_scanned: Optional[str] = None
    scan_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Key:
    """A discovered managed cryptographic key returned by :meth:`PostQ.keys.list`."""

    id: str
    provider: Provider
    external_id: str
    algorithm: str
    pq_safe: bool
    risk: RiskLevel
    first_seen: str
    last_seen: str
    region: Optional[str] = None
    key_size: Optional[int] = None
    key_usage: Optional[str] = None
    scan_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────────── Hybrid Signing ───────────────────────────

HybridAlgorithm = str  # "mldsa44+ed25519" | "mldsa65+ed25519" | "mldsa87+ed25519"


@dataclass
class HybridKey:
    """A managed signing key owned by your PostQ org."""

    id: str
    name: str
    algorithm: HybridAlgorithm
    created_at: str
    revoked_at: Optional[str] = None
    last_used_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HybridKeyWithPublic(HybridKey):
    """A managed key plus its composite public key (JSON string)."""

    # NOTE: dataclass requires defaults for fields that follow defaulted ones,
    # so this carries an empty default and is always set in practice.
    public_key: str = ""


@dataclass
class HybridSignResult:
    """Returned by :meth:`PostQ.sign`."""

    key_id: str
    algorithm: HybridAlgorithm
    signature: str  # base64 composite signature
    public_key: str  # composite public key JSON
    payload_sha256: str
    payload_size: int


@dataclass
class HybridVerifyResult:
    """Returned by :meth:`PostQ.verify`."""

    ok: bool
    algorithm: HybridAlgorithm
    classical_ok: bool
    pq_ok: bool
