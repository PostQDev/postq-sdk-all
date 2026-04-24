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
