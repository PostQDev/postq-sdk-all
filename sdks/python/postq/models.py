"""Typed data classes for SDK inputs and responses."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Type aliases — kept as plain strings for 3.9 compatibility.
Severity = str  # "critical" | "high" | "medium" | "low" | "info"
RiskLevel = str  # "Critical" | "High" | "Medium" | "Low" | "Safe"
ScanType = str  # "url" | "github" | "aws" | "azure" | "kubernetes" | "bulk"
ScanSource = str  # "cli" | "helm" | "lambda" | "bicep" | "web" | "sdk"


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
