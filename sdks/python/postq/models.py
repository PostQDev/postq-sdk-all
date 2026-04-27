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


# ─────────────────────────── Scan detail ───────────────────────────

HndlSeverity = str  # "critical" | "high" | "medium" | "low" | "none"


@dataclass
class HndlAssessment:
    """Harvest-Now-Decrypt-Later exposure for a single scan."""

    score: int
    severity: HndlSeverity
    exposure_window_years: int
    crqc_break_year: int
    data_lifetime_years: int
    pq_safe: bool
    rationale: str
    recommendation: str

    @classmethod
    def from_api(cls, data: Dict[str, Any]) -> "HndlAssessment":
        return cls(
            score=int(data["score"]),
            severity=str(data["severity"]),
            exposure_window_years=int(data["exposureWindowYears"]),
            crqc_break_year=int(data["crqcBreakYear"]),
            data_lifetime_years=int(data["dataLifetimeYears"]),
            pq_safe=bool(data["pqSafe"]),
            rationale=str(data.get("rationale", "")),
            recommendation=str(data.get("recommendation", "")),
        )


@dataclass
class CertificateInfo:
    """Certificate metadata captured during URL scans."""

    subject: str
    issuer: str
    serial_number: str
    valid_from: str
    valid_to: str
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int
    fingerprint: str
    subject_alt_names: list = field(default_factory=list)
    is_expired: bool = False
    days_until_expiry: int = 0


@dataclass
class TlsInfo:
    """TLS handshake metadata captured during URL scans."""

    protocol: str
    cipher_suite: str
    key_exchange: str
    authentication: str
    encryption: str
    mac: str
    key_exchange_size: Optional[int] = None


@dataclass
class ScanFindingRow:
    """A normalized finding row returned with a scan detail."""

    severity: Severity
    title: str
    description: str = ""
    location: str = ""
    algorithm: Optional[str] = None
    remediation: str = ""
    vulnerable: bool = True
    id: Optional[str] = None


@dataclass
class ScanDetail:
    """Full scan record returned by :meth:`PostQ.scans.get`. Fields hndl,
    certificate, and tls are populated for URL scans run from the
    dashboard, and may be ``None`` for CLI/agent submissions."""

    id: str
    type: str
    target: str
    source: str
    risk_score: int
    risk_level: str
    findings_count: int
    mode: str
    created_at: str
    url: str
    cbom_url: str
    agent: Dict[str, Any] = field(default_factory=dict)
    findings: list = field(default_factory=list)
    hndl: Optional[HndlAssessment] = None
    certificate: Optional[CertificateInfo] = None
    tls: Optional[TlsInfo] = None
    summary: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, str]] = None

    @classmethod
    def from_api(cls, data: Dict[str, Any]) -> "ScanDetail":
        cert_raw = data.get("certificate")
        tls_raw = data.get("tls")
        hndl_raw = data.get("hndl")
        return cls(
            id=str(data["id"]),
            type=str(data["type"]),
            target=str(data["target"]),
            source=str(data["source"]),
            risk_score=int(data.get("riskScore") or 0),
            risk_level=str(data.get("riskLevel") or ""),
            findings_count=int(data.get("findingsCount") or 0),
            mode=str(data.get("mode") or "live"),
            created_at=str(data["createdAt"]),
            url=str(data["url"]),
            cbom_url=str(data.get("cbomUrl") or f"/v1/scans/{data['id']}/cbom"),
            agent=dict(data.get("agent") or {}),
            findings=[
                ScanFindingRow(
                    severity=str(f.get("severity", "info")),
                    title=str(f.get("title", "")),
                    description=str(f.get("description", "")),
                    location=str(f.get("location", "")),
                    algorithm=f.get("algorithm"),
                    remediation=str(f.get("remediation", "")),
                    vulnerable=bool(f.get("vulnerable", True)),
                    id=f.get("id"),
                )
                for f in (data.get("findings") or [])
            ],
            hndl=HndlAssessment.from_api(hndl_raw) if hndl_raw else None,
            certificate=CertificateInfo(
                subject=str(cert_raw.get("subject", "")),
                issuer=str(cert_raw.get("issuer", "")),
                serial_number=str(cert_raw.get("serialNumber", "")),
                valid_from=str(cert_raw.get("validFrom", "")),
                valid_to=str(cert_raw.get("validTo", "")),
                signature_algorithm=str(cert_raw.get("signatureAlgorithm", "")),
                public_key_algorithm=str(cert_raw.get("publicKeyAlgorithm", "")),
                public_key_size=int(cert_raw.get("publicKeySize") or 0),
                fingerprint=str(cert_raw.get("fingerprint", "")),
                subject_alt_names=list(cert_raw.get("subjectAltNames") or []),
                is_expired=bool(cert_raw.get("isExpired", False)),
                days_until_expiry=int(cert_raw.get("daysUntilExpiry") or 0),
            ) if cert_raw else None,
            tls=TlsInfo(
                protocol=str(tls_raw.get("protocol", "")),
                cipher_suite=str(tls_raw.get("cipherSuite", "")),
                key_exchange=str(tls_raw.get("keyExchange", "")),
                authentication=str(tls_raw.get("authentication", "")),
                encryption=str(tls_raw.get("encryption", "")),
                mac=str(tls_raw.get("mac", "")),
                key_exchange_size=tls_raw.get("keyExchangeSize"),
            ) if tls_raw else None,
            summary=data.get("summary"),
            metadata=data.get("metadata"),
        )


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
