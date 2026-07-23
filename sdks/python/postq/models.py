"""Typed data classes for SDK inputs and responses."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Generic, Optional, TypeVar

# Type aliases — kept as plain strings for 3.9 compatibility.
Severity = str  # "critical" | "high" | "medium" | "low" | "info"
RiskLevel = str  # "Critical" | "High" | "Medium" | "Low" | "Safe"
ScanType = str  # "url" | "github" | "aws" | "azure" | "kubernetes" | "bulk"
ScanSource = str  # "cli" | "helm" | "lambda" | "bicep" | "web" | "sdk"
Provider = str  # "aws" | "azure" | "gcp" | "kubernetes" | "github" | "vault" | "url" | "other"
AssetType = str  # "ENDPOINT" | "CERTIFICATE" | "KEY" | "DATA_STORE"
ResourceRisk = str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"

T = TypeVar("T")


@dataclass
class Pagination:
    """Cursor pagination metadata returned with every ``list()`` page."""

    limit: int
    next_cursor: Optional[str] = None


@dataclass
class Page(Generic[T]):
    """One page of results from a ``list()`` call.

    Mirrors the ``{ data, pagination }`` envelope returned by the JavaScript and
    .NET SDKs so the surface is consistent across languages. For convenience it
    also behaves like the list of items it wraps — you can iterate it, index it,
    and call ``len()`` on it directly::

        page = pq.scans.list(limit=20)
        for scan in page:            # iterates page.data
            ...
        first = page[0]              # indexes page.data
        count = len(page)            # len(page.data)
        cursor = page.pagination.next_cursor
    """

    data: list[T]
    pagination: Pagination

    def __iter__(self):
        return iter(self.data)

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, index):
        return self.data[index]


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
class CloudScanSummary:
    total_endpoints: int
    quantum_vulnerable: int
    hybrid_enabled: int
    pq_ready: int


@dataclass
class CloudScanResult:
    id: str
    created_at: str
    provider: str
    target: str
    mode: str
    risk_score: int
    risk_level: str
    findings_count: int
    resources_count: int
    summary: CloudScanSummary
    url: str

    @classmethod
    def from_api(cls, data: Dict[str, Any]) -> "CloudScanResult":
        summary = data.get("summary") or {}
        return cls(
            id=str(data["id"]),
            created_at=str(data["createdAt"]),
            provider=str(data["provider"]),
            target=str(data["target"]),
            mode=str(data["mode"]),
            risk_score=int(data["riskScore"]),
            risk_level=str(data["riskLevel"]),
            findings_count=int(data["findingsCount"]),
            resources_count=int(data["resourcesCount"]),
            summary=CloudScanSummary(
                total_endpoints=int(summary.get("totalEndpoints", 0)),
                quantum_vulnerable=int(summary.get("quantumVulnerable", 0)),
                hybrid_enabled=int(summary.get("hybridEnabled", 0)),
                pq_ready=int(summary.get("pqReady", 0)),
            ),
            url=str(data["url"]),
        )


@dataclass
class UrlScanResult:
    id: str
    created_at: str
    target: str
    mode: str
    risk_score: int
    risk_level: str
    findings_count: int
    scan_duration_ms: int
    url: str
    summary: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, str] = field(default_factory=dict)
    findings: list = field(default_factory=list)
    certificate: Optional[Dict[str, Any]] = None
    tls: Optional[Dict[str, Any]] = None
    hndl: Optional[Dict[str, Any]] = None

    @classmethod
    def from_api(cls, data: Dict[str, Any]) -> "UrlScanResult":
        return cls(
            id=str(data["id"]),
            created_at=str(data["createdAt"]),
            target=str(data["target"]),
            mode=str(data["mode"]),
            risk_score=int(data["riskScore"]),
            risk_level=str(data["riskLevel"]),
            findings_count=int(data["findingsCount"]),
            scan_duration_ms=int(data.get("scanDurationMs", 0)),
            url=str(data["url"]),
            summary=dict(data.get("summary") or {}),
            metadata=dict(data.get("metadata") or {}),
            findings=list(data.get("findings") or []),
            certificate=data.get("certificate"),
            tls=data.get("tls"),
            hndl=data.get("hndl"),
        )


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
    workflow_status: Optional[str] = None
    owner_team: Optional[str] = None
    assigned_to: Optional[str] = None
    criticality: str = "medium"
    data_lifetime_years: Optional[int] = None
    exposure: str = "unknown"
    migration_due_at: Optional[str] = None
    exception: Optional[Dict[str, Any]] = None


@dataclass
class MigrationAction:
    id: str
    project_id: str
    title: str
    provider: str
    target_algorithm: str
    execution_mode: str
    status: str
    asset_id: Optional[str] = None
    source_algorithm: Optional[str] = None
    assignee: Optional[str] = None
    due_at: Optional[str] = None
    before_scan_id: Optional[str] = None
    after_scan_id: Optional[str] = None
    downgrade_protected: Optional[bool] = None
    dependent_credentials_rotated: bool = False
    validation: Dict[str, Any] = field(default_factory=dict)
    exception: Optional[Dict[str, Any]] = None
    external_issue_url: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""


@dataclass
class MigrationProject:
    id: str
    name: str
    description: str
    framework: str
    track: str
    status: str
    target_date: Optional[str] = None
    source_scan_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    actions: list = field(default_factory=list)


@dataclass
class MigrationEvidenceBundle:
    id: str
    project_id: str
    format: str
    bundle: Dict[str, Any]
    bundle_sha256: str
    action_id: Optional[str] = None
    ledger_entry_id: Optional[str] = None
    checkpoint_id: Optional[str] = None
    created_at: str = ""


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


# ─────────────────────────── Hybrid key audit ───────────────────────────


@dataclass
class HybridKeyAuditEntry:
    """A single sign/verify audit row for one hybrid key."""

    id: str
    operation: str
    payload_sha256: str
    payload_size: int
    verified: Optional[bool]
    created_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────────── Policies ───────────────────────────

PolicyAction = str  # "enforce" | "warn" | "audit"
PolicyOperation = str  # "sign" | "verify" | "key_create" | "*"


@dataclass
class PolicyRule:
    """Typed cryptographic constraints evaluated by the API."""

    match_operation: PolicyOperation = "*"
    algorithm_in: Optional[list] = None
    algorithm_not_in: Optional[list] = None
    require_hybrid: bool = False
    min_pq_level: Optional[int] = None


@dataclass
class Policy:
    """An org-level policy rule enforced by ``POST /v1/sign``."""

    id: str
    name: str
    description: str
    action: PolicyAction
    enabled: bool
    environments: list
    rule: PolicyRule
    created_at: str
    updated_at: str


# ─────────────────────────── Ledger ───────────────────────────


@dataclass
class LedgerEntry:
    """An entry in the org's tamper-evident hash chain."""

    id: str
    seq: int
    prev_hash_hex: str
    entry_hash_hex: str
    payload: Dict[str, Any]
    event_type: str
    subject_id: Optional[str] = None
    actor_id: Optional[str] = None
    created_at: str = ""


@dataclass
class LedgerCheckpoint:
    """A signed Merkle-root checkpoint over a range of ledger entries."""

    id: str
    tree_size: int
    merkle_root_hex: str
    signature_base64: str
    signing_key_id: str
    published_to: list
    created_at: str


@dataclass
class LedgerInclusionProof:
    """A Merkle inclusion proof for a single ledger entry."""

    entry_id: str
    leaf_index: int
    leaf_hash_hex: str
    checkpoint: Dict[str, Any]
    proof_hex: list


@dataclass
class LedgerSealResult:
    """Returned by ``POST /v1/ledger/seal``."""

    tree_size: int
    merkle_root_hex: str
    signature_base64: str
    signing_key_id: str
    created_at: str
    fresh: bool


@dataclass
class LedgerBundle:
    """A verifiable bundle returned by ``GET /v1/ledger/bundle``."""

    version: int
    org: str
    generated_at: str
    entries: list
    checkpoints: list
    signing_keys: list


# ─────────────────────────── Vault ───────────────────────────


@dataclass
class VaultSettings:
    """Per-org BYOK / KMS settings returned by ``GET /v1/vault/settings``.

    The encrypted secret is never returned in plaintext."""

    default_kek_provider: str  # "env" | "aws-kms" | "azure-kv" | "gcp-kms"
    aws: Optional[Dict[str, Any]] = None
    azure: Optional[Dict[str, Any]] = None
    gcp: Optional[Dict[str, Any]] = None
    updated_at: Optional[str] = None


@dataclass
class VaultSettingsSaveResult:
    saved_at: str
