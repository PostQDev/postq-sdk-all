"""Typed data models for PostQ API responses."""

from __future__ import annotations

from typing import List, Literal, Optional


# Supported hybrid algorithm combinations
Algorithm = Literal[
    "dilithium3+ed25519",
    "dilithium5+p384",
    "falcon512+ed25519",
]


class SignResponse:
    """Response from POST /v1/sign."""

    def __init__(
        self,
        signature: str,
        classical_sig: str,
        pq_sig: str,
        algorithm: str,
        key_id: str,
        timestamp: str,
        policy_compliant: bool,
    ) -> None:
        self.signature = signature
        self.classical_sig = classical_sig
        self.pq_sig = pq_sig
        self.algorithm = algorithm
        self.key_id = key_id
        self.timestamp = timestamp
        self.policy_compliant = policy_compliant

    @classmethod
    def from_dict(cls, data: dict) -> "SignResponse":
        return cls(
            signature=data["signature"],
            classical_sig=data["classical_sig"],
            pq_sig=data["pq_sig"],
            algorithm=data["algorithm"],
            key_id=data["key_id"],
            timestamp=data["timestamp"],
            policy_compliant=data["policy_compliant"],
        )

    def __repr__(self) -> str:
        return (
            f"SignResponse(algorithm={self.algorithm!r}, key_id={self.key_id!r}, "
            f"policy_compliant={self.policy_compliant})"
        )


class VerifyResponse:
    """Response from POST /v1/verify."""

    def __init__(
        self,
        valid: bool,
        classical_valid: bool,
        pq_valid: bool,
        algorithm: str,
        key_id: str,
    ) -> None:
        self.valid = valid
        self.classical_valid = classical_valid
        self.pq_valid = pq_valid
        self.algorithm = algorithm
        self.key_id = key_id

    @classmethod
    def from_dict(cls, data: dict) -> "VerifyResponse":
        return cls(
            valid=data["valid"],
            classical_valid=data["classical_valid"],
            pq_valid=data["pq_valid"],
            algorithm=data["algorithm"],
            key_id=data["key_id"],
        )

    def __repr__(self) -> str:
        return (
            f"VerifyResponse(valid={self.valid}, classical_valid={self.classical_valid}, "
            f"pq_valid={self.pq_valid})"
        )


class Key:
    """A cryptographic key managed by PostQ."""

    def __init__(
        self,
        id: str,
        algorithm: str,
        created_at: str,
        status: str,
        backend: str,
        pq_ready: bool,
    ) -> None:
        self.id = id
        self.algorithm = algorithm
        self.created_at = created_at
        self.status = status
        self.backend = backend
        self.pq_ready = pq_ready

    @classmethod
    def from_dict(cls, data: dict) -> "Key":
        return cls(
            id=data["id"],
            algorithm=data["algorithm"],
            created_at=data["created_at"],
            status=data["status"],
            backend=data["backend"],
            pq_ready=data["pq_ready"],
        )

    def __repr__(self) -> str:
        return (
            f"Key(id={self.id!r}, algorithm={self.algorithm!r}, "
            f"pq_ready={self.pq_ready}, status={self.status!r})"
        )


class ListKeysResponse:
    """Response from GET /v1/keys."""

    def __init__(self, keys: List[Key]) -> None:
        self.keys = keys

    @classmethod
    def from_dict(cls, data: dict) -> "ListKeysResponse":
        return cls(keys=[Key.from_dict(k) for k in data["keys"]])

    def __repr__(self) -> str:
        return f"ListKeysResponse(keys={self.keys!r})"


class ScanSummary:
    """Summary statistics from a completed scan."""

    def __init__(
        self,
        total_endpoints: int,
        quantum_vulnerable: int,
        risk_score: int,
        recommendation: str,
    ) -> None:
        self.total_endpoints = total_endpoints
        self.quantum_vulnerable = quantum_vulnerable
        self.risk_score = risk_score
        self.recommendation = recommendation

    @classmethod
    def from_dict(cls, data: dict) -> "ScanSummary":
        return cls(
            total_endpoints=data["total_endpoints"],
            quantum_vulnerable=data["quantum_vulnerable"],
            risk_score=data["risk_score"],
            recommendation=data["recommendation"],
        )

    def __repr__(self) -> str:
        return (
            f"ScanSummary(risk_score={self.risk_score}, "
            f"quantum_vulnerable={self.quantum_vulnerable}/{self.total_endpoints})"
        )


class ScanResponse:
    """Response from POST /v1/scan."""

    def __init__(
        self,
        scan_id: str,
        status: str,
        summary: Optional[ScanSummary] = None,
    ) -> None:
        self.scan_id = scan_id
        self.status = status
        self.summary = summary

    @classmethod
    def from_dict(cls, data: dict) -> "ScanResponse":
        summary = ScanSummary.from_dict(data["summary"]) if data.get("summary") else None
        return cls(
            scan_id=data["scan_id"],
            status=data["status"],
            summary=summary,
        )

    def __repr__(self) -> str:
        return f"ScanResponse(scan_id={self.scan_id!r}, status={self.status!r})"
