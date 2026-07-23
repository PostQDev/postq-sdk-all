"""HTTP transport for the PostQ API."""
from __future__ import annotations

import os
import platform
from typing import Any, Iterator, Mapping, Optional, Sequence, Union
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import __version__
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
    CloudScanResult,
    Finding,
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
    MigrationAction,
    MigrationEvidenceBundle,
    MigrationProject,
    Page,
    Pagination,
    Policy,
    PolicyRule,
    ScanDetail,
    ScanListItem,
    ScanSubmitResult,
    UrlScanResult,
    VaultSettings,
    VaultSettingsSaveResult,
)

DEFAULT_BASE_URL = "https://api.postq.dev"


def _pagination(body: Mapping[str, Any], default_limit: int) -> Pagination:
    """Build a :class:`Pagination` from a list-response envelope."""
    raw = body.get("pagination") or {}
    return Pagination(
        limit=int(raw.get("limit", default_limit)),
        next_cursor=raw.get("nextCursor"),
    )


class PostQ:
    """Synchronous client for the PostQ API.

    Reads the API key from the ``api_key`` argument or the ``POSTQ_API_KEY``
    environment variable. Raises :class:`PostQConfigError` if neither is set.

    Example::

        from postq import PostQ

        pq = PostQ(api_key="pq_live_…")
        result = pq.scans.submit(
            type="url",
            target="example.com",
            risk_score=85,
            risk_level="High",
        )
        print(result.url)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        key = api_key or os.environ.get("POSTQ_API_KEY")
        if not key:
            raise PostQConfigError(
                "api_key not provided and POSTQ_API_KEY env var is not set"
            )
        self._api_key = key.strip()
        self._base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self._timeout = timeout

        self._session = requests.Session()
        retry = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            # POST endpoints create keys, signatures, scans, and ledger rows;
            # never replay them without an explicit idempotency contract.
            allowed_methods=["GET", "HEAD", "OPTIONS", "DELETE", "PUT"],
            respect_retry_after_header=True,
            # Surface the final response so we can map it to the right exception
            # type instead of urllib3 raising MaxRetryError.
            raise_on_status=False,
        )
        self._session.mount("https://", HTTPAdapter(max_retries=retry))
        self._session.mount("http://", HTTPAdapter(max_retries=retry))
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": (
                    f"postq-sdk-python/{__version__} "
                    f"python/{platform.python_version()}"
                ),
            }
        )

        # Resource namespaces.
        self.scans = ScansResource(self)
        self.assets = AssetsResource(self)
        self.keys = KeysResource(self)
        self.hybrid_keys = HybridKeysResource(self)
        self.policies = PoliciesResource(self)
        self.ledger = LedgerResource(self)
        self.vault = VaultResource(self)
        self.migrations = MigrationsResource(self)

    # ── public ──────────────────────────────────────────────────────────────

    def health(self) -> "dict[str, Any]":
        """Hit ``GET /health``. Returns the parsed JSON or raises."""
        return self._request("GET", "/health")

    def sign(
        self,
        *,
        key_id: str,
        payload: Union[bytes, str],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> HybridSignResult:
        """``POST /v1/sign`` — convenience wrapper around ``hybrid_keys.sign()``."""
        return self.hybrid_keys.sign(key_id=key_id, payload=payload, metadata=metadata)

    def verify(
        self,
        *,
        payload: Union[bytes, str],
        signature: str,
        key_id: Optional[str] = None,
        public_key: Optional[str] = None,
    ) -> HybridVerifyResult:
        """``POST /v1/verify`` — convenience wrapper around ``hybrid_keys.verify()``."""
        return self.hybrid_keys.verify(
            payload=payload, signature=signature, key_id=key_id, public_key=public_key
        )

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "PostQ":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ── internal ────────────────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Mapping[str, Any]] = None,
        params: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        url = urljoin(self._base_url + "/", path.lstrip("/"))
        try:
            resp = self._session.request(
                method,
                url,
                json=json,
                params=params,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise PostQNetworkError(f"{method} {path}: {exc}") from exc

        message, code = _extract_error(resp)
        status = resp.status_code

        if status == 401:
            raise PostQAuthError(message, status=status, code=code)
        if status == 404:
            raise PostQNotFoundError(message, status=status, code=code)
        if status == 429:
            raise PostQRateLimitError(message, status=status, code=code)
        if 500 <= status < 600:
            raise PostQServerError(message, status=status, code=code)
        if status >= 400:
            raise PostQError(message, status=status, code=code)

        if not resp.content:
            return None
        return resp.json()


class ScansResource:
    """Operations under ``/v1/scans``."""

    def __init__(self, client: PostQ) -> None:
        self._client = client

    def submit(
        self,
        *,
        type: str,
        target: str,
        risk_score: int,
        risk_level: str,
        findings: Sequence[Union[Finding, Mapping[str, Any]]] = (),
        source: str = "sdk",
        metadata: Optional[Mapping[str, str]] = None,
        agent: Optional[Mapping[str, str]] = None,
    ) -> ScanSubmitResult:
        """``POST /v1/scans`` — submit a scan from your scanner/agent."""
        payload = {
            "type": type,
            "target": target,
            "source": source,
            "riskScore": risk_score,
            "riskLevel": risk_level,
            "findings": [_normalize_finding(f) for f in findings],
            "metadata": dict(metadata or {}),
            "agent": dict(agent or {}),
        }
        body = self._client._request("POST", "/v1/scans", json=payload)
        data = body["data"]
        return ScanSubmitResult(
            id=data["id"],
            created_at=data["createdAt"],
            url=data["url"],
        )

    def list(
        self,
        *,
        limit: int = 20,
        cursor: Optional[str] = None,
    ) -> "Page[ScanListItem]":
        """``GET /v1/scans`` — one page of recent scans.

        Returns a :class:`Page` with ``.data`` (the rows) and ``.pagination``
        (``.limit`` / ``.next_cursor``), matching the JS and .NET SDKs. The page
        is iterable, so ``for scan in pq.scans.list(): ...`` keeps working.
        """
        params: "dict[str, Any]" = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        body = self._client._request("GET", "/v1/scans", params=params)
        return Page(
            data=[_row_to_item(row) for row in body["data"]],
            pagination=_pagination(body, limit),
        )

    def get(self, scan_id: str) -> ScanDetail:
        """``GET /v1/scans/:id`` — full scan record including HNDL,
        certificate, TLS, and findings when populated."""
        body = self._client._request("GET", f"/v1/scans/{scan_id}")
        return ScanDetail.from_api(body["data"])

    def run_url(
        self,
        *,
        target: str,
        timeout_ms: Optional[int] = None,
    ) -> UrlScanResult:
        """``POST /v1/scans/url`` — run and persist a server-side TLS scan."""
        body = self._client._request(
            "POST",
            "/v1/scans/url",
            json=_strip_none({"target": target, "timeoutMs": timeout_ms}),
        )
        return UrlScanResult.from_api(body["data"])

    def run_cloud(
        self,
        *,
        provider: str,
        target: str,
        aws: Optional[Mapping[str, Any]] = None,
        azure: Optional[Mapping[str, Any]] = None,
        gcp: Optional[Mapping[str, Any]] = None,
    ) -> CloudScanResult:
        """``POST /v1/scans/cloud`` — run and persist a cloud inventory scan."""
        if provider not in {"aws", "azure", "gcp"}:
            raise PostQConfigError(
            "provider must be 'aws', 'azure', or 'gcp'; Kubernetes uses the in-cluster agent"
            )
        body = self._client._request(
            "POST",
            "/v1/scans/cloud",
            json=_strip_none(
                {
                    "provider": provider,
                    "target": target,
                    "aws": dict(aws) if aws is not None else None,
                    "azure": dict(azure) if azure is not None else None,
                    "gcp": dict(gcp) if gcp is not None else None,
                }
            ),
        )
        return CloudScanResult.from_api(body["data"])

    def cbom(self, scan_id: str) -> "dict[str, Any]":
        """``GET /v1/scans/:id/cbom`` — CycloneDX 1.6 CBOM as a parsed dict."""
        body = self._client._request("GET", f"/v1/scans/{scan_id}/cbom")
        # CBOM endpoint returns the CBOM document directly (no envelope).
        return body or {}

    def iter_all(self, *, page_size: int = 100) -> Iterator[ScanListItem]:
        """Generator that walks every scan via cursor pagination."""
        cursor: Optional[str] = None
        while True:
            params: "dict[str, Any]" = {"limit": page_size}
            if cursor:
                params["cursor"] = cursor
            body = self._client._request("GET", "/v1/scans", params=params)
            for row in body["data"]:
                yield _row_to_item(row)
            cursor = (body.get("pagination") or {}).get("nextCursor")
            if not cursor:
                return


def _normalize_finding(f: Union[Finding, Mapping[str, Any]]) -> "dict[str, Any]":
    if isinstance(f, Finding):
        return {
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "location": f.location,
            "algorithm": f.algorithm,
            "remediation": f.remediation,
            "vulnerable": f.vulnerable,
        }
    return dict(f)


def _row_to_item(row: Mapping[str, Any]) -> ScanListItem:
    return ScanListItem(
        id=row["id"],
        type=row["type"],
        target=row["target"],
        source=row["source"],
        risk_score=row["riskScore"],
        risk_level=row["riskLevel"],
        findings_count=row["findingsCount"],
        created_at=row["createdAt"],
        url=row["url"],
    )


def _extract_error(resp: requests.Response) -> "tuple[str, Optional[str]]":
    try:
        body = resp.json()
        if isinstance(body, dict):
            return (
                body.get("error") or body.get("message") or f"HTTP {resp.status_code}",
                body.get("code"),
            )
    except (ValueError, requests.exceptions.JSONDecodeError):
        pass
    return resp.text or f"HTTP {resp.status_code}", None


class AssetsResource:
    """Operations under ``/v1/assets``."""

    def __init__(self, client: PostQ) -> None:
        self._client = client

    def list(
        self,
        *,
        limit: int = 20,
        cursor: Optional[str] = None,
        provider: Optional[str] = None,
        type: Optional[str] = None,
        risk: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> "Page[Asset]":
        """``GET /v1/assets`` — one page of discovered assets.

        Returns a :class:`Page` with ``.data`` and ``.pagination`` (parity with
        the JS and .NET SDKs); the page is also directly iterable.
        """
        params = _strip_none(
            {
                "limit": limit,
                "cursor": cursor,
                "provider": provider,
                "type": type,
                "risk": risk,
                "environment": environment,
            }
        )
        body = self._client._request("GET", "/v1/assets", params=params)
        return Page(
            data=[_row_to_asset(row) for row in body["data"]],
            pagination=_pagination(body, limit),
        )

    def iter_all(
        self,
        *,
        page_size: int = 100,
        provider: Optional[str] = None,
        type: Optional[str] = None,
        risk: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> Iterator[Asset]:
        cursor: Optional[str] = None
        while True:
            params = _strip_none(
                {
                    "limit": page_size,
                    "cursor": cursor,
                    "provider": provider,
                    "type": type,
                    "risk": risk,
                    "environment": environment,
                }
            )
            body = self._client._request("GET", "/v1/assets", params=params)
            for row in body["data"]:
                yield _row_to_asset(row)
            cursor = (body.get("pagination") or {}).get("nextCursor")
            if not cursor:
                return


class MigrationsResource:
    """Migration projects, actions, evidence bundles, and EO 14412 status."""

    def __init__(self, client: PostQ) -> None:
        self._client = client

    def list(self) -> "list[MigrationProject]":
        body = self._client._request("GET", "/v1/migrations")
        return [_project_from_api(row) for row in body["data"]]

    def create(
        self,
        *,
        name: str,
        description: str = "",
        framework: str = "eo-14412",
        track: str = "both",
        target_date: Optional[str] = None,
        source_scan_id: Optional[str] = None,
        asset_ids: Optional[Sequence[str]] = None,
        include_risk: Optional[Sequence[str]] = None,
    ) -> MigrationProject:
        body = self._client._request("POST", "/v1/migrations", json=_strip_none({
            "name": name,
            "description": description,
            "framework": framework,
            "track": track,
            "targetDate": target_date,
            "sourceScanId": source_scan_id,
            "assetIds": list(asset_ids) if asset_ids is not None else None,
            "includeRisk": list(include_risk) if include_risk is not None else None,
        }))
        return _project_from_api(body["data"])

    def get(self, project_id: str) -> MigrationProject:
        body = self._client._request("GET", f"/v1/migrations/{project_id}")
        return _project_from_api(body["data"])

    def update(
        self,
        project_id: str,
        *,
        status: Optional[str] = None,
        target_date: Optional[str] = None,
        description: Optional[str] = None,
    ) -> MigrationProject:
        body = self._client._request("PATCH", f"/v1/migrations/{project_id}", json=_strip_none({
            "status": status, "targetDate": target_date, "description": description,
        }))
        return _project_from_api(body["data"])

    def update_action(self, project_id: str, action_id: str, **update: Any) -> MigrationAction:
        aliases = {
            "due_at": "dueAt", "after_scan_id": "afterScanId",
            "downgrade_protected": "downgradeProtected",
            "dependent_credentials_rotated": "dependentCredentialsRotated",
            "external_issue_url": "externalIssueUrl",
        }
        payload = {aliases.get(key, key): value for key, value in update.items()}
        body = self._client._request("PATCH", f"/v1/migrations/{project_id}/actions/{action_id}", json=payload)
        return _action_from_api(body["data"])

    def finalize_evidence(self, project_id: str, action_id: str) -> MigrationEvidenceBundle:
        body = self._client._request("POST", f"/v1/migrations/{project_id}/actions/{action_id}/evidence")
        data = body["data"]
        return MigrationEvidenceBundle(
            id=data["id"], project_id=data["projectId"], action_id=data.get("actionId"),
            format=data["format"], bundle=dict(data.get("bundle") or {}),
            bundle_sha256=data["bundleSha256"], ledger_entry_id=data.get("ledgerEntryId"),
            checkpoint_id=data.get("checkpointId"), created_at=data.get("createdAt", ""),
        )

    def eo_14412(self) -> "dict[str, Any]":
        return self._client._request("GET", "/v1/migrations/compliance/eo-14412")["data"]


class KeysResource:
    """Operations under ``/v1/keys``."""

    def __init__(self, client: PostQ) -> None:
        self._client = client

    def list(
        self,
        *,
        limit: int = 20,
        cursor: Optional[str] = None,
        provider: Optional[str] = None,
        algorithm: Optional[str] = None,
        risk: Optional[str] = None,
    ) -> "Page[Key]":
        """``GET /v1/keys`` — one page of discovered cryptographic keys.

        Returns a :class:`Page` with ``.data`` and ``.pagination`` (parity with
        the JS and .NET SDKs); the page is also directly iterable.
        """
        params = _strip_none(
            {
                "limit": limit,
                "cursor": cursor,
                "provider": provider,
                "algorithm": algorithm,
                "risk": risk,
            }
        )
        body = self._client._request("GET", "/v1/keys", params=params)
        return Page(
            data=[_row_to_key(row) for row in body["data"]],
            pagination=_pagination(body, limit),
        )

    def iter_all(
        self,
        *,
        page_size: int = 100,
        provider: Optional[str] = None,
        algorithm: Optional[str] = None,
        risk: Optional[str] = None,
    ) -> Iterator[Key]:
        cursor: Optional[str] = None
        while True:
            params = _strip_none(
                {
                    "limit": page_size,
                    "cursor": cursor,
                    "provider": provider,
                    "algorithm": algorithm,
                    "risk": risk,
                }
            )
            body = self._client._request("GET", "/v1/keys", params=params)
            for row in body["data"]:
                yield _row_to_key(row)
            cursor = (body.get("pagination") or {}).get("nextCursor")
            if not cursor:
                return


def _strip_none(d: Mapping[str, Any]) -> "dict[str, Any]":
    return {k: v for k, v in d.items() if v is not None}


def _row_to_asset(row: Mapping[str, Any]) -> Asset:
    return Asset(
        id=row["id"],
        name=row["name"],
        type=row["type"],
        algorithm=row["algorithm"],
        risk=row["risk"],
        environment=row["environment"],
        pq_ready=bool(row.get("pqReady", False)),
        created_at=row["createdAt"],
        updated_at=row["updatedAt"],
        provider=row.get("provider"),
        external_id=row.get("externalId"),
        region=row.get("region"),
        last_scanned=row.get("lastScanned"),
        scan_id=row.get("scanId"),
        metadata=dict(row.get("metadata") or {}),
        workflow_status=row.get("workflowStatus"),
        owner_team=row.get("ownerTeam"),
        assigned_to=row.get("assignedTo"),
        criticality=str(row.get("criticality") or "medium"),
        data_lifetime_years=row.get("dataLifetimeYears"),
        exposure=str(row.get("exposure") or "unknown"),
        migration_due_at=row.get("migrationDueAt"),
        exception=row.get("exception"),
    )


def _action_from_api(data: Mapping[str, Any]) -> MigrationAction:
    return MigrationAction(
        id=data["id"], project_id=data["projectId"], asset_id=data.get("assetId"),
        title=data["title"], provider=data["provider"], source_algorithm=data.get("sourceAlgorithm"),
        target_algorithm=data["targetAlgorithm"], execution_mode=data["executionMode"], status=data["status"],
        assignee=data.get("assignee"), due_at=data.get("dueAt"), before_scan_id=data.get("beforeScanId"),
        after_scan_id=data.get("afterScanId"), downgrade_protected=data.get("downgradeProtected"),
        dependent_credentials_rotated=bool(data.get("dependentCredentialsRotated", False)),
        validation=dict(data.get("validation") or {}), exception=data.get("exception"),
        external_issue_url=data.get("externalIssueUrl"), created_at=data.get("createdAt", ""), updated_at=data.get("updatedAt", ""),
    )


def _project_from_api(data: Mapping[str, Any]) -> MigrationProject:
    return MigrationProject(
        id=data["id"], name=data["name"], description=data.get("description", ""),
        framework=data.get("framework", ""), track=data.get("track", "both"), status=data.get("status", "planned"),
        target_date=data.get("targetDate"), source_scan_id=data.get("sourceScanId"),
        metadata=dict(data.get("metadata") or {}), created_at=data.get("createdAt", ""), updated_at=data.get("updatedAt", ""),
        actions=[_action_from_api(action) for action in data.get("actions", [])],
    )


def _row_to_key(row: Mapping[str, Any]) -> Key:
    return Key(
        id=row["id"],
        provider=row["provider"],
        external_id=row["externalId"],
        algorithm=row["algorithm"],
        pq_safe=bool(row.get("pqSafe", False)),
        risk=row["risk"],
        first_seen=row["firstSeen"],
        last_seen=row["lastSeen"],
        region=row.get("region"),
        key_size=row.get("keySize"),
        key_usage=row.get("keyUsage"),
        scan_id=row.get("scanId"),
        metadata=dict(row.get("metadata") or {}),
    )


class HybridKeysResource:
    """Operations under ``/v1/hybrid-keys``, ``/v1/sign``, and ``/v1/verify``.

    A *hybrid key* is a PostQ-managed signing key whose public component is a
    composite of an Ed25519 public key and an ML-DSA public key. Every signature
    produced by :meth:`sign` validates only when BOTH halves verify.
    """

    def __init__(self, client: PostQ) -> None:
        self._client = client

    def create(
        self,
        *,
        name: str,
        algorithm: HybridAlgorithm = "mldsa65+ed25519",
        kek_provider: Optional[str] = None,
        key_provider: str = "postq-managed",
        pq_provider: str = "postq-managed",
        attestation_policy_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> HybridKeyWithPublic:
        """``POST /v1/hybrid-keys`` — create a new managed signing key."""
        body = self._client._request(
            "POST",
            "/v1/hybrid-keys",
            json=_strip_none(
                {
                    "name": name,
                    "algorithm": algorithm,
                    "kekProvider": kek_provider,
                    "keyProvider": key_provider,
                    "pqProvider": pq_provider,
                    "attestationPolicyId": attestation_policy_id,
                    "metadata": dict(metadata or {}),
                }
            ),
        )
        return _row_to_hybrid_key_with_public(body["data"])

    def list(
        self,
        *,
        limit: int = 20,
        cursor: Optional[str] = None,
        algorithm: Optional[HybridAlgorithm] = None,
        include_revoked: bool = False,
    ) -> "Page[HybridKey]":
        """``GET /v1/hybrid-keys`` — one page of managed signing keys."""
        params = _strip_none(
            {
                "limit": limit,
                "cursor": cursor,
                "algorithm": algorithm,
                "includeRevoked": "true" if include_revoked else None,
            }
        )
        body = self._client._request("GET", "/v1/hybrid-keys", params=params)
        return Page(
            data=[_row_to_hybrid_key(row) for row in body["data"]],
            pagination=_pagination(body, limit),
        )

    def get(self, key_id: str) -> HybridKeyWithPublic:
        """``GET /v1/hybrid-keys/:id`` — fetch one key including public bytes."""
        body = self._client._request("GET", f"/v1/hybrid-keys/{key_id}")
        return _row_to_hybrid_key_with_public(body["data"])

    def revoke(self, key_id: str) -> "dict[str, Any]":
        """``DELETE /v1/hybrid-keys/:id`` — revoke (soft-delete) a key."""
        body = self._client._request("DELETE", f"/v1/hybrid-keys/{key_id}")
        return body["data"]

    def rotate(
        self,
        key_id: str,
        *,
        name: Optional[str] = None,
    ) -> HybridKeyWithPublic:
        """``POST /v1/hybrid-keys/:id/rotate`` — generate a new keypair under
        the same logical key. Old material is retained for verification."""
        body = self._client._request(
            "POST",
            f"/v1/hybrid-keys/{key_id}/rotate",
            json=_strip_none({"name": name}),
        )
        return _row_to_hybrid_key_with_public(body["data"])

    def audit(
        self,
        key_id: str,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> "Page[HybridKeyAuditEntry]":
        """``GET /v1/hybrid-keys/:id/audit`` — recent ledger entries for this key."""
        params = _strip_none({"limit": limit, "cursor": cursor})
        body = self._client._request(
            "GET", f"/v1/hybrid-keys/{key_id}/audit", params=params
        )
        effective_limit = limit or 25
        return Page(
            data=[_row_to_audit_entry(row) for row in body["data"]],
            pagination=_pagination(body, effective_limit),
        )

    def sign(
        self,
        *,
        key_id: str,
        payload: Union[bytes, str],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> HybridSignResult:
        """``POST /v1/sign`` — sign ``payload`` with the named hybrid key."""
        body = self._client._request(
            "POST",
            "/v1/sign",
            json={
                "keyId": key_id,
                "payload": _b64(payload),
                "metadata": dict(metadata or {}),
            },
        )
        d = body["data"]
        return HybridSignResult(
            key_id=d["keyId"],
            algorithm=d["algorithm"],
            signature=d["signature"],
            public_key=d["publicKey"],
            payload_sha256=d["payloadSha256"],
            payload_size=d["payloadSize"],
        )

    def verify(
        self,
        *,
        payload: Union[bytes, str],
        signature: str,
        key_id: Optional[str] = None,
        public_key: Optional[str] = None,
    ) -> HybridVerifyResult:
        """``POST /v1/verify`` — verify a composite signature."""
        if not key_id and not public_key:
            raise PostQConfigError("verify() requires either key_id or public_key")
        body = self._client._request(
            "POST",
            "/v1/verify",
            json=_strip_none(
                {
                    "keyId": key_id,
                    "publicKey": public_key,
                    "payload": _b64(payload),
                    "signature": signature,
                }
            ),
        )
        d = body["data"]
        return HybridVerifyResult(
            ok=bool(d["ok"]),
            algorithm=d["algorithm"],
            classical_ok=bool(d["classicalOk"]),
            pq_ok=bool(d["pqOk"]),
        )


def _b64(payload: Union[bytes, str]) -> str:
    import base64

    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    return base64.b64encode(raw).decode("ascii")


def _row_to_hybrid_key(row: Mapping[str, Any]) -> HybridKey:
    return HybridKey(
        id=row["id"],
        name=row["name"],
        algorithm=row["algorithm"],
        created_at=row["createdAt"],
        revoked_at=row.get("revokedAt"),
        last_used_at=row.get("lastUsedAt"),
        metadata=dict(row.get("metadata") or {}),
    )


def _row_to_hybrid_key_with_public(row: Mapping[str, Any]) -> HybridKeyWithPublic:
    return HybridKeyWithPublic(
        id=row["id"],
        name=row["name"],
        algorithm=row["algorithm"],
        created_at=row["createdAt"],
        revoked_at=row.get("revokedAt"),
        last_used_at=row.get("lastUsedAt"),
        metadata=dict(row.get("metadata") or {}),
        public_key=row["publicKey"],
    )


class PoliciesResource:
    """Operations under ``/v1/policies`` — org-level policy rules enforced
    by ``POST /v1/sign``."""

    def __init__(self, client: PostQ) -> None:
        self._client = client

    def list(self) -> "list[Policy]":
        """``GET /v1/policies`` — all policies for the org (seeds defaults
        on first call)."""
        body = self._client._request("GET", "/v1/policies")
        return [_row_to_policy(row) for row in body["data"]]

    def get(self, policy_id: str) -> Policy:
        body = self._client._request("GET", f"/v1/policies/{policy_id}")
        return _row_to_policy(body["data"])

    def create(
        self,
        *,
        name: str,
        action: str,
        rule: Mapping[str, Any],
        description: Optional[str] = None,
        enabled: bool = True,
        environments: Sequence[str] = (),
    ) -> Policy:
        """``POST /v1/policies`` — create a new policy."""
        body = self._client._request(
            "POST",
            "/v1/policies",
            json=_strip_none(
                {
                    "name": name,
                    "description": description,
                    "action": action,
                    "enabled": enabled,
                    "environments": list(environments),
                    "rule": dict(rule),
                }
            ),
        )
        return _row_to_policy(body["data"])

    def update(
        self,
        policy_id: str,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        action: Optional[str] = None,
        enabled: Optional[bool] = None,
        environments: Optional[Sequence[str]] = None,
        rule: Optional[Mapping[str, Any]] = None,
    ) -> Policy:
        """``PATCH /v1/policies/:id``."""
        body = self._client._request(
            "PATCH",
            f"/v1/policies/{policy_id}",
            json=_strip_none(
                {
                    "name": name,
                    "description": description,
                    "action": action,
                    "enabled": enabled,
                    "environments": list(environments) if environments is not None else None,
                    "rule": dict(rule) if rule is not None else None,
                }
            ),
        )
        return _row_to_policy(body["data"])

    def delete(self, policy_id: str) -> "dict[str, Any]":
        """``DELETE /v1/policies/:id``."""
        body = self._client._request("DELETE", f"/v1/policies/{policy_id}")
        return body["data"]


class LedgerResource:
    """Operations under ``/v1/ledger`` — read the tamper-evident hash chain
    of signing events, fetch checkpoints / inclusion proofs, and download
    verifiable bundles."""

    def __init__(self, client: PostQ) -> None:
        self._client = client

    def entries(
        self,
        *,
        since: Optional[int] = None,
        limit: Optional[int] = None,
        event_type: Optional[str] = None,
    ) -> "Page[LedgerEntry]":
        """``GET /v1/ledger/entries`` — one page of ledger entries."""
        params = _strip_none(
            {"since": since, "limit": limit, "eventType": event_type}
        )
        body = self._client._request("GET", "/v1/ledger/entries", params=params)
        effective_limit = limit or 100
        return Page(
            data=[_row_to_ledger_entry(row) for row in body["data"]],
            pagination=_pagination(body, effective_limit),
        )

    def append(
        self,
        *,
        name: str,
        message: Optional[str] = None,
        subject_id: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> LedgerEntry:
        """``POST /v1/ledger/entries`` — append a custom entry to the org ledger."""
        body = self._client._request(
            "POST",
            "/v1/ledger/entries",
            json=_strip_none(
                {
                    "name": name,
                    "message": message,
                    "subjectId": subject_id,
                    "data": dict(data) if data is not None else None,
                }
            ),
        )
        return _row_to_ledger_entry(body["data"])

    def checkpoints(
        self,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> "Page[LedgerCheckpoint]":
        """``GET /v1/ledger/checkpoints`` — list signed Merkle-root checkpoints."""
        params = _strip_none({"limit": limit, "cursor": cursor})
        body = self._client._request("GET", "/v1/ledger/checkpoints", params=params)
        effective_limit = limit or 20
        return Page(
            data=[_row_to_checkpoint(row) for row in body["data"]],
            pagination=_pagination(body, effective_limit),
        )

    def latest_checkpoint(self) -> Optional[LedgerCheckpoint]:
        """``GET /v1/ledger/checkpoints/latest``. Returns ``None`` if the
        ledger has not been sealed yet."""
        body = self._client._request("GET", "/v1/ledger/checkpoints/latest")
        data = body.get("data")
        return _row_to_checkpoint(data) if data else None

    def seal(self) -> LedgerSealResult:
        """``POST /v1/ledger/seal`` — force a new checkpoint over current entries."""
        body = self._client._request("POST", "/v1/ledger/seal")
        d = body["data"]
        return LedgerSealResult(
            tree_size=int(d["treeSize"]),
            merkle_root_hex=str(d["merkleRootHex"]),
            signature_base64=str(d["signatureBase64"]),
            signing_key_id=str(d["signingKeyId"]),
            created_at=str(d["createdAt"]),
            fresh=bool(d.get("fresh", True)),
        )

    def proof(self, entry_id: str) -> LedgerInclusionProof:
        """``GET /v1/ledger/proof/:entryId`` — Merkle inclusion proof
        (auto-seals if no checkpoint covers the entry yet)."""
        body = self._client._request("GET", f"/v1/ledger/proof/{entry_id}")
        d = body["data"]
        return LedgerInclusionProof(
            entry_id=str(d["entryId"]),
            leaf_index=int(d["leafIndex"]),
            leaf_hash_hex=str(d["leafHashHex"]),
            proof_hex=list(d.get("proofHex") or []),
            checkpoint=dict(d["checkpoint"]),
        )

    def bundle(self) -> LedgerBundle:
        """``GET /v1/ledger/bundle`` — full verifiable bundle: entries +
        checkpoints + signing keys."""
        body = self._client._request("GET", "/v1/ledger/bundle")
        d = body["data"]
        return LedgerBundle(
            version=int(d.get("version", 1)),
            org=str(d.get("org") or ""),
            generated_at=str(d.get("generatedAt", "")),
            entries=list(d.get("entries") or []),
            checkpoints=list(d.get("checkpoints") or []),
            signing_keys=list(d.get("signingKeys") or []),
        )


class VaultResource:
    """Operations under ``/v1/vault`` — manage per-org KMS settings (BYOK).
    The encrypted secret is never returned in plaintext."""

    def __init__(self, client: PostQ) -> None:
        self._client = client

    def get_settings(self) -> Optional[VaultSettings]:
        """``GET /v1/vault/settings`` — current settings, or ``None``."""
        body = self._client._request("GET", "/v1/vault/settings")
        data = body.get("data")
        return _row_to_vault_settings(data) if data else None

    def put_settings(
        self,
        *,
        default_kek_provider: Optional[str] = None,
        kek_provider: Optional[str] = None,
        aws: Optional[Mapping[str, Any]] = None,
        azure: Optional[Mapping[str, Any]] = None,
        gcp: Optional[Mapping[str, Any]] = None,
    ) -> VaultSettingsSaveResult:
        """``PUT /v1/vault/settings`` — set or update KMS settings."""
        provider = default_kek_provider or kek_provider
        if not provider:
            raise PostQConfigError("default_kek_provider is required")
        body = self._client._request(
            "PUT",
            "/v1/vault/settings",
            json=_strip_none(
                {
                    "defaultKekProvider": provider,
                    "aws": dict(aws) if aws is not None else None,
                    "azure": dict(azure) if azure is not None else None,
                    "gcp": dict(gcp) if gcp is not None else None,
                }
            ),
        )
        return VaultSettingsSaveResult(saved_at=str(body["data"]["savedAt"]))

    def clear_settings(self) -> "dict[str, Any]":
        """``DELETE /v1/vault/settings`` — revert to env-managed KEK."""
        body = self._client._request("DELETE", "/v1/vault/settings")
        return body["data"]


# ── row mappers for new resources ────────────────────────────────────────────


def _row_to_audit_entry(row: Mapping[str, Any]) -> HybridKeyAuditEntry:
    return HybridKeyAuditEntry(
        id=str(row["id"]),
        operation=str(row["operation"]),
        payload_sha256=str(row["payloadSha256"]),
        payload_size=int(row["payloadSize"]),
        verified=row.get("verified"),
        created_at=str(row["createdAt"]),
        metadata=dict(row.get("metadata") or {}),
    )


def _row_to_policy(row: Mapping[str, Any]) -> Policy:
    rule_raw = row.get("rule") or {}
    rule = PolicyRule(
        match_operation=str(rule_raw.get("matchOperation") or "*"),
        algorithm_in=rule_raw.get("algorithmIn"),
        algorithm_not_in=rule_raw.get("algorithmNotIn"),
        require_hybrid=bool(rule_raw.get("requireHybrid", False)),
        min_pq_level=rule_raw.get("minPqLevel"),
    )
    return Policy(
        id=str(row["id"]),
        name=str(row["name"]),
        description=str(row.get("description") or ""),
        action=str(row["action"]),
        enabled=bool(row.get("enabled", True)),
        environments=list(row.get("environments") or []),
        rule=rule,
        created_at=str(row["createdAt"]),
        updated_at=str(row["updatedAt"]),
    )


def _row_to_ledger_entry(row: Mapping[str, Any]) -> LedgerEntry:
    return LedgerEntry(
        id=str(row["id"]),
        seq=int(row["seq"]),
        prev_hash_hex=str(row.get("prevHashHex") or ""),
        entry_hash_hex=str(row.get("entryHashHex") or ""),
        payload=dict(row.get("payload") or {}),
        event_type=str(row["eventType"]),
        created_at=str(row["createdAt"]),
        actor_id=row.get("actorId"),
        subject_id=row.get("subjectId"),
    )


def _row_to_checkpoint(row: Mapping[str, Any]) -> LedgerCheckpoint:
    return LedgerCheckpoint(
        id=str(row["id"]),
        tree_size=int(row["treeSize"]),
        merkle_root_hex=str(row["merkleRootHex"]),
        signature_base64=str(row["signatureBase64"]),
        signing_key_id=str(row["signingKeyId"]),
        published_to=list(row.get("publishedTo") or []),
        created_at=str(row["createdAt"]),
    )


def _row_to_vault_settings(row: Mapping[str, Any]) -> VaultSettings:
    return VaultSettings(
        default_kek_provider=str(row["defaultKekProvider"]),
        aws=dict(row["aws"]) if row.get("aws") else None,
        azure=dict(row["azure"]) if row.get("azure") else None,
        gcp=dict(row["gcp"]) if row.get("gcp") else None,
        updated_at=row.get("updatedAt"),
    )
