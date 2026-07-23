"""Tests for the PostQ SDK against a mocked API."""
from __future__ import annotations

import pytest
import responses

from postq import (
    Finding,
    PostQ,
    PostQAuthError,
    PostQConfigError,
    PostQError,
    PostQNotFoundError,
    PostQRateLimitError,
    PostQServerError,
)


# ── constructor ─────────────────────────────────────────────────────────────


def test_constructor_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("POSTQ_API_KEY", raising=False)
    with pytest.raises(PostQConfigError):
        PostQ()


def test_constructor_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POSTQ_API_KEY", "pq_live_envtest")
    pq = PostQ()
    assert pq._api_key == "pq_live_envtest"


def test_constructor_explicit_key_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POSTQ_API_KEY", "pq_live_env")
    pq = PostQ(api_key="pq_live_explicit")
    assert pq._api_key == "pq_live_explicit"


# ── submit ──────────────────────────────────────────────────────────────────


@responses.activate
def test_submit_scan_returns_url() -> None:
    responses.add(
        responses.POST,
        "https://api.postq.dev/v1/scans",
        json={
            "success": True,
            "data": {
                "id": "abc-123",
                "createdAt": "2026-04-23T12:00:00Z",
                "url": "https://app.postq.dev/scans/abc-123",
            },
        },
        status=201,
    )

    pq = PostQ(api_key="pq_live_test")
    result = pq.scans.submit(
        type="url",
        target="example.com",
        risk_score=85,
        risk_level="High",
        findings=[Finding(severity="high", title="RSA-2048 public key")],
    )

    assert result.id == "abc-123"
    assert result.url.endswith("/scans/abc-123")

    # Validate the request
    sent = responses.calls[0].request
    assert sent.headers["Authorization"] == "Bearer pq_live_test"
    body = sent.body
    assert b'"type": "url"' in body
    assert b'"source": "sdk"' in body


@responses.activate
def test_submit_accepts_dict_findings() -> None:
    responses.add(
        responses.POST,
        "https://api.postq.dev/v1/scans",
        json={"success": True, "data": {"id": "x", "createdAt": "x", "url": "x"}},
        status=201,
    )
    pq = PostQ(api_key="pq_live_test")
    result = pq.scans.submit(
        type="url",
        target="a.com",
        risk_score=0,
        risk_level="Safe",
        findings=[{"severity": "info", "title": "All good"}],
    )
    assert result.id == "x"


# ── list ────────────────────────────────────────────────────────────────────


@responses.activate
def test_list_scans() -> None:
    responses.add(
        responses.GET,
        "https://api.postq.dev/v1/scans",
        json={
            "success": True,
            "data": [
                {
                    "id": "s1",
                    "type": "url",
                    "target": "a.com",
                    "source": "cli",
                    "riskScore": 50,
                    "riskLevel": "Medium",
                    "findingsCount": 2,
                    "createdAt": "2026-04-22T00:00:00Z",
                    "url": "https://app.postq.dev/scans/s1",
                },
            ],
            "pagination": {"limit": 20, "nextCursor": None},
        },
        status=200,
    )

    pq = PostQ(api_key="pq_live_test")
    page = pq.scans.list(limit=20)
    assert len(page) == 1
    assert page.data[0].id == "s1"
    assert page.data[0].risk_level == "Medium"
    # Parity with the JS/.NET SDKs: list() returns a Page with pagination.
    assert page.pagination.limit == 20
    assert page.pagination.next_cursor is None
    # Back-compat: a Page is still iterable/indexable like the old bare list.
    assert page[0].id == "s1"
    assert [s.id for s in page] == ["s1"]


@responses.activate
def test_iter_all_walks_cursor() -> None:
    page1 = {
        "success": True,
        "data": [
            {
                "id": "s1", "type": "url", "target": "a.com", "source": "cli",
                "riskScore": 10, "riskLevel": "Low", "findingsCount": 1,
                "createdAt": "2026-04-22T01:00:00Z",
                "url": "https://app.postq.dev/scans/s1",
            },
        ],
        "pagination": {"limit": 1, "nextCursor": "2026-04-22T01:00:00Z"},
    }
    page2 = {
        "success": True,
        "data": [
            {
                "id": "s2", "type": "url", "target": "b.com", "source": "cli",
                "riskScore": 0, "riskLevel": "Safe", "findingsCount": 0,
                "createdAt": "2026-04-22T00:00:00Z",
                "url": "https://app.postq.dev/scans/s2",
            },
        ],
        "pagination": {"limit": 1, "nextCursor": None},
    }
    responses.add(responses.GET, "https://api.postq.dev/v1/scans", json=page1, status=200)
    responses.add(responses.GET, "https://api.postq.dev/v1/scans", json=page2, status=200)

    pq = PostQ(api_key="pq_live_test")
    ids = [s.id for s in pq.scans.iter_all(page_size=1)]
    assert ids == ["s1", "s2"]


# ── error mapping ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "status,exc_type",
    [
        (401, PostQAuthError),
        (404, PostQNotFoundError),
        (429, PostQRateLimitError),
        (500, PostQServerError),
        (503, PostQServerError),
        (400, PostQError),
    ],
)
@responses.activate
def test_error_status_mapping(status: int, exc_type: type) -> None:
    responses.add(
        responses.GET,
        "https://api.postq.dev/v1/scans",
        json={"success": False, "error": f"failed {status}"},
        status=status,
    )
    pq = PostQ(api_key="pq_live_test", max_retries=0)
    with pytest.raises(exc_type):
        pq.scans.list()


# ── health ──────────────────────────────────────────────────────────────────


@responses.activate
def test_health_returns_status() -> None:
    responses.add(
        responses.GET,
        "https://api.postq.dev/health",
        json={"status": "ok"},
        status=200,
    )
    assert PostQ(api_key="pq_live_test").health()["status"] == "ok"


# ── v0.6 contract surfaces ────────────────────────────────────────────────


@responses.activate
def test_run_cloud_scan() -> None:
    responses.add(
        responses.POST,
        "https://api.postq.dev/v1/scans/cloud",
        json={
            "success": True,
            "data": {
                "id": "cloud-1",
                "createdAt": "2026-07-16T00:00:00Z",
                "provider": "aws",
                "target": "123456789012",
                "mode": "live",
                "riskScore": 80,
                "riskLevel": "Critical",
                "findingsCount": 4,
                "resourcesCount": 10,
                "summary": {
                    "totalEndpoints": 10,
                    "quantumVulnerable": 4,
                    "hybridEnabled": 0,
                    "pqReady": 6,
                },
                "url": "https://app.postq.dev/scans/cloud-1",
            },
        },
        status=201,
    )
    result = PostQ(api_key="pq_live_test").scans.run_cloud(
        provider="aws",
        target="123456789012",
        aws={"regions": ["us-east-1"]},
    )
    assert result.provider == "aws"
    assert result.summary.quantum_vulnerable == 4


@responses.activate
def test_hybrid_create_sends_multicloud_provider_fields() -> None:
    responses.add(
        responses.POST,
        "https://api.postq.dev/v1/hybrid-keys",
        json={
            "success": True,
            "data": {
                "id": "key-1",
                "name": "release",
                "algorithm": "mldsa65+ecdsa-p256",
                "createdAt": "2026-07-16T00:00:00Z",
                "publicKey": "{}",
            },
        },
        status=201,
    )
    PostQ(api_key="pq_live_test").hybrid_keys.create(
        name="release",
        algorithm="mldsa65+ecdsa-p256",
        kek_provider="gcp-kms",
        key_provider="gcp-kms",
    )
    body = responses.calls[0].request.body
    assert b'"kekProvider": "gcp-kms"' in body
    assert b'"keyProvider": "gcp-kms"' in body


@responses.activate
def test_policy_maps_enforcement_contract() -> None:
    policy = {
        "id": "policy-1",
        "name": "production hybrid",
        "description": "Require hybrid",
        "action": "enforce",
        "enabled": True,
        "environments": ["production"],
        "rule": {
            "matchOperation": "sign",
            "algorithmIn": None,
            "algorithmNotIn": None,
            "requireHybrid": True,
            "minPqLevel": 3,
        },
        "createdAt": "2026-07-16T00:00:00Z",
        "updatedAt": "2026-07-16T00:00:00Z",
    }
    responses.add(
        responses.GET,
        "https://api.postq.dev/v1/policies",
        json={"success": True, "data": [policy]},
    )
    result = PostQ(api_key="pq_live_test").policies.list()[0]
    assert result.action == "enforce"
    assert result.environments == ["production"]
    assert result.rule.require_hybrid is True


@responses.activate
def test_ledger_maps_hash_chain_and_seal_contract() -> None:
    responses.add(
        responses.GET,
        "https://api.postq.dev/v1/ledger/entries",
        json={
            "success": True,
            "data": [{
                "id": "entry-1",
                "seq": 0,
                "prevHashHex": "00",
                "entryHashHex": "11",
                "payload": {"name": "release"},
                "eventType": "custom.event",
                "subjectId": None,
                "actorId": None,
                "createdAt": "2026-07-16T00:00:00Z",
            }],
            "pagination": {"limit": 100, "nextCursor": None},
        },
    )
    responses.add(
        responses.POST,
        "https://api.postq.dev/v1/ledger/seal",
        json={
            "success": True,
            "data": {
                "treeSize": 1,
                "merkleRootHex": "aa",
                "signatureBase64": "c2ln",
                "signingKeyId": "key-1",
                "createdAt": "2026-07-16T00:00:00Z",
                "fresh": True,
            },
        },
    )
    pq = PostQ(api_key="pq_live_test")
    page = pq.ledger.entries()
    assert page[0].entry_hash_hex == "11"
    seal = pq.ledger.seal()
    assert seal.tree_size == 1
    assert seal.fresh is True


@responses.activate
def test_vault_uses_default_provider_and_save_envelope() -> None:
    responses.add(
        responses.PUT,
        "https://api.postq.dev/v1/vault/settings",
        json={"success": True, "data": {"savedAt": "2026-07-16T00:00:00Z"}},
    )
    result = PostQ(api_key="pq_live_test").vault.put_settings(
        default_kek_provider="gcp-kms",
        gcp={
            "kekKeyName": "projects/acme/locations/global/keyRings/postq/cryptoKeys/kek"
        },
    )
    assert result.saved_at == "2026-07-16T00:00:00Z"
    body = responses.calls[0].request.body
    assert b'"defaultKekProvider": "gcp-kms"' in body


@responses.activate
def test_migrations_create_and_update_contract() -> None:
    project = {
        "id": "project-1", "name": "2030 migration", "description": "",
        "framework": "eo-14412", "track": "both", "status": "planned",
        "targetDate": "2030-12-31", "sourceScanId": None, "metadata": {},
        "createdAt": "2026-07-23T00:00:00Z", "updatedAt": "2026-07-23T00:00:00Z",
    }
    responses.add(responses.POST, "https://api.postq.dev/v1/migrations", json={"success": True, "data": project}, status=201)
    responses.add(responses.PATCH, "https://api.postq.dev/v1/migrations/project-1", json={"success": True, "data": {**project, "status": "active"}})
    pq = PostQ(api_key="pq_live_test")
    created = pq.migrations.create(name="2030 migration", include_risk=["CRITICAL", "HIGH"])
    assert created.id == "project-1"
    assert b'"includeRisk": ["CRITICAL", "HIGH"]' in responses.calls[0].request.body
    assert pq.migrations.update("project-1", status="active").status == "active"
