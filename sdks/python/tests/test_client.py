"""Tests for the PostQ SDK against a mocked API."""
from __future__ import annotations

import os

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
    items = pq.scans.list(limit=20)
    assert len(items) == 1
    assert items[0].id == "s1"
    assert items[0].risk_level == "Medium"


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
