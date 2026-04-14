"""Tests for the PostQ Python SDK."""

from __future__ import annotations

import json
import base64
from unittest.mock import MagicMock, patch

import pytest

from postq import PostQ, PostQError, PostQConfigError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SIGN_RESPONSE = {
    "signature": "base64-combined-signature",
    "classical_sig": "base64-ed25519-signature",
    "pq_sig": "base64-dilithium3-signature",
    "algorithm": "dilithium3+ed25519",
    "key_id": "vault://signing/production",
    "timestamp": "2026-04-05T12:00:00Z",
    "policy_compliant": True,
}

VERIFY_RESPONSE = {
    "valid": True,
    "classical_valid": True,
    "pq_valid": True,
    "algorithm": "dilithium3+ed25519",
    "key_id": "vault://signing/production",
}

LIST_KEYS_RESPONSE = {
    "keys": [
        {
            "id": "vault://signing/production",
            "algorithm": "dilithium3+ed25519",
            "created_at": "2026-01-15T08:00:00Z",
            "status": "active",
            "backend": "azure-key-vault",
            "pq_ready": True,
        },
        {
            "id": "vault://signing/staging",
            "algorithm": "ed25519",
            "created_at": "2025-06-01T10:00:00Z",
            "status": "active",
            "backend": "hashicorp-vault",
            "pq_ready": False,
        },
    ]
}

SCAN_RESPONSE = {
    "scan_id": "scan_abc123",
    "status": "completed",
    "summary": {
        "total_endpoints": 4184,
        "quantum_vulnerable": 3012,
        "risk_score": 72,
        "recommendation": "Begin hybrid migration for signing keys",
    },
}


def _make_mock_response(body: dict, status: int = 200) -> MagicMock:
    mock = MagicMock()
    mock.status = status
    mock.data = json.dumps(body).encode("utf-8")
    return mock


@pytest.fixture
def pq(monkeypatch) -> PostQ:
    client = PostQ(api_key="pq_live_sk_test", base_url="https://api.example.com/v1")
    return client


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


def test_constructor_raises_on_empty_api_key():
    with pytest.raises(PostQConfigError):
        PostQ(api_key="")


def test_constructor_raises_on_whitespace_api_key():
    with pytest.raises(PostQConfigError):
        PostQ(api_key="   ")


def test_constructor_accepts_valid_api_key():
    client = PostQ(api_key="pq_live_sk_test")
    assert client is not None


# ---------------------------------------------------------------------------
# sign()
# ---------------------------------------------------------------------------


def test_sign_sends_post_request_and_returns_sign_response(pq: PostQ):
    mock_resp = _make_mock_response(SIGN_RESPONSE)
    with patch.object(pq._http, "request", return_value=mock_resp) as mock_req:
        result = pq.sign(
            payload=b"Hello Quantum World",
            algorithm="dilithium3+ed25519",
            key_id="vault://signing/production",
        )

    mock_req.assert_called_once()
    args, kwargs = mock_req.call_args
    assert args[0] == "POST"
    assert args[1].endswith("/sign")
    sent_body = json.loads(kwargs["body"])
    assert sent_body["algorithm"] == "dilithium3+ed25519"
    assert sent_body["key_id"] == "vault://signing/production"
    # payload must be base64
    assert base64.b64decode(sent_body["payload"]) == b"Hello Quantum World"

    assert result.algorithm == "dilithium3+ed25519"
    assert result.policy_compliant is True


def test_sign_includes_context_when_provided(pq: PostQ):
    mock_resp = _make_mock_response(SIGN_RESPONSE)
    with patch.object(pq._http, "request", return_value=mock_resp) as mock_req:
        pq.sign(
            payload=b"data",
            algorithm="dilithium3+ed25519",
            key_id="vault://signing/production",
            context={"service": "payment-api", "environment": "production"},
        )

    _, kwargs = mock_req.call_args
    body = json.loads(kwargs["body"])
    assert body["context"] == {"service": "payment-api", "environment": "production"}


def test_sign_raises_postq_error_on_401(pq: PostQ):
    mock_resp = _make_mock_response({"code": "UNAUTHORIZED", "message": "Invalid API key"}, status=401)
    with patch.object(pq._http, "request", return_value=mock_resp):
        with pytest.raises(PostQError) as exc_info:
            pq.sign(
                payload=b"data",
                algorithm="dilithium3+ed25519",
                key_id="vault://signing/production",
            )
    assert exc_info.value.status_code == 401
    assert exc_info.value.code == "UNAUTHORIZED"


def test_sign_sets_authorization_header(pq: PostQ):
    mock_resp = _make_mock_response(SIGN_RESPONSE)
    with patch.object(pq._http, "request", return_value=mock_resp) as mock_req:
        pq.sign(payload=b"data", algorithm="dilithium3+ed25519", key_id="k1")

    _, kwargs = mock_req.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer pq_live_sk_test"


# ---------------------------------------------------------------------------
# verify()
# ---------------------------------------------------------------------------


def test_verify_sends_post_request_and_returns_verify_response(pq: PostQ):
    mock_resp = _make_mock_response(VERIFY_RESPONSE)
    with patch.object(pq._http, "request", return_value=mock_resp) as mock_req:
        result = pq.verify(
            payload=b"Hello Quantum World",
            signature="base64-combined-signature",
            key_id="vault://signing/production",
        )

    args, kwargs = mock_req.call_args
    assert args[0] == "POST"
    assert args[1].endswith("/verify")
    body = json.loads(kwargs["body"])
    assert body["signature"] == "base64-combined-signature"
    assert body["key_id"] == "vault://signing/production"

    assert result.valid is True
    assert result.classical_valid is True
    assert result.pq_valid is True


def test_verify_raises_postq_error_on_invalid_signature(pq: PostQ):
    mock_resp = _make_mock_response(
        {"code": "INVALID_SIGNATURE", "message": "Signature mismatch"}, status=422
    )
    with patch.object(pq._http, "request", return_value=mock_resp):
        with pytest.raises(PostQError) as exc_info:
            pq.verify(payload=b"data", signature="bad-sig", key_id="k1")
    assert exc_info.value.status_code == 422


# ---------------------------------------------------------------------------
# list_keys()
# ---------------------------------------------------------------------------


def test_list_keys_sends_get_request_and_returns_list(pq: PostQ):
    mock_resp = _make_mock_response(LIST_KEYS_RESPONSE)
    with patch.object(pq._http, "request", return_value=mock_resp) as mock_req:
        result = pq.list_keys()

    args, _ = mock_req.call_args
    assert args[0] == "GET"
    assert args[1].endswith("/keys")

    assert len(result.keys) == 2
    assert result.keys[0].pq_ready is True
    assert result.keys[1].pq_ready is False
    assert result.keys[0].id == "vault://signing/production"


# ---------------------------------------------------------------------------
# scan()
# ---------------------------------------------------------------------------


def test_scan_sends_post_request_and_returns_scan_response(pq: PostQ):
    mock_resp = _make_mock_response(SCAN_RESPONSE)
    with patch.object(pq._http, "request", return_value=mock_resp) as mock_req:
        result = pq.scan(
            targets=["kubernetes://production", "azure://subscription-id"],
            depth="full",
            include=["tls", "signing", "encryption"],
        )

    args, kwargs = mock_req.call_args
    assert args[0] == "POST"
    assert args[1].endswith("/scan")
    body = json.loads(kwargs["body"])
    assert body["targets"] == ["kubernetes://production", "azure://subscription-id"]
    assert body["depth"] == "full"

    assert result.scan_id == "scan_abc123"
    assert result.status == "completed"
    assert result.summary is not None
    assert result.summary.risk_score == 72


def test_scan_defaults_depth_and_include(pq: PostQ):
    mock_resp = _make_mock_response(SCAN_RESPONSE)
    with patch.object(pq._http, "request", return_value=mock_resp) as mock_req:
        pq.scan(targets=["kubernetes://production"])

    _, kwargs = mock_req.call_args
    body = json.loads(kwargs["body"])
    assert body["depth"] == "full"
    assert body["include"] == ["tls", "signing", "encryption"]


# ---------------------------------------------------------------------------
# Network errors
# ---------------------------------------------------------------------------


def test_network_error_raises_postq_error(pq: PostQ):
    import urllib3.exceptions

    with patch.object(pq._http, "request", side_effect=urllib3.exceptions.HTTPError("ECONNREFUSED")):
        with pytest.raises(PostQError) as exc_info:
            pq.list_keys()
    assert exc_info.value.status_code == 0
