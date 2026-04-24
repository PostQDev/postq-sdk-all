"""PostQ HTTP client."""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Literal, Optional

import urllib3

from .errors import PostQConfigError, PostQError
from .models import ListKeysResponse, ScanResponse, SignResponse, VerifyResponse

_DEFAULT_BASE_URL = "https://api.postq.dev/v1"
_DEFAULT_ENVIRONMENT = "production"


class PostQ:
    """
    PostQ SDK client.

    Example::

        from postq import PostQ

        pq = PostQ(api_key="pq_live_sk_...")

        sig = pq.sign(
            payload=b"Hello Quantum World",
            algorithm="dilithium3+ed25519",
            key_id="vault://signing/production",
        )

        is_valid = pq.verify(
            payload=b"Hello Quantum World",
            signature=sig.signature,
            key_id="vault://signing/production",
        )
    """

    def __init__(
        self,
        api_key: str,
        environment: Literal["production", "staging", "development"] = _DEFAULT_ENVIRONMENT,
        base_url: str = _DEFAULT_BASE_URL,
    ) -> None:
        if not api_key or not api_key.strip():
            raise PostQConfigError(
                "api_key is required. Provide it when constructing PostQ()."
            )
        self._api_key = api_key
        self._environment = environment
        self._base_url = base_url.rstrip("/")
        self._http = urllib3.PoolManager()

    # ---------------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------------

    def sign(
        self,
        payload: bytes,
        algorithm: str,
        key_id: str,
        context: Optional[Dict[str, str]] = None,
    ) -> SignResponse:
        """
        Create a hybrid signature.

        :param payload: Raw bytes to sign.
        :param algorithm: Hybrid algorithm (e.g. ``"dilithium3+ed25519"``).
        :param key_id: Key identifier (e.g. ``"vault://signing/production"``).
        :param context: Optional metadata dict attached to the signing context.
        :returns: :class:`~postq.models.SignResponse`
        :raises PostQError: If the API returns a non-2xx response.
        """
        body: Dict[str, Any] = {
            "payload": self._to_base64(payload),
            "algorithm": algorithm,
            "key_id": key_id,
        }
        if context is not None:
            body["context"] = context
        data = self._request("POST", "/sign", body)
        return SignResponse.from_dict(data)

    def verify(
        self,
        payload: bytes,
        signature: str,
        key_id: str,
    ) -> VerifyResponse:
        """
        Verify a hybrid signature.

        :param payload: Raw bytes that were signed.
        :param signature: Combined (hybrid) signature to verify, base64-encoded.
        :param key_id: Key identifier used when signing.
        :returns: :class:`~postq.models.VerifyResponse`
        :raises PostQError: If the API returns a non-2xx response.
        """
        data = self._request("POST", "/verify", {
            "payload": self._to_base64(payload),
            "signature": signature,
            "key_id": key_id,
        })
        return VerifyResponse.from_dict(data)

    def list_keys(self) -> ListKeysResponse:
        """
        List all cryptographic keys managed by PostQ.

        :returns: :class:`~postq.models.ListKeysResponse`
        :raises PostQError: If the API returns a non-2xx response.
        """
        data = self._request("GET", "/keys")
        return ListKeysResponse.from_dict(data)

    def scan(
        self,
        targets: List[str],
        depth: Literal["quick", "full"] = "full",
        include: Optional[List[Literal["tls", "signing", "encryption"]]] = None,
    ) -> ScanResponse:
        """
        Trigger a quantum risk scan across specified targets.

        :param targets: Targets to scan (e.g. ``["kubernetes://production"]``).
        :param depth: Scan depth (``"quick"`` or ``"full"``). Defaults to ``"full"``.
        :param include: Cryptographic categories to scan. Defaults to all categories.
        :returns: :class:`~postq.models.ScanResponse`
        :raises PostQError: If the API returns a non-2xx response.
        """
        data = self._request("POST", "/scan", {
            "targets": targets,
            "depth": depth,
            "include": include if include is not None else ["tls", "signing", "encryption"],
        })
        return ScanResponse.from_dict(data)

    # ---------------------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------------------

    @staticmethod
    def _to_base64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    def _build_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "X-PostQ-Environment": self._environment,
        }

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = f"{self._base_url}{path}"
        encoded_body = json.dumps(body).encode("utf-8") if body is not None else None

        try:
            response = self._http.request(
                method,
                url,
                body=encoded_body,
                headers=self._build_headers(),
            )
        except urllib3.exceptions.HTTPError as exc:
            raise PostQError(
                f"Network error while calling {method} {path}: {exc}", 0
            ) from exc

        try:
            data = json.loads(response.data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise PostQError(
                f"Unexpected non-JSON response from {method} {path}",
                response.status,
            ) from exc

        if not (200 <= response.status < 300):
            raise PostQError(
                data.get("message", f"Request failed with status {response.status}"),
                response.status,
                data.get("code"),
            )

        return data
