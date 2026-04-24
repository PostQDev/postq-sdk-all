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
from .models import Finding, ScanListItem, ScanSubmitResult

DEFAULT_BASE_URL = "https://api.postq.dev"


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
            allowed_methods=["GET", "POST"],
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

    # ── public ──────────────────────────────────────────────────────────────

    def health(self) -> "dict[str, Any]":
        """Hit ``GET /health``. Returns the parsed JSON or raises."""
        return self._request("GET", "/health")

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
    ) -> "list[ScanListItem]":
        """``GET /v1/scans`` — one page of recent scans."""
        params: "dict[str, Any]" = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        body = self._client._request("GET", "/v1/scans", params=params)
        return [_row_to_item(row) for row in body["data"]]

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
