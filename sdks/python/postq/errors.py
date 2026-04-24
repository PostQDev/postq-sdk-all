"""Exception hierarchy for the PostQ SDK. Catch :class:`PostQError` to catch them all."""
from __future__ import annotations

from typing import Optional


class PostQError(Exception):
    """Base class for every error raised by this SDK."""

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        code: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class PostQConfigError(PostQError):
    """Bad or missing configuration (e.g. no API key)."""


class PostQAuthError(PostQError):
    """401 — bad, missing, revoked, or expired API key."""


class PostQNotFoundError(PostQError):
    """404 — resource not found."""


class PostQRateLimitError(PostQError):
    """429 — rate limit exceeded."""


class PostQServerError(PostQError):
    """5xx — server error."""


class PostQNetworkError(PostQError):
    """Connection refused, DNS failure, timeout."""
