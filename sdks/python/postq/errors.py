"""Exceptions raised by the PostQ SDK."""


class PostQError(Exception):
    """Raised when the PostQ API returns a non-2xx response."""

    def __init__(self, message: str, status_code: int, code: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code

    def __repr__(self) -> str:
        return f"PostQError(status_code={self.status_code}, code={self.code!r}, message={str(self)!r})"


class PostQConfigError(Exception):
    """Raised when the SDK is misconfigured (e.g. missing API key)."""
