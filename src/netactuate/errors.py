"""Error types raised by the NetActuate SDK."""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def redact_url(url: str) -> str:
    """Return url with the API key query value removed.

    Parameters:
        url: Absolute or relative URL that may contain a `key` query parameter.
    """
    parts = urlsplit(url)
    pairs = []
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if name == "key":
            value = "REDACTED"
        pairs.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


class NetActuateError(Exception):
    """Base error for failed NetActuate API calls.

    Parameters:
        message: Human readable failure context.
        method: HTTP method used for the request.
        url: Request URL. API keys are redacted before storage.
        status_code: HTTP status code when a response was received.
        code: API envelope code when present.
        body: Response body or selected error detail.
    """

    def __init__(
        self,
        message: str,
        *,
        method: str = "",
        url: str = "",
        status_code: Optional[int] = None,
        code: Optional[int] = None,
        body: Any = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.method = method
        self.url = redact_url(url)
        self.status_code = status_code
        self.code = code
        self.body = body

    def __str__(self) -> str:
        parts = [self.message]
        if self.method or self.url:
            parts.append(f"request={self.method} {self.url}".strip())
        if self.status_code is not None:
            parts.append(f"http={self.status_code}")
        if self.code is not None:
            parts.append(f"code={self.code}")
        if self.body not in (None, ""):
            parts.append(f"body={self.body}")
        return "; ".join(parts)


class NotFoundError(NetActuateError):
    """Raised when either API version reports that a resource does not exist."""


class ContractError(NetActuateError):
    """Raised when the account is not entitled to a contract gated capability."""
