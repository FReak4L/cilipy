"""Single canonical hierarchical typed exception tree (RFC 6585, RateLimit, Network, Google)."""

from __future__ import annotations


class PipelineError(Exception):
    """Root exception for all search aggregator v3 pipeline errors."""


class QueryParseError(PipelineError):
    """Raised when a Boolean query string violates AST syntax rules."""


class EngineDegradedError(PipelineError):
    """Raised on 5xx upstream responses, timeouts, or DOM/schema parse drift."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class TransportResetError(EngineDegradedError):
    """Raised on HTTP/2 frame resets, GOAWAY, TLS drops, or proxy tunnel terminations."""


class ProxyDeadError(TransportResetError):
    """Raised when a proxy fails pre-flight checks or drops TCP/TLS handshakes."""


class RateLimitedError(PipelineError):
    """
    RFC 6585-compliant application throttling error (HTTP 429 / 202).
    Carries optional server-advertised `retry_after` seconds for ethical backoff.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 429,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after


class CaptchaTriggeredError(PipelineError):
    """Raised on hard WAF/CAPTCHA/verification gates (HTTP 403/451, /sorry/ redirects)."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class EmptyResultError(PipelineError):
    """Raised when an upstream engine returns HTTP 200 with zero organic results."""


# ---------------------------------------------------------------------------
# Google Federation Exception Hierarchy (Single Canonical Inheritance Tree)
# ---------------------------------------------------------------------------
class GoogleSearchError(PipelineError):
    """Root exception for all Google Search Federation Suite tiers."""


class GoogleRateLimitedError(GoogleSearchError, RateLimitedError):
    """Triggered on Google HTTP 429; signals immediate RFC 6585 backoff and rotation."""


class GoogleChallengeTriggeredError(GoogleSearchError, CaptchaTriggeredError):
    """Triggered when Google redirects to `/sorry/` or serves a verification challenge."""


class GoogleQuotaExhaustedError(GoogleSearchError, RateLimitedError):
    """Triggered when all configured Google CSE API credentials reach daily limits."""


class GoogleDOMStructureChangedError(GoogleSearchError, EngineDegradedError):
    """Raised when an HTTP 200 Google SERP lacks expected organic DOM containers."""
