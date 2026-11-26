"""Transport layer exports: HTTP client, microsecond Token Bucket, Proxy Pool, and SQLite cache."""

from transport.cache import PipelineCacheManager
from transport.http_client import (
    HTTP_VERSION_1_1,
    AdaptiveDOMExtractor,
    AdaptiveHttpTransport,
    CurlError,
    canonicalize_url,
    classify_http_response,
    detect_soft_block,
    extract_root_domain,
    is_h2_or_transport_reset,
    is_valid_http_url,
    parse_retry_after,
)
from transport.proxy_pool import ProxyPoolManager
from transport.token_bucket import TokenBucketRateLimiter

__all__ = [
    "HTTP_VERSION_1_1",
    "AdaptiveDOMExtractor",
    "AdaptiveHttpTransport",
    "CurlError",
    "PipelineCacheManager",
    "ProxyPoolManager",
    "TokenBucketRateLimiter",
    "canonicalize_url",
    "classify_http_response",
    "detect_soft_block",
    "extract_root_domain",
    "is_h2_or_transport_reset",
    "is_valid_http_url",
    "parse_retry_after",
]
