"""Abstract BaseSearchEngine contract, lifecycle hooks, and DirectBrowserEngineBase harness."""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from curl_cffi.requests import AsyncSession
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

from core.constants import CHROME_IMPERSONATION_PROFILES
from core.exceptions import (
    CaptchaTriggeredError,
    EngineDegradedError,
    ProxyDeadError,
    RateLimitedError,
    TransportResetError,
)
from core.models import SearchResult
from math_kernel.pacing_poisson import DynamicPoissonPacer
from transport.http_client import AdaptiveHttpTransport, CurlError
from transport.proxy_pool import ProxyPoolManager
from transport.token_bucket import TokenBucketRateLimiter

logger = logging.getLogger("hybrid_search.v3.engine.base")


class BaseSearchEngine(ABC):
    """
    Standalone search provider contract implemented by every v3 engine plugin.
    Each plugin owns query formatting, network dispatch, pagination, and parsing.
    """

    name: str
    engine_family: str
    base_priority: int = 10

    async def on_startup(self) -> None:
        """Optional lifecycle hook invoked by the orchestrator before dispatching queries."""
        return None

    async def on_shutdown(self) -> None:
        """Optional lifecycle hook invoked by the orchestrator during graceful teardown."""
        return None

    @abstractmethod
    async def search(
        self,
        query: str,
        max_results: int = 20,
        pagination_depth: int = 2,
    ) -> list[SearchResult]:
        """Execute a search query with optional deep pagination and return normalized items."""


class DirectBrowserEngineBase(BaseSearchEngine):
    """
    Shared resilience harness for direct BoringSSL `curl_cffi` plugins:
      - Microsecond TokenBucket rate limiting + optional DynamicPoissonPacer
      - Thompson Sampling proxy selection & circuit-breaker quarantine
      - RFC 6585 Retry-After compliance on HTTP 429
      - Dynamic HTTP/2 -> HTTP/1.1 fallback telemetry hook
      - Exponential backoff retries via `tenacity.AsyncRetrying`
    """

    def __init__(
        self,
        proxy_pool: ProxyPoolManager,
        rate_limiter: TokenBucketRateLimiter,
        transport: AdaptiveHttpTransport,
        registry: Any | None = None,
        *,
        pacer: DynamicPoissonPacer | None = None,
        max_retries: int = 3,
    ) -> None:
        self.proxy_pool = proxy_pool
        self.rate_limiter = rate_limiter
        self.transport = transport
        self.registry = registry
        self.pacer = pacer
        self.max_retries = max(1, int(max_retries))

    async def _run_with_resilience(
        self,
        execute_session_fn: Callable[[AsyncSession, Callable[[], None]], Any],
    ) -> list[SearchResult]:
        excluded_proxies: set[str] = set()
        attempt_counter = 0
        last_proxy_url: str | None = None

        def _before_sleep(retry_state: RetryCallState) -> None:
            exc = retry_state.outcome.exception() if retry_state.outcome else None
            logger.warning(
                "[plugin:%s] transient failure on attempt %d/%d (%s); backing off",
                self.name,
                retry_state.attempt_number,
                self.max_retries,
                exc,
            )

        def _on_http1_fallback() -> None:
            if self.registry is not None and hasattr(self.registry, "record_http1_fallback"):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self.registry.record_http1_fallback(self.name))
                except RuntimeError:
                    pass

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.max_retries),
                wait=wait_random_exponential(multiplier=1.0, max=10.0),
                retry=retry_if_exception_type(
                    (
                        TransportResetError,
                        EngineDegradedError,
                        RateLimitedError,
                        CurlError,
                        TimeoutError,
                    )
                ),
                before_sleep=_before_sleep,
                reraise=True,
            ):
                with attempt:
                    profile = CHROME_IMPERSONATION_PROFILES[
                        attempt_counter % len(CHROME_IMPERSONATION_PROFILES)
                    ]
                    attempt_counter += 1

                    proxy_node = await self.proxy_pool.select_proxy(
                        exclude=excluded_proxies
                    )
                    proxy_url = proxy_node.url if proxy_node else None
                    last_proxy_url = proxy_url

                    started = time.perf_counter()
                    async with self.rate_limiter.throttle(self.engine_family):
                        try:
                            async with self.transport.create_session(
                                impersonate=profile,
                                proxy_url=proxy_url,
                                allow_redirects=True,
                            ) as session:
                                results: list[SearchResult] = await execute_session_fn(
                                    session, _on_http1_fallback
                                )
                        except RateLimitedError as throttle_exc:
                            if self.pacer is not None:
                                self.pacer.record_failure(self.engine_family)
                                if throttle_exc.retry_after:
                                    self.pacer.respect_retry_after(
                                        self.engine_family,
                                        min(throttle_exc.retry_after, 60.0),
                                    )
                            await self.proxy_pool.report_throttle(
                                proxy_url, reason=str(throttle_exc)
                            )
                            raise
                        except (
                            TransportResetError,
                            ProxyDeadError,
                            CurlError,
                            TimeoutError,
                        ) as net_exc:
                            if self.pacer is not None:
                                self.pacer.record_failure(self.engine_family)
                            if proxy_url:
                                excluded_proxies.add(proxy_url)
                                await self.proxy_pool.report_failure(
                                    proxy_url,
                                    reason=str(net_exc),
                                    quarantine=True,
                                    transport_failure=True,
                                )
                            raise
                        except CaptchaTriggeredError as waf_exc:
                            if self.pacer is not None:
                                self.pacer.record_failure(self.engine_family)
                            if proxy_url:
                                excluded_proxies.add(proxy_url)
                                await self.proxy_pool.report_failure(
                                    proxy_url,
                                    reason=str(waf_exc),
                                    quarantine=True,
                                    transport_failure=True,
                                )
                            raise
                        except EngineDegradedError:
                            if self.pacer is not None:
                                self.pacer.record_failure(self.engine_family)
                            raise

                    latency_ms = (time.perf_counter() - started) * 1000.0
                    if self.pacer is not None:
                        self.pacer.record_success(self.engine_family)
                    await self.proxy_pool.report_success(proxy_url, latency_ms)
                    return results
        except TransportResetError as exhausted_exc:
            if last_proxy_url:
                await self.proxy_pool.report_failure(
                    last_proxy_url,
                    reason=f"Transport retry exhaustion: {exhausted_exc}",
                    quarantine=True,
                    transport_failure=True,
                )
            raise

        raise EngineDegradedError(f"[plugin:{self.name}] retry loop exited unexpectedly")


_DirectBrowserPluginBase = DirectBrowserEngineBase
