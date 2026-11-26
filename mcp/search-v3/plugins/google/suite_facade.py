"""Cascading GoogleMultiTierPlugin facade with circuit breaker and Thompson Sampling."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict

from core.exceptions import (
    CaptchaTriggeredError,
    EmptyResultError,
    EngineDegradedError,
    GoogleChallengeTriggeredError,
    GoogleQuotaExhaustedError,
    GoogleRateLimitedError,
    GoogleSearchError,
    RateLimitedError,
    TransportResetError,
)
from core.models import SearchResult
from engine.base import BaseSearchEngine
from math_kernel.bandit_scheduler import ThompsonSamplingScheduler
from math_kernel.pacing_poisson import DynamicPoissonPacer
from plugins.google.basic_html import GoogleBasicHtmlPlugin
from plugins.google.common import GoogleDomainRotator, GoogleSuiteConfig
from plugins.google.cse_api import GoogleCSEKeyPool, GoogleCSEPlugin
from plugins.google.mobile_direct import GoogleMobileDirectPlugin
from plugins.google.web_udm14 import GoogleWebDirectPlugin
from transport.http_client import AdaptiveHttpTransport
from transport.proxy_pool import ProxyPoolManager
from transport.token_bucket import TokenBucketRateLimiter

logger = logging.getLogger("hybrid_search.v3.plugins.google.facade")


class _TierCircuitState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    consecutive_failures: int = 0
    parked_until: float = 0.0
    last_error: str = ""

    @property
    def is_parked(self) -> bool:
        return time.monotonic() < self.parked_until


class GoogleMultiTierPlugin(BaseSearchEngine):
    """
    Composite facade executing Google tiers with circuit-breaker parking and optional
    Thompson Sampling re-balancing across healthy tiers:
        CSE API -> Desktop Web (udm=14) -> Mobile Web -> Basic HTML (gbv=1/2)
    """

    name = "google_suite"
    engine_family = "google_suite"
    base_priority = 1

    def __init__(
        self,
        tiers: Sequence[BaseSearchEngine],
        *,
        base_priority: int = 1,
        failure_threshold: int = 3,
        cooldown_seconds: float = 180.0,
        use_thompson_sampling: bool = False,
        bandit_seed: int | None = None,
    ) -> None:
        self._tiers: list[BaseSearchEngine] = sorted(tiers, key=lambda p: p.base_priority)
        self._tiers_by_name: dict[str, BaseSearchEngine] = {p.name: p for p in self._tiers}
        self.base_priority = base_priority
        self._failure_threshold = max(1, int(failure_threshold))
        self._cooldown_seconds = max(1.0, float(cooldown_seconds))
        self._use_thompson = bool(use_thompson_sampling)
        self._bandit = ThompsonSamplingScheduler(
            arms=[p.name for p in self._tiers],
            seed=bandit_seed,
        )
        self._circuits: dict[str, _TierCircuitState] = {
            p.name: _TierCircuitState() for p in self._tiers
        }
        self._lock = asyncio.Lock()

    @property
    def tiers(self) -> list[BaseSearchEngine]:
        return list(self._tiers)

    @property
    def bandit(self) -> ThompsonSamplingScheduler:
        return self._bandit

    async def is_parked(self, tier_name: str) -> bool:
        async with self._lock:
            state = self._circuits.get(tier_name)
            return state.is_parked if state is not None else False

    async def _record_success(self, tier_name: str, result_count: int) -> None:
        async with self._lock:
            state = self._circuits.get(tier_name)
            if state is not None:
                state.consecutive_failures = 0
                state.parked_until = 0.0
                state.last_error = ""
            self._bandit.record_success(tier_name, yield_count=result_count)

    async def _record_failure(self, tier_name: str, exc: BaseException) -> None:
        async with self._lock:
            state = self._circuits.get(tier_name)
            if state is None:
                return
            state.consecutive_failures += 1
            state.last_error = str(exc)

            if isinstance(exc, RateLimitedError):
                self._bandit.record_rate_limit(tier_name)
            elif isinstance(exc, (TransportResetError, CaptchaTriggeredError)):
                self._bandit.record_network_drop(tier_name)
            else:
                self._bandit.record_failure(tier_name)

            immediate_park = isinstance(
                exc,
                (
                    GoogleQuotaExhaustedError,
                    GoogleChallengeTriggeredError,
                    CaptchaTriggeredError,
                ),
            )
            if immediate_park or state.consecutive_failures >= self._failure_threshold:
                retry_floor = (
                    float(exc.retry_after)
                    if isinstance(exc, RateLimitedError) and exc.retry_after
                    else 0.0
                )
                cooldown = max(self._cooldown_seconds, retry_floor)
                state.parked_until = time.monotonic() + cooldown
                logger.warning(
                    "[google_suite] Circuit breaker parked tier '%s' for %.0fs (%s).",
                    tier_name,
                    cooldown,
                    exc,
                )

    async def _select_tier_order(self) -> list[BaseSearchEngine]:
        async with self._lock:
            available = [
                p for p in self._tiers if not self._circuits[p.name].is_parked
            ]
        if not available:
            return []
        if self._use_thompson:
            ranked = self._bandit.rank(available_arms=[p.name for p in available])
            return [self._tiers_by_name[name] for name, _ in ranked]
        return available

    async def search(
        self,
        query: str,
        max_results: int = 20,
        pagination_depth: int = 2,
    ) -> list[SearchResult]:
        last_error: BaseException | None = None
        ordered_tiers = await self._select_tier_order()
        if not ordered_tiers:
            raise GoogleRateLimitedError(
                "All Google suite tiers are currently parked in circuit-breaker cooldown."
            )

        for plugin in ordered_tiers:
            try:
                results = await plugin.search(
                    query=query,
                    max_results=max_results,
                    pagination_depth=pagination_depth,
                )
                if results:
                    await self._record_success(plugin.name, len(results))
                    return results
            except (
                GoogleSearchError,
                RateLimitedError,
                CaptchaTriggeredError,
                TransportResetError,
                EngineDegradedError,
                EmptyResultError,
            ) as exc:
                last_error = exc
                if not isinstance(exc, EmptyResultError):
                    await self._record_failure(plugin.name, exc)
                logger.warning(
                    "[google_suite] tier '%s' failed (%s); cascading to next tier.",
                    plugin.name,
                    exc,
                )
                continue

        if isinstance(last_error, (GoogleSearchError, CaptchaTriggeredError, RateLimitedError, EmptyResultError)):
            raise last_error
        raise EngineDegradedError(
            f"All Google suite tiers failed for '{query}': {last_error}"
        )


def build_google_plugins(
    proxy_pool: ProxyPoolManager | None = None,
    rate_limiter: TokenBucketRateLimiter | None = None,
    transport: AdaptiveHttpTransport | None = None,
    registry: Any | None = None,
    *,
    config: GoogleSuiteConfig | None = None,
    pacer: DynamicPoissonPacer | None = None,
    include_cse_without_credentials: bool = False,
) -> list[BaseSearchEngine]:
    """Instantiate configured Google tiers sharing a domain rotator and dynamic Poisson pacer."""
    cfg = config or GoogleSuiteConfig.from_env()
    pool = proxy_pool or ProxyPoolManager()
    limiter = rate_limiter or TokenBucketRateLimiter()
    http = transport or AdaptiveHttpTransport()

    shared_rotator = GoogleDomainRotator(
        domains=cfg.regional_domains,
        cooldown_seconds=cfg.domain_cooldown_seconds,
    )
    shared_pacer = pacer or DynamicPoissonPacer(
        mean_delay_seconds=cfg.pacer_mean_delay,
        min_delay_seconds=cfg.pacer_min_delay,
        max_delay_seconds=cfg.pacer_max_delay,
    )
    plugins: list[BaseSearchEngine] = []

    if cfg.cse_credentials or include_cse_without_credentials:
        key_pool = GoogleCSEKeyPool(cfg.cse_credentials)
        plugins.append(
            GoogleCSEPlugin(
                key_pool=key_pool,
                rate_limiter=limiter,
                locale=cfg.locale,
                timeout=cfg.cse_timeout,
                max_retries=cfg.max_retries,
                base_priority=cfg.cse_priority,
            )
        )

    plugins.append(
        GoogleWebDirectPlugin(
            proxy_pool=pool,
            rate_limiter=limiter,
            transport=http,
            registry=registry,
            locale=cfg.locale,
            domain_rotator=shared_rotator,
            pacer=shared_pacer,
            enable_warmup=cfg.enable_warmup,
            max_retries=cfg.max_retries,
            base_priority=cfg.web_udm14_priority,
        )
    )
    plugins.append(
        GoogleMobileDirectPlugin(
            proxy_pool=pool,
            rate_limiter=limiter,
            transport=http,
            registry=registry,
            locale=cfg.locale,
            domain_rotator=shared_rotator,
            pacer=shared_pacer,
            enable_warmup=cfg.enable_warmup,
            max_retries=cfg.max_retries,
            base_priority=cfg.mobile_web_priority,
        )
    )
    plugins.append(
        GoogleBasicHtmlPlugin(
            proxy_pool=pool,
            rate_limiter=limiter,
            transport=http,
            registry=registry,
            locale=cfg.locale,
            domain_rotator=shared_rotator,
            pacer=shared_pacer,
            enable_warmup=False,
            max_retries=cfg.max_retries,
            base_priority=cfg.basic_html_priority,
        )
    )
    return plugins


def register_google_plugins(
    registry: Any,
    proxy_pool: ProxyPoolManager | None = None,
    rate_limiter: TokenBucketRateLimiter | None = None,
    transport: AdaptiveHttpTransport | None = None,
    *,
    config: GoogleSuiteConfig | None = None,
    as_composite_facade: bool = False,
) -> list[BaseSearchEngine]:
    """Register the standalone Google Federation Suite into an `EngineRegistry`."""
    cfg = config or GoogleSuiteConfig.from_env()
    plugins = build_google_plugins(
        proxy_pool=proxy_pool,
        rate_limiter=rate_limiter,
        transport=transport,
        registry=registry,
        config=cfg,
    )
    if as_composite_facade:
        facade = GoogleMultiTierPlugin(
            plugins,
            failure_threshold=cfg.tier_failure_threshold,
            cooldown_seconds=cfg.tier_cooldown_seconds,
        )
        registry.register(facade)
        return [facade]

    for plugin in plugins:
        registry.register(plugin)
    return plugins
