"""Thread-safe plugin registry, engine discovery, Thompson Sampling ordering, and circuit breaker."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, computed_field

from core.constants import DEFAULT_ENGINE_PARK_SECONDS
from core.exceptions import (
    CaptchaTriggeredError,
    EmptyResultError,
    RateLimitedError,
    TransportResetError,
)
from core.models import EngineMetrics
from engine.base import BaseSearchEngine
from math_kernel.bandit_scheduler import ThompsonSamplingScheduler

logger = logging.getLogger("hybrid_search.v3.registry")

EngineFactory = Callable[..., BaseSearchEngine]


class EngineHealthState(BaseModel):
    """Dynamic health, reliability, and circuit-breaker parking state for a plugin."""

    model_config = ConfigDict(extra="forbid")

    name: str
    base_priority: int
    consecutive_bot_gates: int = 0
    consecutive_empty_yields: int = 0
    consecutive_rate_limits: int = 0
    parked_until: float = 0.0
    dynamic_penalty: float = 0.0
    metrics: EngineMetrics

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_parked(self) -> bool:
        return time.monotonic() < self.parked_until


class EngineRegistry:
    """
    Thread-safe & async-compatible plugin registry with:
      - Dynamic plugin registration and factory discovery
      - Thompson Sampling Beta(α, β) multi-armed bandit selection across active plugins
      - Canonical exception-driven circuit breaker parking (bot gates, 429s, empty streaks)
    """

    def __init__(
        self,
        *,
        park_bot_threshold: int = 3,
        park_empty_threshold: int = 5,
        park_rate_limit_threshold: int = 3,
        park_seconds: float = DEFAULT_ENGINE_PARK_SECONDS,
        use_thompson_sampling: bool = True,
        bandit_seed: int | None = None,
    ) -> None:
        self._plugins: dict[str, BaseSearchEngine] = {}
        self._states: dict[str, EngineHealthState] = {}
        self._factories: dict[str, EngineFactory] = {}
        self._park_bot_threshold = max(1, int(park_bot_threshold))
        self._park_empty_threshold = max(1, int(park_empty_threshold))
        self._park_rate_limit_threshold = max(1, int(park_rate_limit_threshold))
        self._park_seconds = max(1.0, float(park_seconds))
        self._use_thompson = bool(use_thompson_sampling)
        self._bandit = ThompsonSamplingScheduler(seed=bandit_seed)
        self._lock = threading.RLock()

    @property
    def bandit(self) -> ThompsonSamplingScheduler:
        return self._bandit

    def register_factory(self, name: str, factory: EngineFactory) -> None:
        """Register a named plugin factory for lazy engine discovery."""
        with self._lock:
            self._factories[name.strip().lower()] = factory

    def discover_factory_names(self) -> list[str]:
        with self._lock:
            return sorted(self._factories.keys())

    def create_from_factory(self, name: str, **kwargs: Any) -> BaseSearchEngine:
        key = name.strip().lower()
        with self._lock:
            factory = self._factories.get(key)
        if factory is None:
            raise KeyError(f"Unknown engine factory '{name}'.")
        plugin = factory(**kwargs)
        self.register(plugin)
        return plugin

    def register(self, plugin: BaseSearchEngine) -> None:
        """Register an instantiated `BaseSearchEngine` plugin thread-safely."""
        with self._lock:
            self._plugins[plugin.name] = plugin
            self._bandit.register_arm(plugin.name)
            arm = self._bandit.get_arm(plugin.name)
            self._states[plugin.name] = EngineHealthState(
                name=plugin.name,
                base_priority=plugin.base_priority,
                metrics=EngineMetrics(
                    engine=plugin.name,
                    priority_tier=plugin.base_priority,
                    bandit_alpha=arm.alpha,
                    bandit_beta=arm.beta,
                ),
            )

    def unregister(self, engine_name: str) -> BaseSearchEngine | None:
        with self._lock:
            self._states.pop(engine_name, None)
            self._bandit.remove_arm(engine_name)
            return self._plugins.pop(engine_name, None)

    def get(self, engine_name: str) -> BaseSearchEngine | None:
        with self._lock:
            return self._plugins.get(engine_name)

    def list_plugins(self) -> list[BaseSearchEngine]:
        with self._lock:
            return list(self._plugins.values())

    def is_engine_parked(self, engine_name: str) -> bool:
        with self._lock:
            state = self._states.get(engine_name)
            if state is None:
                return False
            parked = time.monotonic() < state.parked_until
            state.metrics.parked = parked
            return parked

    def _sync_bandit_metrics(self, engine_name: str) -> None:
        state = self._states.get(engine_name)
        if state is None:
            return
        arm = self._bandit.get_arm(engine_name)
        state.metrics.bandit_alpha = arm.alpha
        state.metrics.bandit_beta = arm.beta

    async def get_ordered_candidates(
        self,
        *,
        use_thompson: bool | None = None,
    ) -> list[BaseSearchEngine]:
        """
        Return active plugins ordered by Thompson Sampling θ̂_k ~ Beta(α_k, β_k)
        (or deterministic effective priority when `use_thompson=False`).
        If all engines are parked, returns earliest-expiring parked engines gracefully.
        """
        thompson_enabled = self._use_thompson if use_thompson is None else use_thompson
        with self._lock:
            now = time.monotonic()
            active_names: list[str] = []
            parked: list[tuple[float, BaseSearchEngine]] = []

            for name, plugin in self._plugins.items():
                state = self._states[name]
                state.metrics.parked = now < state.parked_until
                if state.metrics.parked:
                    parked.append((state.parked_until, plugin))
                else:
                    active_names.append(name)

            if active_names:
                if thompson_enabled:
                    ranked = self._bandit.rank(available_arms=active_names)
                    return [self._plugins[name] for name, _ in ranked]

                ordered_det = sorted(
                    active_names,
                    key=lambda n: (
                        float(self._states[n].base_priority)
                        + self._states[n].dynamic_penalty,
                        -self._states[n].metrics.reliability_score,
                    ),
                )
                return [self._plugins[n] for n in ordered_det]

            parked.sort(key=lambda item: item[0])
            return [item[1] for item in parked]

    async def record_http1_fallback(self, engine_name: str) -> None:
        with self._lock:
            state = self._states.get(engine_name)
            if state is not None:
                state.metrics.http1_fallbacks += 1

    async def record_success(
        self,
        engine_name: str,
        latency_ms: float,
        result_count: int,
    ) -> None:
        with self._lock:
            state = self._states.get(engine_name)
            if state is None:
                return
            state.consecutive_bot_gates = 0
            state.consecutive_empty_yields = 0
            state.consecutive_rate_limits = 0
            state.dynamic_penalty = max(0.0, state.dynamic_penalty - 1.0)
            state.metrics.requests += 1
            state.metrics.successes += 1
            state.metrics.total_latency_ms += latency_ms
            state.metrics.total_results_yielded += result_count
            state.metrics.parked = False

            self._bandit.update(
                engine_name,
                status_code=200,
                yield_count=result_count,
                network_drop=False,
            )
            self._sync_bandit_metrics(engine_name)

    async def record_failure(
        self,
        engine_name: str,
        exc: BaseException,
        latency_ms: float,
    ) -> None:
        with self._lock:
            state = self._states.get(engine_name)
            if state is None:
                return
            state.metrics.requests += 1
            state.metrics.failures += 1
            state.metrics.total_latency_ms += latency_ms

            if isinstance(exc, CaptchaTriggeredError):
                state.metrics.bot_gates += 1
                state.consecutive_bot_gates += 1
                state.dynamic_penalty = min(20.0, state.dynamic_penalty + 3.0)
                self._bandit.record_network_drop(engine_name)
                if state.consecutive_bot_gates >= self._park_bot_threshold:
                    state.parked_until = time.monotonic() + self._park_seconds
                    state.metrics.parked = True
                    logger.warning(
                        "[registry] Parking '%s' for %.0fs after %d consecutive bot gates.",
                        engine_name,
                        self._park_seconds,
                        state.consecutive_bot_gates,
                    )
            elif isinstance(exc, RateLimitedError):
                state.metrics.rate_limits += 1
                state.consecutive_rate_limits += 1
                state.dynamic_penalty = min(15.0, state.dynamic_penalty + 2.0)
                # Formulation 1: HTTP 429 -> β_k <- β_k + 2
                self._bandit.record_rate_limit(engine_name)
                if state.consecutive_rate_limits >= self._park_rate_limit_threshold:
                    cooldown = max(
                        self._park_seconds * 0.5,
                        float(exc.retry_after or 0.0),
                    )
                    state.parked_until = time.monotonic() + cooldown
                    state.metrics.parked = True
                    logger.warning(
                        "[registry] Parking '%s' for %.0fs after %d consecutive HTTP 429s.",
                        engine_name,
                        cooldown,
                        state.consecutive_rate_limits,
                    )
            elif isinstance(exc, TransportResetError):
                state.dynamic_penalty = min(15.0, state.dynamic_penalty + 2.0)
                # Formulation 1: network drop -> β_k <- β_k + 2
                self._bandit.record_network_drop(engine_name)
            elif isinstance(exc, EmptyResultError):
                state.metrics.empty_yields += 1
                state.consecutive_empty_yields += 1
                state.dynamic_penalty = min(10.0, state.dynamic_penalty + 0.5)
                self._bandit.update(engine_name, status_code=200, yield_count=0)
                if state.consecutive_empty_yields >= self._park_empty_threshold:
                    state.parked_until = time.monotonic() + (self._park_seconds * 0.5)
                    state.metrics.parked = True
                    logger.info(
                        "[registry] Temporarily parking '%s' after %d consecutive empty yields.",
                        engine_name,
                        state.consecutive_empty_yields,
                    )
            else:
                state.dynamic_penalty = min(15.0, state.dynamic_penalty + 1.0)
                self._bandit.record_failure(engine_name)

            self._sync_bandit_metrics(engine_name)

    def snapshot_metrics(self) -> list[EngineMetrics]:
        with self._lock:
            now = time.monotonic()
            output: list[EngineMetrics] = []
            for name, state in self._states.items():
                state.metrics.parked = now < state.parked_until
                self._sync_bandit_metrics(name)
                output.append(state.metrics.model_copy())
            return output
