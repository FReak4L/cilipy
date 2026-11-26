"""Formulation 2: Poisson Inter-Arrival Pacing (Exp(lambda)) with Dynamic Hazard Rate."""

from __future__ import annotations

import asyncio
import math
import random
import threading
import time
from collections import deque

from core.constants import (
    DEFAULT_POISSON_FAILURE_THRESHOLD,
    DEFAULT_POISSON_FAILURE_WINDOW,
    DEFAULT_POISSON_MEAN_DELAY_SECONDS,
)


class DynamicPoissonPacer:
    """
    Poisson inter-arrival pacer with exact inverse-transform exponential sampling
    and rolling failure-rate hazard modulation:

        Δt = -(1 / λ) * ln(1 - U),   U ~ Uniform(0, 1)
        λ_0 = 1 / t_bar              (default t_bar = 2.0s => λ_0 = 0.5 s^-1)
        φ   = sum(failures) / sum(requests) over last W = 10 requests
        λ   = λ_0 / (1 + 3φ)         if φ > 0.2 else λ_0
    """

    def __init__(
        self,
        mean_delay_seconds: float = DEFAULT_POISSON_MEAN_DELAY_SECONDS,
        *,
        window_size: int = DEFAULT_POISSON_FAILURE_WINDOW,
        failure_threshold: float = DEFAULT_POISSON_FAILURE_THRESHOLD,
        penalty_multiplier: float = 3.0,
        min_delay_seconds: float = 0.0,
        max_delay_seconds: float | None = None,
        seed: int | None = None,
    ) -> None:
        if mean_delay_seconds <= 0.0:
            raise ValueError("mean_delay_seconds must be strictly positive.")
        if window_size < 1:
            raise ValueError("window_size must be at least 1.")
        if min_delay_seconds < 0.0:
            raise ValueError("min_delay_seconds must be non-negative.")
        if max_delay_seconds is not None and max_delay_seconds < min_delay_seconds:
            raise ValueError("max_delay_seconds must be >= min_delay_seconds.")

        self._mean_delay = float(mean_delay_seconds)
        self._lambda_0 = 1.0 / self._mean_delay
        self._window_size = int(window_size)
        self._failure_threshold = float(failure_threshold)
        self._penalty_multiplier = float(penalty_multiplier)
        self._min_delay = float(min_delay_seconds)
        self._max_delay = float(max_delay_seconds) if max_delay_seconds is not None else None

        self._rng = random.Random(seed)
        self._state_lock = threading.RLock()
        self._outcomes: dict[str, deque[bool]] = {}
        self._next_allowed: dict[str, float] = {}
        self._async_lock: asyncio.Lock | None = None

    @property
    def base_hazard_rate(self) -> float:
        """Base Poisson rate λ_0 = 1 / t_bar."""
        return self._lambda_0

    def record_outcome(self, key: str = "default", *, failed: bool) -> float:
        """Record a request outcome (True = failure, False = success) and return rolling φ."""
        with self._state_lock:
            window = self._outcomes.get(key)
            if window is None:
                window = deque(maxlen=self._window_size)
                self._outcomes[key] = window
            window.append(bool(failed))
            return self.failure_rate(key)

    def record_success(self, key: str = "default") -> float:
        return self.record_outcome(key, failed=False)

    def record_failure(self, key: str = "default") -> float:
        return self.record_outcome(key, failed=True)

    def failure_rate(self, key: str = "default") -> float:
        """Rolling failure rate φ = sum(failures) / sum(requests) over the last W requests."""
        with self._state_lock:
            window = self._outcomes.get(key)
            if not window:
                return 0.0
            return sum(1 for is_fail in window if is_fail) / len(window)

    def hazard_rate(self, key: str = "default") -> float:
        """Dynamic Poisson hazard rate λ = λ_0 / (1 + 3φ) when φ > 0.2, else λ_0."""
        phi = self.failure_rate(key)
        if phi > self._failure_threshold:
            return self._lambda_0 / (1.0 + self._penalty_multiplier * phi)
        return self._lambda_0

    def expected_delay(self, key: str = "default") -> float:
        """Theoretical mean inter-arrival interval E[Δt] = 1 / λ."""
        return 1.0 / self.hazard_rate(key)

    def sample_delay(self, key: str = "default") -> float:
        """
        Draw Δt = -(1 / λ) * ln(1 - U), U ~ Uniform(0, 1).
        Optional clamping is only applied when `min_delay_seconds > 0` or `max_delay_seconds` is set.
        """
        with self._state_lock:
            lam = self.hazard_rate(key)
            u = self._rng.random()  # Uniform in [0.0, 1.0) => 1 - u in (0.0, 1.0]
        delay = -(1.0 / lam) * math.log(1.0 - u)
        if self._min_delay > 0.0 and delay < self._min_delay:
            delay = self._min_delay
        if self._max_delay is not None and delay > self._max_delay:
            delay = self._max_delay
        return delay

    def respect_retry_after(self, key: str, retry_after_seconds: float) -> None:
        """RFC 6585 compliance: push the next allowed slot for `key` out by at least Retry-After."""
        if retry_after_seconds <= 0.0:
            return
        with self._state_lock:
            floor_time = time.monotonic() + retry_after_seconds
            current = self._next_allowed.get(key, 0.0)
            if floor_time > current:
                self._next_allowed[key] = floor_time

    def _get_async_lock(self) -> asyncio.Lock:
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    async def wait(self, key: str = "default") -> float:
        """Reserve the next paced dispatch slot for `key` and sleep outside locks."""
        sleep_for = 0.0
        async with self._get_async_lock():
            with self._state_lock:
                now = time.monotonic()
                scheduled = self._next_allowed.get(key, now)
                if scheduled > now:
                    sleep_for = scheduled - now
                    base_time = scheduled
                else:
                    base_time = now
                self._next_allowed[key] = base_time + self.sample_delay(key)

        if sleep_for > 0.0:
            await asyncio.sleep(sleep_for)
        return sleep_for


PoissonPacer = DynamicPoissonPacer
