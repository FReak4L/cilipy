"""Precise microsecond-level Token Bucket rate limiter using monotonic_ns()."""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any

_NS_PER_SECOND: float = 1_000_000_000.0


class TokenBucketRateLimiter:
    """
    Per-engine-family microsecond-precision Token Bucket rate limiter with
    bounded concurrency semaphore and optional jitter spacing.
    Uses `time.monotonic_ns()` to avoid floating-point drift on sub-millisecond refills.
    """

    class _Guard:
        def __init__(self, limiter: "TokenBucketRateLimiter", family: str) -> None:
            self._limiter = limiter
            self._family = family

        async def __aenter__(self) -> None:
            await self._limiter.acquire(self._family)

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            tb: Any,
        ) -> None:
            self._limiter.release()

    def __init__(
        self,
        max_concurrency: int = 4,
        tokens_per_second: float = 1.2,
        burst_capacity: float = 2.0,
        jitter_min: float = 0.0,
        jitter_max: float = 0.0,
    ) -> None:
        if tokens_per_second <= 0.0:
            raise ValueError("tokens_per_second must be strictly positive.")
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))
        self._rate = float(tokens_per_second)
        self._capacity = max(1.0, float(burst_capacity))
        self._jitter_min = max(0.0, float(jitter_min))
        self._jitter_max = max(self._jitter_min, float(jitter_max))
        # Map engine_family -> (tokens_available, last_refill_ns)
        self._buckets: dict[str, tuple[float, int]] = {}
        self._last_dispatch_ns: dict[str, int] = {}
        self._lock = asyncio.Lock()

    def reserve_wait_seconds(self, engine_family: str) -> float:
        """Synchronously compute and advance bucket state; returns wait duration in seconds."""
        now_ns = time.monotonic_ns()
        tokens, last_refill_ns = self._buckets.get(engine_family, (self._capacity, now_ns))
        elapsed_us = max(0, (now_ns - last_refill_ns) // 1_000)
        elapsed_s = elapsed_us / 1_000_000.0
        tokens = min(self._capacity, tokens + elapsed_s * self._rate)

        if tokens < 1.0:
            token_wait_s = (1.0 - tokens) / self._rate
            tokens = 0.0
        else:
            token_wait_s = 0.0
            tokens -= 1.0

        jitter_wait_s = 0.0
        last_ns = self._last_dispatch_ns.get(engine_family)
        if last_ns is not None and self._jitter_max > 0.0:
            target_gap_s = random.uniform(self._jitter_min, self._jitter_max)
            since_last_s = (now_ns - last_ns) / _NS_PER_SECOND
            remaining_s = target_gap_s - since_last_s
            if remaining_s > 0.0:
                jitter_wait_s = remaining_s

        wait_s = max(token_wait_s, jitter_wait_s)
        scheduled_ns = now_ns + int(wait_s * _NS_PER_SECOND)
        self._buckets[engine_family] = (tokens, scheduled_ns)
        self._last_dispatch_ns[engine_family] = scheduled_ns
        return wait_s

    async def acquire(self, engine_family: str) -> float:
        """Acquire concurrency slot and wait for microsecond token bucket availability."""
        await self._semaphore.acquire()
        try:
            async with self._lock:
                wait_s = self.reserve_wait_seconds(engine_family)
            if wait_s > 0.0:
                await asyncio.sleep(wait_s)
            return wait_s
        except BaseException:
            self._semaphore.release()
            raise

    def release(self) -> None:
        self._semaphore.release()

    def throttle(self, engine_family: str) -> "_Guard":
        return self._Guard(self, engine_family)
