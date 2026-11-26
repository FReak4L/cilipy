"""Proxy health tracker with EWMA latency scoring, quarantine cooldown, and Thompson Sampling."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlparse

from curl_cffi.requests import AsyncSession

from core.constants import (
    DEFAULT_PROXY_PROBE_TIMEOUT_SECONDS,
    DEFAULT_PROXY_QUARANTINE_SECONDS,
    SUPPORTED_PROXY_SCHEMES,
)
from core.models import ProxyNode, ProxyPoolStats
from math_kernel.bandit_scheduler import ThompsonSamplingScheduler

logger = logging.getLogger("hybrid_search.v3.proxy_pool")


class ProxyPoolManager:
    """
    Manages HTTP/HTTPS/SOCKS4/SOCKS5 proxies with:
      - Concurrent pre-flight health probing
      - EWMA latency/success telemetry
      - Automatic circuit-breaker quarantine cooldown
      - Thompson Sampling Beta(α, β) multi-armed selection routing traffic away from
        rate-limited (429 -> β+2) or degraded proxy nodes automatically.
    """

    def __init__(
        self,
        proxy_urls: Sequence[str] | None = None,
        *,
        ewma_alpha_latency: float = 0.30,
        ewma_alpha_success: float = 0.25,
        quarantine_seconds: float = DEFAULT_PROXY_QUARANTINE_SECONDS,
        probe_url: str = "https://www.gstatic.com/generate_204",
        probe_timeout: float = DEFAULT_PROXY_PROBE_TIMEOUT_SECONDS,
        use_thompson_sampling: bool = True,
        bandit_seed: int | None = None,
    ) -> None:
        self._nodes: dict[str, ProxyNode] = {}
        self._alpha_lat = ewma_alpha_latency
        self._alpha_suc = ewma_alpha_success
        self._quarantine_seconds = quarantine_seconds
        self._probe_url = probe_url
        self._probe_timeout = probe_timeout
        self._use_thompson = use_thompson_sampling
        self._bandit = ThompsonSamplingScheduler(seed=bandit_seed)
        self._lock = asyncio.Lock()

        for raw in proxy_urls or []:
            normalized = self._validate_proxy_url(raw)
            if normalized:
                self._nodes[normalized] = ProxyNode(url=normalized)
                self._bandit.register_arm(normalized)

    @staticmethod
    def _validate_proxy_url(raw: str) -> str | None:
        cleaned = raw.strip()
        if not cleaned or cleaned.startswith("#"):
            return None
        if "://" not in cleaned:
            cleaned = f"http://{cleaned}"
        parsed = urlparse(cleaned)
        if parsed.scheme.lower() not in SUPPORTED_PROXY_SCHEMES or not parsed.hostname:
            logger.warning("Skipping invalid proxy entry: %s", raw.strip())
            return None
        return cleaned

    @classmethod
    def from_file(
        cls,
        file_path: Path,
        *,
        quarantine_seconds: float = DEFAULT_PROXY_QUARANTINE_SECONDS,
        probe_timeout: float = DEFAULT_PROXY_PROBE_TIMEOUT_SECONDS,
        use_thompson_sampling: bool = True,
    ) -> "ProxyPoolManager":
        if not file_path.is_file():
            logger.warning("Proxy file '%s' not found; running in direct mode.", file_path)
            return cls(
                proxy_urls=[],
                quarantine_seconds=quarantine_seconds,
                probe_timeout=probe_timeout,
                use_thompson_sampling=use_thompson_sampling,
            )
        lines = file_path.read_text(encoding="utf-8").splitlines()
        return cls(
            proxy_urls=lines,
            quarantine_seconds=quarantine_seconds,
            probe_timeout=probe_timeout,
            use_thompson_sampling=use_thompson_sampling,
        )

    @property
    def has_proxies(self) -> bool:
        return bool(self._nodes)

    @property
    def bandit(self) -> ThompsonSamplingScheduler:
        return self._bandit

    async def preflight_probe(self, max_concurrent_probes: int = 20) -> int:
        if not self._nodes:
            return 0

        sem = asyncio.Semaphore(max_concurrent_probes)

        async def _probe(node: ProxyNode) -> bool:
            async with sem:
                started = time.perf_counter()
                try:
                    async with AsyncSession(
                        impersonate="chrome",
                        proxies={"http": node.url, "https": node.url},
                        timeout=self._probe_timeout,
                    ) as session:
                        resp = await session.get(self._probe_url)
                        elapsed_ms = (time.perf_counter() - started) * 1000.0
                        if resp.status_code in (200, 204):
                            node.alive = True
                            node.ewma_latency_ms = elapsed_ms
                            node.ewma_success = 1.0
                            return True
                        node.alive = False
                        return False
                except Exception:
                    node.alive = False
                    return False

        outcomes = await asyncio.gather(*(_probe(n) for n in self._nodes.values()))
        healthy = sum(1 for ok in outcomes if ok)
        logger.info("Pre-flight proxy probe: %d/%d alive.", healthy, len(self._nodes))
        return healthy

    async def select_proxy(self, exclude: set[str] | None = None) -> ProxyNode | None:
        """Select a healthy proxy via Thompson Sampling (combined with latency score)."""
        if not self._nodes:
            return None
        excluded = exclude or set()
        async with self._lock:
            candidates = [
                n
                for n in self._nodes.values()
                if n.alive and not n.is_quarantined and n.url not in excluded
            ]
            if not candidates:
                return None

            if self._use_thompson:
                ranked = self._bandit.rank(available_arms=[n.url for n in candidates])
                if ranked:
                    # Combine Thompson sample θ̂_k with gentle latency tie-breaking
                    best_url = max(
                        ranked,
                        key=lambda pair: pair[1]
                        / (1.0 + (self._nodes[pair[0]].ewma_latency_ms / 4000.0)),
                    )[0]
                    return self._nodes[best_url]

            candidates.sort(key=lambda n: n.score, reverse=True)
            return candidates[0]

    async def report_success(self, proxy_url: str | None, latency_ms: float) -> None:
        if not proxy_url or proxy_url not in self._nodes:
            return
        async with self._lock:
            node = self._nodes[proxy_url]
            node.total_requests += 1
            node.ewma_latency_ms = (
                self._alpha_lat * latency_ms
                + (1.0 - self._alpha_lat) * node.ewma_latency_ms
            )
            node.ewma_success = (
                self._alpha_suc * 1.0 + (1.0 - self._alpha_suc) * node.ewma_success
            )
            self._bandit.record_success(proxy_url, yield_count=1)

    async def report_throttle(self, proxy_url: str | None, reason: str) -> None:
        """
        Record HTTP 429/202 throttling: update Thompson Sampling β <- β + 2 so traffic
        shifts smoothly away without permanently marking the proxy dead.
        """
        if not proxy_url or proxy_url not in self._nodes:
            return
        async with self._lock:
            self._bandit.record_rate_limit(proxy_url)
        logger.debug(
            "[proxy] Throttling (%s) via %s; applied bandit β+2 penalty.",
            reason,
            self._nodes[proxy_url].redacted_url,
        )

    async def report_failure(
        self,
        proxy_url: str | None,
        reason: str,
        *,
        quarantine: bool = False,
        mark_dead: bool = False,
        transport_failure: bool = True,
    ) -> None:
        """Quarantine proxy node and penalize Thompson arm (β+2) on transport/IP failure."""
        if not proxy_url or proxy_url not in self._nodes or not transport_failure:
            return
        async with self._lock:
            node = self._nodes[proxy_url]
            node.total_requests += 1
            node.total_failures += 1
            node.ewma_success = (
                self._alpha_suc * 0.0 + (1.0 - self._alpha_suc) * node.ewma_success
            )
            self._bandit.record_network_drop(proxy_url)
            if mark_dead:
                node.alive = False
            elif quarantine:
                node.quarantine_until = time.monotonic() + self._quarantine_seconds
                node.last_quarantine_reason = reason

    def snapshot_stats(self) -> ProxyPoolStats:
        alive_nodes = [n for n in self._nodes.values() if n.alive]
        quarantined_nodes = [n for n in alive_nodes if n.is_quarantined]
        healthy_nodes = [n for n in alive_nodes if not n.is_quarantined]
        avg_lat = (
            round(
                sum(n.ewma_latency_ms for n in alive_nodes) / len(alive_nodes), 1
            )
            if alive_nodes
            else 0.0
        )
        return ProxyPoolStats(
            total_loaded=len(self._nodes),
            alive=len(alive_nodes),
            healthy=len(healthy_nodes),
            quarantined=len(quarantined_nodes),
            avg_ewma_latency_ms=avg_lat,
        )
