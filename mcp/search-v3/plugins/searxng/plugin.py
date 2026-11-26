"""Standalone SearXNG Federation Plugin & dynamic local daemon discovery."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence

from curl_cffi.requests import AsyncSession
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

from core.constants import DEFAULT_SEARXNG_TIMEOUT_SECONDS
from core.exceptions import (
    EmptyResultError,
    EngineDegradedError,
    RateLimitedError,
)
from core.models import SearchResult
from engine.base import BaseSearchEngine
from math_kernel.pacing_poisson import DynamicPoissonPacer
from transport.http_client import (
    CurlError,
    canonicalize_url,
    is_valid_http_url,
    parse_retry_after,
)
from transport.token_bucket import TokenBucketRateLimiter

logger = logging.getLogger("hybrid_search.v3.plugins.searxng")


async def discover_local_searxng(
    host: str = "127.0.0.1",
    ports: Sequence[int] = (8888, 8080, 80),
    timeout: float = 2.5,
) -> str | None:
    """
    Probe candidate local ports concurrently via TCP connect followed by an HTTP JSON
    readiness check against `/search?q=searxng&format=json`.
    """

    async def _probe_port(port: int) -> str | None:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=min(1.0, timeout),
            )
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            return None

        base_url = f"http://{host}:{port}"
        try:
            async with AsyncSession(timeout=timeout) as session:
                resp = await session.get(
                    f"{base_url}/search",
                    params={"q": "searxng", "format": "json"},
                    headers={"Accept": "application/json"},
                )
                if resp.status_code != 200:
                    return None
                payload = resp.json()
                if isinstance(payload, dict) and "results" in payload:
                    return base_url
        except Exception:
            return None
        return None

    probe_results = await asyncio.gather(*(_probe_port(p) for p in ports))
    for endpoint in probe_results:
        if endpoint is not None:
            logger.info("[discovery] Active SearXNG JSON daemon detected at %s", endpoint)
            return endpoint
    logger.info(
        "[discovery] No responsive local SearXNG daemon found on %s:%s", host, list(ports)
    )
    return None


class SearXNGEnginePlugin(BaseSearchEngine):
    """Standalone SearXNG JSON Federation Plugin with deep pagination and RFC 6585 compliance."""

    name = "searxng"
    engine_family = "searxng"
    base_priority = 1

    def __init__(
        self,
        base_url: str | None = None,
        rate_limiter: TokenBucketRateLimiter | None = None,
        *,
        pacer: DynamicPoissonPacer | None = None,
        engines: str = "brave,yahoo,wikipedia,qwant,duckduckgo",
        timeout: float = DEFAULT_SEARXNG_TIMEOUT_SECONDS,
        max_retries: int = 3,
        auto_discover_host: str = "127.0.0.1",
        auto_discover_ports: Sequence[int] = (8888, 8080, 80),
    ) -> None:
        self.base_url: str | None = base_url.rstrip("/") if base_url else None
        self.rate_limiter = rate_limiter or TokenBucketRateLimiter()
        self.pacer = pacer
        self.engines = engines
        self.timeout = timeout
        self.max_retries = max_retries
        self._auto_host = auto_discover_host
        self._auto_ports = tuple(auto_discover_ports)

    async def on_startup(self) -> None:
        if self.base_url is None:
            self.base_url = await discover_local_searxng(
                host=self._auto_host,
                ports=self._auto_ports,
            )

    async def _fetch_page(self, query: str, pageno: int) -> list[SearchResult]:
        if not self.base_url:
            raise EngineDegradedError("No active SearXNG endpoint discovered.")

        endpoint = f"{self.base_url}/search"
        params = {
            "q": query,
            "format": "json",
            "categories": "general",
            "engines": self.engines,
            "language": "en",
            "pageno": str(pageno),
        }

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self.max_retries),
            wait=wait_random_exponential(multiplier=1.0, max=8.0),
            retry=retry_if_exception_type(
                (EngineDegradedError, RateLimitedError, CurlError, TimeoutError)
            ),
            reraise=True,
        ):
            with attempt:
                if self.pacer is not None:
                    await self.pacer.wait(self.engine_family)
                async with self.rate_limiter.throttle(self.engine_family):
                    try:
                        async with AsyncSession(timeout=self.timeout) as session:
                            resp = await session.get(
                                endpoint,
                                params=params,
                                headers={"Accept": "application/json"},
                            )
                    except (CurlError, TimeoutError, OSError) as exc:
                        if self.pacer is not None:
                            self.pacer.record_failure(self.engine_family)
                        raise EngineDegradedError(
                            f"SearXNG unreachable at {self.base_url}: {exc}"
                        ) from exc

                    if resp.status_code == 429:
                        retry_after = parse_retry_after(getattr(resp, "headers", None))
                        if self.pacer is not None:
                            self.pacer.record_failure(self.engine_family)
                            if retry_after:
                                self.pacer.respect_retry_after(
                                    self.engine_family, min(retry_after, 60.0)
                                )
                        raise RateLimitedError(
                            "SearXNG rate-limited (HTTP 429)",
                            status_code=429,
                            retry_after=retry_after,
                        )
                    if resp.status_code >= 500 or resp.status_code != 200:
                        if self.pacer is not None:
                            self.pacer.record_failure(self.engine_family)
                        raise EngineDegradedError(
                            f"SearXNG returned HTTP {resp.status_code}",
                            status_code=resp.status_code,
                        )

                    try:
                        payload = resp.json()
                    except ValueError as exc:
                        if self.pacer is not None:
                            self.pacer.record_failure(self.engine_family)
                        raise EngineDegradedError(f"SearXNG invalid JSON: {exc}") from exc

                    raw_items = payload.get("results") or []
                    normalized: list[SearchResult] = []
                    for item in raw_items:
                        url = canonicalize_url(str(item.get("url", "")))
                        title = " ".join(str(item.get("title", "")).split())
                        snippet = " ".join(str(item.get("content", "")).split())
                        sub_engine = str(item.get("engine", "searxng"))
                        if is_valid_http_url(url) and title:
                            normalized.append(
                                SearchResult(
                                    rank=len(normalized) + 1,
                                    title=title[:500],
                                    url=url[:2048],
                                    snippet=snippet[:4000],
                                    engine=f"searxng:{sub_engine}",
                                    query=query,
                                )
                            )
                    if self.pacer is not None:
                        self.pacer.record_success(self.engine_family)
                    return normalized

        raise EngineDegradedError("SearXNG retry loop exited unexpectedly")

    async def search(
        self,
        query: str,
        max_results: int = 20,
        pagination_depth: int = 2,
    ) -> list[SearchResult]:
        collected: list[SearchResult] = []
        seen_urls: set[str] = set()

        for page_num in range(1, pagination_depth + 1):
            page_items = await self._fetch_page(query, page_num)
            if not page_items:
                break
            added_this_page = 0
            for item in page_items:
                key = item.url.rstrip("/").lower()
                if key in seen_urls:
                    continue
                seen_urls.add(key)
                collected.append(item.model_copy(update={"rank": len(collected) + 1}))
                added_this_page += 1
                if len(collected) >= max_results:
                    return collected
            if added_this_page == 0:
                break

        if not collected:
            raise EmptyResultError(f"SearXNG returned 0 results for '{query}'")
        return collected
