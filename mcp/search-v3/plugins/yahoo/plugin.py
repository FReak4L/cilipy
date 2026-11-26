"""Standalone Yahoo Direct Web Search Plugin (`search.yahoo.com/search`)."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Callable
from typing import Any

from curl_cffi.requests import AsyncSession

from core.exceptions import EmptyResultError
from core.models import SearchResult
from engine.base import DirectBrowserEngineBase
from math_kernel.pacing_poisson import DynamicPoissonPacer
from transport.http_client import (
    AdaptiveDOMExtractor,
    AdaptiveHttpTransport,
    classify_http_response,
)
from transport.proxy_pool import ProxyPoolManager
from transport.token_bucket import TokenBucketRateLimiter


class YahooDirectPlugin(DirectBrowserEngineBase):
    """
    Standalone Yahoo Direct Plugin using BoringSSL Chrome impersonation,
    `/RU=` redirector unwrapping, multi-heuristic DOM parsing, and offset pagination.
    """

    name = "yahoo_direct"
    engine_family = "yahoo"
    base_priority = 3
    HOME_URL = "https://search.yahoo.com/"
    SEARCH_URL = "https://search.yahoo.com/search"

    def __init__(
        self,
        proxy_pool: ProxyPoolManager | None = None,
        rate_limiter: TokenBucketRateLimiter | None = None,
        transport: AdaptiveHttpTransport | None = None,
        registry: Any | None = None,
        *,
        pacer: DynamicPoissonPacer | None = None,
        max_retries: int = 3,
    ) -> None:
        super().__init__(
            proxy_pool=proxy_pool or ProxyPoolManager(),
            rate_limiter=rate_limiter or TokenBucketRateLimiter(),
            transport=transport or AdaptiveHttpTransport(),
            registry=registry,
            pacer=pacer,
            max_retries=max_retries,
        )

    @staticmethod
    def parse_yahoo_html(
        raw_html: str,
        query: str,
        max_results: int = 20,
    ) -> list[SearchResult]:
        return AdaptiveDOMExtractor.extract_results(
            raw_html=raw_html,
            query=query,
            engine_label="curl_cffi:yahoo_direct",
            max_results=max_results,
            container_hints=("div.algo", "div.dd.algo", "ol.searchCenterMiddle li"),
            link_hints=("h3.title a", "h3 a", "a[href*='/RU=']", "a[href]"),
            snippet_hints=("div.compText p", "p.s-desc", "p"),
        )

    async def search(
        self,
        query: str,
        max_results: int = 20,
        pagination_depth: int = 2,
    ) -> list[SearchResult]:
        async def _execute(
            session: AsyncSession, on_h1: Callable[[], None]
        ) -> list[SearchResult]:
            if self.pacer is not None:
                await self.pacer.wait(self.engine_family)

            warm_resp = await self.transport.request(
                session,
                "GET",
                self.HOME_URL,
                headers=self.transport.build_nav_headers(),
                on_http1_fallback=on_h1,
            )
            classify_http_response(
                warm_resp.status_code,
                str(warm_resp.url),
                warm_resp.text,
                headers=getattr(warm_resp, "headers", None),
            )
            await asyncio.sleep(random.uniform(0.25, 0.6))

            collected: list[SearchResult] = []
            seen_urls: set[str] = set()

            for page_idx in range(1, pagination_depth + 1):
                offset = 1 + (page_idx - 1) * 10
                params = {
                    "p": query,
                    "b": str(offset),
                    "pz": "10",
                    "ei": "UTF-8",
                }
                resp = await self.transport.request(
                    session,
                    "GET",
                    self.SEARCH_URL,
                    params=params,
                    headers=self.transport.build_nav_headers(referer=self.HOME_URL),
                    on_http1_fallback=on_h1,
                )
                classify_http_response(
                    resp.status_code,
                    str(resp.url),
                    resp.text,
                    headers=getattr(resp, "headers", None),
                )

                page_items = self.parse_yahoo_html(
                    raw_html=resp.text,
                    query=query,
                    max_results=max_results - len(collected),
                )
                added = 0
                for item in page_items:
                    key = item.url.rstrip("/").lower()
                    if key in seen_urls:
                        continue
                    seen_urls.add(key)
                    collected.append(item.model_copy(update={"rank": len(collected) + 1}))
                    added += 1
                    if len(collected) >= max_results:
                        return collected

                if added == 0 or page_idx >= pagination_depth:
                    break
                if self.pacer is not None:
                    await self.pacer.wait(self.engine_family)
                else:
                    await asyncio.sleep(random.uniform(0.8, 1.5))

            if not collected:
                raise EmptyResultError(f"Yahoo Direct parsed 0 organic links for '{query}'")
            return collected

        return await self._run_with_resilience(_execute)
