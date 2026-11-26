"""Standalone DuckDuckGo Plugins (HTML Direct, Lite Direct, and optional DDGS fallback)."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Callable
from typing import Any

from curl_cffi.requests import AsyncSession
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

from core.constants import IGNORED_ENGINE_DOMAINS
from core.exceptions import (
    CaptchaTriggeredError,
    EmptyResultError,
    EngineDegradedError,
    RateLimitedError,
    TransportResetError,
)
from core.models import SearchResult
from engine.base import BaseSearchEngine, DirectBrowserEngineBase
from math_kernel.pacing_poisson import DynamicPoissonPacer
from transport.http_client import (
    AdaptiveDOMExtractor,
    AdaptiveHttpTransport,
    canonicalize_url,
    classify_http_response,
    is_valid_http_url,
)
from transport.proxy_pool import ProxyPoolManager
from transport.token_bucket import TokenBucketRateLimiter

_DDGS_CLASS: Any = None
try:
    from ddgs import DDGS as _DDGS_IMPORTED  # type: ignore[import-not-found]

    _DDGS_CLASS = _DDGS_IMPORTED
except ImportError:
    try:
        from duckduckgo_search import DDGS as _DDGS_LEGACY  # type: ignore[import-not-found]

        _DDGS_CLASS = _DDGS_LEGACY
    except ImportError:
        _DDGS_CLASS = None


class DuckDuckGoHtmlPlugin(DirectBrowserEngineBase):
    """Standalone DuckDuckGo HTML Direct Plugin (`html.duckduckgo.com/html/`)."""

    name = "ddg_html"
    engine_family = "ddg"
    base_priority = 2
    ENDPOINT = "https://html.duckduckgo.com/html/"

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
    def _extract_next_form(raw_html: str) -> dict[str, str] | None:
        tree = AdaptiveDOMExtractor.safe_parse(raw_html)
        if tree is None:
            return None
        for form_el in reversed(tree.xpath("//form")):
            extracted: dict[str, str] = {}
            for inp in form_el.xpath('.//input[@type="hidden" and @name]'):
                extracted[str(inp.get("name"))] = str(inp.get("value") or "")
            if "s" in extracted and ("q" in extracted or "vqd" in extracted):
                return extracted
        return None

    @staticmethod
    def parse_ddg_html(
        raw_html: str,
        query: str,
        max_results: int = 20,
    ) -> list[SearchResult]:
        return AdaptiveDOMExtractor.extract_results(
            raw_html=raw_html,
            query=query,
            engine_label="curl_cffi:ddg_html",
            max_results=max_results,
            container_hints=("div.result.results_links", "div.result", "div.web-result"),
            link_hints=("a.result__a", "h2 a", "a[href]"),
            snippet_hints=("a.result__snippet", "div.result__snippet", "p"),
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
                self.ENDPOINT,
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
            form_data: dict[str, str] = {"q": query, "kl": "us-en"}

            for page_idx in range(1, pagination_depth + 1):
                resp = await self.transport.request(
                    session,
                    "POST",
                    self.ENDPOINT,
                    data=form_data,
                    headers=self.transport.build_nav_headers(
                        referer=self.ENDPOINT,
                        origin="https://html.duckduckgo.com",
                    ),
                    on_http1_fallback=on_h1,
                )
                classify_http_response(
                    resp.status_code,
                    str(resp.url),
                    resp.text,
                    headers=getattr(resp, "headers", None),
                )

                page_items = self.parse_ddg_html(
                    raw_html=resp.text,
                    query=query,
                    max_results=max_results - len(collected),
                )
                for item in page_items:
                    key = item.url.rstrip("/").lower()
                    if key in seen_urls:
                        continue
                    seen_urls.add(key)
                    collected.append(item.model_copy(update={"rank": len(collected) + 1}))
                    if len(collected) >= max_results:
                        return collected

                if page_idx >= pagination_depth:
                    break
                next_form = self._extract_next_form(resp.text)
                if not next_form:
                    break
                form_data = next_form
                if self.pacer is not None:
                    await self.pacer.wait(self.engine_family)
                else:
                    await asyncio.sleep(random.uniform(0.7, 1.4))

            if not collected:
                raise EmptyResultError(f"DDG HTML parsed 0 organic links for '{query}'")
            return collected

        return await self._run_with_resilience(_execute)


class DuckDuckGoLitePlugin(DirectBrowserEngineBase):
    """Lightweight zero-JS DuckDuckGo Lite Plugin (`lite.duckduckgo.com/lite/`)."""

    name = "ddg_lite"
    engine_family = "ddg_lite"
    base_priority = 4
    ENDPOINT = "https://lite.duckduckgo.com/lite/"

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
    def _extract_next_form(raw_html: str) -> dict[str, str] | None:
        tree = AdaptiveDOMExtractor.safe_parse(raw_html)
        if tree is None:
            return None
        for form_el in reversed(tree.xpath("//form")):
            extracted: dict[str, str] = {}
            for inp in form_el.xpath('.//input[@type="hidden" and @name]'):
                extracted[str(inp.get("name"))] = str(inp.get("value") or "")
            if "s" in extracted and "q" in extracted:
                return extracted
        return None

    @staticmethod
    def parse_ddg_lite(
        raw_html: str,
        query: str,
        max_results: int = 20,
    ) -> list[SearchResult]:
        tree = AdaptiveDOMExtractor.safe_parse(raw_html)
        page_items: list[SearchResult] = []
        if tree is not None:
            link_nodes = tree.cssselect("a.result-link")
            snippet_nodes = tree.cssselect("td.result-snippet")
            for idx, link_el in enumerate(link_nodes):
                href = canonicalize_url(str(link_el.get("href") or ""))
                title = AdaptiveDOMExtractor.clean_text(
                    str(link_el.text_content() or ""), max_len=200
                )
                snippet = (
                    AdaptiveDOMExtractor.clean_text(
                        str(snippet_nodes[idx].text_content() or ""), max_len=360
                    )
                    if idx < len(snippet_nodes)
                    else ""
                )
                if (
                    AdaptiveDOMExtractor.is_valid_external_url(href, IGNORED_ENGINE_DOMAINS)
                    and len(title) >= 3
                ):
                    page_items.append(
                        SearchResult(
                            rank=len(page_items) + 1,
                            title=title,
                            url=href,
                            snippet=snippet,
                            engine="curl_cffi:ddg_lite",
                            query=query,
                        )
                    )
                    if len(page_items) >= max_results:
                        return page_items
        if page_items:
            return page_items
        return AdaptiveDOMExtractor.extract_results(
            raw_html=raw_html,
            query=query,
            engine_label="curl_cffi:ddg_lite",
            max_results=max_results,
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
            collected: list[SearchResult] = []
            seen_urls: set[str] = set()
            form_data: dict[str, str] = {"q": query, "kl": "us-en"}

            for page_idx in range(1, pagination_depth + 1):
                if self.pacer is not None:
                    await self.pacer.wait(self.engine_family)

                resp = await self.transport.request(
                    session,
                    "POST",
                    self.ENDPOINT,
                    data=form_data,
                    headers=self.transport.build_nav_headers(
                        referer=self.ENDPOINT,
                        origin="https://lite.duckduckgo.com",
                    ),
                    on_http1_fallback=on_h1,
                )
                classify_http_response(
                    resp.status_code,
                    str(resp.url),
                    resp.text,
                    headers=getattr(resp, "headers", None),
                )

                page_items = self.parse_ddg_lite(
                    raw_html=resp.text,
                    query=query,
                    max_results=max_results - len(collected),
                )
                for item in page_items:
                    key = item.url.rstrip("/").lower()
                    if key in seen_urls:
                        continue
                    seen_urls.add(key)
                    collected.append(item.model_copy(update={"rank": len(collected) + 1}))
                    if len(collected) >= max_results:
                        return collected

                if page_idx >= pagination_depth:
                    break
                next_form = self._extract_next_form(resp.text)
                if not next_form:
                    break
                form_data = next_form
                await asyncio.sleep(random.uniform(0.7, 1.4))

            if not collected:
                raise EmptyResultError(f"DDG Lite parsed 0 organic links for '{query}'")
            return collected

        return await self._run_with_resilience(_execute)


class DDGSFallbackPlugin(BaseSearchEngine):
    """Optional Tier-3 secondary plugin wrapping `ddgs` with proxy & rate-limit awareness."""

    name = "ddgs"
    engine_family = "ddgs"
    base_priority = 5

    def __init__(
        self,
        proxy_pool: ProxyPoolManager | None = None,
        rate_limiter: TokenBucketRateLimiter | None = None,
        timeout: int = 15,
        max_retries: int = 3,
    ) -> None:
        self.proxy_pool = proxy_pool or ProxyPoolManager()
        self.rate_limiter = rate_limiter or TokenBucketRateLimiter()
        self.timeout = timeout
        self.max_retries = max_retries

    async def search(
        self,
        query: str,
        max_results: int = 20,
        pagination_depth: int = 2,
    ) -> list[SearchResult]:
        if _DDGS_CLASS is None:
            raise EngineDegradedError("Optional package 'ddgs' is not installed.")

        excluded_proxies: set[str] = set()
        last_proxy_url: str | None = None
        target_count = min(max_results * max(1, pagination_depth), max_results)

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.max_retries),
                wait=wait_random_exponential(multiplier=1.2, max=12.0),
                retry=retry_if_exception_type(
                    (TransportResetError, EngineDegradedError, RateLimitedError, TimeoutError)
                ),
                reraise=True,
            ):
                with attempt:
                    proxy_node = await self.proxy_pool.select_proxy(exclude=excluded_proxies)
                    proxy_url = proxy_node.url if proxy_node else None
                    last_proxy_url = proxy_url
                    started = time.perf_counter()

                    def _blocking_query() -> list[dict[str, Any]]:
                        with _DDGS_CLASS(proxy=proxy_url, timeout=self.timeout) as client:
                            raw = client.text(query, max_results=target_count)
                            return list(raw) if raw else []

                    async with self.rate_limiter.throttle(self.engine_family):
                        try:
                            raw_results = await asyncio.to_thread(_blocking_query)
                        except Exception as exc:
                            msg = str(exc).lower()
                            if any(k in msg for k in ("ratelimit", "202", "429")):
                                await self.proxy_pool.report_throttle(
                                    proxy_url, reason=str(exc)
                                )
                                raise RateLimitedError(f"DDGS throttled: {exc}") from exc
                            if any(k in msg for k in ("403", "captcha")):
                                if proxy_url:
                                    excluded_proxies.add(proxy_url)
                                    await self.proxy_pool.report_failure(
                                        proxy_url,
                                        reason=str(exc),
                                        quarantine=True,
                                        transport_failure=True,
                                    )
                                raise CaptchaTriggeredError(f"DDGS blocked: {exc}") from exc

                            if proxy_url:
                                excluded_proxies.add(proxy_url)
                                await self.proxy_pool.report_failure(
                                    proxy_url,
                                    reason=str(exc),
                                    quarantine=True,
                                    transport_failure=True,
                                )
                            raise TransportResetError(f"DDGS transport error: {exc}") from exc

                    latency_ms = (time.perf_counter() - started) * 1000.0
                    await self.proxy_pool.report_success(proxy_url, latency_ms)

                    normalized: list[SearchResult] = []
                    for row in raw_results[:max_results]:
                        url = canonicalize_url(str(row.get("href") or row.get("url") or ""))
                        title = " ".join(str(row.get("title", "")).split())
                        snippet = " ".join(
                            str(row.get("body") or row.get("snippet") or "").split()
                        )
                        if is_valid_http_url(url) and title:
                            normalized.append(
                                SearchResult(
                                    rank=len(normalized) + 1,
                                    title=title[:500],
                                    url=url[:2048],
                                    snippet=snippet[:4000],
                                    engine="ddgs:auto",
                                    query=query,
                                )
                            )

                    if not normalized:
                        raise EmptyResultError(f"DDGS returned 0 results for '{query}'")
                    return normalized
        except TransportResetError as exhausted_exc:
            if last_proxy_url:
                await self.proxy_pool.report_failure(
                    last_proxy_url,
                    reason=f"DDGS transport exhaustion: {exhausted_exc}",
                    quarantine=True,
                    transport_failure=True,
                )
            raise

        raise EngineDegradedError("DDGS retry loop exited unexpectedly")
