"""Tier 3: Standalone Android Chrome Client-Hints (Sec-Ch-Ua-Mobile: ?1) Mobile Direct Extractor."""

from __future__ import annotations

import random
from collections.abc import Callable
from typing import Any

from curl_cffi.requests import AsyncSession
from lxml import html as lxml_html

from core.constants import GOOGLE_EXCLUDED_HOSTS, MOBILE_CLIENT_PROFILES
from core.exceptions import (
    GoogleChallengeTriggeredError,
    GoogleDOMStructureChangedError,
)
from core.models import SearchResult
from engine.base import DirectBrowserEngineBase
from math_kernel.pacing_poisson import DynamicPoissonPacer
from plugins.google.common import (
    GoogleDirectHTMLMixin,
    GoogleDomainRotator,
    GoogleLocaleConfig,
    build_chrome_headers,
    build_omnibox_params,
    detect_google_block,
    is_valid_organic_url,
    unwrap_google_url,
)
from transport.http_client import AdaptiveDOMExtractor, AdaptiveHttpTransport
from transport.proxy_pool import ProxyPoolManager
from transport.token_bucket import TokenBucketRateLimiter


class GoogleMobileDirectPlugin(GoogleDirectHTMLMixin, DirectBrowserEngineBase):
    """Tier 3 Plugin: Android/Pixel Chrome Mobile Web SERP (`Sec-Ch-Ua-Mobile: ?1`)."""

    name = "google_mobile_web"
    engine_family = "google_mobile"
    base_priority = 3
    MAX_PAGES = 30

    _CONTAINER_HINTS: tuple[str, ...] = (
        "div.xpd",
        "div.MjjYud",
        "div.Gx5Zad",
        "div.ezO2md",
        "div.g",
    )
    _LINK_HINTS: tuple[str, ...] = (
        "a.cz3goc[href]",
        "a[role='presentation'][href]",
        "div.egMi0 a[href]",
        "a[href^='/url?q=']",
        "a[href]:has(div[role='heading'])",
        "a[href]:has(h3)",
        "a[href]",
    )
    _SNIPPET_HINTS: tuple[str, ...] = (
        "div.VwiC3b",
        "div.BNeawe.s3v9rd",
        "div.yDYNvb",
        "div[data-sncf='1']",
        "span.MUxGbd",
    )

    def __init__(
        self,
        proxy_pool: ProxyPoolManager | None = None,
        rate_limiter: TokenBucketRateLimiter | None = None,
        transport: AdaptiveHttpTransport | None = None,
        registry: Any | None = None,
        *,
        locale: GoogleLocaleConfig | None = None,
        domain_rotator: GoogleDomainRotator | None = None,
        pacer: DynamicPoissonPacer | None = None,
        enable_warmup: bool = True,
        max_retries: int = 3,
        base_priority: int = 3,
    ) -> None:
        resolved_pacer = pacer or DynamicPoissonPacer()
        super().__init__(
            proxy_pool=proxy_pool or ProxyPoolManager(),
            rate_limiter=rate_limiter or TokenBucketRateLimiter(),
            transport=transport or AdaptiveHttpTransport(),
            registry=registry,
            pacer=resolved_pacer,
            max_retries=max_retries,
        )
        self.locale = locale or GoogleLocaleConfig()
        self.domain_rotator = domain_rotator or GoogleDomainRotator()
        self.pacer = resolved_pacer
        self.enable_warmup = enable_warmup
        self.base_priority = base_priority

    @classmethod
    def parse_mobile_html(
        cls,
        raw_html: str,
        query: str,
        max_results: int = 20,
    ) -> list[SearchResult]:
        extracted: list[SearchResult] = []
        seen: set[str] = set()

        try:
            parser = lxml_html.HTMLParser(recover=True, remove_comments=True)
            tree = lxml_html.fromstring(raw_html, parser=parser)
        except Exception:
            tree = None

        if tree is not None:
            for container_sel in ("div.xpd", "div.MjjYud", "div.Gx5Zad", "div.ezO2md"):
                try:
                    cards = tree.cssselect(container_sel)
                except Exception:
                    continue
                for card in cards:
                    heading_nodes = card.xpath('.//div[@role="heading"] | .//h3')
                    link_el: Any | None = None
                    raw_title = ""

                    if heading_nodes:
                        h_el = heading_nodes[0]
                        raw_title = " ".join(str(h_el.text_content() or "").split())
                        anchors = h_el.xpath("./ancestor::a[@href][1] | .//a[@href][1]")
                        if anchors:
                            link_el = anchors[0]

                    if link_el is None:
                        anchors = card.xpath(
                            './/a[starts-with(@href, "/url?q=") or starts-with(@href, "http")]'
                        )
                        if not anchors:
                            continue
                        link_el = anchors[0]
                        if not raw_title:
                            raw_title = " ".join(str(link_el.text_content() or "").split())

                    url = unwrap_google_url(str(link_el.get("href") or ""))
                    if not is_valid_organic_url(url, GOOGLE_EXCLUDED_HOSTS):
                        continue
                    if len(raw_title) < 3:
                        continue

                    dedup_key = url.rstrip("/").lower()
                    if dedup_key in seen:
                        continue

                    snippet = ""
                    for s_sel in cls._SNIPPET_HINTS:
                        try:
                            s_nodes = card.cssselect(s_sel)
                        except Exception:
                            s_nodes = []
                        for s_node in s_nodes:
                            cand = " ".join(str(s_node.text_content() or "").split())
                            if cand and cand != raw_title:
                                snippet = cand
                                break
                        if snippet:
                            break

                    seen.add(dedup_key)
                    extracted.append(
                        SearchResult(
                            rank=len(extracted) + 1,
                            title=raw_title[:500],
                            url=url[:2048],
                            snippet=snippet[:4000],
                            engine="google:mobile_web",
                            query=query,
                        )
                    )
                    if len(extracted) >= max_results:
                        return extracted
                if extracted:
                    return extracted

        fallback_items = AdaptiveDOMExtractor.extract_results(
            raw_html=raw_html,
            query=query,
            engine_label="google:mobile_web",
            max_results=max_results * 2,
            container_hints=cls._CONTAINER_HINTS,
            link_hints=cls._LINK_HINTS,
            snippet_hints=cls._SNIPPET_HINTS,
            excluded_hosts=GOOGLE_EXCLUDED_HOSTS,
            url_unwrapper=unwrap_google_url,
        )
        return cls._post_process_google_results(
            raw_results=fallback_items,
            engine_label="google:mobile_web",
            query=query,
            max_results=max_results,
        )

    async def search(
        self,
        query: str,
        max_results: int = 20,
        pagination_depth: int = 2,
    ) -> list[SearchResult]:
        pages_to_fetch = min(max(1, pagination_depth), self.MAX_PAGES)
        tried_domains: set[str] = set()

        async def _execute(
            session: AsyncSession,
            on_h1: Callable[[], None],
        ) -> list[SearchResult]:
            domain = await self.domain_rotator.select(exclude=tried_domains)
            tried_domains.add(domain)
            profile_idx = random.randrange(len(MOBILE_CLIENT_PROFILES))
            search_endpoint = f"https://{domain}/search"

            assert self.pacer is not None
            await self.pacer.wait(self.engine_family)
            referer = await self._bootstrap_session_cookies(
                session,
                domain,
                on_h1,
                mobile=True,
                profile_index=profile_idx,
            )

            collected: list[SearchResult] = []
            seen_urls: set[str] = set()
            last_body = ""

            for page_idx in range(pages_to_fetch):
                params = build_omnibox_params(
                    query=query,
                    locale=self.locale,
                    page_idx=page_idx,
                    udm="14",
                    mobile=True,
                )
                headers = build_chrome_headers(
                    hl=self.locale.hl,
                    gl=self.locale.gl,
                    mobile=True,
                    referer=referer,
                    profile_index=profile_idx,
                )

                resp = await self.transport.request(
                    session,
                    "GET",
                    search_endpoint,
                    params=params,
                    headers=headers,
                    on_http1_fallback=on_h1,
                )
                last_body = resp.text
                try:
                    detect_google_block(
                        resp.status_code,
                        str(resp.url),
                        last_body,
                        headers=getattr(resp, "headers", None),
                    )
                except (GoogleChallengeTriggeredError, GoogleDOMStructureChangedError) as exc:
                    await self.domain_rotator.mark_challenged(domain, str(exc))
                    raise

                await self.domain_rotator.mark_healthy(domain)
                referer = str(resp.url)

                page_items = self.parse_mobile_html(
                    raw_html=last_body,
                    query=query,
                    max_results=max_results - len(collected),
                )
                added = 0
                for item in page_items:
                    dedup_key = item.url.rstrip("/").lower()
                    if dedup_key in seen_urls:
                        continue
                    seen_urls.add(dedup_key)
                    collected.append(item.model_copy(update={"rank": len(collected) + 1}))
                    added += 1
                    if len(collected) >= max_results:
                        return collected

                if added == 0 or page_idx + 1 >= pages_to_fetch:
                    break

                await self.pacer.wait(self.engine_family)

            if not collected:
                self._classify_zero_extraction(
                    last_body, domain, "Google Mobile Web", query
                )
            return collected

        return await self._run_with_resilience(_execute)
