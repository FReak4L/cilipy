"""Tier 2: Standalone Google Desktop Chrome udm=14 Web-Only Direct Extractor."""

from __future__ import annotations

import random
from collections.abc import Callable
from typing import Any

from curl_cffi.requests import AsyncSession
from lxml import html as lxml_html

from core.constants import DESKTOP_CLIENT_PROFILES, GOOGLE_EXCLUDED_HOSTS
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


class GoogleWebDirectPlugin(GoogleDirectHTMLMixin, DirectBrowserEngineBase):
    """Tier 2 Plugin: Desktop Chrome 130+ Direct Google Web-Only SERP (`udm=14`)."""

    name = "google_web_udm14"
    engine_family = "google_web"
    base_priority = 2
    MAX_PAGES = 50

    _CONTAINER_HINTS: tuple[str, ...] = (
        "div.MjjYud",
        "div.g",
        "div.tF2Cxc",
        "div[data-snhf]",
        "div.Gx5Zad",
    )
    _LINK_HINTS: tuple[str, ...] = (
        "div.yuRUbf a[href]",
        "a[jsname='UWckNb'][href]",
        "a[href]:has(h3)",
        "h3 a[href]",
        "a[href^='/url?q=']",
        "a[href]",
    )
    _SNIPPET_HINTS: tuple[str, ...] = (
        "div.VwiC3b",
        "div[data-sncf='1']",
        "div[data-sncf='2']",
        "span.aCOpRe",
        "div.BNeawe.s3v9rd",
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
        base_priority: int = 2,
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
    def parse_udm14_html(
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
            for container_sel in ("div.tF2Cxc", "div.g", "div.MjjYud"):
                try:
                    cards = tree.cssselect(container_sel)
                except Exception:
                    continue
                for card in cards:
                    h3_list = card.xpath(".//h3")
                    if not h3_list:
                        continue
                    h3_el = h3_list[0]
                    title = " ".join(str(h3_el.text_content() or "").split())
                    if len(title) < 3:
                        continue

                    anchor_list = h3_el.xpath("./ancestor::a[@href][1] | .//a[@href][1]")
                    if not anchor_list:
                        anchor_list = card.xpath(".//a[@href][1]")
                    if not anchor_list:
                        continue

                    url = unwrap_google_url(str(anchor_list[0].get("href") or ""))
                    if not is_valid_organic_url(url, GOOGLE_EXCLUDED_HOSTS):
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
                        if s_nodes:
                            snippet = " ".join(str(s_nodes[0].text_content() or "").split())
                            if snippet:
                                break

                    seen.add(dedup_key)
                    extracted.append(
                        SearchResult(
                            rank=len(extracted) + 1,
                            title=title[:500],
                            url=url[:2048],
                            snippet=snippet[:4000],
                            engine="google:web_udm14",
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
            engine_label="google:web_udm14",
            max_results=max_results * 2,
            container_hints=cls._CONTAINER_HINTS,
            link_hints=cls._LINK_HINTS,
            snippet_hints=cls._SNIPPET_HINTS,
            excluded_hosts=GOOGLE_EXCLUDED_HOSTS,
            url_unwrapper=unwrap_google_url,
        )
        return cls._post_process_google_results(
            raw_results=fallback_items,
            engine_label="google:web_udm14",
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
            profile_idx = random.randrange(len(DESKTOP_CLIENT_PROFILES))
            search_endpoint = f"https://{domain}/search"

            assert self.pacer is not None
            await self.pacer.wait(self.engine_family)
            referer = await self._bootstrap_session_cookies(
                session,
                domain,
                on_h1,
                mobile=False,
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
                    mobile=False,
                )
                headers = build_chrome_headers(
                    hl=self.locale.hl,
                    gl=self.locale.gl,
                    mobile=False,
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

                page_items = self.parse_udm14_html(
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
                    last_body, domain, "Google Web (udm=14)", query
                )
            return collected

        return await self._run_with_resilience(_execute)
