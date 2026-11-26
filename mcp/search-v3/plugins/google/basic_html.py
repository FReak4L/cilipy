"""Tier 4: Standalone Zero-JS Google Basic HTML (`gbv=1` / `gbv=2`) Fallback Parser."""

from __future__ import annotations

import random
from collections.abc import Callable
from typing import Any, Literal

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


class GoogleBasicHtmlPlugin(GoogleDirectHTMLMixin, DirectBrowserEngineBase):
    """Tier 4 Plugin: Lightweight Zero-JS Google Basic HTML (`gbv=1` / `gbv=2`)."""

    name = "google_basic_html"
    engine_family = "google_basic"
    base_priority = 4
    MAX_PAGES = 30

    _CONTAINER_HINTS: tuple[str, ...] = (
        "div.Gx5Zad",
        "div.ZINbbc",
        "div.ezO2md",
        "div.g",
    )
    _LINK_HINTS: tuple[str, ...] = (
        "div.egMi0 a[href]",
        "a[href^='/url?q=']",
        "h3 a[href]",
        "a[href]",
    )
    _SNIPPET_HINTS: tuple[str, ...] = (
        "div.BNeawe.s3v9rd.AP7Wnd",
        "div.BNeawe.s3v9rd",
        "div.s3v9rd",
        "span.fYyStc",
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
        enable_warmup: bool = False,
        max_retries: int = 3,
        base_priority: int = 4,
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
    def parse_basic_html(
        cls,
        raw_html: str,
        query: str,
        gbv_mode: str = "1",
        max_results: int = 20,
    ) -> list[SearchResult]:
        engine_label = f"google:basic_gbv{gbv_mode}"
        extracted: list[SearchResult] = []
        seen: set[str] = set()

        try:
            parser = lxml_html.HTMLParser(recover=True, remove_comments=True)
            tree = lxml_html.fromstring(raw_html, parser=parser)
        except Exception:
            tree = None

        if tree is not None:
            for card in tree.cssselect("div.Gx5Zad, div.ZINbbc, div.ezO2md"):
                anchors = card.xpath(
                    './/a[starts-with(@href, "/url?q=") or starts-with(@href, "http")]'
                )
                if not anchors:
                    continue
                link_el = anchors[0]
                url = unwrap_google_url(str(link_el.get("href") or ""))
                if not is_valid_organic_url(url, GOOGLE_EXCLUDED_HOSTS):
                    continue

                dedup_key = url.rstrip("/").lower()
                if dedup_key in seen:
                    continue

                title_nodes = link_el.cssselect("div.BNeawe.vvjwJb, h3, span")
                raw_title = (
                    str(title_nodes[0].text_content() or "")
                    if title_nodes
                    else str(link_el.text_content() or "")
                )
                title = " ".join(raw_title.split())
                if len(title) < 3:
                    continue

                snippet = ""
                for s_sel in cls._SNIPPET_HINTS:
                    try:
                        s_nodes = card.cssselect(s_sel)
                    except Exception:
                        s_nodes = []
                    for s_node in s_nodes:
                        candidate_snip = " ".join(str(s_node.text_content() or "").split())
                        if candidate_snip and candidate_snip != title:
                            snippet = candidate_snip
                            break
                    if snippet:
                        break

                seen.add(dedup_key)
                extracted.append(
                    SearchResult(
                        rank=len(extracted) + 1,
                        title=title[:500],
                        url=url[:2048],
                        snippet=snippet[:4000],
                        engine=engine_label,
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
            engine_label=engine_label,
            max_results=max_results * 2,
            container_hints=cls._CONTAINER_HINTS,
            link_hints=cls._LINK_HINTS,
            snippet_hints=cls._SNIPPET_HINTS,
            excluded_hosts=GOOGLE_EXCLUDED_HOSTS,
            url_unwrapper=unwrap_google_url,
        )
        return cls._post_process_google_results(
            raw_results=fallback_items,
            engine_label=engine_label,
            query=query,
            max_results=max_results,
        )

    async def _fetch_gbv_pages(
        self,
        session: AsyncSession,
        domain: str,
        on_h1: Callable[[], None],
        query: str,
        gbv_mode: Literal["1", "2"],
        max_results: int,
        pages_to_fetch: int,
        profile_idx: int,
        initial_referer: str,
    ) -> tuple[list[SearchResult], str]:
        collected: list[SearchResult] = []
        seen_urls: set[str] = set()
        referer = initial_referer
        search_endpoint = f"https://{domain}/search"
        last_body = ""

        assert self.pacer is not None

        for page_idx in range(pages_to_fetch):
            params = build_omnibox_params(
                query=query,
                locale=self.locale,
                page_idx=page_idx,
                udm="14",
                gbv=gbv_mode,
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

            page_items = self.parse_basic_html(
                raw_html=last_body,
                query=query,
                gbv_mode=gbv_mode,
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
                    return collected, last_body

            if added == 0 or page_idx + 1 >= pages_to_fetch:
                break

            await self.pacer.wait(self.engine_family)

        return collected, last_body

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

            assert self.pacer is not None
            await self.pacer.wait(self.engine_family)
            referer = await self._bootstrap_session_cookies(
                session,
                domain,
                on_h1,
                mobile=False,
                profile_index=profile_idx,
            )

            last_body = ""
            for gbv_mode in ("1", "2"):
                mode_lit: Literal["1", "2"] = "1" if gbv_mode == "1" else "2"
                results, last_body = await self._fetch_gbv_pages(
                    session=session,
                    domain=domain,
                    on_h1=on_h1,
                    query=query,
                    gbv_mode=mode_lit,
                    max_results=max_results,
                    pages_to_fetch=pages_to_fetch,
                    profile_idx=profile_idx,
                    initial_referer=referer,
                )
                if results:
                    return results

            self._classify_zero_extraction(
                last_body, domain, "Google Basic HTML (gbv=1/2)", query
            )
            return []

        return await self._run_with_resilience(_execute)
