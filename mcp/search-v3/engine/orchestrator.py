"""Concurrent stream orchestrator, Thompson Sampling failover cascade, AST gate, deduper & Katana crawl."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import Counter
from collections.abc import AsyncIterator, Callable, Sequence
from pathlib import Path
from typing import Any, Protocol

from core.exceptions import (
    CaptchaTriggeredError,
    EmptyResultError,
    EngineDegradedError,
    QueryParseError,
    RateLimitedError,
    TransportResetError,
)
from core.models import (
    AllEnginesMatrixOutput,
    CrawlResult,
    DeduplicationStats,
    DomainFrequency,
    EngineMetrics,
    EngineQueryOutcome,
    PipelineOutput,
    PipelineSettings,
    ProxyPoolStats,
    QueryAllEnginesRecord,
    SearchResult,
)
from engine.base import BaseSearchEngine
from engine.crawler import KatanaPipeline
from engine.registry import EngineRegistry
from math_kernel.ast_boolean import BooleanASTParser
from math_kernel.deduplicator import SimHashJaccardDeduplicator
from math_kernel.pacing_poisson import DynamicPoissonPacer
from plugins.duckduckgo import (
    DDGSFallbackPlugin,
    DuckDuckGoHtmlPlugin,
    DuckDuckGoLitePlugin,
)
from plugins.google import GoogleMultiTierPlugin, GoogleSuiteConfig, build_google_plugins
from plugins.searxng import SearXNGEnginePlugin
from plugins.yahoo import YahooDirectPlugin
from transport.cache import PipelineCacheManager
from transport.http_client import AdaptiveHttpTransport, extract_root_domain
from transport.proxy_pool import ProxyPoolManager
from transport.token_bucket import TokenBucketRateLimiter

logger = logging.getLogger("hybrid_search.v3.orchestrator")

_INLINE_DOUBLE_SLASH_COMMENT_RE = re.compile(r"\s+//.*$")
_INLINE_HASH_COMMENT_RE = re.compile(r"\s+#.*$")
_DIFFICULTY_PREFIX_RE = re.compile(r"^\[D=(\d{1,3})\]\s+(.+)$")


def parse_difficulty_prefix(raw_query: str) -> tuple[int | None, str]:
    """Extract optional `[D=001]`..`[D=100]` difficulty tag from a benchmark query line."""
    m = _DIFFICULTY_PREFIX_RE.match(raw_query.strip())
    if not m:
        return None, raw_query.strip()
    diff_val = max(1, min(100, int(m.group(1))))
    return diff_val, m.group(2).strip()


class TelemetrySink(Protocol):
    """Decoupled observability interface satisfied by `cli.ui_dashboard.PipelineDashboard`."""

    def start(self) -> None: ...
    def stop(self) -> None: ...
    def set_searxng_status(self, status: str) -> None: ...
    def set_total_queries(self, total: int) -> None: ...
    def update_proxy_stats(self, stats: ProxyPoolStats) -> None: ...
    def update_engine_metrics(self, metrics: Sequence[EngineMetrics]) -> None: ...
    def record_query_completed(
        self,
        query: str,
        results: Sequence[SearchResult],
        from_cache: bool,
        relaxed: bool = False,
    ) -> None: ...


class _NullTelemetrySink:
    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def set_searxng_status(self, status: str) -> None:
        return None

    def set_total_queries(self, total: int) -> None:
        return None

    def update_proxy_stats(self, stats: ProxyPoolStats) -> None:
        return None

    def update_engine_metrics(self, metrics: Sequence[EngineMetrics]) -> None:
        return None

    def record_query_completed(
        self,
        query: str,
        results: Sequence[SearchResult],
        from_cache: bool,
        relaxed: bool = False,
    ) -> None:
        return None


def strip_query_line(line: str, in_block_comment: bool) -> tuple[str | None, bool]:
    """Strip block (`/* ... */`), full-line, and inline (`#`, `//`) comments safely."""
    text = line
    while True:
        if in_block_comment:
            end_idx = text.find("*/")
            if end_idx == -1:
                return None, True
            text = text[end_idx + 2 :]
            in_block_comment = False
        else:
            start_idx = text.find("/*")
            if start_idx == -1:
                break
            end_idx = text.find("*/", start_idx + 2)
            if end_idx == -1:
                text = text[:start_idx]
                in_block_comment = True
                break
            text = text[:start_idx] + " " + text[end_idx + 2 :]

    stripped = text.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("//"):
        return None, in_block_comment

    stripped = _INLINE_DOUBLE_SLASH_COMMENT_RE.sub("", stripped)
    stripped = _INLINE_HASH_COMMENT_RE.sub("", stripped)
    stripped = stripped.strip()
    return (stripped if stripped else None), in_block_comment


async def stream_queries_from_file(
    file_path: Path,
    chunk_size: int = 256,
) -> AsyncIterator[str]:
    """Stream normalized search queries asynchronously without blocking the event loop."""
    if not file_path.is_file():
        raise FileNotFoundError(f"Query input file not found: {file_path}")

    def _read_batch(handle: Any, max_lines: int) -> list[str]:
        batch: list[str] = []
        for _ in range(max_lines):
            raw_line = handle.readline()
            if not raw_line:
                break
            batch.append(raw_line)
        return batch

    in_block_comment = False
    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        while True:
            raw_lines = await asyncio.to_thread(_read_batch, handle, chunk_size)
            if not raw_lines:
                break
            for raw_line in raw_lines:
                cleaned, in_block_comment = strip_query_line(raw_line, in_block_comment)
                if cleaned:
                    yield cleaned


class QueryRelaxer:
    """Optional zero-result fallback generator (strictly disabled under default `--no-relax`)."""

    _BOOLEAN_OP_RE = re.compile(r"\b(?:AND|OR|NOT)\b")
    _FIELD_OP_RE = re.compile(
        r"\b(?:intitle|allintitle|inurl|allinurl|intext|allintext):", re.IGNORECASE
    )
    _NEGATION_TERM_RE = re.compile(r'(?:^|\s)-"[^"]+"|(?:^|\s)-\S+')

    @classmethod
    def relax(cls, query: str) -> str | None:
        original = " ".join(query.strip().split())
        if not original:
            return None
        candidate = original.replace('"', " ").replace("(", " ").replace(")", " ")
        candidate = cls._BOOLEAN_OP_RE.sub(" ", candidate)
        candidate = cls._NEGATION_TERM_RE.sub(" ", candidate)
        candidate = cls._FIELD_OP_RE.sub("", candidate)
        candidate = " ".join(candidate.split())
        if not candidate or candidate.lower() == original.lower():
            return None
        return candidate


class SearchOrchestrator:
    """
    Standalone v3 Federated Search Orchestrator:
      1. Thompson Sampling Beta(α, β) multi-armed bandit engine & proxy dispatching
      2. Dynamic Poisson Exp(λ) pacing + microsecond Token Bucket + RFC 6585 compliance
      3. Strict deterministic Boolean AST truth-table filtering (B = {0, 1}, zero quote stripping)
      4. 64-bit SimHash (Hamming <= 3) & Jaccard (J >= 0.85) deduplication
      5. Persistent SQLite async caching + bounded asyncio.Queue worker pool
      6. Optional Tier 4 Katana deep crawling & schema extraction
    """

    def __init__(
        self,
        settings: PipelineSettings,
        *,
        plugins: Sequence[BaseSearchEngine] | None = None,
        google_config: GoogleSuiteConfig | None = None,
        telemetry_sink: TelemetrySink | None = None,
        bandit_seed: int | None = None,
    ) -> None:
        self.settings = settings
        self.telemetry: TelemetrySink = telemetry_sink or _NullTelemetrySink()

        self.proxy_pool = (
            ProxyPoolManager.from_file(
                settings.proxies_file,
                quarantine_seconds=settings.proxy_quarantine_seconds,
                probe_timeout=settings.proxy_probe_timeout,
                use_thompson_sampling=settings.enable_thompson_sampling,
            )
            if settings.proxies_file is not None
            else ProxyPoolManager(
                quarantine_seconds=settings.proxy_quarantine_seconds,
                probe_timeout=settings.proxy_probe_timeout,
                use_thompson_sampling=settings.enable_thompson_sampling,
                bandit_seed=bandit_seed,
            )
        )
        self.rate_limiter = TokenBucketRateLimiter(
            max_concurrency=settings.concurrency,
            tokens_per_second=settings.tokens_per_second,
            burst_capacity=max(2.0, float(settings.concurrency)),
            jitter_min=settings.jitter_min,
            jitter_max=settings.jitter_max,
        )
        self.pacer = DynamicPoissonPacer(
            mean_delay_seconds=settings.poisson_mean_delay,
            seed=bandit_seed,
        )
        self.cache = PipelineCacheManager(
            db_path=settings.cache_db_path,
            ttl_seconds=settings.cache_ttl_seconds,
            enabled=settings.enable_cache,
        )
        self.transport = AdaptiveHttpTransport(
            timeout=settings.request_timeout,
            enable_http1_fallback=settings.enable_http1_fallback,
        )
        self.registry = EngineRegistry(
            park_bot_threshold=settings.engine_park_bot_threshold,
            park_empty_threshold=settings.engine_park_empty_threshold,
            park_seconds=settings.engine_park_seconds,
            use_thompson_sampling=settings.enable_thompson_sampling,
            bandit_seed=bandit_seed,
        )
        self.ast_parser = BooleanASTParser()
        self.deduplicator = SimHashJaccardDeduplicator(
            max_hamming=settings.simhash_max_hamming,
            jaccard_threshold=settings.jaccard_threshold,
        )

        self.searxng_plugin: SearXNGEnginePlugin | None = None
        if plugins is not None:
            for plugin in plugins:
                self.registry.register(plugin)
                if isinstance(plugin, SearXNGEnginePlugin):
                    self.searxng_plugin = plugin
        else:
            self._register_configured_plugins(google_config=google_config)

        self.katana = KatanaPipeline(
            depth=settings.crawl_depth,
            rate_limit_rps=settings.crawl_rate_limit_rps,
            concurrency=settings.crawl_concurrency,
            timeout_seconds=settings.crawl_timeout_seconds,
            allowed_domains=settings.allowed_crawl_domains,
            enrich_metadata=settings.crawl_enrich_metadata,
        )
        self._cache_metric = EngineMetrics(engine="sqlite_cache", priority_tier=0)

    def _register_configured_plugins(
        self,
        *,
        google_config: GoogleSuiteConfig | None = None,
    ) -> None:
        self.searxng_plugin = SearXNGEnginePlugin(
            base_url=self.settings.searxng_url,
            rate_limiter=self.rate_limiter,
            pacer=self.pacer,
            engines=self.settings.searxng_engines,
            timeout=self.settings.request_timeout,
            max_retries=self.settings.max_retries,
            auto_discover_host=self.settings.searxng_host,
            auto_discover_ports=self.settings.searxng_probe_ports,
        )
        available: dict[str, BaseSearchEngine] = {
            "searxng": self.searxng_plugin,
            "ddg_html": DuckDuckGoHtmlPlugin(
                proxy_pool=self.proxy_pool,
                rate_limiter=self.rate_limiter,
                transport=self.transport,
                registry=self.registry,
                pacer=self.pacer,
                max_retries=self.settings.max_retries,
            ),
            "yahoo_direct": YahooDirectPlugin(
                proxy_pool=self.proxy_pool,
                rate_limiter=self.rate_limiter,
                transport=self.transport,
                registry=self.registry,
                pacer=self.pacer,
                max_retries=self.settings.max_retries,
            ),
            "ddg_lite": DuckDuckGoLitePlugin(
                proxy_pool=self.proxy_pool,
                rate_limiter=self.rate_limiter,
                transport=self.transport,
                registry=self.registry,
                pacer=self.pacer,
                max_retries=self.settings.max_retries,
            ),
            "ddgs": DDGSFallbackPlugin(
                proxy_pool=self.proxy_pool,
                rate_limiter=self.rate_limiter,
                timeout=int(self.settings.request_timeout),
                max_retries=self.settings.max_retries,
            ),
        }

        resolved_google_cfg = google_config or GoogleSuiteConfig.from_env().model_copy(
            update={"max_retries": self.settings.max_retries}
        )
        google_plugins = build_google_plugins(
            proxy_pool=self.proxy_pool,
            rate_limiter=self.rate_limiter,
            transport=self.transport,
            registry=self.registry,
            config=resolved_google_cfg,
            pacer=self.pacer,
        )
        for gp in google_plugins:
            available[gp.name] = gp
        if "google_web_udm14" in available:
            available["google_direct"] = available["google_web_udm14"]
        if "google_mobile_web" in available:
            available["google_mobile"] = available["google_mobile_web"]
        if "google_basic_html" in available:
            available["google_basic"] = available["google_basic_html"]
        available["google"] = GoogleMultiTierPlugin(
            google_plugins,
            use_thompson_sampling=self.settings.enable_thompson_sampling,
        )
        available["google_suite"] = available["google"]

        for engine_name in self.settings.enabled_engines:
            plugin = available.get(engine_name.strip().lower())
            if plugin is not None:
                self.registry.register(plugin)

    def filter_with_strict_ast(
        self,
        query: str,
        results: Sequence[SearchResult],
    ) -> tuple[list[SearchResult], int]:
        """
        Deterministic Boolean AST truth-table gate:
        If Eval(Q_AST, D) == 0, the candidate document is dropped immediately.
        """
        if not self.settings.strict_ast_filter or not results:
            return list(results), 0
        try:
            compiled = self.ast_parser.parse(query)
        except QueryParseError as exc:
            logger.debug("[ast_gate] Skipping parse for '%s': %s", query, exc)
            return list(results), 0

        admitted, dropped = compiled.filter_documents(results)
        if dropped > 0:
            logger.debug(
                "[ast_gate] query=%r admitted=%d dropped=%d",
                query,
                len(admitted),
                dropped,
            )
        return admitted, dropped

    @staticmethod
    def _backend_dialect_for(plugin: BaseSearchEngine) -> str:
        family = (plugin.engine_family or "").lower()
        if family in ("ddg", "ddg_lite", "ddgs"):
            return "duckduckgo"
        if family == "yahoo":
            return "yahoo"
        if family == "searxng":
            return "searxng"
        return "google"

    async def _query_registry(
        self,
        query: str,
        *,
        apply_strict_ast: bool = True,
    ) -> tuple[list[SearchResult], int]:
        """
        Dispatch `query` across Thompson-ranked plugins with non-destructive dialect
        translation and per-engine strict Boolean AST verification:
          - Only AST-verified yield (>= 1 admitted result) rewards an arm (α += 1).
          - If all raw results fail Eval(Q_AST, D) == 0, the engine records zero
            verified yield (β += 1) and the orchestrator fails over immediately.
        """
        compiled_ast = None
        if apply_strict_ast and self.settings.strict_ast_filter:
            try:
                compiled_ast = self.ast_parser.parse(query)
            except QueryParseError as exc:
                logger.debug("[ast_gate] Skipping AST compile for '%s': %s", query, exc)

        total_dropped = 0
        candidates = await self.registry.get_ordered_candidates()
        for plugin in candidates:
            started = time.perf_counter()
            dialect = self._backend_dialect_for(plugin)
            dispatch_query = (
                compiled_ast.translate_for_backend(dialect)
                if compiled_ast is not None
                else query
            )
            try:
                raw_results = await plugin.search(
                    query=dispatch_query,
                    max_results=self.settings.max_results_per_query,
                    pagination_depth=self.settings.pagination_depth,
                )
                latency_ms = (time.perf_counter() - started) * 1000.0

                # Restore original user query provenance on every candidate
                normalized_raw = [
                    (
                        item.model_copy(update={"query": query})
                        if item.query != query
                        else item
                    )
                    for item in raw_results
                ]

                if compiled_ast is not None:
                    admitted, dropped = compiled_ast.filter_documents(normalized_raw)
                    total_dropped += dropped
                else:
                    admitted = normalized_raw

                if admitted:
                    await self.registry.record_success(
                        plugin.name,
                        latency_ms=latency_ms,
                        result_count=len(admitted),
                    )
                    return admitted, total_dropped

                await self.registry.record_failure(
                    plugin.name,
                    EmptyResultError(
                        f"{plugin.name} yielded 0 AST-verified results "
                        f"(raw={len(normalized_raw)})"
                    ),
                    latency_ms,
                )
                logger.warning(
                    "[orchestrator] plugin '%s' yielded 0 AST-verified matches "
                    "(raw=%d dropped) for '%s' -> failing over",
                    plugin.name,
                    len(normalized_raw),
                    query,
                )
            except (
                CaptchaTriggeredError,
                RateLimitedError,
                TransportResetError,
                EngineDegradedError,
                EmptyResultError,
            ) as exc:
                latency_ms = (time.perf_counter() - started) * 1000.0
                await self.registry.record_failure(plugin.name, exc, latency_ms)
                logger.warning(
                    "[orchestrator] plugin '%s' failed for '%s': %s -> failing over",
                    plugin.name,
                    query,
                    exc,
                )
            except Exception as exc:
                latency_ms = (time.perf_counter() - started) * 1000.0
                await self.registry.record_failure(plugin.name, exc, latency_ms)
                logger.error(
                    "[orchestrator] Unexpected error in '%s' for '%s': %s",
                    plugin.name,
                    query,
                    exc,
                )
        return [], total_dropped

    async def _run_failover_chain(
        self,
        query: str,
    ) -> tuple[list[SearchResult], bool, bool, int]:
        """Returns `(results, from_cache, was_relaxed, ast_dropped_count)`."""
        total_dropped = 0

        cached = await self.cache.get(query, engine_scope="global")
        if cached is not None:
            admitted_cached, dropped = self.filter_with_strict_ast(query, cached)
            total_dropped += dropped
            if admitted_cached:
                self._cache_metric.requests += 1
                self._cache_metric.successes += 1
                self._cache_metric.cache_hits += 1
                return (
                    admitted_cached[: self.settings.max_results_per_query],
                    True,
                    False,
                    total_dropped,
                )

        results, dropped_live = await self._query_registry(query, apply_strict_ast=True)
        total_dropped += dropped_live
        if results:
            await self.cache.set(query, results, engine_scope="global")
            return results, False, False, total_dropped

        if self.settings.enable_query_relaxation:
            relaxed_variant = QueryRelaxer.relax(query)
            if relaxed_variant is not None:
                logger.info(
                    "[relaxer] Zero yield for '%s'; retrying relaxed variant '%s'",
                    query,
                    relaxed_variant,
                )
                relaxed_results, _ = await self._query_registry(
                    relaxed_variant, apply_strict_ast=False
                )
                if relaxed_results:
                    tagged = [
                        item.model_copy(
                            update={
                                "query": query,
                                "engine": f"{item.engine}:relaxed",
                            }
                        )
                        for item in relaxed_results
                    ]
                    await self.cache.set(query, tagged, engine_scope="global")
                    return tagged, False, True, total_dropped

        return [], False, False, total_dropped

    @staticmethod
    def _compute_domain_frequencies(
        results: Sequence[SearchResult],
        top_n: int = 25,
    ) -> tuple[int, list[DomainFrequency]]:
        counts: Counter[str] = Counter()
        engines_by_domain: dict[str, set[str]] = {}
        for item in results:
            dom = extract_root_domain(item.url)
            if not dom:
                continue
            counts[dom] += 1
            engines_by_domain.setdefault(dom, set()).add(item.engine)

        top_domains = [
            DomainFrequency(
                domain=dom,
                count=cnt,
                engines=sorted(engines_by_domain.get(dom, set())),
            )
            for dom, cnt in counts.most_common(top_n)
        ]
        return len(counts), top_domains

    async def execute_stream(
        self,
        query_stream: AsyncIterator[str],
        total_hint: int | None = None,
    ) -> PipelineOutput:
        started = time.perf_counter()
        self.deduplicator.reset()
        await self.cache.initialize()

        if total_hint is not None:
            self.telemetry.set_total_queries(total_hint)
        self.telemetry.start()

        plugins = self.registry.list_plugins()
        try:
            # 1. Lifecycle startup hooks (includes SearXNG local discovery when registered)
            await asyncio.gather(*(p.on_startup() for p in plugins))
            if self.searxng_plugin is not None:
                self.telemetry.set_searxng_status(
                    self.searxng_plugin.base_url or "Offline (fallback tiers active)"
                )
            else:
                self.telemetry.set_searxng_status("Not enabled")

            # 2. Pre-flight proxy probe
            if self.proxy_pool.has_proxies:
                await self.proxy_pool.preflight_probe()
            self.telemetry.update_proxy_stats(self.proxy_pool.snapshot_stats())

            # 3. Bounded asyncio.Queue worker pool with backpressure
            queue: asyncio.Queue[str | None] = asyncio.Queue(
                maxsize=self.settings.queue_maxsize
            )
            collected_batches: list[list[SearchResult]] = []
            cache_hit_counter = 0
            relaxed_counter = 0
            ast_dropped_counter = 0
            results_lock = asyncio.Lock()

            async def _producer() -> int:
                enqueued = 0
                async for query in query_stream:
                    await queue.put(query)
                    enqueued += 1
                if total_hint is None:
                    self.telemetry.set_total_queries(enqueued)
                for _ in range(self.settings.concurrency):
                    await queue.put(None)
                return enqueued

            async def _worker() -> None:
                nonlocal cache_hit_counter, relaxed_counter, ast_dropped_counter
                while True:
                    query = await queue.get()
                    try:
                        if query is None:
                            return
                        (
                            batch,
                            from_cache,
                            was_relaxed,
                            dropped_cnt,
                        ) = await self._run_failover_chain(query)
                        async with results_lock:
                            if batch:
                                collected_batches.append(batch)
                            if from_cache:
                                cache_hit_counter += 1
                            if was_relaxed:
                                relaxed_counter += 1
                            ast_dropped_counter += dropped_cnt
                        self.telemetry.update_proxy_stats(self.proxy_pool.snapshot_stats())
                        self.telemetry.update_engine_metrics(self.registry.snapshot_metrics())
                        self.telemetry.record_query_completed(
                            query, batch, from_cache, relaxed=was_relaxed
                        )
                    finally:
                        queue.task_done()

            producer_task = asyncio.create_task(_producer())
            worker_tasks = [
                asyncio.create_task(_worker()) for _ in range(self.settings.concurrency)
            ]

            await producer_task
            await queue.join()
            await asyncio.gather(*worker_tasks)

            # 4. Information-theoretic deduplication (URL + 64-bit SimHash + Jaccard)
            flattened = [item for batch in collected_batches for item in batch]
            unique_items, dedup_stats = self.deduplicator.deduplicate_results(flattened)
            deduped = [
                item.model_copy(update={"rank": idx + 1})
                for idx, item in enumerate(unique_items)
            ]

            # 5. Optional Tier 4 Katana deep crawling
            crawl_results: list[CrawlResult] = []
            if self.settings.enable_crawl and deduped:
                best_proxy = await self.proxy_pool.select_proxy()
                crawl_results = await self.katana.crawl(
                    seed_urls=[r.url for r in deduped],
                    proxy_url=best_proxy.url if best_proxy else None,
                )
                if self.settings.crawl_output_path is not None:
                    self.katana.export_results(crawl_results, self.settings.crawl_output_path)

            unique_domains, top_domains = self._compute_domain_frequencies(deduped)
            all_metrics = self.registry.snapshot_metrics()
            if self._cache_metric.requests > 0:
                all_metrics.insert(0, self._cache_metric)

            elapsed = round(time.perf_counter() - started, 3)
            return PipelineOutput(
                total_results=len(deduped),
                unique_domains=unique_domains,
                elapsed_seconds=elapsed,
                cache_hits=cache_hit_counter,
                relaxed_queries=relaxed_counter,
                ast_dropped_results=ast_dropped_counter,
                dedup_stats=dedup_stats,
                results=deduped,
                top_domains=top_domains,
                crawl_results=crawl_results,
                engine_metrics=all_metrics,
            )
        finally:
            await asyncio.gather(*(p.on_shutdown() for p in plugins), return_exceptions=True)
            self.telemetry.stop()
            await self.cache.close()

    async def execute_all_engines_matrix(
        self,
        query_stream: AsyncIterator[str],
        *,
        on_query_done: Callable[[QueryAllEnginesRecord, list[EngineMetrics]], None] | None = None,
    ) -> AllEnginesMatrixOutput:
        """
        Fan-out matrix execution mode (`--all-engines`):
          - Queries EVERY registered engine for EVERY dork in `query_stream`.
          - Records per-engine status, latency, AST admitted/dropped counts, and all
            verified links inside every query record.
          - Honors RFC 6585 circuit-breaker parking so throttled endpoints record
            `parked_circuit_breaker` during cooldown instead of hammering 429s.
        """
        started = time.perf_counter()
        raw_items: list[tuple[int, int | None, str]] = []
        idx_counter = 0
        async for raw_line in query_stream:
            diff, clean_q = parse_difficulty_prefix(raw_line)
            if clean_q:
                idx_counter += 1
                raw_items.append((idx_counter, diff, clean_q))

        plugins = self.registry.list_plugins()
        engine_names = [p.name for p in plugins]

        try:
            await asyncio.gather(*(p.on_startup() for p in plugins))
            if self.proxy_pool.has_proxies:
                await self.proxy_pool.preflight_probe()

            per_engine_sem: dict[str, asyncio.Semaphore] = {
                p.name: asyncio.Semaphore(max(1, min(3, self.settings.concurrency)))
                for p in plugins
            }
            query_sem = asyncio.Semaphore(max(1, self.settings.concurrency))

            async def _run_one_engine(
                plugin: BaseSearchEngine,
                query_id: int,
                difficulty: int | None,
                query: str,
                compiled_ast: Any,
            ) -> EngineQueryOutcome:
                if self.registry.is_engine_parked(plugin.name):
                    logger.info(
                        "[matrix q=%03d D=%s engine=%s] skipped (parked_circuit_breaker)",
                        query_id,
                        difficulty if difficulty is not None else "-",
                        plugin.name,
                    )
                    return EngineQueryOutcome(
                        engine=plugin.name,
                        status="parked_circuit_breaker",
                        dispatched_query=query,
                        error="Circuit breaker cooldown active",
                    )

                dialect = self._backend_dialect_for(plugin)
                dispatch_query = (
                    compiled_ast.translate_for_backend(dialect)
                    if compiled_ast is not None
                    else query
                )

                async with per_engine_sem[plugin.name]:
                    if self.registry.is_engine_parked(plugin.name):
                        return EngineQueryOutcome(
                            engine=plugin.name,
                            status="parked_circuit_breaker",
                            dispatched_query=dispatch_query,
                            error="Circuit breaker cooldown active",
                        )

                    t0 = time.perf_counter()
                    try:
                        raw_results = await plugin.search(
                            query=dispatch_query,
                            max_results=self.settings.max_results_per_query,
                            pagination_depth=self.settings.pagination_depth,
                        )
                        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                        normalized_raw = [
                            (
                                item.model_copy(update={"query": query})
                                if item.query != query
                                else item
                            )
                            for item in raw_results
                        ]

                        if compiled_ast is not None:
                            admitted, dropped = compiled_ast.filter_documents(normalized_raw)
                        else:
                            admitted, dropped = normalized_raw, 0

                        if admitted:
                            await self.registry.record_success(
                                plugin.name,
                                latency_ms=latency_ms,
                                result_count=len(admitted),
                            )
                            reranked = [
                                item.model_copy(update={"rank": i + 1})
                                for i, item in enumerate(admitted)
                            ]
                            logger.info(
                                "[matrix q=%03d D=%s engine=%s] OK raw=%d admitted=%d dropped=%d (%.0fms)",
                                query_id,
                                difficulty if difficulty is not None else "-",
                                plugin.name,
                                len(normalized_raw),
                                len(reranked),
                                dropped,
                                latency_ms,
                            )
                            return EngineQueryOutcome(
                                engine=plugin.name,
                                status="ok",
                                dispatched_query=dispatch_query,
                                latency_ms=latency_ms,
                                raw_count=len(normalized_raw),
                                ast_admitted_count=len(reranked),
                                ast_dropped_count=dropped,
                                links=reranked,
                            )

                        await self.registry.record_failure(
                            plugin.name,
                            EmptyResultError(
                                f"{plugin.name} yielded 0 AST-verified matches (raw={len(normalized_raw)})"
                            ),
                            latency_ms,
                        )
                        status_val: Any = "empty_ast_dropped" if normalized_raw else "empty_raw"
                        logger.warning(
                            "[matrix q=%03d D=%s engine=%s] %s raw=%d dropped=%d (%.0fms)",
                            query_id,
                            difficulty if difficulty is not None else "-",
                            plugin.name,
                            status_val,
                            len(normalized_raw),
                            dropped,
                            latency_ms,
                        )
                        return EngineQueryOutcome(
                            engine=plugin.name,
                            status=status_val,
                            dispatched_query=dispatch_query,
                            latency_ms=latency_ms,
                            raw_count=len(normalized_raw),
                            ast_admitted_count=0,
                            ast_dropped_count=dropped,
                            error=(
                                f"All {len(normalized_raw)} raw results rejected by strict Boolean AST"
                                if normalized_raw
                                else "0 raw results returned"
                            ),
                        )
                    except RateLimitedError as exc:
                        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                        await self.registry.record_failure(plugin.name, exc, latency_ms)
                        logger.warning(
                            "[matrix q=%03d D=%s engine=%s] rate_limited: %s (%.0fms)",
                            query_id,
                            difficulty if difficulty is not None else "-",
                            plugin.name,
                            exc,
                            latency_ms,
                        )
                        return EngineQueryOutcome(
                            engine=plugin.name,
                            status="rate_limited",
                            dispatched_query=dispatch_query,
                            latency_ms=latency_ms,
                            error=str(exc),
                        )
                    except CaptchaTriggeredError as exc:
                        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                        await self.registry.record_failure(plugin.name, exc, latency_ms)
                        logger.warning(
                            "[matrix q=%03d D=%s engine=%s] captcha_blocked: %s (%.0fms)",
                            query_id,
                            difficulty if difficulty is not None else "-",
                            plugin.name,
                            exc,
                            latency_ms,
                        )
                        return EngineQueryOutcome(
                            engine=plugin.name,
                            status="captcha_blocked",
                            dispatched_query=dispatch_query,
                            latency_ms=latency_ms,
                            error=str(exc),
                        )
                    except EmptyResultError as exc:
                        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                        await self.registry.record_failure(plugin.name, exc, latency_ms)
                        logger.info(
                            "[matrix q=%03d D=%s engine=%s] empty_raw: %s (%.0fms)",
                            query_id,
                            difficulty if difficulty is not None else "-",
                            plugin.name,
                            exc,
                            latency_ms,
                        )
                        return EngineQueryOutcome(
                            engine=plugin.name,
                            status="empty_raw",
                            dispatched_query=dispatch_query,
                            latency_ms=latency_ms,
                            error=str(exc),
                        )
                    except (TransportResetError, EngineDegradedError) as exc:
                        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                        await self.registry.record_failure(plugin.name, exc, latency_ms)
                        logger.warning(
                            "[matrix q=%03d D=%s engine=%s] transport_error: %s (%.0fms)",
                            query_id,
                            difficulty if difficulty is not None else "-",
                            plugin.name,
                            exc,
                            latency_ms,
                        )
                        return EngineQueryOutcome(
                            engine=plugin.name,
                            status="transport_error",
                            dispatched_query=dispatch_query,
                            latency_ms=latency_ms,
                            error=str(exc),
                        )
                    except Exception as exc:
                        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                        await self.registry.record_failure(plugin.name, exc, latency_ms)
                        logger.error(
                            "[matrix q=%03d D=%s engine=%s] error: %s (%.0fms)",
                            query_id,
                            difficulty if difficulty is not None else "-",
                            plugin.name,
                            exc,
                            latency_ms,
                        )
                        return EngineQueryOutcome(
                            engine=plugin.name,
                            status="error",
                            dispatched_query=dispatch_query,
                            latency_ms=latency_ms,
                            error=str(exc),
                        )

            async def _run_one_query(
                query_id: int,
                difficulty: int | None,
                query: str,
            ) -> QueryAllEnginesRecord:
                async with query_sem:
                    compiled_ast = None
                    if self.settings.strict_ast_filter:
                        try:
                            compiled_ast = self.ast_parser.parse(query)
                        except QueryParseError as exc:
                            logger.warning("[matrix q=%03d] AST parse bypass: %s", query_id, exc)

                    outcomes = await asyncio.gather(
                        *(
                            _run_one_engine(plugin, query_id, difficulty, query, compiled_ast)
                            for plugin in plugins
                        )
                    )
                    per_engine_map = {out.engine: out for out in outcomes}
                    combined_links = [
                        link for out in outcomes for link in out.links
                    ]
                    q_deduper = SimHashJaccardDeduplicator(
                        max_hamming=self.settings.simhash_max_hamming,
                        jaccard_threshold=self.settings.jaccard_threshold,
                    )
                    merged_unique, _ = q_deduper.deduplicate_results(combined_links)
                    merged_ranked = [
                        item.model_copy(update={"rank": i + 1})
                        for i, item in enumerate(merged_unique)
                    ]

                    rec = QueryAllEnginesRecord(
                        query_id=query_id,
                        difficulty=difficulty,
                        query=query,
                        total_raw=sum(o.raw_count for o in outcomes),
                        total_ast_admitted=sum(o.ast_admitted_count for o in outcomes),
                        total_ast_dropped=sum(o.ast_dropped_count for o in outcomes),
                        unique_verified_count=len(merged_ranked),
                        per_engine=per_engine_map,
                        merged_links=merged_ranked,
                    )
                    if on_query_done is not None:
                        try:
                            on_query_done(rec, self.registry.snapshot_metrics())
                        except Exception:
                            pass
                    return rec

            records = await asyncio.gather(
                *(_run_one_query(qid, diff, q) for qid, diff, q in raw_items)
            )
            records_sorted = sorted(records, key=lambda r: r.query_id)

            # Global deduplication & analytics across all queries
            all_admitted = [
                link
                for rec in records_sorted
                for link in rec.merged_links
            ]
            global_deduper = SimHashJaccardDeduplicator(
                max_hamming=self.settings.simhash_max_hamming,
                jaccard_threshold=self.settings.jaccard_threshold,
            )
            global_unique, global_dedup_stats = global_deduper.deduplicate_results(all_admitted)
            unique_domains, top_domains = self._compute_domain_frequencies(global_unique)

            elapsed = round(time.perf_counter() - started, 3)
            return AllEnginesMatrixOutput(
                total_queries=len(records_sorted),
                engines=engine_names,
                elapsed_seconds=elapsed,
                total_verified_links=len(global_unique),
                unique_domains=unique_domains,
                total_ast_dropped=sum(r.total_ast_dropped for r in records_sorted),
                dedup_stats=global_dedup_stats,
                proxy_stats=self.proxy_pool.snapshot_stats(),
                engine_metrics=self.registry.snapshot_metrics(),
                top_domains=top_domains,
                records=records_sorted,
            )
        finally:
            await asyncio.gather(*(p.on_shutdown() for p in plugins), return_exceptions=True)


def export_all_engines_links_report(
    output: AllEnginesMatrixOutput,
    report_path: Path,
) -> None:
    """Write a complete program-generated per-dork, per-engine links & metrics Markdown report."""
    lines: list[str] = [
        "# Search Pipeline v3 — All-Engines Live Output (Per-Dork Links & Telemetry)",
        "",
        f"- **Queries Executed:** `{output.total_queries}`",
        f"- **Engines Tested Per Query:** `{', '.join(output.engines)}`",
        f"- **Elapsed Seconds:** `{output.elapsed_seconds}s`",
        f"- **Global Unique AST-Verified Links:** `{output.total_verified_links}` (`{output.unique_domains}` unique domains)",
        f"- **Total Raw Candidates Dropped by Strict Boolean AST:** `{output.total_ast_dropped}`",
        f"- **Global Dedup Stats:** `input={output.dedup_stats.input_count}`, `kept={output.dedup_stats.kept_count}`, "
        f"`url_dup={output.dedup_stats.dropped_url_exact}`, `simhash_dup={output.dedup_stats.dropped_simhash}`, "
        f"`jaccard_dup={output.dedup_stats.dropped_jaccard}`",
        f"- **Proxy Pool:** `alive={output.proxy_stats.alive}/{output.proxy_stats.total_loaded}`, "
        f"`healthy={output.proxy_stats.healthy}`, `quarantined={output.proxy_stats.quarantined}`, "
        f"`ewma={output.proxy_stats.avg_ewma_latency_ms:.0f}ms`",
        "",
        "## Engine Telemetry Summary (Thompson Sampling + Circuit Breaker)",
        "",
        "| Engine | Reqs | OK | Fails | Empty | 429/202 | Bot | Links Yielded | Avg Latency (ms) | α / β | Posterior θ | Parked |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|",
    ]
    for m in output.engine_metrics:
        lines.append(
            f"| `{m.engine}` | {m.requests} | {m.successes} | {m.failures} | {m.empty_yields} | "
            f"{m.rate_limits} | {m.bot_gates} | {m.total_results_yielded} | {m.avg_latency_ms:.1f} | "
            f"{m.bandit_alpha:.0f} / {m.bandit_beta:.0f} | {m.thompson_posterior_mean:.4f} | {m.parked} |"
        )

    # Difficulty Band Summary (1-20, 21-40, 41-60, 61-80, 81-100)
    if any(r.difficulty is not None for r in output.records):
        lines.extend(
            [
                "",
                "## Yield & AST Precision by Difficulty Tier",
                "",
                "| Difficulty Band | Queries | Queries w/ Hits | Total Raw | AST Admitted | AST Dropped | Unique Merged Links |",
                "|---|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for lo, hi in ((1, 20), (21, 40), (41, 60), (61, 80), (81, 100)):
            band = [r for r in output.records if r.difficulty is not None and lo <= r.difficulty <= hi]
            if not band:
                continue
            q_hit = sum(1 for r in band if r.unique_verified_count > 0)
            lines.append(
                f"| `D={lo:03d}..{hi:03d}` | {len(band)} | {q_hit}/{len(band)} | "
                f"{sum(r.total_raw for r in band)} | {sum(r.total_ast_admitted for r in band)} | "
                f"{sum(r.total_ast_dropped for r in band)} | {sum(r.unique_verified_count for r in band)} |"
            )

    lines.extend(["", "## Per-Dork Results (All Engines Included For Every Query)", ""])
    for rec in output.records:
        diff_tag = f"D={rec.difficulty:03d}" if rec.difficulty is not None else "D=N/A"
        lines.append(
            f"### #{rec.query_id:03d} [{diff_tag}] `{rec.query}` "
            f"— unique={rec.unique_verified_count} | raw={rec.total_raw} | ast_dropped={rec.total_ast_dropped}"
        )
        for eng_name in output.engines:
            out = rec.per_engine.get(eng_name)
            if out is None:
                continue
            if out.status == "ok":
                lines.append(
                    f"- **`{eng_name}`** (`ok`, `{out.latency_ms:.0f}ms`, "
                    f"admitted={out.ast_admitted_count}/{out.raw_count}, dropped={out.ast_dropped_count}):"
                )
                for lk in out.links:
                    safe_title = lk.title.replace("\n", " ").replace("|", "\\|")
                    lines.append(f"  - [{safe_title}]({lk.url})")
            else:
                err_short = out.error[:140].replace("\n", " ")
                lines.append(
                    f"- **`{eng_name}`** (`{out.status}`, `{out.latency_ms:.0f}ms`, "
                    f"raw={out.raw_count}, dropped={out.ast_dropped_count}): {err_short}"
                )
        lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")


EnterpriseSearchOrchestrator = SearchOrchestrator
