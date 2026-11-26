"""Full v3 pipeline end-to-end integration tests (source.txt replay, failover, dedup, cache, CLI)."""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from cli.main import parse_cli_args
from core.exceptions import CaptchaTriggeredError, RateLimitedError
from core.models import PipelineSettings, SearchResult
from engine.base import BaseSearchEngine
from engine.crawler import StructuralSchemaExtractor
from engine.orchestrator import (
    SearchOrchestrator,
    export_all_engines_links_report,
    parse_difficulty_prefix,
    stream_queries_from_file,
)
from math_kernel.ast_boolean import (
    ExactPhraseNode,
    FileTypeNode,
    InTextNode,
    InTitleNode,
    InURLNode,
    NotNode,
    SiteNode,
    TermNode,
    compile_boolean_query,
)
from plugins.duckduckgo import DuckDuckGoHtmlPlugin, DuckDuckGoLitePlugin
from plugins.yahoo import YahooDirectPlugin
from transport.http_client import canonicalize_url, is_valid_http_url
from transport.proxy_pool import ProxyPoolManager


def _synthesize_matching_result(query: str, engine: str, variant_idx: int = 0) -> SearchResult:
    """Build a synthetic candidate document guaranteed to satisfy every positive atom of `query`."""
    compiled = compile_boolean_query(query)
    host = f"site{variant_idx}.example.org"
    path_parts = ["page"]
    ext = ""
    title_parts = [f"Result {variant_idx}"]
    snippet_parts = [f"Unique corpus detail token{variant_idx} hash{abs(hash(query)) % 100000}"]

    def _walk(node: object, negated: bool) -> None:
        nonlocal host, ext
        if isinstance(node, NotNode):
            _walk(node.operand, not negated)
            return
        if hasattr(node, "left") and hasattr(node, "right"):
            _walk(getattr(node, "left"), negated)
            _walk(getattr(node, "right"), negated)
            return
        if negated:
            return
        if isinstance(node, SiteNode):
            val = node.value.lower().lstrip("*.")
            if "." in val:
                host = val
            else:
                host = f"org{variant_idx}.{val}"
        elif isinstance(node, InURLNode):
            path_parts.append(node.value.strip("/"))
        elif isinstance(node, FileTypeNode):
            ext = "." + node.value.lstrip(".")
        elif isinstance(node, InTitleNode):
            title_parts.append(node.value)
        elif isinstance(node, (ExactPhraseNode, InTextNode, TermNode)):
            snippet_parts.append(node.value)

    _walk(compiled.root, False)
    path = "/" + "/".join(p for p in path_parts if p) + ext
    return SearchResult(
        rank=1,
        title=" ".join(title_parts),
        url=f"https://{host}{path}",
        snippet=" ".join(snippet_parts),
        engine=engine,
        query=query,
    )


class _RateLimitedMockEngine(BaseSearchEngine):
    name = "mock_rate_limited"
    engine_family = "mock_rl"
    base_priority = 1

    def __init__(self) -> None:
        self.calls = 0

    async def search(self, query: str, max_results: int = 20, pagination_depth: int = 2) -> list[SearchResult]:
        self.calls += 1
        raise RateLimitedError("mock HTTP 429", status_code=429, retry_after=15.0)


class _BotGateMockEngine(BaseSearchEngine):
    name = "mock_bot_gated"
    engine_family = "mock_bot"
    base_priority = 2

    def __init__(self) -> None:
        self.calls = 0

    async def search(self, query: str, max_results: int = 20, pagination_depth: int = 2) -> list[SearchResult]:
        self.calls += 1
        raise CaptchaTriggeredError("mock /sorry/ challenge", status_code=403)


class _HealthyReplayEngine(BaseSearchEngine):
    name = "mock_healthy"
    engine_family = "mock_ok"
    base_priority = 3

    def __init__(self) -> None:
        self.calls = 0

    async def search(self, query: str, max_results: int = 20, pagination_depth: int = 2) -> list[SearchResult]:
        self.calls += 1
        valid = _synthesize_matching_result(query, engine="mock:healthy", variant_idx=self.calls)
        # Emit an identical-content near-duplicate on a different mirror URL
        near_dup = valid.model_copy(
            update={
                "rank": 2,
                "url": valid.url.replace("https://", "https://mirror."),
            }
        )
        # Emit an unrelated noise link that MUST be dropped 100% by the strict AST gate
        noise = SearchResult(
            rank=3,
            title="Unrelated Cooking Recipe Blog",
            url=f"https://noise{self.calls}.cooking.invalid/pasta",
            snippet="Fresh basil and tomato sauce instructions.",
            engine="mock:healthy",
            query=query,
        )
        return [valid, near_dup, noise]


class TestEndToEndPipeline(unittest.IsolatedAsyncioTestCase):
    async def test_full_source_txt_pipeline_replay_zero_false_positives(self) -> None:
        """
        Execute the complete v3 orchestrator over `/root/ntest/pack/source.txt` in offline
        replay mode and verify:
          - 0 crashes across all 170+ queries
          - 100% strict AST precision (0 noise links admitted)
          - Thompson Sampling + circuit breaker shifts load away from 429 & CAPTCHA engines
          - SimHash/Jaccard deduplication eliminates near-duplicate mirrors
          - SQLite cache hits on repeat execution
        """
        local_source = Path("/root/ntest/pack/source.txt")
        bundled_source = Path(__file__).resolve().parent / "sample_queries.txt"
        try:
            source_path = local_source if local_source.is_file() else bundled_source
        except PermissionError:
            source_path = bundled_source
        self.assertTrue(source_path.is_file(), f"Missing fixture: {source_path}")

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_db = Path(tmpdir) / "v3_e2e_cache.db"
            settings = PipelineSettings(
                cache_db_path=cache_db,
                enable_cache=True,
                enable_tui=False,
                enable_thompson_sampling=True,
                strict_ast_filter=True,
                enable_query_relaxation=False,
                concurrency=4,
                engine_park_bot_threshold=3,
                engine_park_seconds=120.0,
            )

            rl_engine = _RateLimitedMockEngine()
            bot_engine = _BotGateMockEngine()
            ok_engine = _HealthyReplayEngine()

            orch = SearchOrchestrator(
                settings,
                plugins=[rl_engine, bot_engine, ok_engine],
                bandit_seed=42,
            )
            output = await orch.execute_stream(stream_queries_from_file(source_path))

            self.assertGreater(output.total_results, 100)
            self.assertEqual(output.relaxed_queries, 0)
            # Every query had at least 1 noise link dropped by the strict AST gate
            self.assertGreaterEqual(output.ast_dropped_results, 150)
            # Near-duplicate mirrors must be caught by SimHash/Jaccard deduplication
            self.assertGreater(
                output.dedup_stats.dropped_simhash + output.dedup_stats.dropped_jaccard, 50
            )

            # Prove ZERO false positives: every admitted result satisfies Eval(Q_AST, D) == 1
            for item in output.results:
                self.assertNotIn("cooking.invalid", item.url)
                ast_obj = compile_boolean_query(item.query)
                self.assertEqual(
                    ast_obj.evaluate(item),
                    1,
                    f"False positive leaked through AST gate for query={item.query!r}: {item.url}",
                )

            # Verify Thompson Sampling + circuit breaker routed almost all traffic to ok_engine
            self.assertLessEqual(rl_engine.calls, 10)
            self.assertLessEqual(bot_engine.calls, 10)
            self.assertGreater(ok_engine.calls, 150)

            metrics = {m.engine: m for m in output.engine_metrics}
            self.assertTrue(
                metrics["mock_rate_limited"].parked or rl_engine.calls < 3,
                "Rate-limited engine must either be parked or suppressed by Thompson Sampling in <3 calls",
            )
            self.assertTrue(
                metrics["mock_bot_gated"].parked or bot_engine.calls < 3,
                "Bot-gated engine must either be parked or suppressed by Thompson Sampling in <3 calls",
            )
            self.assertFalse(metrics["mock_healthy"].parked)
            self.assertGreater(metrics["mock_healthy"].thompson_posterior_mean, 0.95)
            self.assertLessEqual(metrics["mock_rate_limited"].thompson_posterior_mean, 0.25)
            self.assertLessEqual(metrics["mock_bot_gated"].thompson_posterior_mean, 0.25)

            # Second run with same SQLite cache should serve cached results with 0 upstream calls
            ok_engine_2 = _HealthyReplayEngine()
            orch2 = SearchOrchestrator(settings, plugins=[ok_engine_2], bandit_seed=42)
            output2 = await orch2.execute_stream(stream_queries_from_file(source_path))
            self.assertGreater(output2.cache_hits, 100)
            self.assertEqual(ok_engine_2.calls, 0)

    async def test_proxy_pool_thompson_sampling_routes_away_from_throttled_proxy(self) -> None:
        pool = ProxyPoolManager(
            proxy_urls=["http://10.0.0.1:8080", "http://10.0.0.2:8080"],
            use_thompson_sampling=True,
            bandit_seed=7,
        )
        for _ in range(15):
            await pool.report_success("http://10.0.0.1:8080", latency_ms=120.0)
        for _ in range(10):
            await pool.report_throttle("http://10.0.0.2:8080", reason="HTTP 429")

        picks = []
        for _ in range(50):
            node = await pool.select_proxy()
            self.assertIsNotNone(node)
            assert node is not None
            picks.append(node.url)
        self.assertGreater(picks.count("http://10.0.0.1:8080"), 42)

    def test_standalone_yahoo_ddg_parsers_and_katana_schema_extractor(self) -> None:
        yahoo_html = """
        <html><body>
          <div class="algo">
            <h3 class="title">
              <a href="https://r.search.yahoo.com/_ylt=abc/RU=https%3a%2f%2fexample.org%2fdocs/RK=2">
                Example Docs Portal
              </a>
            </h3>
            <div class="compText"><p>Official reference documentation and API guides.</p></div>
          </div>
        </body></html>
        """
        y_res = YahooDirectPlugin.parse_yahoo_html(yahoo_html, query="example docs")
        self.assertEqual(len(y_res), 1)
        self.assertEqual(y_res[0].url, "https://example.org/docs")

        ddg_html = """
        <html><body>
          <div class="result results_links">
            <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fdocs.python.org%2F3%2F">
              Python 3 Documentation
            </a>
            <a class="result__snippet">Official Python 3.12 standard library docs.</a>
          </div>
        </body></html>
        """
        d_res = DuckDuckGoHtmlPlugin.parse_ddg_html(ddg_html, query="python 3")
        self.assertEqual(len(d_res), 1)
        self.assertEqual(d_res[0].url, "https://docs.python.org/3/")

        ddg_lite = """
        <html><body><table>
          <tr><td><a class="result-link" href="https://peps.python.org/">PEPs Index</a></td></tr>
          <tr><td class="result-snippet">Python Enhancement Proposals index.</td></tr>
        </table></body></html>
        """
        l_res = DuckDuckGoLitePlugin.parse_ddg_lite(ddg_lite, query="peps")
        self.assertEqual(len(l_res), 1)
        self.assertEqual(l_res[0].url, "https://peps.python.org/")

        # Katana HTML structural schema extraction
        page_html = """
        <html><head>
          <link rel="canonical" href="https://example.org/login"/>
          <meta property="og:title" content="Login Portal"/>
          <script src="/static/app.js"></script>
        </head><body>
          <form action="/auth" method="post">
            <input name="email" type="email" required/>
            <input name="password" type="password" required/>
          </form>
        </body></html>
        """
        forms, meta = StructuralSchemaExtractor.extract_from_html("https://example.org/", page_html)
        self.assertEqual(len(forms), 1)
        self.assertTrue(forms[0].has_auth_fields)
        self.assertEqual(forms[0].action, "https://example.org/auth")
        self.assertEqual(meta.canonical_url, "https://example.org/login")
        self.assertEqual(meta.open_graph["og:title"], "Login Portal")

    def test_cli_flags_and_zero_circular_imports_in_v3_graph(self) -> None:
        args = parse_cli_args(["-q", '"python" site:python.org', "--no-relax", "--no-tui"])
        self.assertEqual(args.query, ['"python" site:python.org'])
        self.assertTrue(args.no_relax)
        self.assertTrue(args.no_tui)

        # Static DAG verification: prove zero circular imports across all v3 Python modules
        v3_root = Path(__file__).resolve().parent.parent
        top_pkgs = {"core", "math_kernel", "transport", "engine", "plugins", "cli"}
        edges: dict[str, set[str]] = {}

        for py_file in v3_root.rglob("*.py"):
            if "tests" in py_file.parts:
                continue
            rel = py_file.relative_to(v3_root).with_suffix("")
            mod_name = ".".join(rel.parts[:-1] if rel.name == "__init__" else rel.parts)
            edges.setdefault(mod_name, set())
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.split(".")[0] in top_pkgs and node.module != mod_name:
                        edges[mod_name].add(node.module)

        # Standard 3-color DFS cycle detection
        color: dict[str, int] = {}

        def _has_cycle(u: str) -> bool:
            color[u] = 1
            for v in edges.get(u, ()):
                if color.get(v, 0) == 1:
                    return True
                if color.get(v, 0) == 0 and v in edges and _has_cycle(v):
                    return True
            color[u] = 2
            return False

        for m in list(edges):
            if color.get(m, 0) == 0:
                self.assertFalse(_has_cycle(m), f"Circular import detected involving {m}")

    async def test_ast_verified_failover_dialect_translation_and_hostless_url_filter(self) -> None:
        """
        Regression tests for three production bugs caught during live audit:
          1. Hostless Brave/SearXNG redirectors (`http:///go/v1/...`) are rejected cleanly.
          2. An engine returning 100% AST-rejected noise does NOT earn α+=1 and fails over
             immediately to the next engine.
          3. Non-destructive dialect translation rewrites `site:*.org` -> `site:org` for DDG
             without stripping quotes while preserving original query provenance.
        """
        self.assertFalse(is_valid_http_url("http:///go/v1/AX91NX-broken-redirector"))
        self.assertEqual(canonicalize_url("http:///go/v1/AX91NX-broken-redirector"), "")
        self.assertTrue(is_valid_http_url("https://developer.paypal.com/braintree/docs"))

        received_queries: list[str] = []

        class _NoisyPrimaryEngine(BaseSearchEngine):
            name = "noisy_primary"
            engine_family = "searxng"
            base_priority = 1

            async def search(self, query: str, max_results: int = 20, pagination_depth: int = 2) -> list[SearchResult]:
                return [
                    SearchResult(
                        rank=1,
                        title="Completely Unrelated News",
                        url="https://news.example.com/sports",
                        snippet="Football match highlights.",
                        engine="searxng:noise",
                        query=query,
                    )
                ]

        class _AccurateDDGSecondary(BaseSearchEngine):
            name = "accurate_ddg"
            engine_family = "ddg"
            base_priority = 2

            async def search(self, query: str, max_results: int = 20, pagination_depth: int = 2) -> list[SearchResult]:
                received_queries.append(query)
                return [
                    SearchResult(
                        rank=1,
                        title="Donate Now - Charity Org",
                        url="https://support.charity.org/donate",
                        snippet="Official donation portal powered by braintree checkout.",
                        engine="curl_cffi:ddg_html",
                        query=query,
                    )
                ]

        original_query = '"braintree" site:*.org inurl:donate'

        async def _single_query():
            yield original_query

        settings = PipelineSettings(
            enable_cache=False,
            enable_tui=False,
            enable_thompson_sampling=False,  # Deterministic order: noisy_primary -> accurate_ddg
            strict_ast_filter=True,
            enable_query_relaxation=False,
        )
        orch = SearchOrchestrator(
            settings,
            plugins=[_NoisyPrimaryEngine(), _AccurateDDGSecondary()],
        )
        output = await orch.execute_stream(_single_query(), total_hint=1)

        # Must fail over from noisy_primary to accurate_ddg and return the valid result
        self.assertEqual(output.total_results, 1)
        self.assertEqual(output.ast_dropped_results, 1)
        self.assertEqual(output.results[0].url, "https://support.charity.org/donate")
        self.assertEqual(output.results[0].query, original_query)

        # DDG received non-destructive translated query (site:org, quotes intact!)
        self.assertEqual(len(received_queries), 1)
        self.assertIn('"braintree"', received_queries[0])
        self.assertIn("site:org", received_queries[0])
        self.assertNotIn("site:*.org", received_queries[0])

        # noisy_primary must have beta=2.0 (empty verified yield), NOT alpha=2.0!
        metrics = {m.engine: m for m in output.engine_metrics}
        self.assertEqual(metrics["noisy_primary"].bandit_alpha, 1.0)
        self.assertEqual(metrics["noisy_primary"].bandit_beta, 2.0)
        self.assertEqual(metrics["noisy_primary"].empty_yields, 1)
        self.assertEqual(metrics["accurate_ddg"].bandit_alpha, 2.0)
        self.assertEqual(metrics["accurate_ddg"].successes, 1)

    async def test_all_engines_matrix_mode_and_100_query_corpus_parse(self) -> None:
        """Verify `--all-engines` fan-out includes every engine per dork & exports links report."""
        diff, q = parse_difficulty_prefix("[D=042] site:docs.python.org asyncio")
        self.assertEqual(diff, 42)
        self.assertEqual(q, "site:docs.python.org asyncio")

        bench_path = Path(__file__).resolve().parent.parent / "benchmark_100_queries.txt"
        self.assertTrue(bench_path.is_file())
        parsed_rows = []
        async for line in stream_queries_from_file(bench_path):
            d_val, clean_q = parse_difficulty_prefix(line)
            self.assertIsNotNone(d_val)
            ast_obj = compile_boolean_query(clean_q)
            self.assertGreaterEqual(len(ast_obj.atoms()), 1)
            parsed_rows.append((d_val, clean_q))
        self.assertEqual(len(parsed_rows), 100)
        self.assertEqual([d for d, _ in parsed_rows], list(range(1, 101)))

        class _MockA(BaseSearchEngine):
            name = "eng_a"
            engine_family = "searxng"
            base_priority = 1

            async def search(self, query: str, max_results: int = 20, pagination_depth: int = 2) -> list[SearchResult]:
                return [
                    SearchResult(
                        rank=1,
                        title="Python AsyncIO Docs",
                        url="https://docs.python.org/3/library/asyncio.html",
                        snippet="Official asyncio library documentation.",
                        engine="eng_a",
                        query=query,
                    )
                ]

        class _MockB(BaseSearchEngine):
            name = "eng_b"
            engine_family = "google_web"
            base_priority = 2

            async def search(self, query: str, max_results: int = 20, pagination_depth: int = 2) -> list[SearchResult]:
                raise RateLimitedError("mock 429", status_code=429)

        async def _stream():
            yield "[D=041] site:docs.python.org asyncio"

        settings = PipelineSettings(
            enable_cache=False,
            enable_tui=False,
            strict_ast_filter=True,
            enable_query_relaxation=False,
        )
        orch = SearchOrchestrator(settings, plugins=[_MockA(), _MockB()])
        matrix = await orch.execute_all_engines_matrix(_stream())
        self.assertEqual(matrix.total_queries, 1)
        self.assertEqual(matrix.engines, ["eng_a", "eng_b"])
        rec = matrix.records[0]
        self.assertEqual(rec.difficulty, 41)
        self.assertEqual(set(rec.per_engine.keys()), {"eng_a", "eng_b"})
        self.assertEqual(rec.per_engine["eng_a"].status, "ok")
        self.assertEqual(rec.per_engine["eng_b"].status, "rate_limited")
        self.assertEqual(rec.unique_verified_count, 1)

        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = Path(tmpdir) / "links.md"
            export_all_engines_links_report(matrix, md_path)
            content = md_path.read_text(encoding="utf-8")
            self.assertIn("https://docs.python.org/3/library/asyncio.html", content)
            self.assertIn("eng_b", content)
            self.assertIn("rate_limited", content)


if __name__ == "__main__":
    unittest.main()
