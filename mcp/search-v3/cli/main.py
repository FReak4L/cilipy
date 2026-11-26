"""Standalone CLI entry-point for Hybrid Search Architecture v3."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import AsyncIterator, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cli.tui_app import render_status_view, run_tui
from cli.tui_exporters import ensure_workspace, export_links_only_txt
from cli.tui_status import RunStatusTracker
from cli.ui_dashboard import PipelineDashboard
from core.models import PipelineSettings
from engine.orchestrator import (
    SearchOrchestrator,
    export_all_engines_links_report,
    stream_queries_from_file,
)

logger = logging.getLogger("hybrid_search.v3")


def configure_logging(
    debug: bool,
    quiet_for_tui: bool,
    log_file: Path | None = None,
) -> None:
    """Configure v3 package logging on stderr and optional log file without corrupting stdout."""
    logger.handlers.clear()
    logger.propagate = False
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, mode="w", encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    if quiet_for_tui and not debug:
        if log_file is None:
            logger.addHandler(logging.NullHandler())
            logger.setLevel(logging.CRITICAL)
            return
        logger.setLevel(logging.INFO)
        return

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)


def parse_cli_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Standalone Modular Federated Search Pipeline v3 "
            "(Thompson Sampling + Dynamic Poisson Pacing + Strict Boolean AST + 64-bit SimHash)."
        )
    )
    parser.add_argument(
        "-q",
        "--query",
        action="append",
        default=[],
        help="Inline search query (repeatable).",
    )
    parser.add_argument(
        "-i",
        "--input-file",
        type=Path,
        default=None,
        help="Path to batch query file (supports #, //, and /* */ comments).",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional configuration file (.toml, .yaml, or .yml).",
    )
    parser.add_argument(
        "--searxng-url",
        default=None,
        help="Explicit SearXNG base URL (overrides local [8888, 8080, 80] auto-discovery).",
    )
    parser.add_argument(
        "--engines",
        default=None,
        help=(
            "Comma-separated plugins (e.g. searxng,ddg_html,yahoo_direct,ddg_lite,ddgs,"
            "google,google_cse,google_web_udm14,google_mobile_web,google_basic_html)."
        ),
    )
    parser.add_argument(
        "--pagination-depth",
        type=int,
        default=None,
        help="Deep pagination depth per healthy engine (1-5, default: 2).",
    )
    parser.add_argument(
        "--no-relax",
        action="store_true",
        default=False,
        help="Enforce strict zero-relaxation mode (default behavior in v3).",
    )
    parser.add_argument(
        "--allow-relax",
        action="store_true",
        default=False,
        help="Opt-in to query relaxation when strict queries return zero matches.",
    )
    parser.add_argument(
        "--no-ast-filter",
        action="store_true",
        default=False,
        help="Disable strict Boolean AST truth-table verification gate.",
    )
    parser.add_argument(
        "--no-thompson",
        action="store_true",
        default=False,
        help="Disable Thompson Sampling bandit scheduling (use static priority).",
    )
    parser.add_argument(
        "--poisson-mean",
        type=float,
        default=None,
        help="Base Poisson inter-arrival mean delay in seconds (default: 2.0).",
    )
    parser.add_argument(
        "--simhash-hamming",
        type=int,
        default=None,
        help="Maximum 64-bit SimHash Hamming distance for duplicate detection (default: 3).",
    )
    parser.add_argument(
        "--jaccard-threshold",
        type=float,
        default=None,
        help="Minimum token-level Jaccard overlap for duplicate detection (default: 0.85).",
    )
    parser.add_argument(
        "--no-http1-fallback",
        action="store_true",
        default=False,
        help="Disable automatic HTTP/2 -> HTTP/1.1 fallback on tunnel resets.",
    )
    parser.add_argument(
        "--proxies",
        type=Path,
        default=None,
        help="Path to proxies.txt (http, https, socks4, socks5).",
    )
    parser.add_argument(
        "--cache-db",
        type=Path,
        default=None,
        help="Path to SQLite cache database (default: search_cache.db).",
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=None,
        help="Cache TTL in seconds (default: 86400; 0 disables caching).",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        default=False,
        help="Disable persistent SQLite cache lookups/writes.",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=None,
        help="Maximum organic results per query.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="Maximum concurrent search worker tasks.",
    )
    parser.add_argument(
        "--crawl",
        action="store_true",
        default=False,
        help="Enable Tier 4 Katana deep crawling & structural schema extraction.",
    )
    parser.add_argument(
        "--allowed-domains",
        default=None,
        help="Comma-separated domain allowlist for Tier 4 crawling.",
    )
    parser.add_argument(
        "--crawl-output",
        type=Path,
        default=None,
        help="Optional export filepath for structured crawl findings (.json or .jsonl).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional JSON filepath for final normalized search output (defaults to stdout).",
    )
    parser.add_argument(
        "--all-engines",
        action="store_true",
        default=False,
        help="Fan-out mode: execute EVERY enabled engine per query and emit full per-engine output.",
    )
    parser.add_argument(
        "--links-output",
        type=Path,
        default=None,
        help="Optional Markdown filepath for program-generated per-dork, per-engine links report (--all-engines).",
    )
    parser.add_argument(
        "--links-txt",
        type=Path,
        default=None,
        help="Export ONLY unique verified URLs (1 URL per line) into a plain .txt file via jq.",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Optional file path to write full live runtime execution logs.",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        default=False,
        help="Launch the embedded Pure-ANSI + jq interactive TUI wizard (default when run with no flags).",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        default=False,
        help="Display active run status and recent history via jq tables and exit.",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Custom workspace directory for TUI folders (dorks/, proxies/, configs/, exports/, logs/).",
    )
    parser.add_argument(
        "--no-tui",
        action="store_true",
        default=False,
        help="Disable the live Rich terminal telemetry dashboard.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable verbose debug logging on stderr.",
    )
    return parser.parse_args(argv)


class _TeeTelemetrySink:
    """Broadcasts orchestrator telemetry to both Rich dashboard and atomic status tracker."""

    def __init__(self, *sinks: Any) -> None:
        self._sinks = sinks

    def start(self) -> None:
        for s in self._sinks:
            s.start()

    def stop(self) -> None:
        for s in self._sinks:
            s.stop()

    def set_searxng_status(self, status: str) -> None:
        for s in self._sinks:
            s.set_searxng_status(status)

    def set_total_queries(self, total: int) -> None:
        for s in self._sinks:
            s.set_total_queries(total)

    def update_proxy_stats(self, stats: Any) -> None:
        for s in self._sinks:
            s.update_proxy_stats(stats)

    def update_engine_metrics(self, metrics: Sequence[Any]) -> None:
        for s in self._sinks:
            s.update_engine_metrics(metrics)

    def record_query_completed(
        self,
        query: str,
        results: Sequence[Any],
        from_cache: bool,
        relaxed: bool = False,
    ) -> None:
        for s in self._sinks:
            s.record_query_completed(query, results, from_cache, relaxed=relaxed)


async def _combined_query_stream(
    inline_queries: Sequence[str],
    input_file: Path | None,
) -> AsyncIterator[str]:
    for q in inline_queries:
        cleaned = q.strip()
        if cleaned:
            yield cleaned
    if input_file is not None:
        async for file_query in stream_queries_from_file(input_file):
            yield file_query


async def async_main(args: argparse.Namespace) -> int:
    if args.status:
        ws = ensure_workspace(args.workspace)
        print(render_status_view(ws))
        return 0

    if not args.query and args.input_file is None:
        print(
            "Error: Provide at least one --query (-q) or --input-file (-i), or run with --tui.",
            file=sys.stderr,
        )
        return 2

    cli_overrides: dict[str, Any] = {
        "searxng_url": args.searxng_url,
        "proxies_file": args.proxies,
        "cache_db_path": args.cache_db,
        "cache_ttl_seconds": args.cache_ttl,
        "max_results_per_query": args.max_results,
        "concurrency": args.concurrency,
        "pagination_depth": args.pagination_depth,
        "crawl_output_path": args.crawl_output,
        "poisson_mean_delay": args.poisson_mean,
        "simhash_max_hamming": args.simhash_hamming,
        "jaccard_threshold": args.jaccard_threshold,
    }
    if args.engines is not None:
        cli_overrides["enabled_engines"] = [
            e.strip().lower() for e in args.engines.split(",") if e.strip()
        ]
    if args.allow_relax and not args.no_relax:
        cli_overrides["enable_query_relaxation"] = True
    if args.no_relax:
        cli_overrides["enable_query_relaxation"] = False
    if args.no_ast_filter:
        cli_overrides["strict_ast_filter"] = False
    if args.no_thompson:
        cli_overrides["enable_thompson_sampling"] = False
    if args.no_http1_fallback:
        cli_overrides["enable_http1_fallback"] = False
    if args.no_cache:
        cli_overrides["enable_cache"] = False
    if args.crawl:
        cli_overrides["enable_crawl"] = True
    if args.no_tui:
        cli_overrides["enable_tui"] = False
    if args.debug:
        cli_overrides["debug"] = True
    if args.allowed_domains is not None:
        cli_overrides["allowed_crawl_domains"] = [
            d.strip() for d in args.allowed_domains.split(",") if d.strip()
        ]

    settings = PipelineSettings.load(
        config_path=args.config,
        cli_overrides=cli_overrides,
    )
    configure_logging(
        debug=settings.debug,
        quiet_for_tui=settings.enable_tui,
        log_file=args.log_file,
    )

    total_hint = len(args.query) if args.input_file is None else None
    ws = ensure_workspace(args.workspace)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    input_label = (
        args.input_file.name
        if args.input_file is not None
        else f"{len(args.query)} inline"
    )
    status_tracker = RunStatusTracker(
        ws,
        run_id=run_id,
        profile="cli",
        mode="all_engines" if args.all_engines else "failover",
        input_label=input_label,
        total_queries=total_hint or 0,
        render_live=False,
    )
    dashboard = PipelineDashboard(total_queries=total_hint, enabled=settings.enable_tui)
    sink: Any = (
        _TeeTelemetrySink(dashboard, status_tracker)
        if settings.enable_tui
        else status_tracker
    )
    orchestrator = SearchOrchestrator(settings, telemetry_sink=sink)

    if args.all_engines:
        status_tracker.start()
        matrix_output = await orchestrator.execute_all_engines_matrix(
            query_stream=_combined_query_stream(args.query, args.input_file),
            on_query_done=status_tracker.record_matrix_query_done,
        )
        serialized = matrix_output.model_dump_json(indent=2)
        exports_map: dict[str, str] = {}
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(serialized + "\n", encoding="utf-8")
            exports_map["json"] = str(args.output)
            logger.info("Wrote all-engines matrix JSON output to %s", args.output)
        else:
            print(serialized)
        if args.links_output is not None:
            args.links_output.parent.mkdir(parents=True, exist_ok=True)
            export_all_engines_links_report(matrix_output, args.links_output)
            exports_map["markdown"] = str(args.links_output)
            logger.info("Wrote per-dork per-engine links report to %s", args.links_output)
        if args.links_txt is not None:
            cnt = export_links_only_txt(matrix_output, args.links_txt)
            exports_map["links_txt"] = str(args.links_txt)
            logger.info("Wrote %d unique links (1/line) to %s", cnt, args.links_txt)
        status_tracker.finalize(
            state="completed",
            done_queries=matrix_output.total_queries,
            total_queries=matrix_output.total_queries,
            total_verified_links=matrix_output.total_verified_links,
            total_ast_dropped=matrix_output.total_ast_dropped,
            engine_metrics=matrix_output.engine_metrics,
            export_paths=exports_map,
        )
        return 0

    output = await orchestrator.execute_stream(
        query_stream=_combined_query_stream(args.query, args.input_file),
        total_hint=total_hint,
    )

    serialized = output.model_dump_json(indent=2)
    exports_map = {}
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized + "\n", encoding="utf-8")
        exports_map["json"] = str(args.output)
        logger.info("Wrote normalized JSON output to %s", args.output)
    else:
        print(serialized)
    if args.links_txt is not None:
        cnt = export_links_only_txt(output, args.links_txt)
        exports_map["links_txt"] = str(args.links_txt)
        logger.info("Wrote %d unique links (1/line) to %s", cnt, args.links_txt)
    status_tracker.finalize(
        state="completed",
        total_verified_links=output.total_results,
        total_ast_dropped=output.ast_dropped_results,
        engine_metrics=output.engine_metrics,
        export_paths=exports_map,
    )

    return 0


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_cli_args(argv)
    if args.tui or (not args.query and args.input_file is None and not args.status):
        try:
            exit_code = run_tui(workspace_root=args.workspace)
        except KeyboardInterrupt:
            print("\nInterrupted by user.", file=sys.stderr)
            exit_code = 130
        sys.exit(exit_code)
    try:
        exit_code = asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        exit_code = 130
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
