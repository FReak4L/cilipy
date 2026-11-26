"""Complete project & per-engine isolated test runner across all v3 search engines."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from core.models import PipelineSettings
from engine.orchestrator import SearchOrchestrator
from math_kernel.ast_boolean import DocumentView, compile_boolean_query
from transport.http_client import is_valid_http_url

SAFE_DOCS_QUERIES: tuple[str, ...] = (
    "site:developer.paypal.com braintree hosted-fields",
    "site:developer.paypal.com braintree dropin",
    "site:developer.paypal.com braintree client_token",
    "site:developer.paypal.com braintree 3ds",
    "site:community.braintreepayments.com",
    "site:stackoverflow.com braintree hosted-fields",
    "site:stackoverflow.com braintree dropin",
    "site:stackoverflow.com braintree client_token",
)

ENGINES_TO_TEST: tuple[str, ...] = (
    "searxng",
    "yahoo_direct",
    "ddg_html",
    "ddg_lite",
    "ddgs",
    "google_web_udm14",
    "google_mobile_web",
    "google_basic_html",
    "google",
)


async def _iter_queries(queries: tuple[str, ...]) -> AsyncIterator[str]:
    for q in queries:
        yield q


async def run_single_engine(engine_name: str, out_dir: Path) -> dict[str, Any]:
    started = time.perf_counter()
    settings = PipelineSettings(
        enabled_engines=[engine_name],
        enable_cache=False,
        enable_tui=False,
        enable_thompson_sampling=True,
        strict_ast_filter=True,
        enable_query_relaxation=False,
        pagination_depth=1,
        max_results_per_query=10,
        concurrency=2,
        max_retries=1,
        poisson_mean_delay=0.35,
        jitter_min=0.1,
        jitter_max=0.3,
        request_timeout=12.0,
    )
    orch = SearchOrchestrator(settings)
    output = await orch.execute_stream(
        _iter_queries(SAFE_DOCS_QUERIES),
        total_hint=len(SAFE_DOCS_QUERIES),
    )

    out_file = out_dir / f"{engine_name}.json"
    out_file.write_text(output.model_dump_json(indent=2) + "\n", encoding="utf-8")

    # Independent zero-FP and URL validity audit
    false_positives = 0
    bad_urls = 0
    unique_urls: set[str] = set()
    queries_matched: set[str] = set()
    for item in output.results:
        if not is_valid_http_url(item.url):
            bad_urls += 1
        ast_obj = compile_boolean_query(item.query)
        if ast_obj.evaluate(DocumentView(title=item.title, url=item.url, snippet=item.snippet)) != 1:
            false_positives += 1
        unique_urls.add(item.url.rstrip("/").lower())
        queries_matched.add(item.query)

    m = output.engine_metrics[0].model_dump() if output.engine_metrics else {}
    return {
        "engine": engine_name,
        "output_file": str(out_file),
        "queries_tested": len(SAFE_DOCS_QUERIES),
        "queries_with_hits": len(queries_matched),
        "total_results": output.total_results,
        "unique_domains": output.unique_domains,
        "ast_dropped_results": output.ast_dropped_results,
        "dedup_stats": output.dedup_stats.model_dump(),
        "false_positives": false_positives,
        "bad_urls": bad_urls,
        "elapsed_seconds": round(time.perf_counter() - started, 2),
        "metrics": m,
        "urls": sorted(unique_urls),
    }


async def main() -> None:
    out_dir = Path("/root/ntest/v3/per_engine_runs")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Run independent provider groups in parallel (respecting per-provider rate limits:
    # searxng, yahoo, ddg group, google group run cleanly without colliding on same host)
    async def _run_sequential(names: list[str]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for n in names:
            rows.append(await run_single_engine(n, out_dir))
        return rows

    group_results = await asyncio.gather(
        _run_sequential(["searxng"]),
        _run_sequential(["yahoo_direct"]),
        _run_sequential(["ddg_html", "ddg_lite", "ddgs"]),
        _run_sequential(["google_web_udm14", "google_mobile_web", "google_basic_html", "google"]),
    )
    by_name = {row["engine"]: row for grp in group_results for row in grp}
    ordered = [by_name[e] for e in ENGINES_TO_TEST]

    # Compute cross-engine union & unique contributions
    all_urls: set[str] = set()
    for row in ordered:
        all_urls.update(row["urls"])

    summary_payload = {
        "queries_scope": "source.txt safe official docs/community subset (L189-196, 8 queries)",
        "queries": list(SAFE_DOCS_QUERIES),
        "engines_tested": len(ordered),
        "union_unique_verified_urls": len(all_urls),
        "per_engine": ordered,
    }
    summary_path = out_dir / "per_engine_summary.json"
    summary_path.write_text(
        json.dumps(summary_payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("=== PER-ENGINE ISOLATED TEST MATRIX (8 SAFE DOCS QUERIES FROM source.txt L189-196) ===")
    hdr = (
        f"{'Engine':18s} | {'Hits':>4s} | {'Q-Hit':>5s} | {'ASTDrop':>7s} | {'FP':>2s} | "
        f"{'Req':>3s} | {'OK':>2s} | {'429':>3s} | {'Bot':>3s} | {'θ':>6s} | {'Parked':>6s} | {'Time(s)':>7s}"
    )
    print(hdr)
    print("-" * len(hdr))
    for r in ordered:
        m = r["metrics"]
        print(
            f"{r['engine']:18s} | {r['total_results']:4d} | {r['queries_with_hits']:2d}/8  | "
            f"{r['ast_dropped_results']:7d} | {r['false_positives']:2d} | "
            f"{int(m.get('requests', 0)):3d} | {int(m.get('successes', 0)):2d} | "
            f"{int(m.get('rate_limits', 0)):3d} | {int(m.get('bot_gates', 0)):3d} | "
            f"{float(m.get('thompson_posterior_mean', 0.5)):6.3f} | "
            f"{str(bool(m.get('parked', False))):>6s} | {r['elapsed_seconds']:7.2f}"
        )
    print(f"\nUNION UNIQUE VERIFIED URLS ACROSS ALL ENGINES: {len(all_urls)}")


if __name__ == "__main__":
    asyncio.run(main())
