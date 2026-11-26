"""Tool definitions and async handlers for the `search-v3` professional MCP server."""

from __future__ import annotations

import json
import os
import re
import shutil
from collections.abc import AsyncIterator, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cli.tui_exporters import (
    WorkspacePaths,
    discover_dork_files,
    discover_proxy_files,
    ensure_workspace,
    export_links_only_txt,
    extract_unique_urls_with_jq,
)
from cli.tui_profiles import (
    ALL_SELECTABLE_ENGINES,
    API_ENGINES,
    DIRECT_ENGINES,
    HYBRID_ENGINES,
)
from cli.tui_status import RunStatusTracker, load_active_status, load_run_history
from cli.tui_tables import jq_version
from core.exceptions import QueryParseError
from core.models import AllEnginesMatrixOutput, PipelineOutput, PipelineSettings
from engine.crawler import KatanaPipeline
from engine.orchestrator import SearchOrchestrator, stream_queries_from_file
from math_kernel.ast_boolean import DocumentView, compile_boolean_query
from mcp_server.fetcher import FetchError, fetch_url_content, validate_public_url
from plugins.google import GoogleLocaleConfig, GoogleSuiteConfig
from plugins.searxng import discover_local_searxng

VALID_ENGINES = {name for name, _ in ALL_SELECTABLE_ENGINES}


class ToolExecutionError(RuntimeError):
    """Raised when a tool call fails validation or execution; surfaced as `isError: true`."""


def _default_workspace() -> WorkspacePaths:
    env_ws = os.environ.get("SEARCH_V3_WORKSPACE")
    return ensure_workspace(Path(env_ws) if env_ws else None)


def _resolve_engines(profile: str | None, engines: Sequence[str] | None) -> list[str]:
    if engines:
        cleaned = [str(e).strip().lower() for e in engines if str(e).strip()]
        invalid = [e for e in cleaned if e not in VALID_ENGINES]
        if invalid:
            raise ToolExecutionError(
                f"Unknown engine(s): {', '.join(invalid)}. "
                f"Valid engines: {', '.join(sorted(VALID_ENGINES))}"
            )
        if not cleaned:
            raise ToolExecutionError("At least one valid engine must be specified.")
        return cleaned

    p = (profile or "hybrid").strip().lower()
    if p in ("direct", "fast"):
        return list(DIRECT_ENGINES)
    if p == "api":
        return list(API_ENGINES)
    if p in ("hybrid", "balanced", "medium"):
        return list(HYBRID_ENGINES)
    if p == "all":
        return [name for name, _ in ALL_SELECTABLE_ENGINES]
    raise ToolExecutionError(
        f"Unknown profile {profile!r}. Use 'hybrid', 'direct', 'api', 'fast', or 'all'."
    )


def _safe_child_file(base_dir: Path, filename: str) -> Path:
    if not filename or "/" in filename or "\\" in filename or ".." in filename:
        raise ToolExecutionError(
            f"Invalid filename {filename!r}: pass a plain filename inside {base_dir.name}/"
        )
    candidate = (base_dir / filename).resolve()
    base_resolved = base_dir.resolve()
    if not candidate.is_relative_to(base_resolved):
        raise ToolExecutionError(f"Path traversal rejected: {filename!r}")
    return candidate


def _sanitize_export_stem(raw: str, fallback: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", raw.strip()).strip("._")
    if not stem:
        return fallback
    if stem.endswith(".txt"):
        stem = stem[:-4]
    return stem[:80] or fallback


async def _iter_queries(queries: Sequence[str]) -> AsyncIterator[str]:
    for q in queries:
        cleaned = q.strip()
        if cleaned:
            yield cleaned


async def _collect_queries(
    ws: WorkspacePaths,
    queries: Sequence[str] | None,
    dork_file: str | None,
    *,
    max_queries: int,
) -> tuple[list[str], str]:
    collected: list[str] = []
    labels: list[str] = []

    if queries:
        for q in queries:
            s = str(q).strip()
            if s:
                collected.append(s)
        labels.append(f"{len(collected)} inline")

    if dork_file:
        path = _safe_child_file(ws.dorks, dork_file)
        if not path.is_file():
            avail = [d["name"] for d in discover_dork_files(ws.dorks)]
            raise ToolExecutionError(
                f"Dork file {dork_file!r} not found in {ws.dorks}. Available: {', '.join(avail) or '(none)'}"
            )
        async for q in stream_queries_from_file(path):
            collected.append(q)
            if len(collected) >= max_queries:
                break
        labels.append(path.name)

    if not collected:
        raise ToolExecutionError("Provide at least one non-empty query or a valid `dork_file`.")
    return collected[:max_queries], "+".join(labels)


def _build_settings(
    ws: WorkspacePaths,
    *,
    engines: list[str],
    max_results: int,
    pagination_depth: int,
    concurrency: int,
    strict_ast: bool,
    allow_relax: bool,
    use_cache: bool,
    thompson: bool = True,
    poisson_mean: float = 0.6,
    searxng_url: str | None = None,
) -> PipelineSettings:
    return PipelineSettings.load(
        cli_overrides={
            "enabled_engines": engines,
            "max_results_per_query": max(1, min(int(max_results), 50)),
            "pagination_depth": max(1, min(int(pagination_depth), 5)),
            "concurrency": max(1, min(int(concurrency), 16)),
            "strict_ast_filter": bool(strict_ast),
            "enable_query_relaxation": bool(allow_relax),
            "enable_thompson_sampling": bool(thompson),
            "poisson_mean_delay": max(0.05, min(float(poisson_mean), 10.0)),
            "max_retries": 1,
            "request_timeout": 10.0,
            "enable_cache": bool(use_cache),
            "cache_db_path": ws.cache / "search_cache.db",
            "searxng_url": searxng_url or os.environ.get("SEARXNG_URL") or None,
            "enable_tui": False,
            "enable_crawl": False,
        }
    )


def _build_google_config(settings: PipelineSettings, hl: str = "en", gl: str = "us") -> GoogleSuiteConfig:
    return GoogleSuiteConfig.from_env().model_copy(
        update={
            "max_retries": settings.max_retries,
            "locale": GoogleLocaleConfig(hl=(hl or "en").strip(), gl=(gl or "us").strip()),
        }
    )


def _format_failover_text(
    output: PipelineOutput,
    *,
    query_label: str,
    links_txt_path: Path | None = None,
) -> str:
    lines: list[str] = [
        f"## Search v3 Results ({query_label})",
        (
            f"Verified: **{output.total_results}** | Unique domains: **{output.unique_domains}** | "
            f"AST dropped: {output.ast_dropped_results} | Cache hits: {output.cache_hits} | "
            f"Elapsed: {output.elapsed_seconds:.2f}s"
        ),
        "",
    ]
    if not output.results:
        lines.append("_No AST-verified results matched. Try `allow_relax=true`, `strict_ast=false`, or `profile='direct'`._")
    else:
        for idx, r in enumerate(output.results, 1):
            snippet = " ".join(r.snippet.split())[:260]
            lines.append(f"{idx}. **{r.title}** (`{r.engine}`)")
            lines.append(f"   - URL: {r.url}")
            if snippet:
                lines.append(f"   - Snippet: {snippet}")

    active_metrics = [m for m in output.engine_metrics if m.requests > 0]
    if active_metrics:
        lines.append("")
        lines.append("### Engine Telemetry")
        for m in active_metrics:
            lines.append(
                f"- `{m.engine}`: req={m.requests} ok={m.successes} hits={m.total_results_yielded} "
                f"429={m.rate_limits} avg={m.avg_latency_ms:.0f}ms theta={m.thompson_posterior_mean:.0%}"
            )
    if links_txt_path is not None:
        lines.append(f"\nExported links-only `.txt` (1 URL/line): `{links_txt_path}`")
    return "\n".join(lines)


def _format_matrix_text(
    matrix: AllEnginesMatrixOutput,
    *,
    links_txt_path: Path | None = None,
    json_path: Path | None = None,
) -> str:
    lines: list[str] = [
        f"## Search v3 All-Engines Matrix ({matrix.total_queries} queries × {len(matrix.engines)} engines)",
        (
            f"Unique verified links: **{matrix.total_verified_links}** | "
            f"AST dropped: {matrix.total_ast_dropped} | Elapsed: {matrix.elapsed_seconds:.2f}s"
        ),
        "",
    ]
    for rec in matrix.records:
        lines.append(f"### Q{rec.query_id}: `{rec.query}` ({rec.unique_verified_count} verified)")
        eng_summary = [
            f"`{name}`={outcome.status}({outcome.ast_admitted_count}/{outcome.raw_count}, {outcome.latency_ms:.0f}ms)"
            for name, outcome in rec.per_engine.items()
        ]
        lines.append("Engines: " + " | ".join(eng_summary))
        if rec.merged_links:
            for idx, item in enumerate(rec.merged_links[:15], 1):
                snip = " ".join(item.snippet.split())[:180]
                lines.append(f"{idx}. **{item.title}** (`{item.engine}`) — {item.url}")
                if snip:
                    lines.append(f"   {snip}")
            if len(rec.merged_links) > 15:
                lines.append(f"_... +{len(rec.merged_links) - 15} more links_")
        else:
            lines.append("_No AST-verified matches from any engine._")
        lines.append("")

    if links_txt_path is not None:
        lines.append(f"- Links-only `.txt` (1 URL/line): `{links_txt_path}`")
    if json_path is not None:
        lines.append(f"- Full Matrix JSON: `{json_path}`")
    return "\n".join(lines).strip()


# ---------------------------------------------------------------------------
# Tool JSON Schemas (MCP `tools/list`)
# ---------------------------------------------------------------------------
TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "search_web_v3",
        "description": (
            "Federated web & dork search powered by Hybrid Search Pipeline v3 "
            "(Thompson Sampling engine scheduling, Dynamic Poisson pacing, Strict Boolean AST "
            "verification, 64-bit SimHash/Jaccard deduplication, and SQLite cache). "
            "Use `profile='hybrid'` (default, SearXNG + Yahoo + DDG + Google), `'direct'` "
            "(all 6 browser engines), or `'api'` (SearXNG, Google CSE, DDGS). "
            "Supports exact dork operators (`site:`, `inurl:`, `intitle:`, `filetype:`, quotes, OR, -negation)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query or Boolean dork string.",
                    "minLength": 1,
                },
                "profile": {
                    "type": "string",
                    "enum": ["hybrid", "direct", "api", "fast", "all"],
                    "default": "hybrid",
                    "description": "Engine group preset when `engines` is not explicitly provided.",
                },
                "engines": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional explicit engine list overriding `profile`: searxng, yahoo_direct, "
                        "ddg_html, ddg_lite, ddgs, google_web_udm14, google_mobile_web, "
                        "google_basic_html, google_cse, google."
                    ),
                },
                "max_results": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "default": 10,
                    "description": "Maximum verified organic results to return.",
                },
                "pagination_depth": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 5,
                    "default": 1,
                    "description": "Deep pagination pages per healthy engine (1-5).",
                },
                "strict_ast": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enforce deterministic Boolean AST truth-table verification (zero false positives).",
                },
                "allow_relax": {
                    "type": "boolean",
                    "default": False,
                    "description": "Allow progressive query relaxation if strict query returns zero matches.",
                },
                "use_cache": {
                    "type": "boolean",
                    "default": True,
                    "description": "Use persistent SQLite cache.",
                },
                "google_hl": {
                    "type": "string",
                    "default": "en",
                    "description": "Google interface language (e.g. 'en', 'fa', 'de').",
                },
                "google_gl": {
                    "type": "string",
                    "default": "us",
                    "description": "Google geolocation country code (e.g. 'us', 'gb', 'ir').",
                },
                "save_links_txt": {
                    "type": "boolean",
                    "default": False,
                    "description": "Also export unique verified URLs (1 URL/line via jq) into workspace/exports/links/.",
                },
                "response_format": {
                    "type": "string",
                    "enum": ["text", "json"],
                    "default": "text",
                    "description": "Return concise Markdown (`text`) or full structured JSON (`json`).",
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "search_all_engines",
        "description": (
            "All-Engines Matrix fan-out (`--all-engines`): queries EVERY selected engine concurrently "
            "for each query (e.g. all 6 Direct engines or Hybrid 8 engines), returning full per-engine "
            "status/latency/AST counts plus deduplicated merged links and optional links-only `.txt` export via `jq`."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "queries": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "1 to 25 search queries or dorks.",
                },
                "dork_file": {
                    "type": "string",
                    "description": "Optional `.txt` filename inside `workspace/dorks/` (alternative or addition to `queries`).",
                },
                "max_queries": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "default": 15,
                    "description": "Cap on total queries processed from `dork_file`/`queries`.",
                },
                "profile": {
                    "type": "string",
                    "enum": ["direct", "hybrid", "api", "fast", "all"],
                    "default": "direct",
                    "description": "Default `'direct'` runs all 6 browser engines (Yahoo, DDG HTML/Lite, Google Web/Mobile/Basic).",
                },
                "engines": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional explicit engine list overriding `profile`.",
                },
                "max_results": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 30,
                    "default": 10,
                },
                "pagination_depth": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 3,
                    "default": 1,
                },
                "strict_ast": {"type": "boolean", "default": True},
                "allow_relax": {"type": "boolean", "default": False},
                "save_links_txt": {
                    "type": "boolean",
                    "default": False,
                    "description": "Save unique verified links (1 URL/line via jq) to workspace/exports/links/.",
                },
                "save_json": {
                    "type": "boolean",
                    "default": False,
                    "description": "Save complete matrix JSON to workspace/exports/json/.",
                },
                "response_format": {
                    "type": "string",
                    "enum": ["text", "json"],
                    "default": "text",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "batch_search",
        "description": (
            "Concurrent multi-query Failover search across a list of queries or a `.txt` file in "
            "`workspace/dorks/` using Thompson Sampling, Dynamic Poisson pacing, AST filtering, "
            "SimHash/Jaccard deduplication, and optional links-only `.txt` export."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "queries": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of search queries.",
                },
                "dork_file": {
                    "type": "string",
                    "description": "Optional `.txt` filename in `workspace/dorks/`.",
                },
                "max_queries": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 25,
                },
                "profile": {
                    "type": "string",
                    "enum": ["hybrid", "direct", "api", "fast", "all"],
                    "default": "hybrid",
                },
                "engines": {"type": "array", "items": {"type": "string"}},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 30, "default": 10},
                "concurrency": {"type": "integer", "minimum": 1, "maximum": 16, "default": 4},
                "strict_ast": {"type": "boolean", "default": True},
                "allow_relax": {"type": "boolean", "default": False},
                "use_cache": {"type": "boolean", "default": True},
                "save_links_txt": {"type": "boolean", "default": False},
                "save_json": {"type": "boolean", "default": False},
                "response_format": {
                    "type": "string",
                    "enum": ["text", "json"],
                    "default": "text",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "fetch_url",
        "description": (
            "Fetch and read a public HTTP(S) webpage, JSON API, Markdown file, or GitHub repository README "
            "using BoringSSL (`curl_cffi` Chrome TLS + HTTP/2→HTTP/1.1 fallback) and `lxml` readability extraction. "
            "SSRF-protected against private/loopback/metadata IPs. Supports `headings_only`, `section`, "
            "`include_links`, and `start_char`/`max_chars` pagination."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Public http:// or https:// URL to fetch.",
                    "minLength": 8,
                },
                "max_chars": {
                    "type": "integer",
                    "minimum": 500,
                    "maximum": 100000,
                    "default": 18000,
                    "description": "Maximum characters to return in this page.",
                },
                "start_char": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "Character offset for paginating large documents.",
                },
                "headings_only": {
                    "type": "boolean",
                    "default": False,
                    "description": "Return only the heading outline (Table of Contents).",
                },
                "section": {
                    "type": "string",
                    "description": "Extract only content under a heading matching this substring.",
                },
                "include_links": {
                    "type": "boolean",
                    "default": False,
                    "description": "Append deduplicated links extracted from the page.",
                },
                "prefer_github_readme": {
                    "type": "boolean",
                    "default": True,
                    "description": "When URL is a GitHub repo root, fetch raw README.md cleanly.",
                },
                "timeout": {
                    "type": "number",
                    "minimum": 2.0,
                    "maximum": 60.0,
                    "default": 15.0,
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "parse_dork_ast",
        "description": (
            "Offline deterministic Boolean AST compiler & dialect translator for search dorks. "
            "Validates syntax, lists atomic predicates (`site`, `inurl`, `intitle`, `filetype`, exact phrases), "
            "translates non-destructively to Google/Yahoo/DDG/SearXNG dialects, and optionally evaluates "
            "against a candidate `{title, url, snippet}` document."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 1},
                "test_document": {
                    "type": "object",
                    "description": "Optional document to evaluate against the compiled Boolean AST.",
                    "properties": {
                        "title": {"type": "string"},
                        "url": {"type": "string"},
                        "snippet": {"type": "string"},
                    },
                    "required": ["url"],
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "crawl_urls",
        "description": (
            "Tier 4 Katana deep crawler & HTML structural schema extractor (forms, input fields, "
            "OpenGraph metadata, canonical URLs, asset endpoints). Enforces SSRF protection and "
            "a strict `allowed_domains` scope allowlist."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "maxItems": 20,
                    "description": "Seed public http(s) URLs to inspect/crawl.",
                },
                "allowed_domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": "Mandatory domain allowlist (e.g. ['docs.python.org']).",
                },
                "depth": {"type": "integer", "minimum": 1, "maximum": 3, "default": 1},
                "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 120, "default": 30},
            },
            "required": ["urls", "allowed_domains"],
            "additionalProperties": False,
        },
    },
    {
        "name": "search_status",
        "description": (
            "Inspect live `search-v3` health & workspace state: local SearXNG daemon reachability, "
            "available engines/profiles, `jq` and `katana` availability, `workspace/dorks/*.txt` files "
            "with exact query counts `(N)`, active run status (`.active_run.json` with stale-PID check), "
            "and recent run history."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "history_limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 30,
                    "default": 8,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "export_links_txt",
        "description": (
            "List saved run JSON files in `workspace/exports/json/` or extract ONLY unique verified URLs "
            "(1 URL per line via `jq`) from a specified saved run JSON into `workspace/exports/links/`."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_file": {
                    "type": "string",
                    "description": "Filename inside `workspace/exports/json/`. Omit to list available saved runs.",
                },
                "output_name": {
                    "type": "string",
                    "description": "Optional `.txt` filename in `workspace/exports/links/`.",
                },
            },
            "additionalProperties": False,
        },
    },
]


# ---------------------------------------------------------------------------
# Tool Handlers
# ---------------------------------------------------------------------------
async def _handle_search_web_v3(args: dict[str, Any]) -> str:
    query = str(args.get("query") or "").strip()
    if not query:
        raise ToolExecutionError("`query` is required and cannot be empty.")

    ws = _default_workspace()
    engines = _resolve_engines(args.get("profile"), args.get("engines"))
    settings = _build_settings(
        ws,
        engines=engines,
        max_results=int(args.get("max_results", 10)),
        pagination_depth=int(args.get("pagination_depth", 1)),
        concurrency=1,
        strict_ast=bool(args.get("strict_ast", True)),
        allow_relax=bool(args.get("allow_relax", False)),
        use_cache=bool(args.get("use_cache", True)),
        poisson_mean=0.25,
    )
    google_cfg = _build_google_config(
        settings,
        hl=str(args.get("google_hl", "en")),
        gl=str(args.get("google_gl", "us")),
    )
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    tracker = RunStatusTracker(
        ws,
        run_id=run_id,
        profile="mcp",
        mode="failover",
        input_label=query[:48],
        total_queries=1,
        render_live=False,
    )
    orch = SearchOrchestrator(settings, google_config=google_cfg, telemetry_sink=tracker)
    output = await orch.execute_stream(_iter_queries([query]), total_hint=1)

    exports_map: dict[str, str] = {}
    links_path: Path | None = None
    if bool(args.get("save_links_txt", False)):
        links_path = ws.exports_links / f"{run_id}_mcp_links.txt"
        export_links_only_txt(output, links_path)
        exports_map["links_txt"] = str(links_path)

    tracker.finalize(
        state="completed",
        total_verified_links=output.total_results,
        total_ast_dropped=output.ast_dropped_results,
        engine_metrics=output.engine_metrics,
        export_paths=exports_map,
    )

    if str(args.get("response_format", "text")).lower() == "json":
        payload = json.loads(output.model_dump_json())
        if links_path is not None:
            payload["links_txt_path"] = str(links_path)
        return json.dumps(payload, indent=2, ensure_ascii=False)
    return _format_failover_text(output, query_label=query, links_txt_path=links_path)


async def _handle_search_all_engines(args: dict[str, Any]) -> str:
    ws = _default_workspace()
    max_q = max(1, min(int(args.get("max_queries", 15)), 50))
    queries, label = await _collect_queries(
        ws, args.get("queries"), args.get("dork_file"), max_queries=max_q
    )
    engines = _resolve_engines(args.get("profile", "direct"), args.get("engines"))
    settings = _build_settings(
        ws,
        engines=engines,
        max_results=int(args.get("max_results", 10)),
        pagination_depth=int(args.get("pagination_depth", 1)),
        concurrency=min(4, len(queries)),
        strict_ast=bool(args.get("strict_ast", True)),
        allow_relax=bool(args.get("allow_relax", False)),
        use_cache=False,
        poisson_mean=0.35,
    )
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    tracker = RunStatusTracker(
        ws,
        run_id=run_id,
        profile="mcp",
        mode="all_engines",
        input_label=label,
        total_queries=len(queries),
        render_live=False,
    )
    orch = SearchOrchestrator(settings, telemetry_sink=tracker)
    tracker.start()
    matrix = await orch.execute_all_engines_matrix(
        _iter_queries(queries),
        on_query_done=tracker.record_matrix_query_done,
    )

    exports_map: dict[str, str] = {}
    json_path: Path | None = None
    links_path: Path | None = None
    if bool(args.get("save_json", False)):
        json_path = ws.exports_json / f"{run_id}_mcp_matrix.json"
        json_path.write_text(matrix.model_dump_json(indent=2) + "\n", encoding="utf-8")
        exports_map["json"] = str(json_path)
    if bool(args.get("save_links_txt", False)):
        links_path = ws.exports_links / f"{run_id}_mcp_matrix_links.txt"
        export_links_only_txt(matrix, links_path)
        exports_map["links_txt"] = str(links_path)

    tracker.finalize(
        state="completed",
        done_queries=matrix.total_queries,
        total_queries=matrix.total_queries,
        total_verified_links=matrix.total_verified_links,
        total_ast_dropped=matrix.total_ast_dropped,
        engine_metrics=matrix.engine_metrics,
        export_paths=exports_map,
    )

    if str(args.get("response_format", "text")).lower() == "json":
        payload = json.loads(matrix.model_dump_json())
        payload["exports"] = exports_map
        return json.dumps(payload, indent=2, ensure_ascii=False)
    return _format_matrix_text(matrix, links_txt_path=links_path, json_path=json_path)


async def _handle_batch_search(args: dict[str, Any]) -> str:
    ws = _default_workspace()
    max_q = max(1, min(int(args.get("max_queries", 25)), 100))
    queries, label = await _collect_queries(
        ws, args.get("queries"), args.get("dork_file"), max_queries=max_q
    )
    engines = _resolve_engines(args.get("profile", "hybrid"), args.get("engines"))
    settings = _build_settings(
        ws,
        engines=engines,
        max_results=int(args.get("max_results", 10)),
        pagination_depth=1,
        concurrency=int(args.get("concurrency", 4)),
        strict_ast=bool(args.get("strict_ast", True)),
        allow_relax=bool(args.get("allow_relax", False)),
        use_cache=bool(args.get("use_cache", True)),
        poisson_mean=0.4,
    )
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    tracker = RunStatusTracker(
        ws,
        run_id=run_id,
        profile="mcp",
        mode="failover",
        input_label=label,
        total_queries=len(queries),
        render_live=False,
    )
    orch = SearchOrchestrator(settings, telemetry_sink=tracker)
    output = await orch.execute_stream(_iter_queries(queries), total_hint=len(queries))

    exports_map: dict[str, str] = {}
    json_path: Path | None = None
    links_path: Path | None = None
    if bool(args.get("save_json", False)):
        json_path = ws.exports_json / f"{run_id}_mcp_batch.json"
        json_path.write_text(output.model_dump_json(indent=2) + "\n", encoding="utf-8")
        exports_map["json"] = str(json_path)
    if bool(args.get("save_links_txt", False)):
        links_path = ws.exports_links / f"{run_id}_mcp_batch_links.txt"
        export_links_only_txt(output, links_path)
        exports_map["links_txt"] = str(links_path)

    tracker.finalize(
        state="completed",
        total_verified_links=output.total_results,
        total_ast_dropped=output.ast_dropped_results,
        engine_metrics=output.engine_metrics,
        export_paths=exports_map,
    )

    if str(args.get("response_format", "text")).lower() == "json":
        payload = json.loads(output.model_dump_json())
        payload["exports"] = exports_map
        return json.dumps(payload, indent=2, ensure_ascii=False)
    text = _format_failover_text(output, query_label=f"batch: {label}", links_txt_path=links_path)
    if json_path is not None:
        text += f"\nExported full JSON: `{json_path}`"
    return text


async def _handle_fetch_url(args: dict[str, Any]) -> str:
    url = str(args.get("url") or "").strip()
    if not url:
        raise ToolExecutionError("`url` is required.")
    try:
        doc = await fetch_url_content(
            url,
            max_chars=int(args.get("max_chars", 18_000)),
            start_char=int(args.get("start_char", 0)),
            headings_only=bool(args.get("headings_only", False)),
            section=args.get("section"),
            include_links=bool(args.get("include_links", False)),
            prefer_github_readme=bool(args.get("prefer_github_readme", True)),
            timeout=float(args.get("timeout", 15.0)),
        )
    except FetchError as exc:
        raise ToolExecutionError(str(exc)) from exc

    header_lines = [
        f"# {doc.title or doc.final_url}",
        f"- URL: {doc.final_url}",
        f"- HTTP: {doc.status_code} | Content-Type: `{doc.content_type}` | Chars: {doc.returned_chars}/{doc.total_chars}",
    ]
    if doc.truncated and doc.next_start_char is not None:
        header_lines.append(f"- Truncated: call `fetch_url` with `start_char={doc.next_start_char}` for more.")
    parts = ["\n".join(header_lines), "", doc.markdown]
    if doc.links:
        parts.append("\n## Extracted Links\n" + "\n".join(f"- {u}" for u in doc.links))
    return "\n".join(parts).strip()


async def _handle_parse_dork_ast(args: dict[str, Any]) -> str:
    query = str(args.get("query") or "").strip()
    if not query:
        raise ToolExecutionError("`query` is required.")
    try:
        compiled = compile_boolean_query(query)
    except QueryParseError as exc:
        raise ToolExecutionError(f"Boolean AST parse error: {exc}") from exc

    atoms = [a.atom_key for a in compiled.atoms()]
    result: dict[str, Any] = {
        "valid": True,
        "raw_query": compiled.raw_query,
        "normalized_query": compiled.normalized_query,
        "atom_count": len(atoms),
        "atoms": atoms,
        "dialects": {
            "google": compiled.translate_for_backend("google"),
            "yahoo": compiled.translate_for_backend("yahoo"),
            "ddg": compiled.translate_for_backend("ddg"),
            "searxng": compiled.translate_for_backend("searxng"),
        },
    }
    test_doc = args.get("test_document")
    if isinstance(test_doc, dict):
        dv = DocumentView(
            title=str(test_doc.get("title") or ""),
            url=str(test_doc.get("url") or ""),
            snippet=str(test_doc.get("snippet") or ""),
        )
        verdict = compiled.evaluate(dv)
        result["test_evaluation"] = {
            "admitted": verdict == 1,
            "bit": verdict,
            "per_atom": {a.atom_key: a.evaluate(dv) for a in compiled.atoms()},
        }
    return json.dumps(result, indent=2, ensure_ascii=False)


async def _handle_crawl_urls(args: dict[str, Any]) -> str:
    raw_urls = args.get("urls") or []
    allowed_domains = [str(d).strip() for d in (args.get("allowed_domains") or []) if str(d).strip()]
    if not raw_urls or not allowed_domains:
        raise ToolExecutionError("Both `urls` and `allowed_domains` are required.")

    validated_urls: list[str] = []
    for u in raw_urls[:20]:
        try:
            validated_urls.append(await validate_public_url(str(u)))
        except FetchError as exc:
            raise ToolExecutionError(str(exc)) from exc

    crawler = KatanaPipeline(
        depth=max(1, min(int(args.get("depth", 1)), 3)),
        timeout_seconds=max(5, min(int(args.get("timeout_seconds", 30)), 120)),
        allowed_domains=allowed_domains,
    )
    records = await crawler.crawl(validated_urls)
    payload = {
        "katana_binary": crawler.binary_path or "fallback_direct_html_extractor",
        "crawled_count": len(records),
        "results": [r.model_dump() for r in records],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


async def _handle_search_status(args: dict[str, Any]) -> str:
    ws = _default_workspace()
    limit = max(1, min(int(args.get("history_limit", 8)), 30))
    searx_url = await discover_local_searxng(timeout=1.5)
    dorks = discover_dork_files(ws.dorks)
    proxies = discover_proxy_files(ws.proxies)
    active = load_active_status(ws)
    history = load_run_history(ws, limit=limit)

    payload = {
        "server": "search-v3",
        "version": "3.0.0",
        "searxng_local": searx_url or "offline",
        "jq": jq_version(),
        "katana_binary": shutil.which("katana") or "not installed (HTML schema fallback active)",
        "workspace_root": str(ws.root),
        "profiles": {
            "direct": list(DIRECT_ENGINES),
            "api": list(API_ENGINES),
            "hybrid": list(HYBRID_ENGINES),
            "all": [name for name, _ in ALL_SELECTABLE_ENGINES],
        },
        "dork_files": [
            {"name": d["name"], "queries": d["query_count"], "size": d["size_human"]}
            for d in dorks
        ],
        "proxy_files": [
            {"name": p["name"], "entries": p["query_count"], "size": p["size_human"]}
            for p in proxies
        ],
        "active_run": active,
        "recent_history": history,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


async def _handle_export_links_txt(args: dict[str, Any]) -> str:
    ws = _default_workspace()
    run_file = args.get("run_file")
    if not run_file:
        saved = sorted(ws.exports_json.glob("*.json"), reverse=True)[:25]
        return json.dumps(
            {
                "exports_json_dir": str(ws.exports_json),
                "available_runs": [
                    {"file": p.name, "size_kb": round(p.stat().st_size / 1024, 1)} for p in saved
                ],
            },
            indent=2,
            ensure_ascii=False,
        )

    src = _safe_child_file(ws.exports_json, str(run_file))
    if not src.is_file():
        raise ToolExecutionError(f"Saved run JSON not found: {run_file!r}")

    stem = _sanitize_export_stem(str(args.get("output_name") or f"{src.stem}_links"), f"{src.stem}_links")
    dest = ws.exports_links / f"{stem}.txt"
    urls = extract_unique_urls_with_jq(src)
    count = export_links_only_txt(src, dest)
    return json.dumps(
        {
            "source_json": str(src),
            "links_txt_path": str(dest),
            "unique_links_count": count,
            "preview_first_20": urls[:20],
        },
        indent=2,
        ensure_ascii=False,
    )


_HANDLERS = {
    "search_web_v3": _handle_search_web_v3,
    "search_all_engines": _handle_search_all_engines,
    "batch_search": _handle_batch_search,
    "fetch_url": _handle_fetch_url,
    "parse_dork_ast": _handle_parse_dork_ast,
    "crawl_urls": _handle_crawl_urls,
    "search_status": _handle_search_status,
    "export_links_txt": _handle_export_links_txt,
}


async def dispatch_tool(name: str, arguments: dict[str, Any] | None) -> str:
    """Execute a registered MCP tool by name and return its string payload."""
    handler = _HANDLERS.get(name)
    if handler is None:
        raise ToolExecutionError(f"Unknown tool: {name!r}")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise ToolExecutionError("Tool arguments must be a JSON object.")
    return await handler(arguments)
