"""Minimalist Pure-ANSI + jq Interactive TUI Wizard, Live Dashboard, Status & Exports."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cli.tui_ansi import (
    Ansi,
    clear_screen,
    get_screen_size,
    horizontal_rule,
    layout_breakpoint,
    render_header,
    truncate_visible,
)
from cli.tui_exporters import (
    WorkspacePaths,
    count_valid_queries,
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
    ProfileConfig,
    build_advanced_profile,
    build_equivalent_cli_command,
    build_fast_profile,
    build_medium_profile,
    load_profile_toml,
    save_profile_toml,
)
from cli.tui_status import RunStatusTracker, load_active_status, load_run_history
from cli.tui_tables import (
    jq_version,
    render_domains_table,
    render_dork_files_table,
    render_engine_metrics_table,
    render_status_history_table,
    render_table,
)
from core.models import AllEnginesMatrixOutput, PipelineOutput
from engine.orchestrator import (
    SearchOrchestrator,
    export_all_engines_links_report,
    stream_queries_from_file,
)
from plugins.google import GoogleLocaleConfig, GoogleSuiteConfig
from plugins.searxng import discover_local_searxng


class _TUIExit(Exception):
    """Raised cleanly on EOF to exit interactive prompt loops without spinning."""


def _prompt(label: str, default: str = "", *, ansi: Ansi) -> str:
    hint = f" [{default}]" if default else ""
    try:
        raw = input(f"  {ansi.bold_cyan('>')} {label}{ansi.dim(hint)}: ").strip()
    except EOFError as exc:
        raise _TUIExit() from exc
    except KeyboardInterrupt:
        return "q"
    return raw if raw else default


def _prompt_yes_no(label: str, default: bool, *, ansi: Ansi) -> bool:
    d_str = "Y/n" if default else "y/N"
    ans = _prompt(f"{label} ({d_str})", "y" if default else "n", ansi=ansi).lower()
    if ans in ("y", "yes", "1", "true"):
        return True
    if ans in ("n", "no", "0", "false"):
        return False
    return default


def _prompt_int(label: str, default: int, *, min_val: int, max_val: int, ansi: Ansi) -> int:
    raw = _prompt(label, str(default), ansi=ansi)
    try:
        val = int(raw)
        return max(min_val, min(max_val, val))
    except ValueError:
        return default


def _prompt_float(
    label: str, default: float, *, min_val: float, max_val: float, ansi: Ansi
) -> float:
    raw = _prompt(label, str(default), ansi=ansi)
    try:
        val = float(raw)
        return max(min_val, min(max_val, val))
    except ValueError:
        return default


def _pause(ansi: Ansi, msg: str = "Press Enter to continue") -> None:
    try:
        input(f"\n  {ansi.dim(msg + '...')}")
    except (EOFError, KeyboardInterrupt):
        return


def _configure_file_only_logging(log_path: Path | None, debug: bool) -> None:
    root_log = logging.getLogger("hybrid_search.v3")
    root_log.handlers.clear()
    root_log.propagate = False
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path, mode="w", encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        root_log.addHandler(fh)
        root_log.setLevel(logging.DEBUG if debug else logging.INFO)
    else:
        root_log.addHandler(logging.NullHandler())
        root_log.setLevel(logging.CRITICAL)


async def _stream_multiple_files(files: list[Path]) -> AsyncIterator[str]:
    for path in files:
        async for query in stream_queries_from_file(path):
            yield query


def render_status_view(
    ws: WorkspacePaths,
    *,
    cols: int | None = None,
    ansi: Ansi | None = None,
) -> str:
    """Build the Pure-ANSI + `jq` Status overview (usable from TUI `[S]` and `search-v3 --status`)."""
    term_cols = cols if cols is not None else get_screen_size()[0]
    a = ansi or Ansi()
    active = load_active_status(ws)
    history = load_run_history(ws, limit=8)

    lines = [
        render_header(
            "SEARCH-V3 STATUS",
            [f"jq: {jq_version()}", f"Cols: {term_cols} ({layout_breakpoint(term_cols)})"],
            cols=term_cols,
            ansi=a,
        ),
        "",
    ]

    if active is None:
        lines.append(f"  Active Run: {a.dim('Idle (no runs recorded yet)')}")
    else:
        state = str(active.get("state", "unknown"))
        tone = "info" if state == "running" else ("ok" if state == "completed" else "warn")
        bp = layout_breakpoint(term_cols)
        if bp == "compact":
            lines.append(
                f"  Run: {a.bold(str(active.get('run_id', '-')))}  {a.badge(state.upper(), tone)}"
            )
            lines.append(
                f"  {a.cyan(str(active.get('profile', '-')).upper())} · {active.get('mode', '-')} · "
                f"{active.get('done_queries', 0)}/{active.get('total_queries', 0)}"
            )
            lines.append(
                f"  Links: {a.bold_green(str(active.get('verified_links', 0)))} · "
                f"Drop: {active.get('ast_dropped', 0)} · {active.get('elapsed_seconds', 0)}s"
            )
        elif bp == "standard":
            lines.append(
                f"  Run: {a.bold(str(active.get('run_id', '-')))}  "
                f"State: {a.badge(state.upper(), tone)}  "
                f"PID: {a.dim(str(active.get('pid', '-')))}"
            )
            lines.append(
                f"  Profile: {a.cyan(str(active.get('profile', '-')).upper())}  "
                f"Mode: {active.get('mode', '-')}  "
                f"Progress: {active.get('done_queries', 0)}/{active.get('total_queries', 0)}"
            )
            lines.append(
                f"  Verified Links: {a.bold_green(str(active.get('verified_links', 0)))}  "
                f"AST Drop: {active.get('ast_dropped', 0)}  "
                f"Elapsed: {active.get('elapsed_seconds', 0)}s"
            )
        else:
            lines.append(
                f"  Latest / Active Run: {a.bold(str(active.get('run_id', '-')))}  "
                f"State: {a.badge(state.upper(), tone)}  "
                f"PID: {a.dim(str(active.get('pid', '-')))}"
            )
            lines.append(
                f"  Profile: {a.cyan(str(active.get('profile', '-')).upper())}  "
                f"Mode: {active.get('mode', '-')}  "
                f"Progress: {active.get('done_queries', 0)}/{active.get('total_queries', 0)}  "
                f"Verified Links: {a.bold_green(str(active.get('verified_links', 0)))}  "
                f"AST Drop: {active.get('ast_dropped', 0)}  "
                f"Elapsed: {active.get('elapsed_seconds', 0)}s"
            )
        exports = active.get("exports") or {}
        if isinstance(exports, dict) and exports:
            for k, v in exports.items():
                lines.append(f"  Export ({k}): {a.dim(truncate_visible(str(v), max(24, term_cols - 20)))}")
        eng_metrics = active.get("engine_metrics") or []
        if eng_metrics:
            lines.append("")
            lines.append(render_engine_metrics_table(eng_metrics, cols=term_cols, ansi=a))

    if history:
        lines.append("")
        lines.append(a.bold("Recent Run History"))
        lines.append(render_status_history_table(history, cols=term_cols, ansi=a))

    return "\n".join(lines)


class SearchV3TUI:
    """Minimalist, responsive, zero-library Pure-ANSI + jq TUI embedded in `search-v3`."""

    def __init__(self, workspace_root: Path | None = None) -> None:
        self.ws = ensure_workspace(workspace_root)
        self.ansi = Ansi()
        self._searxng_label = "Probing..."
        self._install_resize_handler()

    @staticmethod
    def _install_resize_handler() -> None:
        if hasattr(signal, "SIGWINCH"):
            try:
                signal.signal(signal.SIGWINCH, lambda *_: None)
            except (ValueError, OSError):
                pass

    def _clear(self) -> None:
        if self.ansi.enabled:
            sys.stdout.write(clear_screen())
            sys.stdout.flush()
        else:
            print("\n" + "-" * 40)

    def _cols(self) -> int:
        return get_screen_size()[0]

    def _probe_searxng_once(self) -> str:
        try:
            url = asyncio.run(discover_local_searxng(timeout=1.2))
            return f"UP ({url.split('//')[-1]})" if url else "OFF"
        except Exception:
            return "OFF"

    def _pick_dork_files(self, step_title: str) -> list[Path] | None:
        """Fetch `workspace/dorks/*.txt`, show exact `(count)` via `jq` table, and pick file(s)."""
        while True:
            self._clear()
            cols = self._cols()
            print(render_header(step_title, [f"Folder: {self.ws.dorks.name}/"], cols=cols, ansi=self.ansi))
            print()

            entries = discover_dork_files(self.ws.dorks)
            total_all = sum(int(e["query_count"]) for e in entries)

            if entries:
                print(render_dork_files_table(entries, cols=cols, ansi=self.ansi))
                print()
                print(f"  {self.ansi.bold_cyan('[A]')} All files combined  {self.ansi.green(f'({total_all})')}")
            else:
                print(self.ansi.yellow(f"  No .txt files found in {self.ws.dorks}"))

            print(f"  {self.ansi.bold_cyan('[P]')} Enter custom .txt path")
            print(f"  {self.ansi.dim('[B]')} Back")
            print()

            default_choice = "1" if entries else "P"
            choice = _prompt("Select query file", default_choice, ansi=self.ansi).strip()
            low = choice.lower()
            if low in ("b", "back", "q"):
                return None
            if low == "a" and entries:
                return [Path(e["path"]) for e in entries]
            if low == "p":
                custom = _prompt("Absolute path to .txt query file", "", ansi=self.ansi)
                if custom:
                    p = Path(custom).expanduser().resolve()
                    if p.is_file():
                        cnt = count_valid_queries(p)
                        print(f"  {self.ansi.green('OK')} Loaded {p.name} ({cnt} queries)")
                        return [p]
                    print(self.ansi.red(f"  File not found: {p}"))
                    _pause(self.ansi)
                continue

            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(entries):
                    return [Path(entries[idx]["path"])]

            print(self.ansi.yellow("  Invalid selection."))
            _pause(self.ansi)

    def _pick_proxy_file(self, current: Path | None) -> Path | None:
        entries = discover_proxy_files(self.ws.proxies)
        print()
        if entries:
            print(
                render_dork_files_table(
                    entries,
                    cols=self._cols(),
                    ansi=self.ansi,
                    folder_label="workspace/proxies/",
                    count_label="Proxies",
                )
            )
        print(f"  {self.ansi.bold_cyan('[0]')} Direct IP (no proxies)")
        print(f"  {self.ansi.bold_cyan('[P]')} Custom proxy file path")
        ans = _prompt("Select proxy list", "0" if current is None else "P", ansi=self.ansi).strip()
        if ans == "0":
            return None
        if ans.lower() == "p":
            raw = _prompt("Proxy file path", str(current or ""), ansi=self.ansi)
            if raw:
                p = Path(raw).expanduser().resolve()
                return p if p.is_file() else current
            return current
        if ans.isdigit():
            idx = int(ans) - 1
            if 0 <= idx < len(entries):
                return Path(entries[idx]["path"])
        return current

    # -----------------------------------------------------------------------
    # Profile 1: FAST (Direct All-Engine — Minimal Rapid Prompts)
    # -----------------------------------------------------------------------
    def _wizard_fast(self) -> ProfileConfig | None:
        cfg = build_fast_profile(self.ws)
        files = self._pick_dork_files("FAST PROFILE · Step 1/2 · Select Dorks")
        if not files:
            return None
        cfg.input_files = files

        self._clear()
        cols = self._cols()
        total_q = sum(count_valid_queries(f) for f in files)
        print(
            render_header(
                "FAST PROFILE · Step 2/2 · Quick Options",
                [f"Direct All-Engine (6)", f"Queries: ({total_q})"],
                cols=cols,
                ansi=self.ansi,
            )
        )
        print()
        strict_exact = _prompt_yes_no(
            "Match exact dorks strictly (--no-relax + AST)? (No = allow relaxed variants)",
            default=True,
            ansi=self.ansi,
        )
        cfg.settings.enable_query_relaxation = not strict_exact
        cfg.settings.strict_ast_filter = strict_exact

        run_katana = _prompt_yes_no(
            "Run Katana schema crawler after search?",
            default=False,
            ansi=self.ansi,
        )
        cfg.settings.enable_crawl = run_katana
        if run_katana:
            doms = _prompt("Allowed crawl domains (comma-separated, blank=all)", "", ansi=self.ansi)
            if doms:
                cfg.settings.allowed_crawl_domains = [d.strip() for d in doms.split(",") if d.strip()]

        cfg.export_links_txt = _prompt_yes_no(
            "Export links-only .txt (1 URL per line)?",
            default=True,
            ansi=self.ansi,
        )
        return cfg

    # -----------------------------------------------------------------------
    # Profile 2: MEDIUM (Balanced Mode + Core Feature Toggles)
    # -----------------------------------------------------------------------
    def _wizard_medium(self) -> ProfileConfig | None:
        cfg = build_medium_profile(self.ws)
        files = self._pick_dork_files("MEDIUM PROFILE · Step 1/3 · Select Dorks")
        if not files:
            return None
        cfg.input_files = files

        # Step 2: Engine Mode (Direct / API / Hybrid) + Failover vs All-Engines
        self._clear()
        cols = self._cols()
        bp = layout_breakpoint(cols)
        print(render_header("MEDIUM PROFILE · Step 2/3 · Search Mode", ["Balanced"], cols=cols, ansi=self.ansi))
        print()
        if bp == "compact":
            print(f"  {self.ansi.bold_cyan('[1]')} Direct All (6 browser engines)")
            print(f"  {self.ansi.bold_cyan('[2]')} API / Federated (SearXNG, CSE, DDGS)")
            print(f"  {self.ansi.bold_cyan('[3]')} Hybrid (Direct + API · 8 engines)")
        else:
            print(f"  {self.ansi.bold_cyan('[1]')} Direct All (6 browser engines: Yahoo, DDG HTML/Lite, Google Web/Mobile/Basic)")
            print(f"  {self.ansi.bold_cyan('[2]')} API / Federated (SearXNG, Google CSE API, DDGS)")
            print(f"  {self.ansi.bold_cyan('[3]')} Hybrid (Direct + API combined — 8 engines)")
        print()
        mode_choice = _prompt("Engine mode", "3", ansi=self.ansi)
        if mode_choice == "1":
            cfg.settings.enabled_engines = list(DIRECT_ENGINES)
        elif mode_choice == "2":
            cfg.settings.enabled_engines = list(API_ENGINES)
        else:
            cfg.settings.enabled_engines = list(HYBRID_ENGINES)

        print()
        if bp == "compact":
            print(f"  {self.ansi.bold_cyan('[1]')} Smart Failover (Thompson)")
            print(f"  {self.ansi.bold_cyan('[2]')} All-Engines Matrix")
        else:
            print(f"  {self.ansi.bold_cyan('[1]')} Smart Failover (Thompson Sampling picks best engine per query)")
            print(f"  {self.ansi.bold_cyan('[2]')} All-Engines Matrix (query EVERY selected engine per dork)")
        exec_choice = _prompt("Dispatch mode", "1", ansi=self.ansi)
        cfg.all_engines_mode = exec_choice == "2"

        # Step 3: Core Feature Toggles
        while True:
            self._clear()
            cols = self._cols()
            s = cfg.settings
            print(
                render_header(
                    "MEDIUM PROFILE · Step 3/3 · Toggle Features",
                    [f"Engines: {len(s.enabled_engines)}", "all-engines" if cfg.all_engines_mode else "failover"],
                    cols=cols,
                    ansi=self.ansi,
                )
            )
            print()
            rows = [
                ["1", "AST Strict Filter (Boolean B={0,1})", "ON" if s.strict_ast_filter else "OFF"],
                ["2", "Query Relaxation (--allow-relax)", "ON" if s.enable_query_relaxation else "OFF"],
                ["3", "Thompson Sampling Bandit", "ON" if s.enable_thompson_sampling else "OFF"],
                ["4", "SQLite Persistent Cache", "ON" if s.enable_cache else "OFF"],
                ["5", "HTTP/2 -> HTTP/1.1 Fallback", "ON" if s.enable_http1_fallback else "OFF"],
                ["6", "Proxies File", s.proxies_file.name if s.proxies_file else "Direct IP"],
                ["7", "Katana Deep Crawl", "ON" if s.enable_crawl else "OFF"],
                ["8", "Export Links-Only (.txt, 1/line)", "ON" if cfg.export_links_txt else "OFF"],
                ["9", "Concurrency / Max Results / Depth", f"{s.concurrency} / {s.max_results_per_query} / {s.pagination_depth}"],
            ]
            print(
                render_table(
                    ["#", "Setting", "Value"],
                    rows,
                    cols=cols,
                    ansi=self.ansi,
                    alignments=["right", "left", "left"],
                    flex_cols={1},
                    cell_styler=lambda i, v: (
                        self.ansi.bold_cyan(v)
                        if i == 0
                        else (
                            self.ansi.bold_green(v)
                            if i == 2 and v == "ON"
                            else (self.ansi.dim(v) if i == 2 and v == "OFF" else v)
                        )
                    ),
                )
            )
            print()
            print(f"  {self.ansi.bold_green('[R]')} Run Search   {self.ansi.dim('[B] Back')}")
            ch = _prompt("Toggle [1-9] or Run [R]", "R", ansi=self.ansi).lower()
            if ch in ("b", "q"):
                return None
            if ch in ("r", "run", ""):
                return cfg
            if ch == "1":
                s.strict_ast_filter = not s.strict_ast_filter
            elif ch == "2":
                s.enable_query_relaxation = not s.enable_query_relaxation
            elif ch == "3":
                s.enable_thompson_sampling = not s.enable_thompson_sampling
            elif ch == "4":
                s.enable_cache = not s.enable_cache
            elif ch == "5":
                s.enable_http1_fallback = not s.enable_http1_fallback
            elif ch == "6":
                s.proxies_file = self._pick_proxy_file(s.proxies_file)
            elif ch == "7":
                s.enable_crawl = not s.enable_crawl
                if s.enable_crawl:
                    doms = _prompt("Allowed crawl domains (comma-separated)", ",".join(s.allowed_crawl_domains), ansi=self.ansi)
                    s.allowed_crawl_domains = [d.strip() for d in doms.split(",") if d.strip()]
            elif ch == "8":
                cfg.export_links_txt = not cfg.export_links_txt
            elif ch == "9":
                s.concurrency = _prompt_int("Concurrency (1-64)", s.concurrency, min_val=1, max_val=64, ansi=self.ansi)
                s.max_results_per_query = _prompt_int("Max results per query (1-200)", s.max_results_per_query, min_val=1, max_val=200, ansi=self.ansi)
                s.pagination_depth = _prompt_int("Pagination depth (1-5)", s.pagination_depth, min_val=1, max_val=5, ansi=self.ansi)

    # -----------------------------------------------------------------------
    # Profile 3: ADVANCED (Full 39-Parameter Control + TOML Presets)
    # -----------------------------------------------------------------------
    def _wizard_advanced(self) -> ProfileConfig | None:
        cfg = build_advanced_profile(self.ws)
        files = self._pick_dork_files("ADVANCED PROFILE · Step 1 · Select Dorks")
        if not files:
            return None
        cfg.input_files = files

        while True:
            self._clear()
            cols = self._cols()
            s = cfg.settings
            print(
                render_header(
                    "ADVANCED PROFILE · Full Config Control",
                    [f"Engines: {len(s.enabled_engines)}", "all-engines" if cfg.all_engines_mode else "failover"],
                    cols=cols,
                    ansi=self.ansi,
                )
            )
            print()
            menu = [
                ["1", "Engines & Dispatch Mode", f"{','.join(s.enabled_engines[:3])}{'…' if len(s.enabled_engines) > 3 else ''} ({len(s.enabled_engines)})"],
                ["2", "Math & Boolean AST Kernel", f"AST={s.strict_ast_filter} TS={s.enable_thompson_sampling} λ̄={s.poisson_mean_delay}s SH≤{s.simhash_max_hamming} J≥{s.jaccard_threshold}"],
                ["3", "Network, Rate-Limit & Proxies", f"conc={s.concurrency} rps={s.tokens_per_second} retries={s.max_retries} to={s.request_timeout}s"],
                ["4", "Circuit Breaker & Pagination", f"depth={s.pagination_depth} max={s.max_results_per_query} park={s.engine_park_seconds}s"],
                ["5", "SearXNG & Google Locale", f"searx={s.searxng_url or 'auto'} hl={cfg.google_hl} gl={cfg.google_gl}"],
                ["6", "Cache, Katana Crawl & Exports", f"cache={s.enable_cache} crawl={s.enable_crawl} links.txt={cfg.export_links_txt}"],
                ["L", "Load Saved TOML/YAML Preset", f"workspace/configs/"],
                ["P", "Save Current Preset (.toml)", "Reusable config"],
                ["C", "Preview Equivalent CLI Command", "Copy-pasteable search-v3"],
            ]
            print(
                render_table(
                    ["#", "Section", "Current"],
                    menu,
                    cols=cols,
                    ansi=self.ansi,
                    alignments=["right", "left", "left"],
                    flex_cols={2},
                    cell_styler=lambda i, v: self.ansi.bold_cyan(v) if i == 0 else v,
                )
            )
            print()
            print(f"  {self.ansi.bold_green('[R]')} Run Now   {self.ansi.dim('[B] Back')}")
            ch = _prompt("Section [1-6, L, P, C, R]", "R", ansi=self.ansi).lower()

            if ch in ("b", "q"):
                return None
            if ch in ("r", "run"):
                return cfg
            if ch == "1":
                self._adv_edit_engines(cfg)
            elif ch == "2":
                s.strict_ast_filter = _prompt_yes_no("Strict Boolean AST filter (Eval==1)?", s.strict_ast_filter, ansi=self.ansi)
                s.enable_query_relaxation = _prompt_yes_no("Enable query relaxation (--allow-relax)?", s.enable_query_relaxation, ansi=self.ansi)
                s.enable_thompson_sampling = _prompt_yes_no("Enable Thompson Sampling?", s.enable_thompson_sampling, ansi=self.ansi)
                s.poisson_mean_delay = _prompt_float("Poisson mean delay t_bar (seconds)", s.poisson_mean_delay, min_val=0.05, max_val=30.0, ansi=self.ansi)
                s.simhash_max_hamming = _prompt_int("SimHash max Hamming (0-64)", s.simhash_max_hamming, min_val=0, max_val=64, ansi=self.ansi)
                s.jaccard_threshold = _prompt_float("Jaccard threshold (0.0-1.0)", s.jaccard_threshold, min_val=0.0, max_val=1.0, ansi=self.ansi)
            elif ch == "3":
                s.concurrency = _prompt_int("Concurrency (1-64)", s.concurrency, min_val=1, max_val=64, ansi=self.ansi)
                s.queue_maxsize = _prompt_int("Queue maxsize", s.queue_maxsize, min_val=1, max_val=10000, ansi=self.ansi)
                s.tokens_per_second = _prompt_float("Tokens per second", s.tokens_per_second, min_val=0.1, max_val=100.0, ansi=self.ansi)
                s.jitter_min = _prompt_float("Jitter min (s)", s.jitter_min, min_val=0.0, max_val=30.0, ansi=self.ansi)
                s.jitter_max = _prompt_float("Jitter max (s)", max(s.jitter_min, s.jitter_max), min_val=s.jitter_min, max_val=60.0, ansi=self.ansi)
                s.max_retries = _prompt_int("Max retries (1-10)", s.max_retries, min_val=1, max_val=10, ansi=self.ansi)
                s.request_timeout = _prompt_float("Request timeout (s)", s.request_timeout, min_val=1.0, max_val=120.0, ansi=self.ansi)
                s.enable_http1_fallback = _prompt_yes_no("HTTP/2 -> HTTP/1.1 fallback?", s.enable_http1_fallback, ansi=self.ansi)
                s.proxies_file = self._pick_proxy_file(s.proxies_file)
                if s.proxies_file:
                    s.proxy_quarantine_seconds = _prompt_float("Proxy quarantine (s)", s.proxy_quarantine_seconds, min_val=1.0, max_val=3600.0, ansi=self.ansi)
                    s.proxy_probe_timeout = _prompt_float("Proxy probe timeout (s)", s.proxy_probe_timeout, min_val=0.5, max_val=30.0, ansi=self.ansi)
            elif ch == "4":
                s.pagination_depth = _prompt_int("Pagination depth (1-5)", s.pagination_depth, min_val=1, max_val=5, ansi=self.ansi)
                s.max_results_per_query = _prompt_int("Max results per query (1-200)", s.max_results_per_query, min_val=1, max_val=200, ansi=self.ansi)
                s.engine_park_bot_threshold = _prompt_int("Park bot threshold", s.engine_park_bot_threshold, min_val=1, max_val=20, ansi=self.ansi)
                s.engine_park_empty_threshold = _prompt_int("Park empty threshold", s.engine_park_empty_threshold, min_val=1, max_val=50, ansi=self.ansi)
                s.engine_park_seconds = _prompt_float("Park duration (s)", s.engine_park_seconds, min_val=10.0, max_val=3600.0, ansi=self.ansi)
            elif ch == "5":
                raw_url = _prompt("SearXNG URL (blank = auto-discover)", s.searxng_url or "", ansi=self.ansi)
                s.searxng_url = raw_url or None
                s.searxng_host = _prompt("SearXNG host", s.searxng_host, ansi=self.ansi)
                s.searxng_engines = _prompt("SearXNG sub-engines", s.searxng_engines, ansi=self.ansi)
                cfg.google_hl = _prompt("Google interface language (hl)", cfg.google_hl, ansi=self.ansi)
                cfg.google_gl = _prompt("Google geolocation country (gl)", cfg.google_gl, ansi=self.ansi)
            elif ch == "6":
                s.enable_cache = _prompt_yes_no("Enable SQLite cache?", s.enable_cache, ansi=self.ansi)
                if s.enable_cache:
                    s.cache_ttl_seconds = _prompt_int("Cache TTL (seconds)", s.cache_ttl_seconds, min_val=0, max_val=31536000, ansi=self.ansi)
                s.enable_crawl = _prompt_yes_no("Enable Katana Tier 4 crawl?", s.enable_crawl, ansi=self.ansi)
                if s.enable_crawl:
                    s.crawl_depth = _prompt_int("Crawl depth (1-5)", s.crawl_depth, min_val=1, max_val=5, ansi=self.ansi)
                    s.crawl_rate_limit_rps = _prompt_int("Crawl rate limit (req/s)", s.crawl_rate_limit_rps, min_val=1, max_val=100, ansi=self.ansi)
                    s.crawl_concurrency = _prompt_int("Crawl concurrency", s.crawl_concurrency, min_val=1, max_val=32, ansi=self.ansi)
                    s.crawl_timeout_seconds = _prompt_int("Crawl timeout (s)", s.crawl_timeout_seconds, min_val=5, max_val=600, ansi=self.ansi)
                    doms = _prompt("Allowed crawl domains (comma-separated)", ",".join(s.allowed_crawl_domains), ansi=self.ansi)
                    s.allowed_crawl_domains = [d.strip() for d in doms.split(",") if d.strip()]
                cfg.export_links_txt = _prompt_yes_no("Export links-only .txt (1 URL/line)?", cfg.export_links_txt, ansi=self.ansi)
                cfg.export_json = _prompt_yes_no("Export full JSON?", cfg.export_json, ansi=self.ansi)
                cfg.export_markdown = _prompt_yes_no("Export per-dork Markdown report?", cfg.export_markdown, ansi=self.ansi)
                cfg.export_log = _prompt_yes_no("Save live log file?", cfg.export_log, ansi=self.ansi)
                s.debug = _prompt_yes_no("Enable DEBUG logging?", s.debug, ansi=self.ansi)
            elif ch == "p":
                name = _prompt("Preset name (saved in workspace/configs/)", "custom", ansi=self.ansi)
                clean_name = "".join(c for c in name if c.isalnum() or c in ("-", "_")) or "custom"
                saved = save_profile_toml(s, self.ws.configs / f"{clean_name}.toml")
                print(f"  {self.ansi.green('Saved:')} {saved}")
                _pause(self.ansi)
            elif ch == "l":
                presets = sorted(
                    list(self.ws.configs.glob("*.toml"))
                    + list(self.ws.configs.glob("*.yaml"))
                    + list(self.ws.configs.glob("*.yml"))
                )
                if not presets:
                    print(self.ansi.yellow(f"  No saved configs in {self.ws.configs}"))
                    _pause(self.ansi)
                else:
                    for idx, p in enumerate(presets, 1):
                        print(f"  [{idx}] {p.name}")
                    pick = _prompt("Load preset #", "1", ansi=self.ansi)
                    if pick.isdigit() and 1 <= int(pick) <= len(presets):
                        cfg.settings = load_profile_toml(presets[int(pick) - 1])
                        cfg.settings.enable_tui = False
                        print(f"  {self.ansi.green('Loaded:')} {presets[int(pick) - 1].name}")
                        _pause(self.ansi)
            elif ch == "c":
                print("\n" + self.ansi.cyan(build_equivalent_cli_command(cfg)))
                _pause(self.ansi)

    def _adv_edit_engines(self, cfg: ProfileConfig) -> None:
        selected = set(cfg.settings.enabled_engines)
        while True:
            self._clear()
            cols = self._cols()
            print(render_header("ADVANCED · Engines & Dispatch Mode", [], cols=cols, ansi=self.ansi))
            print()
            rows = [
                [str(i), name, desc, "ON" if name in selected else "OFF"]
                for i, (name, desc) in enumerate(ALL_SELECTABLE_ENGINES, 1)
            ]
            print(
                render_table(
                    ["#", "Engine", "Description", "State"],
                    rows,
                    cols=cols,
                    ansi=self.ansi,
                    alignments=["right", "left", "left", "left"],
                    flex_cols={2},
                    cell_styler=lambda i, v: (
                        self.ansi.bold_cyan(v)
                        if i == 0
                        else (
                            self.ansi.bold_green(v)
                            if i == 3 and v == "ON"
                            else (self.ansi.dim(v) if i == 3 and v == "OFF" else v)
                        )
                    ),
                )
            )
            print()
            print(
                f"  Mode: {self.ansi.bold_cyan('ALL-ENGINES' if cfg.all_engines_mode else 'FAILOVER')}  "
                f"([M] Switch Mode · [D] Direct Preset · [H] Hybrid Preset · [0] Done)"
            )
            ans = _prompt("Toggle [1-10], [M/D/H], or [0] Done", "0", ansi=self.ansi).lower()
            if ans in ("0", "done", ""):
                if selected:
                    cfg.settings.enabled_engines = [
                        n for n, _ in ALL_SELECTABLE_ENGINES if n in selected
                    ]
                return
            if ans == "m":
                cfg.all_engines_mode = not cfg.all_engines_mode
            elif ans == "d":
                selected = set(DIRECT_ENGINES)
            elif ans == "h":
                selected = set(HYBRID_ENGINES)
            elif ans.isdigit():
                idx = int(ans) - 1
                if 0 <= idx < len(ALL_SELECTABLE_ENGINES):
                    ename = ALL_SELECTABLE_ENGINES[idx][0]
                    if ename in selected:
                        selected.remove(ename)
                    else:
                        selected.add(ename)

    # -----------------------------------------------------------------------
    # Execution Engine + Post-Run Export Menu
    # -----------------------------------------------------------------------
    def _execute_profile(self, cfg: ProfileConfig) -> None:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        total_q = sum(count_valid_queries(f) for f in cfg.input_files)
        input_label = (
            cfg.input_files[0].name
            if len(cfg.input_files) == 1
            else f"{len(cfg.input_files)} files"
        )

        json_out = self.ws.exports_json / f"{run_id}_{cfg.profile_name}.json"
        links_out = self.ws.exports_links / f"{run_id}_{cfg.profile_name}_links.txt"
        md_out = self.ws.exports_reports / f"{run_id}_{cfg.profile_name}_report.md"
        log_out = (self.ws.logs / f"{run_id}_{cfg.profile_name}.log") if cfg.export_log else None
        if cfg.settings.enable_crawl and cfg.settings.crawl_output_path is None:
            cfg.settings.crawl_output_path = (
                self.ws.exports_crawl / f"{run_id}_{cfg.profile_name}_crawl.jsonl"
            )

        _configure_file_only_logging(log_out, cfg.settings.debug)

        tracker = RunStatusTracker(
            self.ws,
            run_id=run_id,
            profile=cfg.profile_name,
            mode="all_engines" if cfg.all_engines_mode else "failover",
            input_label=input_label,
            total_queries=total_q,
            render_live=True,
            ansi=self.ansi,
        )

        google_cfg = GoogleSuiteConfig.from_env().model_copy(
            update={
                "max_retries": cfg.settings.max_retries,
                "locale": GoogleLocaleConfig(hl=cfg.google_hl, gl=cfg.google_gl),
            }
        )
        orch = SearchOrchestrator(
            cfg.settings,
            google_config=google_cfg,
            telemetry_sink=tracker,
        )

        output_obj: PipelineOutput | AllEnginesMatrixOutput | None = None
        final_state: str = "completed"
        try:
            if cfg.all_engines_mode:
                tracker.start()
                output_obj = asyncio.run(
                    orch.execute_all_engines_matrix(
                        _stream_multiple_files(cfg.input_files),
                        on_query_done=tracker.record_matrix_query_done,
                    )
                )
            else:
                output_obj = asyncio.run(
                    orch.execute_stream(
                        _stream_multiple_files(cfg.input_files),
                        total_hint=total_q,
                    )
                )
        except KeyboardInterrupt:
            final_state = "stopped"
            print(f"\n  {self.ansi.bold_yellow('Interrupted by user.')}")
        except Exception as exc:
            final_state = "failed"
            print(f"\n  {self.ansi.bold_red(f'Run error: {exc}')}")

        saved_exports: dict[str, str] = {}
        if output_obj is not None:
            if cfg.export_json:
                json_out.write_text(output_obj.model_dump_json(indent=2) + "\n", encoding="utf-8")
                saved_exports["json"] = str(json_out)
            if cfg.export_links_txt:
                export_links_only_txt(output_obj, links_out)
                saved_exports["links_txt"] = str(links_out)
            if cfg.export_markdown and isinstance(output_obj, AllEnginesMatrixOutput):
                export_all_engines_links_report(output_obj, md_out)
                saved_exports["markdown"] = str(md_out)
            if log_out is not None:
                saved_exports["log"] = str(log_out)

            total_links = (
                output_obj.total_verified_links
                if isinstance(output_obj, AllEnginesMatrixOutput)
                else output_obj.total_results
            )
            total_drop = (
                output_obj.total_ast_dropped
                if isinstance(output_obj, AllEnginesMatrixOutput)
                else output_obj.ast_dropped_results
            )
            is_matrix = isinstance(output_obj, AllEnginesMatrixOutput)
            tracker.finalize(
                state="completed",
                done_queries=output_obj.total_queries if is_matrix else None,
                total_queries=output_obj.total_queries if is_matrix else None,
                total_verified_links=total_links,
                total_ast_dropped=total_drop,
                engine_metrics=output_obj.engine_metrics,
                export_paths=saved_exports,
            )
            self._post_run_menu(output_obj, run_id, saved_exports)
        else:
            tracker.finalize(
                state="stopped" if final_state == "stopped" else "failed",
                export_paths={"log": str(log_out)} if log_out else {},
            )
            _pause(self.ansi)

    def _post_run_menu(
        self,
        output_obj: PipelineOutput | AllEnginesMatrixOutput,
        run_id: str,
        saved_exports: dict[str, str],
    ) -> None:
        while True:
            self._clear()
            cols = self._cols()
            total_links = (
                output_obj.total_verified_links
                if isinstance(output_obj, AllEnginesMatrixOutput)
                else output_obj.total_results
            )
            total_drop = (
                output_obj.total_ast_dropped
                if isinstance(output_obj, AllEnginesMatrixOutput)
                else output_obj.ast_dropped_results
            )
            print(
                render_header(
                    f"RUN COMPLETE · {run_id}",
                    [
                        f"Verified: {total_links}",
                        f"AST Drop: {total_drop}",
                        f"Time: {output_obj.elapsed_seconds}s",
                    ],
                    cols=cols,
                    ansi=self.ansi,
                )
            )
            print()
            print(
                render_engine_metrics_table(
                    [m.model_dump() for m in output_obj.engine_metrics],
                    cols=cols,
                    ansi=self.ansi,
                )
            )
            print()
            for label, path_str in saved_exports.items():
                print(
                    f"  {self.ansi.green('✓')} {label:10s}: "
                    f"{self.ansi.dim(truncate_visible(path_str, max(20, cols - 18)))}"
                )
            print()
            if layout_breakpoint(cols) == "compact":
                print(f"  {self.ansi.bold_cyan('[1]')} Export Links-Only .txt")
                print(f"  {self.ansi.bold_cyan('[2]')} Preview Links")
                print(f"  {self.ansi.bold_cyan('[3]')} Top Domains (jq)")
                print(f"  {self.ansi.dim('[0]')} Main Menu")
            else:
                print(
                    f"  {self.ansi.bold_cyan('[1]')} Export Links-Only .txt (custom path)   "
                    f"{self.ansi.bold_cyan('[2]')} Preview Links"
                )
                print(
                    f"  {self.ansi.bold_cyan('[3]')} Top Domains (jq table)               "
                    f"{self.ansi.dim('[0] Main Menu')}"
                )
            ch = _prompt("Action", "0", ansi=self.ansi).lower()
            if ch in ("0", "b", "q", ""):
                return
            if ch == "1":
                default_p = str(self.ws.exports_links / f"{run_id}_custom_links.txt")
                dest = Path(_prompt("Destination .txt path", default_p, ansi=self.ansi)).expanduser()
                cnt = export_links_only_txt(output_obj, dest)
                print(f"  {self.ansi.bold_green(f'Saved {cnt} unique links (1/line) -> {dest}')}")
                _pause(self.ansi)
            elif ch == "2":
                urls = extract_unique_urls_with_jq(output_obj)
                print()
                for idx, u in enumerate(urls[:30], 1):
                    print(f"  {self.ansi.dim(f'{idx:2d}.')} {truncate_visible(u, max(24, cols - 8))}")
                if len(urls) > 30:
                    print(self.ansi.dim(f"  ... +{len(urls) - 30} more links"))
                _pause(self.ansi)
            elif ch == "3":
                print()
                doms = [d.model_dump() for d in output_obj.top_domains]
                if doms:
                    print(render_domains_table(doms, cols=cols, ansi=self.ansi))
                else:
                    print(self.ansi.dim("  No domains recorded."))
                _pause(self.ansi)

    # -----------------------------------------------------------------------
    # Exports Browser (Re-Export Any Saved JSON Run into links.txt via jq)
    # -----------------------------------------------------------------------
    def _exports_browser(self) -> None:
        while True:
            self._clear()
            cols = self._cols()
            print(render_header("EXPORTS BROWSER", [f"jq: {jq_version()}"], cols=cols, ansi=self.ansi))
            print()
            json_files = sorted(self.ws.exports_json.glob("*.json"), reverse=True)[:15]
            if not json_files:
                print(self.ansi.dim(f"  No exported JSON runs in {self.ws.exports_json}"))
                _pause(self.ansi)
                return

            rows = [
                [str(i), f.name, f"{f.stat().st_size / 1024:.1f} KB"]
                for i, f in enumerate(json_files, 1)
            ]
            print(
                render_table(
                    ["#", "Saved JSON Run", "Size"],
                    rows,
                    cols=cols,
                    ansi=self.ansi,
                    alignments=["right", "left", "right"],
                    flex_cols={1},
                    cell_styler=lambda i, v: self.ansi.bold_cyan(v) if i == 0 else v,
                )
            )
            print()
            ans = _prompt("Select run # to export links.txt (or [B] Back)", "B", ansi=self.ansi).lower()
            if ans in ("b", "q", "0", ""):
                return
            if ans.isdigit() and 1 <= int(ans) <= len(json_files):
                chosen = json_files[int(ans) - 1]
                dest = self.ws.exports_links / f"{chosen.stem}_links.txt"
                cnt = export_links_only_txt(chosen, dest)
                print(f"  {self.ansi.bold_green(f'Exported {cnt} unique links (1/line) -> {dest}')}")
                try:
                    payload = json.loads(chosen.read_text(encoding="utf-8"))
                    doms = payload.get("top_domains") or []
                    if doms:
                        print()
                        print(render_domains_table(doms, cols=cols, ansi=self.ansi, limit=8))
                except Exception:
                    pass
                _pause(self.ansi)

    # -----------------------------------------------------------------------
    # Main Loop
    # -----------------------------------------------------------------------
    def run(self) -> int:
        self._searxng_label = self._probe_searxng_once()
        try:
            while True:
                self._clear()
                cols = self._cols()
                active = load_active_status(self.ws)
                run_tag = (
                    f"Run: {active.get('state', 'idle')}"
                    if active is not None
                    else "Run: idle"
                )
                print(
                    render_header(
                        "SEARCH-V3",
                        [f"SearXNG: {self._searxng_label}", f"{jq_version()}", run_tag],
                        cols=cols,
                        ansi=self.ansi,
                    )
                )
                bp = layout_breakpoint(cols)
                print()
                print(f"  {self.ansi.bold('Profiles')}")
                if bp == "compact":
                    print(f"    {self.ansi.bold_cyan('[1]')} {self.ansi.bold('Fast')}     Direct All-Engine")
                    print(f"    {self.ansi.bold_cyan('[2]')} {self.ansi.bold('Medium')}   Balanced + Toggles")
                    print(f"    {self.ansi.bold_cyan('[3]')} {self.ansi.bold('Advanced')} Full 39-Param Control")
                    print()
                    print(f"  {self.ansi.bold('Tools')}")
                    print(f"    {self.ansi.bold_cyan('[S]')} Status   Live + History (jq)")
                    print(f"    {self.ansi.bold_cyan('[E]')} Exports  Links-Only .txt")
                    print(f"    {self.ansi.dim('[Q]')} Quit")
                else:
                    print(f"    {self.ansi.bold_cyan('[1]')} {self.ansi.bold('Fast')}      Direct All-Engine · minimal prompts · full kernel")
                    print(f"    {self.ansi.bold_cyan('[2]')} {self.ansi.bold('Medium')}    Direct/API/Hybrid · toggle AST, Cache, Proxy, Katana")
                    print(f"    {self.ansi.bold_cyan('[3]')} {self.ansi.bold('Advanced')}  All 39 parameters · TOML presets · CLI preview")
                    print()
                    print(f"  {self.ansi.bold('Tools')}")
                    print(f"    {self.ansi.bold_cyan('[S]')} Status    Live run state + history (jq tables)")
                    print(f"    {self.ansi.bold_cyan('[E]')} Exports   Extract links-only .txt (1 URL/line) from runs")
                    print(f"    {self.ansi.dim('[Q]')} Quit")
                print()
                print(horizontal_rule(min(cols, 76), self.ansi))

                choice = _prompt("Select [1-3, S, E, Q]", "", ansi=self.ansi).lower()
                if choice in ("q", "quit", "exit"):
                    return 0
                if choice == "1":
                    cfg = self._wizard_fast()
                    if cfg is not None:
                        self._execute_profile(cfg)
                elif choice == "2":
                    cfg = self._wizard_medium()
                    if cfg is not None:
                        self._execute_profile(cfg)
                elif choice == "3":
                    cfg = self._wizard_advanced()
                    if cfg is not None:
                        self._execute_profile(cfg)
                elif choice == "s":
                    self._clear()
                    print(render_status_view(self.ws, cols=self._cols(), ansi=self.ansi))
                    _pause(self.ansi)
                elif choice == "e":
                    self._exports_browser()
        except _TUIExit:
            return 0


def run_tui(workspace_root: Path | None = None) -> int:
    """Entrypoint launching the embedded Pure-ANSI + jq interactive TUI."""
    app = SearchV3TUI(workspace_root=workspace_root)
    return app.run()
