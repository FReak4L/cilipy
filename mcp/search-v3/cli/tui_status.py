"""Atomic run status tracker (.active_run.json + run_history.jsonl) and minimalist live ANSI sink."""

from __future__ import annotations

import json
import os
import sys
import time
from collections import deque
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from cli.tui_ansi import (
    Ansi,
    cursor_home,
    get_screen_size,
    layout_breakpoint,
    render_header,
    render_progress_bar,
    truncate_visible,
)
from cli.tui_exporters import WorkspacePaths
from cli.tui_tables import render_engine_metrics_table
from core.models import EngineMetrics, ProxyPoolStats, QueryAllEnginesRecord, SearchResult


def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp_path, path)


def load_active_status(ws: WorkspacePaths) -> dict[str, Any] | None:
    """Read `.active_run.json` and auto-classify dead PIDs as `stale (exited)`."""
    if not ws.active_run_file.is_file():
        return None
    try:
        data = json.loads(ws.active_run_file.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if data.get("state") == "running":
        pid = int(data.get("pid") or 0)
        if not is_pid_alive(pid):
            data["state"] = "stale (exited)"
    return data


def load_run_history(ws: WorkspacePaths, limit: int = 8) -> list[dict[str, Any]]:
    if not ws.run_history_file.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in ws.run_history_file.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                rows.append(obj)
        except json.JSONDecodeError:
            continue
    return list(reversed(rows[-limit:]))


class RunStatusTracker:
    """
    Implements `TelemetrySink` for Failover runs AND live progress hooks for
    `--all-engines` matrix runs:
      - Persists live atomic JSON state to `workspace/logs/.active_run.json`
      - Appends final summary to `workspace/logs/run_history.jsonl`
      - Optionally renders a minimalist, zero-library responsive Pure-ANSI live dashboard
    """

    def __init__(
        self,
        ws: WorkspacePaths,
        *,
        run_id: str,
        profile: str,
        mode: Literal["failover", "all_engines"],
        input_label: str,
        total_queries: int = 0,
        render_live: bool = True,
        ansi: Ansi | None = None,
    ) -> None:
        self.ws = ws
        self.run_id = run_id
        self.profile = profile
        self.mode = mode
        self.input_label = input_label
        self.total_queries = total_queries
        self.render_live = render_live and bool(getattr(sys.stdout, "isatty", lambda: False)())
        self.ansi = ansi or Ansi()

        self._started_mono = time.perf_counter()
        self._started_iso = datetime.now(timezone.utc).isoformat()
        self._done_queries = 0
        self._verified_links = 0
        self._ast_dropped = 0
        self._cache_hits = 0
        self._searxng_status = "Checking..."
        self._proxy_stats = ProxyPoolStats()
        self._engine_metrics: list[EngineMetrics] = []
        self._recent_hits: deque[tuple[str, str]] = deque(maxlen=5)
        self._last_draw = 0.0
        self._state: str = "running"

    def _build_snapshot(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "pid": os.getpid(),
            "state": self._state,
            "profile": self.profile,
            "mode": self.mode,
            "input": self.input_label,
            "started_at": self._started_iso,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(time.perf_counter() - self._started_mono, 2),
            "done_queries": self._done_queries,
            "total_queries": self.total_queries,
            "verified_links": self._verified_links,
            "ast_dropped": self._ast_dropped,
            "cache_hits": self._cache_hits,
            "searxng_status": self._searxng_status,
            "proxy_stats": self._proxy_stats.model_dump(),
            "engine_metrics": [m.model_dump() for m in self._engine_metrics],
        }

    def _persist(self) -> None:
        try:
            _atomic_write_json(self.ws.active_run_file, self._build_snapshot())
        except Exception:
            pass

    def _draw(self, *, force: bool = False) -> None:
        if not self.render_live:
            return
        now = time.perf_counter()
        if not force and (now - self._last_draw) < 0.25:
            return
        self._last_draw = now

        cols, _ = get_screen_size()
        bp = layout_breakpoint(cols)
        elapsed = int(now - self._started_mono)
        mins, secs = divmod(elapsed, 60)
        elapsed_str = f"{mins:02d}:{secs:02d}"

        header = render_header(
            f"RUN {self.run_id}",
            [f"Profile: {self.profile.upper()}", self.mode, elapsed_str],
            cols=cols,
            ansi=self.ansi,
        )
        bar = render_progress_bar(
            self._done_queries,
            max(self.total_queries, self._done_queries, 1),
            width=18 if bp == "compact" else 28,
            ansi=self.ansi,
        )
        stats_line = (
            f"{bar}  "
            f"Hits: {self.ansi.bold_green(str(self._verified_links))}  "
            f"Drop: {self.ansi.dim(str(self._ast_dropped))}"
        )
        if bp != "compact" and self._proxy_stats.total_loaded > 0:
            stats_line += (
                f"  Proxies: {self._proxy_stats.healthy}/{self._proxy_stats.total_loaded}"
            )

        parts = [cursor_home(), header, "", stats_line, ""]
        if self._engine_metrics:
            parts.append(
                render_engine_metrics_table(
                    [m.model_dump() for m in self._engine_metrics],
                    cols=cols,
                    ansi=self.ansi,
                )
            )

        if self._recent_hits and bp != "compact":
            parts.append("")
            parts.append(self.ansi.dim("Recent Verified Links:"))
            max_url_w = max(24, min(cols, 118) - 22)
            for eng, url in self._recent_hits:
                parts.append(
                    f"  {self.ansi.cyan('•')} {self.ansi.dim(f'[{eng}]')} "
                    f"{truncate_visible(url, max_url_w)}"
                )

        parts.append("")
        parts.append(self.ansi.dim("Ctrl+C: Stop safely & export partial results"))
        sys.stdout.write("\n".join(parts) + "\n")
        sys.stdout.flush()

    # --- TelemetrySink interface ---
    def start(self) -> None:
        self._state = "running"
        self._persist()
        self._draw(force=True)

    def stop(self) -> None:
        self._draw(force=True)

    def finalize(
        self,
        *,
        state: Literal["completed", "stopped", "failed"],
        done_queries: int | None = None,
        total_queries: int | None = None,
        total_verified_links: int | None = None,
        total_ast_dropped: int | None = None,
        engine_metrics: Sequence[EngineMetrics] | None = None,
        export_paths: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self._state = state
        if done_queries is not None:
            self._done_queries = done_queries
        if total_queries is not None:
            self.total_queries = total_queries
        if total_verified_links is not None:
            self._verified_links = total_verified_links
        if total_ast_dropped is not None:
            self._ast_dropped = total_ast_dropped
        if engine_metrics is not None:
            self._engine_metrics = list(engine_metrics)

        snap = self._build_snapshot()
        if export_paths:
            snap["exports"] = export_paths
        _atomic_write_json(self.ws.active_run_file, snap)

        # Append compact history entry
        hist_entry = {
            "run_id": snap["run_id"],
            "profile": snap["profile"],
            "mode": snap["mode"],
            "state": snap["state"],
            "input": snap["input"],
            "done_queries": snap["done_queries"],
            "total_queries": snap["total_queries"],
            "verified_links": snap["verified_links"],
            "ast_dropped": snap["ast_dropped"],
            "elapsed_seconds": snap["elapsed_seconds"],
            "exports": export_paths or {},
        }
        self.ws.run_history_file.parent.mkdir(parents=True, exist_ok=True)
        with self.ws.run_history_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(hist_entry, ensure_ascii=False) + "\n")
        return snap

    def set_searxng_status(self, status: str) -> None:
        self._searxng_status = status
        self._persist()

    def set_total_queries(self, total: int) -> None:
        self.total_queries = total
        self._persist()
        self._draw()

    def update_proxy_stats(self, stats: ProxyPoolStats) -> None:
        self._proxy_stats = stats

    def update_engine_metrics(self, metrics: Sequence[EngineMetrics]) -> None:
        self._engine_metrics = list(metrics)
        self._persist()
        self._draw()

    def record_query_completed(
        self,
        query: str,
        results: Sequence[SearchResult],
        from_cache: bool,
        relaxed: bool = False,
    ) -> None:
        self._done_queries += 1
        self._verified_links += len(results)
        if from_cache:
            self._cache_hits += 1
        for item in results[:2]:
            self._recent_hits.appendleft((item.engine, item.url))
        self._persist()
        self._draw()

    def record_matrix_query_done(
        self,
        record: QueryAllEnginesRecord,
        metrics: Sequence[EngineMetrics],
    ) -> None:
        self._done_queries += 1
        self._verified_links += record.unique_verified_count
        self._ast_dropped += record.total_ast_dropped
        self._engine_metrics = list(metrics)
        for item in record.merged_links[:2]:
            self._recent_hits.appendleft((item.engine, item.url))
        self._persist()
        self._draw()
