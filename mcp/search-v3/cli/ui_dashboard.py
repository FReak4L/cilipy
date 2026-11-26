"""Optional Rich live terminal observability dashboard displaying Thompson Sampling telemetry."""

from __future__ import annotations

import time
from collections import Counter, deque
from collections.abc import Sequence

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from core.models import EngineMetrics, ProxyPoolStats, SearchResult
from transport.http_client import extract_root_domain


class PipelineDashboard:
    """Real-time terminal observability dashboard built with `rich.live.Live`."""

    def __init__(
        self,
        total_queries: int | None = None,
        enabled: bool = True,
        max_rows: int = 16,
    ) -> None:
        self._console = Console(stderr=True)
        self.enabled = enabled and self._console.is_terminal
        self._started_at = time.perf_counter()
        self._processed_queries = 0
        self._cache_hits = 0
        self._relaxed_hits = 0
        self._searxng_status = "Probing..."
        self._proxy_stats = ProxyPoolStats()
        self._engine_metrics: list[EngineMetrics] = []
        self._domain_counter: Counter[str] = Counter()
        self._recent_rows: deque[tuple[str, str, str, str]] = deque(maxlen=max_rows)
        self._live: Live | None = None

        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self._console,
            expand=True,
        )
        self._task_id: TaskID = self._progress.add_task(
            "Processing queries", total=total_queries
        )

    def start(self) -> None:
        if not self.enabled:
            return
        self._live = Live(
            self._render(),
            console=self._console,
            refresh_per_second=6,
            transient=False,
        )
        self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            self._live.update(self._render())
            self._live.stop()
            self._live = None

    def set_searxng_status(self, status: str) -> None:
        self._searxng_status = status
        self._refresh()

    def set_total_queries(self, total: int) -> None:
        self._progress.update(self._task_id, total=total)
        self._refresh()

    def update_proxy_stats(self, stats: ProxyPoolStats) -> None:
        self._proxy_stats = stats
        self._refresh()

    def update_engine_metrics(self, metrics: Sequence[EngineMetrics]) -> None:
        self._engine_metrics = list(metrics)
        self._refresh()

    def record_query_completed(
        self,
        query: str,
        results: Sequence[SearchResult],
        from_cache: bool,
        relaxed: bool = False,
    ) -> None:
        self._processed_queries += 1
        if from_cache:
            self._cache_hits += 1
        if relaxed:
            self._relaxed_hits += 1
        self._progress.advance(self._task_id, 1)

        for item in results:
            root_dom = extract_root_domain(item.url)
            if root_dom:
                self._domain_counter[root_dom] += 1

        for item in results[:5]:
            status_tag = "CACHE" if from_cache else ("RELAX" if relaxed else "200 OK")
            self._recent_rows.appendleft(
                (item.engine, status_tag, item.url[:76], query[:30])
            )
        self._refresh()

    def _refresh(self) -> None:
        if self._live is not None:
            self._live.update(self._render())

    def _render(self) -> Layout:
        elapsed = max(0.001, time.perf_counter() - self._started_at)
        qps = self._processed_queries / elapsed

        ps = self._proxy_stats
        engine_badges: list[str] = []
        for em in self._engine_metrics:
            if em.parked:
                engine_badges.append(f"[red]{em.engine}:PARKED[/red]")
            else:
                mean_pct = int(em.thompson_posterior_mean * 100)
                color = "green" if mean_pct >= 65 else ("yellow" if mean_pct >= 35 else "red")
                engine_badges.append(
                    f"[{color}]{em.engine}:θ={mean_pct}%[/{color}]"
                )
        engines_summary = " ".join(engine_badges) if engine_badges else "Initializing..."

        metrics_text = (
            f"[bold]SearXNG:[/bold] {self._searxng_status}   "
            f"[bold]Proxies:[/bold] healthy={ps.healthy}/{ps.total_loaded} "
            f"(quar={ps.quarantined}, ewma={ps.avg_ewma_latency_ms:.0f}ms)   "
            f"[bold]Cache:[/bold] {self._cache_hits}  "
            f"[bold]Relaxed:[/bold] {self._relaxed_hits}  "
            f"[bold]QPS:[/bold] [magenta]{qps:.2f}[/magenta]\n"
            f"[bold]Bandit Posteriors:[/bold] {engines_summary}"
        )
        metrics_panel = Panel(
            metrics_text,
            title="Search Pipeline v3 Telemetry & Thompson Sampling",
            border_style="bright_blue",
        )

        progress_panel = Panel(
            self._progress,
            title="Batch Queue Throughput",
            border_style="cyan",
        )

        stream_table = Table(expand=True, show_lines=False, box=None)
        stream_table.add_column("Engine", style="bold green", width=20, no_wrap=True)
        stream_table.add_column("Tag", style="cyan", width=7, no_wrap=True)
        stream_table.add_column("Discovered URL", style="white", overflow="fold")
        stream_table.add_column("Query", style="dim", width=28, no_wrap=True)

        for engine_name, status_tag, url, query_label in self._recent_rows:
            stream_table.add_row(engine_name, status_tag, url, query_label)

        results_panel = Panel(
            stream_table,
            title=f"Discovered URL Stream (Processed: {self._processed_queries})",
            border_style="green",
        )

        dom_table = Table(expand=True, show_lines=False, box=None)
        dom_table.add_column("Root Domain", style="bold yellow", overflow="fold")
        dom_table.add_column("Hits", style="cyan", justify="right", width=6)
        for dom, count in self._domain_counter.most_common(12):
            dom_table.add_row(dom, str(count))

        domains_panel = Panel(
            dom_table,
            title=f"Top Domains ({len(self._domain_counter)} unique)",
            border_style="yellow",
        )

        bottom_split = Layout()
        bottom_split.split_row(
            Layout(results_panel, ratio=3),
            Layout(domains_panel, ratio=1),
        )

        layout = Layout()
        layout.split_column(
            Layout(metrics_panel, size=4),
            Layout(progress_panel, size=4),
            bottom_split,
        )
        return layout
