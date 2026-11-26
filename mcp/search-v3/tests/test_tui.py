"""Unit & integration tests for the zero-library Pure-ANSI + jq TUI, profiles, status & exporters."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cli.main import parse_cli_args
from cli.tui_ansi import (
    Ansi,
    layout_breakpoint,
    render_header,
    render_progress_bar,
    strip_ansi,
    visible_len,
)
from cli.tui_app import SearchV3TUI, render_status_view
from cli.tui_exporters import (
    discover_dork_files,
    ensure_workspace,
    export_links_only_txt,
    extract_unique_urls_with_jq,
)
from cli.tui_profiles import (
    DIRECT_ENGINES,
    build_advanced_profile,
    build_equivalent_cli_command,
    build_fast_profile,
    build_medium_profile,
    load_profile_toml,
    save_profile_toml,
)
from cli.tui_status import RunStatusTracker, load_active_status, load_run_history
from cli.tui_tables import (
    has_jq,
    render_domains_table,
    render_dork_files_table,
    render_engine_metrics_table,
    render_status_history_table,
)
from core.models import (
    AllEnginesMatrixOutput,
    EngineMetrics,
    EngineQueryOutcome,
    PipelineOutput,
    QueryAllEnginesRecord,
    SearchResult,
)


class TestPureAnsiAndResponsiveJqTables(unittest.TestCase):
    """Verify Pure-ANSI styling (zero UI libraries) and overflow-free `jq` tables at all sizes."""

    def test_ansi_colors_no_color_and_breakpoints(self) -> None:
        a_on = Ansi(enabled=True)
        colored = a_on.bold_cyan("SEARCH-V3")
        self.assertIn("\x1b[1;36m", colored)
        self.assertEqual(strip_ansi(colored), "SEARCH-V3")
        self.assertEqual(visible_len(colored), 9)

        a_off = Ansi(enabled=False)
        self.assertEqual(a_off.bold_cyan("SEARCH-V3"), "SEARCH-V3")

        self.assertEqual(layout_breakpoint(48), "compact")
        self.assertEqual(layout_breakpoint(84), "standard")
        self.assertEqual(layout_breakpoint(130), "wide")

        for width in (45, 80, 130):
            hdr = render_header("SEARCH-V3", ["SearXNG: UP", "jq-1.7"], cols=width, ansi=a_on)
            for line in hdr.splitlines():
                self.assertLessEqual(visible_len(line), width)

            bar = render_progress_bar(42, 100, width=20, ansi=a_on)
            self.assertIn("42/100 (42%)", strip_ansi(bar))

    def test_jq_tables_fit_all_screen_widths_without_overflow(self) -> None:
        self.assertTrue(has_jq(), "jq should be installed on this host")
        a = Ansi(enabled=True)

        dork_entries = [
            {"idx": "1", "name": "very_long_research_dorks_collection_2026.txt", "query_count": 100, "size_human": "5.2 KB"},
            {"idx": "2", "name": "docs.txt", "query_count": 8, "size_human": "0.4 KB"},
        ]
        metrics = [
            EngineMetrics(
                engine="google_web_udm14",
                requests=40,
                successes=12,
                rate_limits=8,
                total_results_yielded=55,
                total_latency_ms=48000.0,
                parked=True,
                bandit_alpha=13.0,
                bandit_beta=17.0,
            ).model_dump(),
            EngineMetrics(
                engine="yahoo_direct",
                requests=40,
                successes=34,
                rate_limits=0,
                total_results_yielded=140,
                total_latency_ms=22000.0,
                parked=False,
                bandit_alpha=35.0,
                bandit_beta=7.0,
            ).model_dump(),
        ]
        history = [
            {
                "run_id": "20261123-162000",
                "profile": "fast",
                "mode": "all_engines",
                "state": "completed",
                "done_queries": 100,
                "total_queries": 100,
                "verified_links": 270,
                "elapsed_seconds": 124.5,
            }
        ]
        domains = [{"domain": "docs.python.org", "count": 42, "engines": ["searxng", "yahoo_direct"]}]

        for width in (45, 76, 130):
            for rendered in (
                render_dork_files_table(dork_entries, cols=width, ansi=a),
                render_engine_metrics_table(metrics, cols=width, ansi=a),
                render_status_history_table(history, cols=width, ansi=a),
                render_domains_table(domains, cols=width, ansi=a),
            ):
                self.assertTrue(rendered.strip())
                for line in rendered.splitlines():
                    self.assertLessEqual(
                        visible_len(line),
                        width,
                        f"Line overflowed {width} cols: {strip_ansi(line)!r}",
                    )
            self.assertIn("(100)", strip_ansi(render_dork_files_table(dork_entries, cols=width, ansi=a)))
            self.assertIn("PARKED", strip_ansi(render_engine_metrics_table(metrics, cols=width, ansi=a)))


class TestWorkspaceDiscoveryProfilesStatusAndLinksExport(unittest.TestCase):
    """Verify workspace layout, dork `(N)` counting, 3 profiles, atomic status, and links.txt."""

    def test_workspace_dork_discovery_and_links_only_txt_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = ensure_workspace(Path(tmpdir) / "ws")
            for p in (ws.dorks, ws.proxies, ws.configs, ws.cache, ws.logs, ws.exports_links, ws.exports_json, ws.exports_reports, ws.exports_crawl):
                self.assertTrue(p.is_dir())

            # Write a custom dork file with comments and blank lines
            sample = ws.dorks / "sample_set.txt"
            sample.write_text(
                "# header comment\n\n"
                'site:docs.python.org asyncio // inline comment\n'
                '/* block\ncomment */\n'
                'site:peps.python.org "PEP 492"\n',
                encoding="utf-8",
            )
            discovered = discover_dork_files(ws.dorks)
            by_name = {d["name"]: d for d in discovered}
            self.assertIn("sample_set.txt", by_name)
            self.assertEqual(by_name["sample_set.txt"]["query_count"], 2)

            # Verify links-only .txt export via jq on both PipelineOutput & AllEnginesMatrixOutput
            r1 = SearchResult(rank=1, title="Asyncio", url="https://docs.python.org/3/library/asyncio.html", engine="searxng", query="asyncio")
            r2 = SearchResult(rank=2, title="Asyncio dup", url="https://docs.python.org/3/library/asyncio.html/", engine="yahoo", query="asyncio")
            r3 = SearchResult(rank=3, title="PEP 492", url="https://peps.python.org/pep-0492/", engine="yahoo", query="pep 492")

            pipe_out = PipelineOutput(total_results=3, elapsed_seconds=1.2, results=[r1, r2, r3])
            txt1 = ws.exports_links / "pipe_links.txt"
            cnt1 = export_links_only_txt(pipe_out, txt1)
            self.assertEqual(cnt1, 2)
            self.assertEqual(
                txt1.read_text(encoding="utf-8").splitlines(),
                ["https://docs.python.org/3/library/asyncio.html", "https://peps.python.org/pep-0492/"],
            )

            matrix_out = AllEnginesMatrixOutput(
                total_queries=1,
                engines=["searxng"],
                elapsed_seconds=1.0,
                total_verified_links=2,
                records=[
                    QueryAllEnginesRecord(
                        query_id=1,
                        difficulty=10,
                        query="asyncio",
                        unique_verified_count=2,
                        per_engine={"searxng": EngineQueryOutcome(engine="searxng", status="ok", links=[r1, r3])},
                        merged_links=[r1, r3],
                    )
                ],
            )
            txt2 = ws.exports_links / "matrix_links.txt"
            cnt2 = export_links_only_txt(matrix_out, txt2)
            self.assertEqual(cnt2, 2)
            self.assertEqual(
                extract_unique_urls_with_jq(matrix_out),
                ["https://docs.python.org/3/library/asyncio.html", "https://peps.python.org/pep-0492/"],
            )

    def test_three_profiles_toml_roundtrip_and_cli_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = ensure_workspace(Path(tmpdir) / "ws")
            fast = build_fast_profile(ws)
            med = build_medium_profile(ws)
            adv = build_advanced_profile(ws)

            self.assertEqual(fast.settings.enabled_engines, list(DIRECT_ENGINES))
            self.assertTrue(fast.all_engines_mode)
            self.assertTrue(fast.settings.strict_ast_filter)
            self.assertFalse(fast.settings.enable_query_relaxation)
            self.assertEqual(med.profile_name, "medium")
            self.assertEqual(adv.profile_name, "advanced")

            toml_file = ws.configs / "my_preset.toml"
            adv.settings.concurrency = 9
            adv.settings.poisson_mean_delay = 1.35
            save_profile_toml(adv.settings, toml_file)
            reloaded = load_profile_toml(toml_file)
            self.assertEqual(reloaded.concurrency, 9)
            self.assertAlmostEqual(reloaded.poisson_mean_delay, 1.35)

            fast.input_files = [ws.dorks / "benchmark_100_queries.txt"]
            cli_str = build_equivalent_cli_command(fast, links_txt_path=ws.exports_links / "out.txt")
            self.assertIn("--all-engines", cli_str)
            self.assertIn("--no-relax", cli_str)
            self.assertIn("--links-txt", cli_str)

    def test_atomic_status_tracker_stale_pid_and_interactive_quit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = ensure_workspace(Path(tmpdir) / "ws")
            tracker = RunStatusTracker(
                ws,
                run_id="20261123-163000",
                profile="fast",
                mode="all_engines",
                input_label="benchmark_100_queries.txt",
                total_queries=10,
                render_live=False,
            )
            tracker.start()
            active = load_active_status(ws)
            self.assertIsNotNone(active)
            assert active is not None
            self.assertEqual(active["state"], "running")
            self.assertEqual(active["pid"], os.getpid())

            tracker.finalize(
                state="completed",
                done_queries=10,
                total_queries=10,
                total_verified_links=15,
                total_ast_dropped=4,
                export_paths={"links_txt": "/tmp/links.txt"},
            )
            hist = load_run_history(ws)
            self.assertEqual(len(hist), 1)
            self.assertEqual(hist[0]["verified_links"], 15)
            self.assertEqual(hist[0]["done_queries"], 10)
            self.assertEqual(hist[0]["total_queries"], 10)

            # Simulate crashed PID -> must report `stale (exited)`
            stale_payload = dict(active)
            stale_payload["pid"] = 99999999
            stale_payload["state"] = "running"
            ws.active_run_file.write_text(json.dumps(stale_payload), encoding="utf-8")
            stale_loaded = load_active_status(ws)
            self.assertIsNotNone(stale_loaded)
            assert stale_loaded is not None
            self.assertEqual(stale_loaded["state"], "stale (exited)")

            # Status view renders cleanly without horizontal overflow across all 3 breakpoints
            for w in (45, 80, 130):
                view = render_status_view(ws, cols=w, ansi=Ansi(enabled=False))
                self.assertIn("SEARCH-V3 STATUS", view)
                for line in view.splitlines():
                    self.assertLessEqual(
                        visible_len(line),
                        w,
                        f"Status line exceeded {w} cols: {line!r}",
                    )

            # Interactive TUI cleanly quits on 'q' or EOF
            tui = SearchV3TUI(workspace_root=ws.root)
            with patch.object(tui, "_probe_searxng_once", return_value="OFF"), patch("builtins.input", side_effect=["q"]):
                self.assertEqual(tui.run(), 0)

            args = parse_cli_args(["--tui", "--status", "--links-txt", "/tmp/l.txt"])
            self.assertTrue(args.tui)
            self.assertTrue(args.status)
            self.assertEqual(args.links_txt, Path("/tmp/l.txt"))


if __name__ == "__main__":
    unittest.main()
