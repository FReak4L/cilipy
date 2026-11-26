"""Standalone CLI, Pure-ANSI + jq TUI, and Rich dashboard package (lazy main export)."""

from __future__ import annotations

from typing import Any

from cli.ui_dashboard import PipelineDashboard

__all__ = [
    "PipelineDashboard",
    "async_main",
    "configure_logging",
    "main",
    "parse_cli_args",
    "render_status_view",
    "run_tui",
]


def __getattr__(name: str) -> Any:
    if name in ("async_main", "configure_logging", "main", "parse_cli_args"):
        from cli import main as cli_main

        return getattr(cli_main, name)
    if name in ("render_status_view", "run_tui"):
        from cli import tui_app

        return getattr(tui_app, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
