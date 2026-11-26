"""Responsive Pure-ANSI table engine backed by `jq` JSON projection."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable, Sequence
from typing import Any, Literal

from cli.tui_ansi import (
    Ansi,
    get_screen_size,
    layout_breakpoint,
    pad_visible,
    supports_utf8,
    truncate_visible,
)

Align = Literal["left", "right"]
CellStyler = Callable[[int, str], str]


def has_jq() -> bool:
    return shutil.which("jq") is not None


def jq_version() -> str:
    if not has_jq():
        return "fallback-py"
    try:
        proc = subprocess.run(
            ["jq", "--version"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        out = proc.stdout.strip()
        return out if out else "jq"
    except Exception:
        return "jq"


def run_jq_tsv(
    payload: Any,
    jq_filter: str,
    *,
    fallback_fn: Callable[[Any], list[list[str]]] | None = None,
) -> list[list[str]]:
    """
    Project structured JSON into TSV rows using `jq -r <jq_filter>`.
    Falls back cleanly to `fallback_fn` only if `jq` is unavailable.
    """
    if has_jq():
        try:
            raw_json = json.dumps(payload, ensure_ascii=False)
            proc = subprocess.run(
                ["jq", "-r", jq_filter],
                input=raw_json,
                capture_output=True,
                text=True,
                timeout=5.0,
                check=True,
            )
            rows: list[list[str]] = []
            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                rows.append(line.split("\t"))
            return rows
        except Exception:
            if fallback_fn is None:
                raise
    if fallback_fn is not None:
        return fallback_fn(payload)
    return []


def render_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    cols: int | None = None,
    ansi: Ansi | None = None,
    alignments: Sequence[Align] | None = None,
    flex_cols: set[int] | None = None,
    cell_styler: CellStyler | None = None,
) -> str:
    """
    Render a minimalist, overflow-safe Pure-ANSI table that adapts cleanly to any
    terminal width (32..300 cols) without external libraries.
    """
    term_cols = cols if cols is not None else get_screen_size()[0]
    target_w = max(32, min(term_cols, 124))
    a = ansi or Ansi()
    num_cols = len(headers)
    if num_cols == 0:
        return ""

    aligns: list[Align] = (
        list(alignments) if alignments is not None else ["left"] * num_cols
    )
    normalized_rows: list[list[str]] = [
        [str(r[i]) if i < len(r) else "" for i in range(num_cols)] for r in rows
    ]

    # Natural widths
    widths = [len(h) for h in headers]
    for r in normalized_rows:
        for i, cell in enumerate(r):
            if len(cell) > widths[i]:
                widths[i] = len(cell)

    sep = "  "
    sep_total = len(sep) * (num_cols - 1)
    max_content_w = max(num_cols * 3, target_w - sep_total)

    # Shrink flexible columns first (or widest columns) until total fits `target_w`
    shrink_order = sorted(
        range(num_cols),
        key=lambda i: (0 if (flex_cols and i in flex_cols) else 1, -widths[i]),
    )
    while sum(widths) > max_content_w:
        reduced = False
        for idx in shrink_order:
            min_w = 4 if (flex_cols and idx in flex_cols) else max(3, min(len(headers[idx]), 6))
            if widths[idx] > min_w:
                widths[idx] -= 1
                reduced = True
                if sum(widths) <= max_content_w:
                    break
        if not reduced:
            # Hard floor squeeze for extreme ultra-narrow terminals
            widest = max(range(num_cols), key=lambda i: widths[i])
            if widths[widest] <= 2:
                break
            widths[widest] -= 1

    rule_ch = "─" if supports_utf8() else "-"
    header_cells = [
        pad_visible(a.bold_cyan(truncate_visible(headers[i], widths[i])), widths[i], aligns[i])
        for i in range(num_cols)
    ]
    lines: list[str] = [
        sep.join(header_cells),
        a.dim(rule_ch * min(target_w, sum(widths) + sep_total)),
    ]

    for r in normalized_rows:
        rendered_row: list[str] = []
        for i in range(num_cols):
            clipped = truncate_visible(r[i], widths[i])
            styled = cell_styler(i, clipped) if cell_styler is not None else clipped
            rendered_row.append(pad_visible(styled, widths[i], aligns[i]))
        lines.append(sep.join(rendered_row))

    return "\n".join(lines)


def render_dork_files_table(
    entries: Sequence[dict[str, Any]],
    *,
    cols: int | None = None,
    ansi: Ansi | None = None,
    folder_label: str = "workspace/dorks/",
    count_label: str = "Queries",
) -> str:
    """Render discovered `.txt` files with `(count)` via `jq`."""
    term_cols = cols if cols is not None else get_screen_size()[0]
    bp = layout_breakpoint(term_cols)
    a = ansi or Ansi()

    jq_filter = (
        '.[] | [.idx, .name, "(" + (.query_count|tostring) + ")", .size_human] | @tsv'
        if bp != "compact"
        else '.[] | [.idx, .name, "(" + (.query_count|tostring) + ")"] | @tsv'
    )

    def _fb(data: Any) -> list[list[str]]:
        if bp != "compact":
            return [[str(e["idx"]), str(e["name"]), f"({e['query_count']})", str(e["size_human"])] for e in data]
        return [[str(e["idx"]), str(e["name"]), f"({e['query_count']})"] for e in data]

    rows = run_jq_tsv(list(entries), jq_filter, fallback_fn=_fb)
    if bp == "compact":
        return render_table(
            ["#", "File", "Count"],
            rows,
            cols=term_cols,
            ansi=a,
            alignments=["right", "left", "right"],
            flex_cols={1},
            cell_styler=lambda i, v: a.bold_cyan(v) if i == 0 else (a.green(v) if i == 2 else v),
        )
    return render_table(
        ["#", f"File ({folder_label})", count_label, "Size"],
        rows,
        cols=term_cols,
        ansi=a,
        alignments=["right", "left", "right", "right"],
        flex_cols={1},
        cell_styler=lambda i, v: (
            a.bold_cyan(v) if i == 0 else (a.green(v) if i == 2 else (a.dim(v) if i == 3 else v))
        ),
    )


def render_engine_metrics_table(
    metrics: Sequence[dict[str, Any]],
    *,
    cols: int | None = None,
    ansi: Ansi | None = None,
) -> str:
    """Render responsive live Engine Telemetry table using `jq` across all 3 breakpoints."""
    term_cols = cols if cols is not None else get_screen_size()[0]
    bp = layout_breakpoint(term_cols)
    a = ansi or Ansi()

    if bp == "compact":
        jq_filter = (
            '.[] | [.engine, (.successes|tostring), (.rate_limits|tostring), '
            '(if .parked then "PARKED" else "ACTIVE" end)] | @tsv'
        )
        headers = ["Engine", "OK", "429", "State"]
        aligns: list[Align] = ["left", "right", "right", "left"]
        state_idx = 3
        fb = lambda data: [
            [str(m["engine"]), str(m.get("successes", 0)), str(m.get("rate_limits", 0)), "PARKED" if m.get("parked") else "ACTIVE"]
            for m in data
        ]
    elif bp == "standard":
        jq_filter = (
            '.[] | [.engine, (.requests|tostring), (.successes|tostring), '
            '(.rate_limits|tostring), ((.thompson_posterior_mean * 100 | round | tostring) + "%"), '
            '(if .parked then "PARKED" else "ACTIVE" end)] | @tsv'
        )
        headers = ["Engine", "Req", "OK", "429", "Theta", "State"]
        aligns = ["left", "right", "right", "right", "right", "left"]
        state_idx = 5
        fb = lambda data: [
            [
                str(m["engine"]),
                str(m.get("requests", 0)),
                str(m.get("successes", 0)),
                str(m.get("rate_limits", 0)),
                f"{round(float(m.get('thompson_posterior_mean', 0.5)) * 100)}%",
                "PARKED" if m.get("parked") else "ACTIVE",
            ]
            for m in data
        ]
    else:
        jq_filter = (
            '.[] | [.engine, (.requests|tostring), (.successes|tostring), '
            '(.total_results_yielded|tostring), (.rate_limits|tostring), '
            '((.avg_latency_ms | round | tostring) + "ms"), '
            '((.bandit_alpha|floor|tostring) + "/" + (.bandit_beta|floor|tostring)), '
            '((.thompson_posterior_mean * 100 | round | tostring) + "%"), '
            '(if .parked then "PARKED" else "ACTIVE" end)] | @tsv'
        )
        headers = ["Engine", "Req", "OK", "Hits", "429", "Avg", "α/β", "Theta", "State"]
        aligns = ["left", "right", "right", "right", "right", "right", "right", "right", "left"]
        state_idx = 8
        fb = lambda data: [
            [
                str(m["engine"]),
                str(m.get("requests", 0)),
                str(m.get("successes", 0)),
                str(m.get("total_results_yielded", 0)),
                str(m.get("rate_limits", 0)),
                f"{round(float(m.get('avg_latency_ms', 0.0)))}ms",
                f"{int(m.get('bandit_alpha', 1))}/{int(m.get('bandit_beta', 1))}",
                f"{round(float(m.get('thompson_posterior_mean', 0.5)) * 100)}%",
                "PARKED" if m.get("parked") else "ACTIVE",
            ]
            for m in data
        ]

    rows = run_jq_tsv(list(metrics), jq_filter, fallback_fn=fb)

    def _style(col_idx: int, val: str) -> str:
        if col_idx == state_idx:
            return a.bold_yellow(val) if val == "PARKED" else a.bold_green(val)
        return val

    return render_table(
        headers,
        rows,
        cols=term_cols,
        ansi=a,
        alignments=aligns,
        flex_cols={0},
        cell_styler=_style,
    )


def render_status_history_table(
    runs: Sequence[dict[str, Any]],
    *,
    cols: int | None = None,
    ansi: Ansi | None = None,
) -> str:
    """Render recent run history table using `jq`."""
    term_cols = cols if cols is not None else get_screen_size()[0]
    bp = layout_breakpoint(term_cols)
    a = ansi or Ansi()

    if bp == "compact":
        jq_filter = (
            '.[] | [.profile, .state, ((.done_queries|tostring) + "/" + (.total_queries|tostring)), '
            '(.verified_links|tostring)] | @tsv'
        )
        headers = ["Prof", "State", "Prog", "Links"]
        aligns: list[Align] = ["left", "left", "right", "right"]
        state_idx = 1
        fb = lambda data: [
            [str(r.get("profile", "-")), str(r.get("state", "-")), f"{r.get('done_queries', 0)}/{r.get('total_queries', 0)}", str(r.get("verified_links", 0))]
            for r in data
        ]
    else:
        jq_filter = (
            '.[] | [.run_id, .profile, .mode, .state, '
            '((.done_queries|tostring) + "/" + (.total_queries|tostring)), '
            '(.verified_links|tostring), ((.elapsed_seconds|round|tostring) + "s")] | @tsv'
        )
        headers = ["Run ID", "Profile", "Mode", "State", "Progress", "Links", "Time"]
        aligns = ["left", "left", "left", "left", "right", "right", "right"]
        state_idx = 3
        fb = lambda data: [
            [
                str(r.get("run_id", "-")),
                str(r.get("profile", "-")),
                str(r.get("mode", "-")),
                str(r.get("state", "-")),
                f"{r.get('done_queries', 0)}/{r.get('total_queries', 0)}",
                str(r.get("verified_links", 0)),
                f"{round(float(r.get('elapsed_seconds', 0.0)))}s",
            ]
            for r in data
        ]

    rows = run_jq_tsv(list(runs), jq_filter, fallback_fn=fb)

    def _style(col_idx: int, val: str) -> str:
        if col_idx == state_idx:
            low = val.lower()
            if "running" in low:
                return a.bold_cyan(val)
            if "completed" in low:
                return a.bold_green(val)
            if "stopped" in low or "stale" in low:
                return a.bold_yellow(val)
            return a.bold_red(val)
        return val

    return render_table(
        headers,
        rows,
        cols=term_cols,
        ansi=a,
        alignments=aligns,
        flex_cols={0},
        cell_styler=_style,
    )


def render_domains_table(
    top_domains: Sequence[dict[str, Any]],
    *,
    cols: int | None = None,
    ansi: Ansi | None = None,
    limit: int = 12,
) -> str:
    """Render top root domains table via `jq`."""
    term_cols = cols if cols is not None else get_screen_size()[0]
    a = ansi or Ansi()
    sliced = list(top_domains)[:limit]
    jq_filter = '.[] | [.domain, (.count|tostring), ((.engines // []) | join(","))] | @tsv'
    fb = lambda data: [
        [str(d.get("domain", "")), str(d.get("count", 0)), ",".join(d.get("engines") or [])]
        for d in data
    ]
    rows = run_jq_tsv(sliced, jq_filter, fallback_fn=fb)
    return render_table(
        ["Root Domain", "Hits", "Engines"],
        rows,
        cols=term_cols,
        ansi=a,
        alignments=["left", "right", "left"],
        flex_cols={0, 2},
        cell_styler=lambda i, v: a.green(v) if i == 1 else v,
    )
