"""Organized workspace layout manager, dork/proxy discovery, and 1-URL-per-line jq exporter."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.models import AllEnginesMatrixOutput, PipelineOutput
from engine.orchestrator import strip_query_line

DEFAULT_WORKSPACE_ROOT = Path(__file__).resolve().parent.parent / "workspace"


@dataclass(frozen=True, slots=True)
class WorkspacePaths:
    """Clean categorized directory structure managed by the v3 TUI."""

    root: Path
    dorks: Path
    proxies: Path
    configs: Path
    cache: Path
    logs: Path
    exports_links: Path
    exports_json: Path
    exports_reports: Path
    exports_crawl: Path

    @property
    def active_run_file(self) -> Path:
        return self.logs / ".active_run.json"

    @property
    def run_history_file(self) -> Path:
        return self.logs / "run_history.jsonl"


def ensure_workspace(root: Path | None = None) -> WorkspacePaths:
    """Create the clean categorized workspace folder hierarchy if missing."""
    base = (root or DEFAULT_WORKSPACE_ROOT).resolve()
    ws = WorkspacePaths(
        root=base,
        dorks=base / "dorks",
        proxies=base / "proxies",
        configs=base / "configs",
        cache=base / "cache",
        logs=base / "logs",
        exports_links=base / "exports" / "links",
        exports_json=base / "exports" / "json",
        exports_reports=base / "exports" / "reports",
        exports_crawl=base / "exports" / "crawl",
    )
    for folder in (
        ws.dorks,
        ws.proxies,
        ws.configs,
        ws.cache,
        ws.logs,
        ws.exports_links,
        ws.exports_json,
        ws.exports_reports,
        ws.exports_crawl,
    ):
        folder.mkdir(parents=True, exist_ok=True)

    # Seed default benign benchmark file in workspace/dorks/ on first setup if empty
    v3_root = Path(__file__).resolve().parent.parent
    sample_bench = v3_root / "benchmark_100_queries.txt"
    if not any(ws.dorks.glob("*.txt")) and sample_bench.is_file():
        shutil.copy2(sample_bench, ws.dorks / "benchmark_100_queries.txt")

    return ws


def _format_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes / (1024 * 1024):.1f} MB"


def count_valid_queries(file_path: Path) -> int:
    """Count exact executable queries in a `.txt` file (ignoring blanks & `#`/`//`/`/* */` comments)."""
    count = 0
    in_block = False
    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            cleaned, in_block = strip_query_line(raw_line, in_block)
            if cleaned:
                count += 1
    return count


def discover_dork_files(dorks_dir: Path) -> list[dict[str, Any]]:
    """Fetch `*.txt` files from `dorks_dir` and report exact valid query count per file."""
    if not dorks_dir.is_dir():
        return []
    entries: list[dict[str, Any]] = []
    for idx, txt_file in enumerate(sorted(dorks_dir.glob("*.txt")), start=1):
        if not txt_file.is_file():
            continue
        size = txt_file.stat().st_size
        q_count = count_valid_queries(txt_file)
        entries.append(
            {
                "idx": str(idx),
                "name": txt_file.name,
                "path": str(txt_file),
                "query_count": q_count,
                "size_bytes": size,
                "size_human": _format_size(size),
            }
        )
    return entries


def discover_proxy_files(proxies_dir: Path) -> list[dict[str, Any]]:
    """Scan `proxies_dir/*.txt` and count non-comment proxy lines."""
    if not proxies_dir.is_dir():
        return []
    entries: list[dict[str, Any]] = []
    for idx, txt_file in enumerate(sorted(proxies_dir.glob("*.txt")), start=1):
        if not txt_file.is_file():
            continue
        count = 0
        for line in txt_file.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                count += 1
        entries.append(
            {
                "idx": str(idx),
                "name": txt_file.name,
                "path": str(txt_file),
                "query_count": count,
                "size_human": _format_size(txt_file.stat().st_size),
            }
        )
    return entries


def extract_unique_urls_with_jq(source: PipelineOutput | AllEnginesMatrixOutput | Path | dict[str, Any]) -> list[str]:
    """
    Extract ordered unique verified URLs from either `PipelineOutput` or
    `AllEnginesMatrixOutput` using `jq -r` (with pure-Python fallback if `jq` is absent).
    """
    if isinstance(source, Path):
        raw_json = source.read_text(encoding="utf-8", errors="replace")
        payload_dict: dict[str, Any] | None = None
    elif isinstance(source, (PipelineOutput, AllEnginesMatrixOutput)):
        raw_json = source.model_dump_json()
        payload_dict = None
    else:
        payload_dict = source
        raw_json = json.dumps(source, ensure_ascii=False)

    jq_filter = (
        'if .mode == "all_engines_matrix" then '
        '  [.records[]? | .merged_links[]? | .url] '
        'else '
        '  [.results[]? | .url] '
        'end | .[] | select(type == "string" and length > 0)'
    )

    urls_raw: list[str] = []
    if shutil.which("jq") is not None:
        try:
            proc = subprocess.run(
                ["jq", "-r", jq_filter],
                input=raw_json,
                capture_output=True,
                text=True,
                timeout=10.0,
                check=True,
            )
            urls_raw = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        except Exception:
            urls_raw = []

    if not urls_raw:
        data = payload_dict if payload_dict is not None else json.loads(raw_json)
        if data.get("mode") == "all_engines_matrix":
            for rec in data.get("records") or []:
                for lk in rec.get("merged_links") or []:
                    u = str(lk.get("url") or "").strip()
                    if u:
                        urls_raw.append(u)
        else:
            for item in data.get("results") or []:
                u = str(item.get("url") or "").strip()
                if u:
                    urls_raw.append(u)

    seen: set[str] = set()
    unique: list[str] = []
    for u in urls_raw:
        key = u.rstrip("/").lower()
        if key not in seen:
            seen.add(key)
            unique.append(u)
    return unique


def export_links_only_txt(
    source: PipelineOutput | AllEnginesMatrixOutput | Path | dict[str, Any],
    dest_path: Path,
) -> int:
    """Write strictly 1 unique verified URL per line into `dest_path` (.txt)."""
    urls = extract_unique_urls_with_jq(source)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(urls) + ("\n" if urls else "")
    dest_path.write_text(body, encoding="utf-8")
    return len(urls)
