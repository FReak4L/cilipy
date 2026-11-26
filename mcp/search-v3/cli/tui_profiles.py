"""Built-in TUI execution profiles (Fast, Medium, Advanced), TOML presets & CLI builder."""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from cli.tui_exporters import WorkspacePaths
from core.models import PipelineSettings

DIRECT_ENGINES: tuple[str, ...] = (
    "yahoo_direct",
    "ddg_html",
    "ddg_lite",
    "google_web_udm14",
    "google_mobile_web",
    "google_basic_html",
)

API_ENGINES: tuple[str, ...] = (
    "searxng",
    "google_cse",
    "ddgs",
)

HYBRID_ENGINES: tuple[str, ...] = (
    "searxng",
    "yahoo_direct",
    "ddg_html",
    "ddg_lite",
    "ddgs",
    "google_web_udm14",
    "google_mobile_web",
    "google_basic_html",
)

ALL_SELECTABLE_ENGINES: tuple[tuple[str, str], ...] = (
    ("searxng", "Local SearXNG JSON Federation"),
    ("yahoo_direct", "Yahoo Direct (BoringSSL HTML)"),
    ("ddg_html", "DuckDuckGo HTML Direct"),
    ("ddg_lite", "DuckDuckGo Lite Zero-JS"),
    ("ddgs", "DDGS Python Library Fallback"),
    ("google", "Google Multi-Tier Facade (Auto Cascade)"),
    ("google_cse", "Google Tier 1: Official CSE JSON API"),
    ("google_web_udm14", "Google Tier 2: Desktop Web udm=14"),
    ("google_mobile_web", "Google Tier 3: Android Mobile Direct"),
    ("google_basic_html", "Google Tier 4: Zero-JS Basic HTML"),
)


@dataclass
class ProfileConfig:
    """Complete interactive run configuration constructed by any TUI profile."""

    profile_name: Literal["fast", "medium", "advanced"]
    input_files: list[Path] = field(default_factory=list)
    all_engines_mode: bool = True
    settings: PipelineSettings = field(default_factory=PipelineSettings)
    google_hl: str = "en"
    google_gl: str = "us"
    export_links_txt: bool = True
    export_json: bool = True
    export_markdown: bool = True
    export_log: bool = True


def build_fast_profile(ws: WorkspacePaths) -> ProfileConfig:
    """Profile 1: FAST (Direct All-Engine) — maximum v3 features with minimal prompts."""
    settings = PipelineSettings(
        enabled_engines=list(DIRECT_ENGINES),
        concurrency=6,
        max_results_per_query=10,
        pagination_depth=1,
        max_retries=1,
        request_timeout=12.0,
        poisson_mean_delay=0.8,
        jitter_min=0.2,
        jitter_max=0.6,
        enable_thompson_sampling=True,
        strict_ast_filter=True,
        enable_query_relaxation=False,
        simhash_max_hamming=3,
        jaccard_threshold=0.85,
        enable_http1_fallback=True,
        engine_park_bot_threshold=3,
        engine_park_empty_threshold=5,
        engine_park_seconds=60.0,
        enable_cache=True,
        cache_db_path=ws.cache / "search_cache.db",
        enable_crawl=False,
        enable_tui=False,
    )
    return ProfileConfig(
        profile_name="fast",
        all_engines_mode=True,
        settings=settings,
        export_links_txt=True,
        export_json=True,
        export_markdown=True,
        export_log=True,
    )


def build_medium_profile(ws: WorkspacePaths) -> ProfileConfig:
    """Profile 2: MEDIUM — balanced mode with engine-group choice and core feature toggles."""
    settings = PipelineSettings(
        enabled_engines=list(HYBRID_ENGINES),
        concurrency=4,
        max_results_per_query=15,
        pagination_depth=2,
        max_retries=2,
        request_timeout=15.0,
        poisson_mean_delay=1.2,
        enable_thompson_sampling=True,
        strict_ast_filter=True,
        enable_query_relaxation=False,
        simhash_max_hamming=3,
        jaccard_threshold=0.85,
        enable_http1_fallback=True,
        engine_park_seconds=90.0,
        enable_cache=True,
        cache_db_path=ws.cache / "search_cache.db",
        enable_crawl=False,
        enable_tui=False,
    )
    return ProfileConfig(
        profile_name="medium",
        all_engines_mode=False,
        settings=settings,
        export_links_txt=True,
        export_json=True,
        export_markdown=False,
        export_log=True,
    )


def build_advanced_profile(ws: WorkspacePaths) -> ProfileConfig:
    """Profile 3: ADVANCED — full control over all 39 PipelineSettings + Google Suite."""
    settings = PipelineSettings(
        enabled_engines=list(HYBRID_ENGINES),
        concurrency=4,
        max_results_per_query=15,
        pagination_depth=2,
        max_retries=3,
        request_timeout=18.0,
        poisson_mean_delay=2.0,
        enable_thompson_sampling=True,
        strict_ast_filter=True,
        enable_query_relaxation=False,
        simhash_max_hamming=3,
        jaccard_threshold=0.85,
        enable_http1_fallback=True,
        enable_cache=True,
        cache_db_path=ws.cache / "search_cache.db",
        enable_crawl=False,
        enable_tui=False,
    )
    return ProfileConfig(
        profile_name="advanced",
        all_engines_mode=False,
        settings=settings,
        export_links_txt=True,
        export_json=True,
        export_markdown=True,
        export_log=True,
    )


def _toml_value(val: object) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, Path):
        return json.dumps(str(val))
    if isinstance(val, list):
        inner = ", ".join(_toml_value(v) for v in val)
        return f"[{inner}]"
    return json.dumps(str(val))


def save_profile_toml(settings: PipelineSettings, dest_path: Path) -> Path:
    """Serialize `PipelineSettings` cleanly into a valid TOML file (zero extra deps)."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    data = settings.model_dump()
    lines = ["# Saved by search-v3 Interactive TUI"]
    for key, val in data.items():
        if val is None:
            continue
        lines.append(f"{key} = {_toml_value(val)}")
    dest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest_path


def load_profile_toml(config_path: Path) -> PipelineSettings:
    """Load a saved `.toml`/`.yaml` preset via `PipelineSettings.load`."""
    return PipelineSettings.load(config_path=config_path)


def build_equivalent_cli_command(
    cfg: ProfileConfig,
    *,
    json_path: Path | None = None,
    links_txt_path: Path | None = None,
    md_path: Path | None = None,
    log_path: Path | None = None,
) -> str:
    """Generate the exact reproducible `search-v3` CLI command for a TUI configuration."""
    s = cfg.settings
    env_parts: list[str] = [
        f"SEARCH_MAX_RETRIES={s.max_retries}",
        f"SEARCH_REQUEST_TIMEOUT={s.request_timeout}",
        f"SEARCH_ENGINE_PARK_SECONDS={s.engine_park_seconds}",
    ]
    cmd: list[str] = ["search-v3"]
    if cfg.input_files:
        cmd.extend(["-i", str(cfg.input_files[0])])
    cmd.extend(["--engines", ",".join(s.enabled_engines)])
    if cfg.all_engines_mode:
        cmd.append("--all-engines")
    if s.enable_query_relaxation:
        cmd.append("--allow-relax")
    else:
        cmd.append("--no-relax")
    if not s.strict_ast_filter:
        cmd.append("--no-ast-filter")
    if not s.enable_thompson_sampling:
        cmd.append("--no-thompson")
    if not s.enable_http1_fallback:
        cmd.append("--no-http1-fallback")
    if not s.enable_cache:
        cmd.append("--no-cache")
    else:
        cmd.extend(["--cache-db", str(s.cache_db_path), "--cache-ttl", str(s.cache_ttl_seconds)])
    if s.proxies_file:
        cmd.extend(["--proxies", str(s.proxies_file)])
    cmd.extend(
        [
            "--concurrency",
            str(s.concurrency),
            "--max-results",
            str(s.max_results_per_query),
            "--pagination-depth",
            str(s.pagination_depth),
            "--poisson-mean",
            str(s.poisson_mean_delay),
            "--simhash-hamming",
            str(s.simhash_max_hamming),
            "--jaccard-threshold",
            str(s.jaccard_threshold),
        ]
    )
    if s.enable_crawl:
        cmd.append("--crawl")
        if s.allowed_crawl_domains:
            cmd.extend(["--allowed-domains", ",".join(s.allowed_crawl_domains)])
        if s.crawl_output_path:
            cmd.extend(["--crawl-output", str(s.crawl_output_path)])
    if json_path:
        cmd.extend(["--output", str(json_path)])
    if links_txt_path:
        cmd.extend(["--links-txt", str(links_txt_path)])
    if md_path and cfg.all_engines_mode:
        cmd.extend(["--links-output", str(md_path)])
    if log_path:
        cmd.extend(["--log-file", str(log_path)])
    cmd.append("--no-tui")
    return " ".join(env_parts) + " " + " ".join(shlex.quote(c) for c in cmd)
