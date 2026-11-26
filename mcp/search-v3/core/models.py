"""Pydantic v2 data schemas, telemetry models, and layered PipelineSettings."""

from __future__ import annotations

import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, computed_field
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from core.constants import (
    DEFAULT_ENGINE_PARK_SECONDS,
    DEFAULT_JACCARD_THRESHOLD,
    DEFAULT_POISSON_MEAN_DELAY_SECONDS,
    DEFAULT_PROXY_PROBE_TIMEOUT_SECONDS,
    DEFAULT_PROXY_QUARANTINE_SECONDS,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_SIMHASH_MAX_HAMMING,
)
from core.exceptions import PipelineError

try:
    import yaml as _yaml_module  # type: ignore[import-untyped]
except ImportError:
    _yaml_module = None


class SearchResult(BaseModel):
    """Normalized organic search result contract shared across all plugins and layers."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    rank: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=500)
    url: str = Field(min_length=1, max_length=2048)
    snippet: str = Field(default="", max_length=4000)
    engine: str = Field(min_length=1, max_length=64)
    query: str = Field(min_length=1, max_length=1000)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


SEARCH_RESULT_LIST_ADAPTER: TypeAdapter[list[SearchResult]] = TypeAdapter(
    list[SearchResult]
)


class FormInputField(BaseModel):
    """Structured metadata for a single HTML form input control."""

    model_config = ConfigDict(extra="forbid")

    name: str = ""
    input_type: str = "text"
    required: bool = False


class FormMetadata(BaseModel):
    """Categorized HTML form structure extracted during deep crawling."""

    model_config = ConfigDict(extra="forbid")

    action: str = ""
    method: str = "GET"
    inputs: list[FormInputField] = Field(default_factory=list)
    has_auth_fields: bool = False


class PageMetadata(BaseModel):
    """Indexed page metadata: OpenGraph tags, canonical links, and static assets."""

    model_config = ConfigDict(extra="forbid")

    canonical_url: str | None = None
    open_graph: dict[str, str] = Field(default_factory=dict)
    asset_endpoints: list[str] = Field(default_factory=list)


class CrawlResult(BaseModel):
    """Structured site-mapping record combining Katana output and schema extraction."""

    model_config = ConfigDict(extra="forbid")

    endpoint: str = Field(min_length=1)
    source: str = "katana"
    method: str = "GET"
    status_code: int | None = None
    forms: list[FormMetadata] = Field(default_factory=list)
    metadata: PageMetadata = Field(default_factory=PageMetadata)


class ProxyNode(BaseModel):
    """State, EWMA telemetry, and cooldown tracking for an individual proxy endpoint."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1)
    ewma_latency_ms: float = Field(default=400.0, ge=0.0)
    ewma_success: float = Field(default=1.0, ge=0.0, le=1.0)
    total_requests: int = Field(default=0, ge=0)
    total_failures: int = Field(default=0, ge=0)
    quarantine_until: float = Field(default=0.0, ge=0.0)
    last_quarantine_reason: str = ""
    alive: bool = True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_quarantined(self) -> bool:
        return time.monotonic() < self.quarantine_until

    @computed_field  # type: ignore[prop-decorator]
    @property
    def score(self) -> float:
        """Higher score favors high EWMA success rate and low EWMA latency."""
        if not self.alive or self.is_quarantined:
            return -1.0
        latency_penalty = 1.0 + (self.ewma_latency_ms / 1000.0)
        return self.ewma_success / latency_penalty

    @property
    def redacted_url(self) -> str:
        """Mask embedded credentials before emitting proxy URLs to logs or UI."""
        parsed = urlparse(self.url)
        if parsed.username or parsed.password:
            host = parsed.hostname or ""
            port = f":{parsed.port}" if parsed.port else ""
            return f"{parsed.scheme}://***:***@{host}{port}"
        return self.url


class ProxyPoolStats(BaseModel):
    """Point-in-time proxy pool metrics snapshot."""

    model_config = ConfigDict(extra="forbid")

    total_loaded: int = 0
    alive: int = 0
    healthy: int = 0
    quarantined: int = 0
    avg_ewma_latency_ms: float = 0.0


class EngineMetrics(BaseModel):
    """Per-engine runtime reliability, yield, and Thompson Sampling Beta(alpha, beta) telemetry."""

    model_config = ConfigDict(extra="forbid")

    engine: str
    priority_tier: int = 10
    requests: int = 0
    successes: int = 0
    failures: int = 0
    empty_yields: int = 0
    bot_gates: int = 0
    rate_limits: int = 0
    http1_fallbacks: int = 0
    cache_hits: int = 0
    total_results_yielded: int = 0
    total_latency_ms: float = 0.0
    parked: bool = False
    bandit_alpha: float = Field(default=1.0, gt=0.0)
    bandit_beta: float = Field(default=1.0, gt=0.0)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def avg_latency_ms(self) -> float:
        if self.requests == 0:
            return 0.0
        return round(self.total_latency_ms / self.requests, 2)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reliability_score(self) -> float:
        if self.requests == 0:
            return 1.0
        return round(self.successes / self.requests, 3)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def thompson_posterior_mean(self) -> float:
        return round(self.bandit_alpha / (self.bandit_alpha + self.bandit_beta), 4)


class DomainFrequency(BaseModel):
    """Root-domain diversity and yield frequency summary."""

    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=1)
    count: int = Field(ge=1)
    engines: list[str] = Field(default_factory=list)


class DeduplicationStats(BaseModel):
    """Information-theoretic deduplication counters (URL + SimHash + Jaccard)."""

    model_config = ConfigDict(extra="forbid")

    input_count: int = 0
    kept_count: int = 0
    dropped_url_exact: int = 0
    dropped_simhash: int = 0
    dropped_jaccard: int = 0


class PipelineOutput(BaseModel):
    """Top-level normalized JSON contract returned by the v3 orchestrator."""

    model_config = ConfigDict(extra="forbid")

    total_results: int
    unique_domains: int = 0
    elapsed_seconds: float
    cache_hits: int = 0
    relaxed_queries: int = 0
    ast_dropped_results: int = 0
    dedup_stats: DeduplicationStats = Field(default_factory=DeduplicationStats)
    results: list[SearchResult] = Field(default_factory=list)
    top_domains: list[DomainFrequency] = Field(default_factory=list)
    crawl_results: list[CrawlResult] = Field(default_factory=list)
    engine_metrics: list[EngineMetrics] = Field(default_factory=list)


class EngineQueryOutcome(BaseModel):
    """Per-engine live outcome for a single query in `--all-engines` fan-out mode."""

    model_config = ConfigDict(extra="forbid")

    engine: str
    status: Literal[
        "ok",
        "empty_ast_dropped",
        "empty_raw",
        "rate_limited",
        "captcha_blocked",
        "parked_circuit_breaker",
        "transport_error",
        "error",
    ]
    dispatched_query: str = ""
    latency_ms: float = 0.0
    raw_count: int = 0
    ast_admitted_count: int = 0
    ast_dropped_count: int = 0
    error: str = ""
    links: list[SearchResult] = Field(default_factory=list)


class QueryAllEnginesRecord(BaseModel):
    """All-engines live results for a single query/dork (every registered engine included)."""

    model_config = ConfigDict(extra="forbid")

    query_id: int = Field(ge=1)
    difficulty: int | None = Field(default=None, ge=1, le=100)
    query: str
    total_raw: int = 0
    total_ast_admitted: int = 0
    total_ast_dropped: int = 0
    unique_verified_count: int = 0
    per_engine: dict[str, EngineQueryOutcome] = Field(default_factory=dict)
    merged_links: list[SearchResult] = Field(default_factory=list)


class AllEnginesMatrixOutput(BaseModel):
    """Complete output contract emitted by `search-v3 --all-engines`."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["all_engines_matrix"] = "all_engines_matrix"
    total_queries: int
    engines: list[str]
    elapsed_seconds: float
    total_verified_links: int = 0
    unique_domains: int = 0
    total_ast_dropped: int = 0
    dedup_stats: DeduplicationStats = Field(default_factory=DeduplicationStats)
    proxy_stats: ProxyPoolStats = Field(default_factory=ProxyPoolStats)
    engine_metrics: list[EngineMetrics] = Field(default_factory=list)
    top_domains: list[DomainFrequency] = Field(default_factory=list)
    records: list[QueryAllEnginesRecord] = Field(default_factory=list)


class ConfigFileSettingsSource(PydanticBaseSettingsSource):
    """Custom Pydantic v2 settings source supporting `.toml`, `.yaml`, and `.yml`."""

    def __init__(
        self,
        settings_cls: type[BaseSettings],
        config_path: Path | None,
    ) -> None:
        super().__init__(settings_cls)
        self._config_data: dict[str, Any] = self._load_config_file(config_path)

    @staticmethod
    def _load_config_file(config_path: Path | None) -> dict[str, Any]:
        candidates: list[Path] = []
        if config_path is not None:
            candidates.append(config_path)
        else:
            candidates.extend(
                [Path("config.toml"), Path("config.yaml"), Path("config.yml")]
            )

        for candidate in candidates:
            if not candidate.is_file():
                continue
            suffix = candidate.suffix.lower()
            raw_bytes = candidate.read_bytes()
            if suffix == ".toml":
                loaded = tomllib.loads(raw_bytes.decode("utf-8"))
                return loaded if isinstance(loaded, dict) else {}
            if suffix in (".yaml", ".yml"):
                if _yaml_module is None:
                    raise PipelineError(
                        f"Config file '{candidate}' requires PyYAML (`pip install pyyaml`)."
                    )
                loaded_yaml = _yaml_module.safe_load(raw_bytes.decode("utf-8"))
                return loaded_yaml if isinstance(loaded_yaml, dict) else {}
        return {}

    def get_field_value(
        self,
        field: FieldInfo,
        field_name: str,
    ) -> tuple[Any, str, bool]:
        value = self._config_data.get(field_name)
        return value, field_name, False

    def __call__(self) -> dict[str, Any]:
        return dict(self._config_data)


class PipelineSettings(BaseSettings):
    """
    Centralized configuration with guaranteed precedence:
        CLI Flags (init kwargs) > Environment Variables (SEARCH_*) > Config File > Defaults
    """

    model_config = SettingsConfigDict(
        env_prefix="SEARCH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    _active_config_path: ClassVar[Path | None] = None

    searxng_url: str | None = Field(default=None)
    searxng_host: str = Field(default="127.0.0.1")
    searxng_probe_ports: list[int] = Field(default_factory=lambda: [8888, 8080, 80])
    searxng_engines: str = Field(default="brave,yahoo,wikipedia,qwant,duckduckgo")

    proxies_file: Path | None = Field(default=None)
    proxy_quarantine_seconds: float = Field(
        default=DEFAULT_PROXY_QUARANTINE_SECONDS, ge=1.0
    )
    proxy_probe_timeout: float = Field(
        default=DEFAULT_PROXY_PROBE_TIMEOUT_SECONDS, ge=0.5
    )

    cache_db_path: Path = Field(default=Path("search_cache.db"))
    cache_ttl_seconds: int = Field(default=86400, ge=0)
    enable_cache: bool = Field(default=True)

    max_results_per_query: int = Field(default=15, ge=1, le=200)
    concurrency: int = Field(default=4, ge=1, le=64)
    queue_maxsize: int = Field(default=128, ge=1)
    tokens_per_second: float = Field(default=1.2, gt=0.0)
    jitter_min: float = Field(default=0.8, ge=0.0)
    jitter_max: float = Field(default=1.8, ge=0.0)
    max_retries: int = Field(default=3, ge=1, le=10)
    request_timeout: float = Field(default=DEFAULT_REQUEST_TIMEOUT_SECONDS, ge=1.0)

    # Pure-Math & NLP Kernel Controls
    enable_thompson_sampling: bool = Field(default=True)
    poisson_mean_delay: float = Field(
        default=DEFAULT_POISSON_MEAN_DELAY_SECONDS, gt=0.0
    )
    strict_ast_filter: bool = Field(
        default=True,
        description="Deterministic Boolean AST truth-table filtering (Eval == 1 required).",
    )
    enable_query_relaxation: bool = Field(
        default=False,
        description="Disabled by default (--no-relax) to enforce 100% AST precision.",
    )
    simhash_max_hamming: int = Field(default=DEFAULT_SIMHASH_MAX_HAMMING, ge=0, le=64)
    jaccard_threshold: float = Field(default=DEFAULT_JACCARD_THRESHOLD, ge=0.0, le=1.0)

    # Engine Registry & Resilience
    pagination_depth: int = Field(default=2, ge=1, le=5)
    enable_http1_fallback: bool = Field(default=True)
    engine_park_bot_threshold: int = Field(default=3, ge=1)
    engine_park_empty_threshold: int = Field(default=5, ge=1)
    engine_park_seconds: float = Field(default=DEFAULT_ENGINE_PARK_SECONDS, ge=10.0)
    enabled_engines: list[str] = Field(
        default_factory=lambda: [
            "searxng",
            "ddg_html",
            "yahoo_direct",
            "ddg_lite",
            "ddgs",
        ]
    )

    # Tier 4 Katana Crawl
    enable_crawl: bool = Field(default=False)
    crawl_depth: int = Field(default=2, ge=1, le=5)
    crawl_rate_limit_rps: int = Field(default=10, ge=1)
    crawl_concurrency: int = Field(default=5, ge=1)
    crawl_timeout_seconds: int = Field(default=90, ge=5)
    crawl_enrich_metadata: bool = Field(default=True)
    allowed_crawl_domains: list[str] = Field(default_factory=list)
    crawl_output_path: Path | None = Field(default=None)

    enable_tui: bool = Field(default=True)
    debug: bool = Field(default=False)

    @classmethod
    def load(
        cls,
        config_path: Path | None = None,
        cli_overrides: dict[str, Any] | None = None,
    ) -> "PipelineSettings":
        """Instantiate settings with guaranteed CLI > Env > Config File precedence."""
        cls._active_config_path = config_path
        try:
            overrides = {
                k: v for k, v in (cli_overrides or {}).items() if v is not None
            }
            return cls(**overrides)
        finally:
            cls._active_config_path = None

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            ConfigFileSettingsSource(settings_cls, cls._active_config_path),
            file_secret_settings,
        )
