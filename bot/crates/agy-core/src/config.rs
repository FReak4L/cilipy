//! Typed runtime configuration loaded from environment variables with secret-safe Debug.

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::accounts::{AccountPolicy, AccountPolicyPreset};
use crate::error::{BridgeError, Result};
use crate::proxies::ProxyFallbackPolicy;

pub const DEFAULT_OWNER_ID: i64 = 1_000_000_001;
pub const DEFAULT_STATE_DIR: &str = "/var/lib/agy-telegram";
pub const DEFAULT_WORKSPACE: &str = "/root/agy-workspace";
pub const DEFAULT_AGY_BIN: &str = "/root/.local/bin/agy";
pub const DEFAULT_WEBAPP_BASE_URL: &str = "https://example.sslip.io";
pub const DEFAULT_WIDGET_PORT: u16 = 8787;
pub const DEFAULT_POLL_TIMEOUT: u64 = 30;
pub const DEFAULT_WD_SOFT: f64 = 75.0;
pub const DEFAULT_WD_HARD: f64 = 300.0;
pub const DEFAULT_STREAM_INTERVAL: f64 = 20.0;
pub const DEFAULT_AGY_JOB_TIMEOUT: u64 = 1800;
pub const DEFAULT_SKILLS_DIR: &str = "/root/.gemini/config/skills";
pub const DEFAULT_SKILLPORT_DIR: &str = "/root/.skillport/skills";
pub const DEFAULT_SKILLS_CATALOG_JSON: &str = "/opt/skills-mcp/data/catalog.json";
pub const DEFAULT_MCP_CONFIG_PATH: &str = "/root/.gemini/config/mcp_config.json";
pub const DEFAULT_AI_MEMORY_MCP_BIN: &str = "/root/.local/bin/ai-memory-mcp";
pub const DEFAULT_SKILLS_CATALOG_MCP_BIN: &str = "/root/.local/bin/skills-catalog-mcp";
pub const DEFAULT_SYNC_INTERVAL_S: u64 = 300;
pub const DEFAULT_VENICE_API_BASE: &str = "https://api.example.com/v1";
/// Must be provided via `VENICE_API_KEY` environment variable (never hardcoded in source).
pub const DEFAULT_VENICE_API_KEY: &str = "";

/// Telegram update delivery transport mode (`TG_TRANSPORT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    #[default]
    Polling,
    Webhook,
    Auto,
}

impl TransportMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Polling => "polling",
            Self::Webhook => "webhook",
            Self::Auto => "auto",
        }
    }
}

impl FromStr for TransportMode {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "polling" => Ok(Self::Polling),
            "webhook" => Ok(Self::Webhook),
            "auto" => Ok(Self::Auto),
            other => Err(BridgeError::Config(format!(
                "invalid TG_TRANSPORT value '{other}' (expected polling, webhook, or auto)"
            ))),
        }
    }
}

/// Outbound proxy selection strategy (`PROXY_MODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    #[default]
    Failover,
    RoundRobin,
    Race,
}

impl ProxyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Failover => "failover",
            Self::RoundRobin => "round_robin",
            Self::Race => "race",
        }
    }
}

impl FromStr for ProxyMode {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "failover" => Ok(Self::Failover),
            "round_robin" | "round-robin" | "roundrobin" => Ok(Self::RoundRobin),
            "race" => Ok(Self::Race),
            other => Err(BridgeError::Config(format!(
                "invalid PROXY_MODE value '{other}' (expected failover, round_robin, or race)"
            ))),
        }
    }
}

/// Agent CLI execution engine (`AGY_ENGINE`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EngineKind {
    #[default]
    Agy,
    Custom(String),
}

impl EngineKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Agy => "agy",
            Self::Custom(name) => name.as_str(),
        }
    }
}

impl FromStr for EngineKind {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("agy") {
            Ok(Self::Agy)
        } else {
            Ok(Self::Custom(trimmed.to_string()))
        }
    }
}

/// Redacts embedded credentials (`user:pass@` or `token@`) inside a proxy URL.
pub fn redact_proxy_url(raw: &str) -> String {
    let trimmed = raw.trim();
    let (prefix, rest) = match trimmed.find("://") {
        Some(pos) => (&trimmed[..pos + 3], &trimmed[pos + 3..]),
        None => ("", trimmed),
    };

    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, suffix) = rest.split_at(authority_end);

    match authority.rfind('@') {
        Some(at_pos) => {
            let host_port = &authority[at_pos + 1..];
            format!("{prefix}[REDACTED]@{host_port}{suffix}")
        }
        None => trimmed.to_string(),
    }
}

/// Complete typed bridge configuration.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub bot_token: String,
    pub state_dir: PathBuf,
    pub agy_workspace: PathBuf,
    pub agy_bin: PathBuf,
    pub owner_id: i64,
    pub owner_ids: Vec<i64>,
    pub allowed_user_ids: Vec<i64>,
    pub allow_inline_widgets: bool,
    pub webapp_base_url: String,
    pub widget_port: u16,
    pub force_ipv4: bool,
    pub poll_timeout: u64,
    pub wd_soft: f64,
    pub wd_hard: f64,
    pub stream_interval: f64,
    pub agy_job_timeout: u64,
    pub agy_skills_dir: PathBuf,
    pub skillport_skills_dir: PathBuf,
    pub skills_catalog_json: PathBuf,
    pub mcp_config_path: PathBuf,
    pub ai_memory_mcp_bin: PathBuf,
    pub skills_catalog_mcp_bin: PathBuf,
    pub premium_ui: bool,
    pub tg_transport: TransportMode,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub proxy_urls: Vec<String>,
    pub proxy_mode: ProxyMode,
    pub agy_engine: EngineKind,
    pub cron_enabled: bool,
    pub sync_interval_s: u64,
    pub venice_api_base: String,
    pub venice_api_key: String,
    pub acct_policy_preset: String,
    pub acct_weekly_reserve_pct: f64,
    pub acct_weekly_token_budget: u64,
    pub acct_max_concurrency: Option<u32>,
    pub acct_min_gap_secs: Option<u64>,
    pub acct_switch_delay_secs: Option<u64>,
    pub acct_max_attempts: Option<usize>,
    pub pool_severe_breaker_n: u32,
    pub pool_severe_breaker_window_secs: u64,
    pub acct_proxy_fallback: ProxyFallbackPolicy,
    /// Phase 3: live `agy` stream guard — max distinct tool calls per turn (0 = disabled).
    pub agy_max_steps_per_turn: usize,
    /// Phase 3: live `agy` stream guard — max consecutive identical tool calls (0 = disabled).
    pub agy_tool_repeat_limit: usize,
    /// Phase 3: live `agy` stream guard — max tool calls per sliding 60s window (0 = disabled).
    pub agy_max_tools_per_min: usize,
    /// Phase 3: HTTP server (`:8787`) per-IP requests/min limit (0 = disabled).
    pub http_rl_per_min: u32,
    /// Phase 3: HTTP server max concurrent in-flight requests.
    pub http_max_concurrency: usize,
    /// Phase 3: HTTP server per-request timeout in seconds.
    pub http_req_timeout_secs: u64,
    /// Phase 3: Telegram per-UID commands/callbacks/messages per minute (0 = disabled).
    pub tg_user_rl_per_min: u32,
    /// Phase 3: Global server-wide cap on concurrent AI jobs (anti-OOM).
    pub max_global_ai_jobs: usize,
    /// Phase 3: Maximum pending unapproved `/start` records persisted in `acl.json`.
    pub acl_max_pending: usize,
    /// Phase 3: Scan text/config outbox files for suspected secret leaks before Telegram upload.
    pub outbox_secret_scan: bool,
    /// Phase 4: Use compact 1-line bridge header on resumed conversations (full header on first turn/failover).
    pub prompt_compact_resume: bool,
    /// Phase 4: Classify prompts locally into lite/standard/full without disabling MCPs/skills/.md rules.
    pub agy_dynamic_profile: bool,
    /// Phase 4: Answer unambiguous ping/time/status/math queries locally in Rust (zero AI tokens).
    pub local_fast_path: bool,
    /// Phase 4: Short-TTL cache (seconds) for verified read-only MCP calls (0 = disabled).
    pub mcp_ro_cache_ttl_secs: u64,
    /// Phase 4: Early head+tail compaction cap (bytes) for heavy Grok/Venice tool outputs.
    pub agent_tool_output_max_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bot_token: String::new(),
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
            agy_workspace: PathBuf::from(DEFAULT_WORKSPACE),
            agy_bin: PathBuf::from(DEFAULT_AGY_BIN),
            owner_id: DEFAULT_OWNER_ID,
            owner_ids: vec![DEFAULT_OWNER_ID],
            allowed_user_ids: Vec::new(),
            allow_inline_widgets: false,
            webapp_base_url: DEFAULT_WEBAPP_BASE_URL.to_string(),
            widget_port: DEFAULT_WIDGET_PORT,
            force_ipv4: true,
            poll_timeout: DEFAULT_POLL_TIMEOUT,
            wd_soft: DEFAULT_WD_SOFT,
            wd_hard: DEFAULT_WD_HARD,
            stream_interval: DEFAULT_STREAM_INTERVAL,
            agy_job_timeout: DEFAULT_AGY_JOB_TIMEOUT,
            agy_skills_dir: PathBuf::from(DEFAULT_SKILLS_DIR),
            skillport_skills_dir: PathBuf::from(DEFAULT_SKILLPORT_DIR),
            skills_catalog_json: PathBuf::from(DEFAULT_SKILLS_CATALOG_JSON),
            mcp_config_path: PathBuf::from(DEFAULT_MCP_CONFIG_PATH),
            ai_memory_mcp_bin: PathBuf::from(DEFAULT_AI_MEMORY_MCP_BIN),
            skills_catalog_mcp_bin: PathBuf::from(DEFAULT_SKILLS_CATALOG_MCP_BIN),
            premium_ui: true,
            tg_transport: TransportMode::Polling,
            webhook_url: None,
            webhook_secret: None,
            proxy_urls: Vec::new(),
            proxy_mode: ProxyMode::Failover,
            agy_engine: EngineKind::Agy,
            cron_enabled: true,
            sync_interval_s: DEFAULT_SYNC_INTERVAL_S,
            venice_api_base: DEFAULT_VENICE_API_BASE.to_string(),
            venice_api_key: DEFAULT_VENICE_API_KEY.to_string(),
            acct_policy_preset: "strict_safe".to_string(),
            acct_weekly_reserve_pct: 1.0,
            acct_weekly_token_budget: 0,
            acct_max_concurrency: None,
            acct_min_gap_secs: None,
            acct_switch_delay_secs: None,
            acct_max_attempts: None,
            pool_severe_breaker_n: 2,
            pool_severe_breaker_window_secs: 900,
            acct_proxy_fallback: ProxyFallbackPolicy::FailClosed,
            agy_max_steps_per_turn: 120,
            agy_tool_repeat_limit: 4,
            agy_max_tools_per_min: 90,
            http_rl_per_min: 120,
            http_max_concurrency: 64,
            http_req_timeout_secs: 30,
            tg_user_rl_per_min: 30,
            max_global_ai_jobs: 4,
            acl_max_pending: 100,
            outbox_secret_scan: true,
            prompt_compact_resume: true,
            agy_dynamic_profile: true,
            local_fast_path: true,
            mcp_ro_cache_ttl_secs: 45,
            agent_tool_output_max_bytes: 32_768,
        }
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token_view = if self.bot_token.is_empty() {
            ""
        } else {
            "[REDACTED]"
        };
        let secret_view = self.webhook_secret.as_ref().map(|_| "[REDACTED]");
        let redacted_proxies: Vec<String> =
            self.proxy_urls.iter().map(|u| redact_proxy_url(u)).collect();

        f.debug_struct("Config")
            .field("bot_token", &token_view)
            .field("state_dir", &self.state_dir)
            .field("agy_workspace", &self.agy_workspace)
            .field("agy_bin", &self.agy_bin)
            .field("owner_id", &self.owner_id)
            .field("owner_ids", &self.owner_ids)
            .field("allowed_user_ids", &self.allowed_user_ids)
            .field("allow_inline_widgets", &self.allow_inline_widgets)
            .field("webapp_base_url", &self.webapp_base_url)
            .field("widget_port", &self.widget_port)
            .field("force_ipv4", &self.force_ipv4)
            .field("poll_timeout", &self.poll_timeout)
            .field("wd_soft", &self.wd_soft)
            .field("wd_hard", &self.wd_hard)
            .field("stream_interval", &self.stream_interval)
            .field("agy_job_timeout", &self.agy_job_timeout)
            .field("agy_skills_dir", &self.agy_skills_dir)
            .field("skillport_skills_dir", &self.skillport_skills_dir)
            .field("skills_catalog_json", &self.skills_catalog_json)
            .field("mcp_config_path", &self.mcp_config_path)
            .field("ai_memory_mcp_bin", &self.ai_memory_mcp_bin)
            .field("skills_catalog_mcp_bin", &self.skills_catalog_mcp_bin)
            .field("premium_ui", &self.premium_ui)
            .field("tg_transport", &self.tg_transport)
            .field("webhook_url", &self.webhook_url)
            .field("webhook_secret", &secret_view)
            .field("proxy_urls", &redacted_proxies)
            .field("proxy_mode", &self.proxy_mode)
            .field("agy_engine", &self.agy_engine)
            .field("cron_enabled", &self.cron_enabled)
            .field("sync_interval_s", &self.sync_interval_s)
            .field("venice_api_base", &self.venice_api_base)
            .field("venice_api_key", &if self.venice_api_key.is_empty() { "" } else { "[REDACTED]" })
            .field("acct_policy_preset", &self.acct_policy_preset)
            .field("acct_weekly_reserve_pct", &self.acct_weekly_reserve_pct)
            .field("acct_weekly_token_budget", &self.acct_weekly_token_budget)
            .field("acct_max_concurrency", &self.acct_max_concurrency)
            .field("acct_min_gap_secs", &self.acct_min_gap_secs)
            .field("acct_switch_delay_secs", &self.acct_switch_delay_secs)
            .field("acct_max_attempts", &self.acct_max_attempts)
            .field("pool_severe_breaker_n", &self.pool_severe_breaker_n)
            .field("pool_severe_breaker_window_secs", &self.pool_severe_breaker_window_secs)
            .field("acct_proxy_fallback", &self.acct_proxy_fallback)
            .field("agy_max_steps_per_turn", &self.agy_max_steps_per_turn)
            .field("agy_tool_repeat_limit", &self.agy_tool_repeat_limit)
            .field("agy_max_tools_per_min", &self.agy_max_tools_per_min)
            .field("http_rl_per_min", &self.http_rl_per_min)
            .field("http_max_concurrency", &self.http_max_concurrency)
            .field("http_req_timeout_secs", &self.http_req_timeout_secs)
            .field("tg_user_rl_per_min", &self.tg_user_rl_per_min)
            .field("max_global_ai_jobs", &self.max_global_ai_jobs)
            .field("acl_max_pending", &self.acl_max_pending)
            .field("outbox_secret_scan", &self.outbox_secret_scan)
            .field("prompt_compact_resume", &self.prompt_compact_resume)
            .field("agy_dynamic_profile", &self.agy_dynamic_profile)
            .field("local_fast_path", &self.local_fast_path)
            .field("mcp_ro_cache_ttl_secs", &self.mcp_ro_cache_ttl_secs)
            .field("agent_tool_output_max_bytes", &self.agent_tool_output_max_bytes)
            .finish()
    }
}

impl Config {
    /// Loads configuration from process environment variables.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Loads configuration using an arbitrary key lookup closure (useful in tests).
    pub fn from_lookup<F>(mut get: F) -> Result<Self>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut cfg = Self::default();

        if let Some(v) = non_empty(get("BOT_TOKEN")) {
            cfg.bot_token = v;
        }
        if let Some(v) = non_empty(get("STATE_DIR")) {
            cfg.state_dir = PathBuf::from(v);
        }
        if let Some(v) = non_empty(get("AGY_WORKSPACE")) {
            cfg.agy_workspace = PathBuf::from(v);
        }
        if let Some(v) = non_empty(get("AGY_BIN")) {
            cfg.agy_bin = PathBuf::from(v);
        }
        let mut owner_from_env = false;
        if let Some(v) = non_empty(get("OWNER_ID")) {
            let ids = parse_id_list(&v)?;
            if let Some(&first) = ids.first() {
                cfg.owner_id = first;
                cfg.owner_ids = ids;
                owner_from_env = true;
            }
        }
        if let Some(v) = non_empty(get("OWNER_IDS")) {
            let ids = parse_id_list(&v)?;
            if !ids.is_empty() {
                if !owner_from_env {
                    cfg.owner_id = ids[0];
                    cfg.owner_ids = ids;
                } else {
                    for id in ids {
                        if !cfg.owner_ids.contains(&id) {
                            cfg.owner_ids.push(id);
                        }
                    }
                }
            }
        }
        if let Some(v) = get("ALLOWED_USER_IDS") {
            cfg.allowed_user_ids = parse_id_list(&v)?;
        }
        if let Some(v) = get("ALLOW_INLINE_WIDGETS") {
            cfg.allow_inline_widgets = parse_bool(&v, "ALLOW_INLINE_WIDGETS", false)?;
        }
        if let Some(v) = non_empty(get("WEBAPP_BASE_URL")) {
            cfg.webapp_base_url = v.trim_end_matches('/').to_string();
        }
        if let Some(v) = non_empty(get("WIDGET_PORT")) {
            cfg.widget_port = parse_int(&v, "WIDGET_PORT")?;
        }
        if let Some(v) = get("FORCE_IPV4") {
            cfg.force_ipv4 = parse_bool(&v, "FORCE_IPV4", true)?;
        }
        if let Some(v) = non_empty(get("POLL_TIMEOUT")) {
            cfg.poll_timeout = parse_int(&v, "POLL_TIMEOUT")?;
        }
        if let Some(v) = non_empty(get("WD_SOFT")) {
            cfg.wd_soft = parse_f64(&v, "WD_SOFT")?;
        }
        if let Some(v) = non_empty(get("WD_HARD")) {
            cfg.wd_hard = parse_f64(&v, "WD_HARD")?;
        }
        if let Some(v) = non_empty(get("STREAM_INTERVAL")) {
            cfg.stream_interval = parse_f64(&v, "STREAM_INTERVAL")?;
        }
        if let Some(v) = non_empty(get("AGY_JOB_TIMEOUT")) {
            cfg.agy_job_timeout = parse_int(&v, "AGY_JOB_TIMEOUT")?;
        }
        if let Some(v) = non_empty(get("AGY_SKILLS_DIR")) {
            cfg.agy_skills_dir = PathBuf::from(v);
        }
        if let Some(v) = non_empty(get("SKILLPORT_SKILLS_DIR")) {
            cfg.skillport_skills_dir = PathBuf::from(v);
        }
        if let Some(v) = non_empty(get("SKILLS_CATALOG_JSON")) {
            cfg.skills_catalog_json = PathBuf::from(v);
        }
        if let Some(v) = non_empty(get("MCP_CONFIG_PATH")) {
            cfg.mcp_config_path = PathBuf::from(v);
        }
        if let Some(v) = non_empty(get("AI_MEMORY_MCP_BIN")) {
            cfg.ai_memory_mcp_bin = PathBuf::from(v);
        }
        if let Some(v) = non_empty(get("SKILLS_CATALOG_MCP_BIN")) {
            cfg.skills_catalog_mcp_bin = PathBuf::from(v);
        }
        if let Some(v) = get("PREMIUM_UI") {
            cfg.premium_ui = parse_bool(&v, "PREMIUM_UI", true)?;
        }
        if let Some(v) = non_empty(get("TG_TRANSPORT")) {
            cfg.tg_transport = v.parse()?;
        }
        cfg.webhook_url = non_empty(get("WEBHOOK_URL"));
        cfg.webhook_secret = non_empty(get("WEBHOOK_SECRET"));
        if let Some(v) = get("PROXY_URLS") {
            cfg.proxy_urls = parse_string_list(&v);
        }
        if let Some(v) = non_empty(get("PROXY_MODE")) {
            cfg.proxy_mode = v.parse()?;
        }
        if let Some(v) = non_empty(get("AGY_ENGINE")) {
            cfg.agy_engine = v.parse()?;
        }
        if let Some(v) = get("CRON_ENABLED") {
            cfg.cron_enabled = parse_bool(&v, "CRON_ENABLED", true)?;
        }
        if let Some(v) = non_empty(get("SYNC_INTERVAL_S")) {
            cfg.sync_interval_s = parse_int(&v, "SYNC_INTERVAL_S")?;
        }
        if let Some(v) = non_empty(get("VENICE_API_BASE")) {
            cfg.venice_api_base = v;
        }
        if let Some(v) = non_empty(get("VENICE_API_KEY")) {
            cfg.venice_api_key = v;
        }
        if let Some(v) = non_empty(get("ACCT_POLICY_PRESET")) {
            let preset: AccountPolicyPreset = v.parse()?;
            cfg.acct_policy_preset = preset.as_str().to_string();
        }
        if let Some(v) = non_empty(get("ACCT_WEEKLY_RESERVE_PCT")) {
            cfg.acct_weekly_reserve_pct = parse_f64(&v, "ACCT_WEEKLY_RESERVE_PCT")?.clamp(0.0, 25.0);
        }
        if let Some(v) = non_empty(get("ACCT_WEEKLY_TOKEN_BUDGET")) {
            cfg.acct_weekly_token_budget = parse_int(&v, "ACCT_WEEKLY_TOKEN_BUDGET")?;
        }
        if let Some(v) = non_empty(get("ACCT_MAX_CONCURRENCY")) {
            cfg.acct_max_concurrency = Some(parse_int::<u32>(&v, "ACCT_MAX_CONCURRENCY")?.clamp(1, 8));
        }
        if let Some(v) = non_empty(get("ACCT_MIN_GAP_SECS")) {
            cfg.acct_min_gap_secs = Some(parse_int::<u64>(&v, "ACCT_MIN_GAP_SECS")?.min(300));
        }
        if let Some(v) = non_empty(get("ACCT_SWITCH_DELAY_SECS")) {
            cfg.acct_switch_delay_secs = Some(parse_int::<u64>(&v, "ACCT_SWITCH_DELAY_SECS")?.min(120));
        }
        if let Some(v) = non_empty(get("ACCT_MAX_ATTEMPTS")) {
            cfg.acct_max_attempts = Some(parse_int::<usize>(&v, "ACCT_MAX_ATTEMPTS")?.clamp(1, 8));
        }
        if let Some(v) = non_empty(get("POOL_SEVERE_BREAKER_N")) {
            cfg.pool_severe_breaker_n = parse_int(&v, "POOL_SEVERE_BREAKER_N")?;
        }
        if let Some(v) = non_empty(get("POOL_SEVERE_BREAKER_WINDOW_SECS")) {
            cfg.pool_severe_breaker_window_secs =
                parse_int::<u64>(&v, "POOL_SEVERE_BREAKER_WINDOW_SECS")?.clamp(60, 86_400);
        }
        if let Some(v) = non_empty(get("ACCT_PROXY_FALLBACK")) {
            cfg.acct_proxy_fallback = v.parse()?;
        }
        if let Some(v) = non_empty(get("AGY_MAX_STEPS_PER_TURN")) {
            cfg.agy_max_steps_per_turn =
                parse_int::<usize>(&v, "AGY_MAX_STEPS_PER_TURN")?.min(1000);
        }
        if let Some(v) = non_empty(get("AGY_TOOL_REPEAT_LIMIT")) {
            cfg.agy_tool_repeat_limit = parse_int::<usize>(&v, "AGY_TOOL_REPEAT_LIMIT")?.min(50);
        }
        if let Some(v) = non_empty(get("AGY_MAX_TOOLS_PER_MIN")) {
            cfg.agy_max_tools_per_min = parse_int::<usize>(&v, "AGY_MAX_TOOLS_PER_MIN")?.min(300);
        }
        if let Some(v) = non_empty(get("HTTP_RL_PER_MIN")) {
            cfg.http_rl_per_min = parse_int::<u32>(&v, "HTTP_RL_PER_MIN")?.min(10_000);
        }
        if let Some(v) = non_empty(get("HTTP_MAX_CONCURRENCY")) {
            cfg.http_max_concurrency =
                parse_int::<usize>(&v, "HTTP_MAX_CONCURRENCY")?.clamp(4, 1024);
        }
        if let Some(v) = non_empty(get("HTTP_REQ_TIMEOUT_SECS")) {
            cfg.http_req_timeout_secs =
                parse_int::<u64>(&v, "HTTP_REQ_TIMEOUT_SECS")?.clamp(5, 300);
        }
        if let Some(v) = non_empty(get("TG_USER_RL_PER_MIN")) {
            cfg.tg_user_rl_per_min = parse_int::<u32>(&v, "TG_USER_RL_PER_MIN")?.min(600);
        }
        if let Some(v) = non_empty(get("MAX_GLOBAL_AI_JOBS"))
            .or_else(|| non_empty(get("MAX_GLOBAL_CONCURRENT_JOBS")))
        {
            cfg.max_global_ai_jobs = parse_int::<usize>(&v, "MAX_GLOBAL_AI_JOBS")?.clamp(1, 32);
        }
        if let Some(v) = non_empty(get("ACL_MAX_PENDING")) {
            cfg.acl_max_pending = parse_int::<usize>(&v, "ACL_MAX_PENDING")?.clamp(10, 5000);
        }
        if let Some(v) = get("OUTBOX_SECRET_SCAN") {
            cfg.outbox_secret_scan = parse_bool(&v, "OUTBOX_SECRET_SCAN", true)?;
        }
        if let Some(v) = get("PROMPT_COMPACT_RESUME") {
            cfg.prompt_compact_resume = parse_bool(&v, "PROMPT_COMPACT_RESUME", true)?;
        }
        if let Some(v) = get("AGY_DYNAMIC_PROFILE") {
            cfg.agy_dynamic_profile = parse_bool(&v, "AGY_DYNAMIC_PROFILE", true)?;
        }
        if let Some(v) = get("LOCAL_FAST_PATH") {
            cfg.local_fast_path = parse_bool(&v, "LOCAL_FAST_PATH", true)?;
        }
        if let Some(v) = non_empty(get("MCP_RO_CACHE_TTL_SECS")) {
            cfg.mcp_ro_cache_ttl_secs = parse_int::<u64>(&v, "MCP_RO_CACHE_TTL_SECS")?.min(600);
        }
        if let Some(v) = non_empty(get("AGENT_TOOL_OUTPUT_MAX_BYTES")) {
            cfg.agent_tool_output_max_bytes =
                parse_int::<usize>(&v, "AGENT_TOOL_OUTPUT_MAX_BYTES")?.clamp(4096, 65_536);
        }

        Ok(cfg)
    }

    /// Validates runtime invariants required to start the bridge daemon.
    pub fn validate(&self) -> Result<()> {
        if self.bot_token.trim().is_empty() {
            return Err(BridgeError::Config("BOT_TOKEN must be non-empty".into()));
        }
        if !self.wd_soft.is_finite()
            || !self.wd_hard.is_finite()
            || self.wd_soft <= 0.0
            || self.wd_hard < self.wd_soft
            || self.wd_hard > 86_400.0
        {
            return Err(BridgeError::Config(format!(
                "invalid watchdog thresholds: WD_SOFT={} WD_HARD={}",
                self.wd_soft, self.wd_hard
            )));
        }
        if self.poll_timeout == 0 {
            return Err(BridgeError::Config("POLL_TIMEOUT must be > 0".into()));
        }
        if (self.poll_timeout as f64) >= self.wd_soft {
            return Err(BridgeError::Config(format!(
                "POLL_TIMEOUT ({}) must be strictly less than WD_SOFT ({})",
                self.poll_timeout, self.wd_soft
            )));
        }
        if self.sync_interval_s == 0 {
            return Err(BridgeError::Config("SYNC_INTERVAL_S must be > 0".into()));
        }
        if matches!(self.tg_transport, TransportMode::Webhook) {
            let url_ok = self
                .webhook_url
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty());
            let sec_ok = self
                .webhook_secret
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty());
            if !url_ok {
                return Err(BridgeError::Config(
                    "WEBHOOK_URL must be set when TG_TRANSPORT=webhook".into(),
                ));
            }
            if !sec_ok {
                return Err(BridgeError::Config(
                    "WEBHOOK_SECRET must be set when TG_TRANSPORT=webhook".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn state_path(&self) -> PathBuf {
        self.state_dir.join("state.json")
    }

    pub fn acl_path(&self) -> PathBuf {
        self.state_dir.join("acl.json")
    }

    pub fn outbox_path(&self) -> PathBuf {
        self.state_dir.join("outqueue.json")
    }

    pub fn health_path(&self) -> PathBuf {
        self.state_dir.join("health.json")
    }

    pub fn offset_path(&self) -> PathBuf {
        self.state_dir.join("offset")
    }

    pub fn widgets_path(&self) -> PathBuf {
        self.state_dir.join("widgets.json")
    }

    pub fn cron_jobs_path(&self) -> PathBuf {
        self.state_dir.join("cron_jobs.json")
    }

    pub fn proxies_path(&self) -> PathBuf {
        self.state_dir.join("proxies.json")
    }

    /// Construct the effective [`AccountPolicy`] from preset + explicit env overrides.
    pub fn account_policy(&self) -> AccountPolicy {
        let preset = self
            .acct_policy_preset
            .parse::<AccountPolicyPreset>()
            .unwrap_or(AccountPolicyPreset::StrictSafe);
        let mut pol = AccountPolicy::from_preset(preset);
        pol.weekly_reserve_pct = self.acct_weekly_reserve_pct.clamp(0.0, 25.0);
        pol.default_weekly_token_budget = self.acct_weekly_token_budget;
        if let Some(c) = self.acct_max_concurrency {
            pol.max_concurrency_per_account = c.clamp(1, 8);
        }
        if let Some(g) = self.acct_min_gap_secs {
            pol.min_gap_secs = g.min(300);
        }
        if let Some(d) = self.acct_switch_delay_secs {
            pol.switch_delay_secs = d.min(120);
        }
        if let Some(a) = self.acct_max_attempts {
            pol.max_failover_attempts = a.clamp(1, 8);
        }
        pol.pool_breaker_threshold = self.pool_severe_breaker_n;
        pol.pool_breaker_window_secs = self.pool_severe_breaker_window_secs.clamp(60, 86_400);
        pol.sanitized()
    }

    pub fn inbox_dir(&self) -> PathBuf {
        self.agy_workspace.join("inbox")
    }

    pub fn outbox_dir(&self) -> PathBuf {
        self.agy_workspace.join("outbox")
    }
}

fn non_empty(raw: Option<String>) -> Option<String> {
    raw.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn parse_int<T: FromStr>(raw: &str, name: &str) -> Result<T>
where
    T::Err: fmt::Display,
{
    raw.trim()
        .parse::<T>()
        .map_err(|e| BridgeError::Config(format!("invalid {name}='{raw}': {e}")))
}

fn parse_f64(raw: &str, name: &str) -> Result<f64> {
    let val = raw
        .trim()
        .parse::<f64>()
        .map_err(|e| BridgeError::Config(format!("invalid {name}='{raw}': {e}")))?;
    if !val.is_finite() {
        return Err(BridgeError::Config(format!(
            "invalid {name}='{raw}': must be finite"
        )));
    }
    Ok(val)
}

fn parse_bool(raw: &str, name: &str, default_val: bool) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default_val),
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(BridgeError::Config(format!(
            "invalid boolean for {name}: '{other}'"
        ))),
    }
}

fn parse_id_list(raw: &str) -> Result<Vec<i64>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for part in raw.split([',', ';']) {
        let s = part.trim();
        if s.is_empty() {
            continue;
        }
        let uid = s
            .parse::<i64>()
            .map_err(|e| BridgeError::Config(format!("invalid ALLOWED_USER_IDS entry '{s}': {e}")))?;
        if seen.insert(uid) {
            out.push(uid);
        }
    }
    Ok(out)
}

fn parse_string_list(raw: &str) -> Vec<String> {
    raw.split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn defaults_match_python_bridge() {
        let empty: HashMap<&str, &str> = HashMap::new();
        let cfg = Config::from_lookup(|k| empty.get(k).map(|s| (*s).to_string())).unwrap();

        assert_eq!(cfg.bot_token, "");
        assert_eq!(cfg.state_dir, PathBuf::from("/var/lib/agy-telegram"));
        assert_eq!(cfg.agy_workspace, PathBuf::from("/root/agy-workspace"));
        assert_eq!(cfg.agy_bin, PathBuf::from("/root/.local/bin/agy"));
        assert_eq!(cfg.owner_id, 1_000_000_001);
        assert!(cfg.allowed_user_ids.is_empty());
        assert!(!cfg.allow_inline_widgets);
        assert_eq!(cfg.webapp_base_url, "https://example.sslip.io");
        assert_eq!(cfg.widget_port, 8787);
        assert!(cfg.force_ipv4);
        assert_eq!(cfg.poll_timeout, 30);
        assert_eq!(cfg.wd_soft, 75.0);
        assert_eq!(cfg.wd_hard, 300.0);
        assert_eq!(cfg.stream_interval, 20.0);
        assert_eq!(cfg.agy_job_timeout, 1800);
        assert!(cfg.premium_ui);
        assert_eq!(cfg.tg_transport, TransportMode::Polling);
        assert_eq!(cfg.proxy_mode, ProxyMode::Failover);
        assert_eq!(cfg.agy_engine, EngineKind::Agy);
        assert!(cfg.cron_enabled);
        assert_eq!(cfg.sync_interval_s, 300);
    }

    #[test]
    fn parses_all_env_keys_and_redacts_secrets_in_debug() {
        let mut map = HashMap::new();
        map.insert("BOT_TOKEN", "123456:SUPER_SECRET_BOT_TOKEN");
        map.insert("STATE_DIR", "/tmp/agy-state");
        map.insert("AGY_WORKSPACE", "/tmp/ws");
        map.insert("AGY_BIN", "/usr/local/bin/agy");
        map.insert("OWNER_ID", "999");
        map.insert("ALLOWED_USER_IDS", "101; 202, 101, -303,");
        map.insert("ALLOW_INLINE_WIDGETS", "1");
        map.insert("WEBAPP_BASE_URL", "https://example.org/app///");
        map.insert("WIDGET_PORT", "9090");
        map.insert("FORCE_IPV4", "0");
        map.insert("POLL_TIMEOUT", "45");
        map.insert("WD_SOFT", "90.5");
        map.insert("WD_HARD", "400");
        map.insert("STREAM_INTERVAL", "12.5");
        map.insert("AGY_JOB_TIMEOUT", "2400");
        map.insert("AGY_SKILLS_DIR", "/tmp/skills");
        map.insert("SKILLPORT_SKILLS_DIR", "/tmp/skillport");
        map.insert("SKILLS_CATALOG_JSON", "/tmp/catalog.json");
        map.insert("MCP_CONFIG_PATH", "/tmp/mcp.json");
        map.insert("AI_MEMORY_MCP_BIN", "/tmp/aimem");
        map.insert("SKILLS_CATALOG_MCP_BIN", "/tmp/skcat");
        map.insert("PREMIUM_UI", "0");
        map.insert("TG_TRANSPORT", "auto");
        map.insert("WEBHOOK_URL", "https://example.org/hook");
        map.insert("WEBHOOK_SECRET", "my-webhook-secret-xyz");
        map.insert(
            "PROXY_URLS",
            "http://alice:p@ssword@10.0.0.1:8080, socks5h://bob:s3cr3t@[::1]:1080; http://127.0.0.1:3128",
        );
        map.insert("PROXY_MODE", "round_robin");
        map.insert("AGY_ENGINE", "claude-code");
        map.insert("CRON_ENABLED", "false");
        map.insert("SYNC_INTERVAL_S", "120");

        let cfg = Config::from_lookup(|k| map.get(k).map(|s| (*s).to_string())).unwrap();
        cfg.validate().unwrap();

        assert_eq!(cfg.allowed_user_ids, vec![101, 202, -303]);
        assert!(cfg.allow_inline_widgets);
        assert_eq!(cfg.webapp_base_url, "https://example.org/app");
        assert_eq!(cfg.widget_port, 9090);
        assert!(!cfg.force_ipv4);
        assert!(!cfg.premium_ui);
        assert_eq!(cfg.tg_transport, TransportMode::Auto);
        assert_eq!(cfg.proxy_mode, ProxyMode::RoundRobin);
        assert_eq!(cfg.agy_engine, EngineKind::Custom("claude-code".into()));
        assert!(!cfg.cron_enabled);
        assert_eq!(cfg.sync_interval_s, 120);

        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("SUPER_SECRET_BOT_TOKEN"));
        assert!(!dbg.contains("my-webhook-secret-xyz"));
        assert!(!dbg.contains("alice"));
        assert!(!dbg.contains("p@ssword"));
        assert!(!dbg.contains("bob"));
        assert!(!dbg.contains("s3cr3t"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(dbg.contains("http://[REDACTED]@10.0.0.1:8080"));
        assert!(dbg.contains("socks5h://[REDACTED]@[::1]:1080"));
        assert!(dbg.contains("http://127.0.0.1:3128"));
    }

    #[test]
    fn redact_proxy_url_preserves_at_in_path_and_handles_no_scheme() {
        assert_eq!(
            redact_proxy_url("http://proxy.local:8080/foo@bar"),
            "http://proxy.local:8080/foo@bar"
        );
        assert_eq!(
            redact_proxy_url("user:secret@10.0.0.2:1080"),
            "[REDACTED]@10.0.0.2:1080"
        );
        assert_eq!(
            redact_proxy_url("http://token@proxy.local:8080"),
            "http://[REDACTED]@proxy.local:8080"
        );
    }

    #[test]
    fn invalid_values_return_config_error() {
        let mut map = HashMap::new();
        map.insert("TG_TRANSPORT", "carrier_pigeon");
        assert!(matches!(
            Config::from_lookup(|k| map.get(k).map(|s| (*s).to_string())),
            Err(BridgeError::Config(_))
        ));

        map.clear();
        map.insert("PROXY_MODE", "random");
        assert!(matches!(
            Config::from_lookup(|k| map.get(k).map(|s| (*s).to_string())),
            Err(BridgeError::Config(_))
        ));

        map.clear();
        map.insert("WIDGET_PORT", "not_a_port");
        assert!(matches!(
            Config::from_lookup(|k| map.get(k).map(|s| (*s).to_string())),
            Err(BridgeError::Config(_))
        ));

        map.clear();
        map.insert("WD_SOFT", "NaN");
        assert!(matches!(
            Config::from_lookup(|k| map.get(k).map(|s| (*s).to_string())),
            Err(BridgeError::Config(_))
        ));
    }

    #[test]
    fn validate_rejects_missing_token_webhook_url_and_bad_bounds() {
        let mut cfg = Config::default();
        assert!(matches!(cfg.validate(), Err(BridgeError::Config(_))));

        cfg.bot_token = "123:abc".into();
        cfg.validate().unwrap();

        cfg.tg_transport = TransportMode::Webhook;
        assert!(matches!(cfg.validate(), Err(BridgeError::Config(_))));
        cfg.webhook_url = Some("https://example.org/hook".into());
        assert!(matches!(cfg.validate(), Err(BridgeError::Config(_))));
        cfg.webhook_secret = Some("test-webhook-secret".into());
        cfg.validate().unwrap();

        cfg.wd_soft = 400.0;
        cfg.wd_hard = 100.0;
        assert!(matches!(cfg.validate(), Err(BridgeError::Config(_))));
    }

    #[test]
    fn phase3_guard_env_vars_parse_and_clamp() {
        let mut map = HashMap::new();
        map.insert("AGY_MAX_STEPS_PER_TURN", "80");
        map.insert("AGY_TOOL_REPEAT_LIMIT", "5");
        map.insert("AGY_MAX_TOOLS_PER_MIN", "60");
        map.insert("HTTP_RL_PER_MIN", "240");
        map.insert("HTTP_MAX_CONCURRENCY", "128");
        map.insert("HTTP_REQ_TIMEOUT_SECS", "45");
        map.insert("TG_USER_RL_PER_MIN", "50");
        map.insert("MAX_GLOBAL_AI_JOBS", "6");
        map.insert("ACL_MAX_PENDING", "250");
        map.insert("OUTBOX_SECRET_SCAN", "false");

        let cfg = Config::from_lookup(|k| map.get(k).map(|s| (*s).to_string())).unwrap();
        assert_eq!(cfg.agy_max_steps_per_turn, 80);
        assert_eq!(cfg.agy_tool_repeat_limit, 5);
        assert_eq!(cfg.agy_max_tools_per_min, 60);
        assert_eq!(cfg.http_rl_per_min, 240);
        assert_eq!(cfg.http_max_concurrency, 128);
        assert_eq!(cfg.http_req_timeout_secs, 45);
        assert_eq!(cfg.tg_user_rl_per_min, 50);
        assert_eq!(cfg.max_global_ai_jobs, 6);
        assert_eq!(cfg.acl_max_pending, 250);
        assert!(!cfg.outbox_secret_scan);

        // Out-of-range bounds clamp safely
        let mut hi = HashMap::new();
        hi.insert("MAX_GLOBAL_CONCURRENT_JOBS", "999");
        hi.insert("HTTP_REQ_TIMEOUT_SECS", "1");
        hi.insert("ACL_MAX_PENDING", "2");
        let cfg2 = Config::from_lookup(|k| hi.get(k).map(|s| (*s).to_string())).unwrap();
        assert_eq!(cfg2.max_global_ai_jobs, 32);
        assert_eq!(cfg2.http_req_timeout_secs, 5);
        assert_eq!(cfg2.acl_max_pending, 10);
    }

    #[test]
    fn phase4_token_hygiene_env_vars_parse_and_clamp() {
        let mut map = HashMap::new();
        map.insert("PROMPT_COMPACT_RESUME", "0");
        map.insert("AGY_DYNAMIC_PROFILE", "false");
        map.insert("LOCAL_FAST_PATH", "no");
        map.insert("MCP_RO_CACHE_TTL_SECS", "90");
        map.insert("AGENT_TOOL_OUTPUT_MAX_BYTES", "24576");
        let cfg = Config::from_lookup(|k| map.get(k).map(|s| (*s).to_string())).unwrap();
        assert!(!cfg.prompt_compact_resume);
        assert!(!cfg.agy_dynamic_profile);
        assert!(!cfg.local_fast_path);
        assert_eq!(cfg.mcp_ro_cache_ttl_secs, 90);
        assert_eq!(cfg.agent_tool_output_max_bytes, 24576);

        let mut clamp = HashMap::new();
        clamp.insert("MCP_RO_CACHE_TTL_SECS", "9999");
        clamp.insert("AGENT_TOOL_OUTPUT_MAX_BYTES", "128");
        let cfg2 = Config::from_lookup(|k| clamp.get(k).map(|s| (*s).to_string())).unwrap();
        assert_eq!(cfg2.mcp_ro_cache_ttl_secs, 600);
        assert_eq!(cfg2.agent_tool_output_max_bytes, 4096);
    }

    #[test]
    fn owner_ids_only_replaces_default_owner_id() {
        let mut map = HashMap::new();
        map.insert("OWNER_IDS", "1111, 2222");
        let cfg = Config::from_lookup(|k| map.get(k).map(|s| (*s).to_string())).unwrap();
        assert_eq!(cfg.owner_id, 1111);
        assert_eq!(cfg.owner_ids, vec![1111, 2222]);
        assert!(
            !cfg.owner_ids.contains(&DEFAULT_OWNER_ID),
            "DEFAULT_OWNER_ID must not leak as a ghost owner when only OWNER_IDS is configured"
        );

        let mut both = HashMap::new();
        both.insert("OWNER_ID", "3333");
        both.insert("OWNER_IDS", "4444, 3333");
        let cfg_both = Config::from_lookup(|k| both.get(k).map(|s| (*s).to_string())).unwrap();
        assert_eq!(cfg_both.owner_id, 3333);
        assert_eq!(cfg_both.owner_ids, vec![3333, 4444]);

        let mut multi = HashMap::new();
        multi.insert("OWNER_ID", "5555, 6666");
        let cfg_multi = Config::from_lookup(|k| multi.get(k).map(|s| (*s).to_string())).unwrap();
        assert_eq!(cfg_multi.owner_id, 5555);
        assert_eq!(cfg_multi.owner_ids, vec![5555, 6666]);
    }
}
