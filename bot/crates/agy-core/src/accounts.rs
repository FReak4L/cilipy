//! Multi-account Antigravity (`agy`) pool: persisted per-account health, failure
//! classification, sticky/least-loaded selection, and per-account isolated `HOME`
//! overlays ("shadow homes").
//!
//! Verified facts about `agy` 1.5.x this module relies on (see docs/ACCOUNTS.md):
//! * every path `agy` touches is `$HOME`-relative (`$HOME/.gemini/...`);
//! * the OAuth credential lives in `$HOME/.gemini/antigravity-cli/antigravity-oauth-token`
//!   (file storage on Linux servers without a keyring);
//! * conversations are local SQLite files in `.../antigravity-cli/conversations/<id>.db`
//!   and `--conversation <id>` resolves them locally (`GetConversationDetail: found
//!   conversation`); an unknown id is silently ignored and a NEW conversation starts.
//!
//! A shadow home therefore symlinks everything from the primary home except the token and
//! a small set of per-process runtime files, so every account shares conversations,
//! artifacts (`brain/`), MCP config, rules and skills while keeping its own credential.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

use crate::atomic::atomic_write_bytes;
use crate::error::{BridgeError, Result};

/// Id of the implicit account that uses the service's own `HOME` login.
pub const PRIMARY_ACCOUNT_ID: &str = "primary";
/// Relative token path inside an account `HOME`.
pub const TOKEN_REL_PATH: &str = ".gemini/antigravity-cli/antigravity-oauth-token";
/// Relative conversations directory inside a `HOME`.
pub const CONVERSATIONS_REL_DIR: &str = ".gemini/antigravity-cli/conversations";
/// Upper bound on configured accounts (sanity guard, not a product limit).
pub const MAX_ACCOUNTS: usize = 64;

/// Files/dirs under `.gemini/antigravity-cli/` that must stay private to each account.
/// Everything else is symlinked to the primary home (shared conversations, brain, MCP...).
pub const PER_ACCOUNT_ENTRIES: &[&str] = &[
    "antigravity-oauth-token",
    "cache",
    "log",
    "cli.log",
    "crashes",
    "updater",
    "last_check.timestamp",
    "installation_id",
    "jetski_state.pbtxt",
    "presence",
    "conversation_summaries.db",
    "conversation_summaries.db-shm",
    "conversation_summaries.db-wal",
    "jetbox_summaries_proto.pb",
    "history.jsonl",
    "implicit",
];

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Failure classification
// ---------------------------------------------------------------------------

/// Category of an `agy` run failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    /// 403 "disabled ... violation of Terms of Service".
    Banned,
    /// "not eligible for Antigravity ... location".
    Ineligible,
    /// Not logged in / token revoked / `invalid_grant` / 401.
    AuthInvalid,
    /// Subscription / plan / credits / seat problems.
    Subscription,
    /// Individual / 5-hour / weekly / daily quota exhausted.
    QuotaExhausted,
    /// Short rate limit (429) that `agy` gave up on.
    RateLimited,
    /// 503 / model capacity / overloaded / 5xx.
    Capacity,
    /// Host network failure (DNS, TCP, TLS). Switching accounts does not help.
    Network,
    /// Process crash / panic / killed without a result.
    Crash,
    /// Request too large / invalid argument (context problem, not account problem).
    ContextProblem,
    /// The requested model is unknown / not offered by this account. Not a health problem:
    /// the caller asks the user to pick one of the account's models.
    ModelUnavailable,
    /// Content safety block — not an account problem.
    ContentBlocked,
    /// Anything else.
    Other,
}

impl FailureClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Banned => "banned (ToS)",
            Self::Ineligible => "not eligible (location)",
            Self::AuthInvalid => "signed out / token invalid",
            Self::Subscription => "subscription / credits",
            Self::QuotaExhausted => "quota exhausted",
            Self::RateLimited => "rate limited",
            Self::Capacity => "model capacity",
            Self::Network => "network error",
            Self::Crash => "agy crashed",
            Self::ContextProblem => "request/context rejected",
            Self::ModelUnavailable => "model not available on this account",
            Self::ContentBlocked => "content blocked",
            Self::Other => "error",
        }
    }

    /// Whether another account may succeed where this one failed.
    pub fn is_account_scoped(self) -> bool {
        matches!(
            self,
            Self::Banned
                | Self::Ineligible
                | Self::AuthInvalid
                | Self::Subscription
                | Self::QuotaExhausted
                | Self::RateLimited
                | Self::Capacity
                | Self::Crash
        )
    }
}

/// What the pool should do with the account after a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureAction {
    /// Retry on the same account after `delay_s` (no health penalty beyond the counter).
    RetrySame { delay_s: u64 },
    /// Put the account in cooldown for `secs` and fail over.
    Cooldown { secs: u64 },
    /// Disable the account until the owner re-logs in / re-enables it, and fail over.
    Disable,
    /// Not an account problem: deliver the error as-is.
    Deliver,
}

/// Which quota horizon was exhausted (used to keep the 1% reserve strictly on weekly usage,
/// never on the 5-hour rolling window).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaScope {
    FiveHour,
    Daily,
    Weekly,
    Unknown,
}

impl QuotaScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::FiveHour => "5-hour",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Unknown => "quota",
        }
    }
}

/// Classification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub class: FailureClass,
    pub action: FailureAction,
    /// Reset hint parsed from the error text (seconds), if any.
    pub reset_secs: Option<u64>,
    /// Quota horizon when `class == FailureClass::QuotaExhausted`.
    pub quota_scope: Option<QuotaScope>,
}

/// Default cooldowns (seconds).
pub const COOLDOWN_QUOTA_DEFAULT: u64 = 5 * 3600;
pub const COOLDOWN_WEEKLY_DEFAULT: u64 = 24 * 3600;
pub const COOLDOWN_DAILY_DEFAULT: u64 = 6 * 3600;
pub const COOLDOWN_RATE_DEFAULT: u64 = 90;
pub const COOLDOWN_CAPACITY_DEFAULT: u64 = 120;
pub const COOLDOWN_CRASH_DEFAULT: u64 = 300;
pub const COOLDOWN_SUBSCRIPTION_DEFAULT: u64 = 24 * 3600;

/// True when agy rejected the requested model (unknown, or not available for this account).
/// Matches the strings found in agy 1.5.x.
pub fn is_model_unavailable(message: &str) -> bool {
    let l = message.to_ascii_lowercase();
    contains_any(
        &l,
        &[
            "available models:",
            "requested model was not found",
            "does not have access to it",
            "cannot be resolved",
            "unknown model",
            "invalid model",
            "model not found",
            "no model is selected",
            "no model configuration is available",
            "references an unknown model",
        ],
    ) || (l.contains("model ") && l.contains(" not found"))
}

fn contains_any(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| hay.contains(n))
}

/// Parse a duration that follows `idx` in `s` (lower-case). Accepts forms such as
/// `3h20m`, `3h 20m 5s`, `45s`, `34.5s`, `2 hours`, `15 minutes`, `1 day`.
fn parse_duration_from(s: &str, idx: usize) -> Option<u64> {
    let tail: String = s[idx..].chars().take(48).collect();
    let bytes = tail.as_bytes();
    let mut i = 0usize;
    let mut total: f64 = 0.0;
    let mut matched = false;
    // skip until first digit (but not too far)
    while i < bytes.len() && !bytes[i].is_ascii_digit() {
        if i > 16 {
            return None;
        }
        i += 1;
    }
    while i < bytes.len() {
        let start = i;
        // digits with an optional fractional part; a trailing '.' (sentence end) is not numeric
        while i < bytes.len()
            && (bytes[i].is_ascii_digit()
                || (bytes[i] == b'.' && i > start && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit()))
        {
            i += 1;
        }
        if start == i {
            break;
        }
        let Ok(num) = tail[start..i].parse::<f64>() else { break };
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        let unit_start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let unit = &tail[unit_start..i];
        let mult = match unit {
            "d" | "day" | "days" => 86400.0,
            "h" | "hr" | "hrs" | "hour" | "hours" => 3600.0,
            "m" | "min" | "mins" | "minute" | "minutes" => 60.0,
            "s" | "sec" | "secs" | "second" | "seconds" => 1.0,
            "ms" => 0.001,
            _ => break,
        };
        total += num * mult;
        matched = true;
        // allow separators: spaces, "and", commas
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b',') {
            i += 1;
        }
        if tail[i..].starts_with("and ") {
            i += 4;
        }
    }
    if matched && total > 0.0 {
        Some(total.ceil() as u64)
    } else {
        None
    }
}

/// Find a reset/retry hint in `low` (already lower-cased).
pub fn parse_reset_hint(low: &str) -> Option<u64> {
    const KEYS: &[&str] = &[
        "resets in",
        "reset in",
        "reset after",
        "resets after",
        "retry in",
        "retry after",
        "try again in",
        "try again after",
        "available again in",
        "retrydelay",
        "retry_delay",
        "retry-after",
        "wait ",
    ];
    for k in KEYS {
        let mut from = 0usize;
        while let Some(pos) = low[from..].find(k) {
            let at = from + pos + k.len();
            if let Some(secs) = parse_duration_from(low, at) {
                return Some(secs);
            }
            from = at;
            if from >= low.len() {
                break;
            }
        }
    }
    None
}

/// True for agy diagnostic log lines (glog/klog style, `level=` style, or the known
/// transient token-cache WARN) that must not drive failure classification.
fn is_agy_log_line(l: &str) -> bool {
    let t = l.trim_start();
    let b = t.as_bytes();
    let glog = b.len() > 6
        && matches!(b[0], b'i' | b'w' | b'e' | b'd')
        && b[1..5].iter().all(u8::is_ascii_digit)
        && b[5] == b' ';
    glog || t.contains("singleflight")
        || t.contains("level=warn")
        || t.contains("level=info")
        || t.contains("level=debug")
        || t.contains("[warn]")
        || t.starts_with("warn ")
}

/// Classify an `agy` failure from its error message, optional code/status and exit code.
///
/// `had_result` is true when a `result` event (or any answer text) was produced.
pub fn classify_failure(
    message: &str,
    code: Option<&str>,
    exit_code: Option<i32>,
    had_result: bool,
) -> Classified {
    // Drop agy's own log lines (stderr tail fallback): e.g. the startup WARN
    // `cache.go:157 … Singleflight refresh failed: … You are not logged into Antigravity.`
    // appears even with a valid login and must never disable an account.
    let low: String = message
        .to_ascii_lowercase()
        .lines()
        .filter(|l| !is_agy_log_line(l))
        .collect::<Vec<_>>()
        .join("\n");
    let code = code.unwrap_or("").trim().to_ascii_lowercase();
    let reset = parse_reset_hint(&low);
    let mk = |class: FailureClass, action: FailureAction| Classified {
        class,
        action,
        reset_secs: reset,
        quota_scope: None,
    };

    if contains_any(&low, &["terms of service", "disabled in this account", "submit an appeal"]) {
        return mk(FailureClass::Banned, FailureAction::Disable);
    }
    if contains_any(&low, &["verify your account", "validation_required", "further action is required", "account_disabled", "user_disabled"]) {
        // needs owner action (verification URL is kept in the health detail / owner alert)
        return mk(FailureClass::AuthInvalid, FailureAction::Disable);
    }
    if contains_any(&low, &["not eligible", "not currently available in your location", "eligibility check failed", "unable to verify account eligibility"]) {
        // "Eligibility check failed" / "Unable to verify" can be transient; treat as cooldown.
        if low.contains("eligibility check failed") || low.contains("unable to verify account eligibility") {
            return mk(FailureClass::Ineligible, FailureAction::Cooldown { secs: reset.unwrap_or(600) });
        }
        return mk(FailureClass::Ineligible, FailureAction::Disable);
    }
    if contains_any(
        &low,
        &[
            "not logged into antigravity",
            "not logged in",
            "authentication failed or timed out",
            "waiting for authentication",
            "please sign in",
            "invalid_grant",
            "token has been expired or revoked",
            "unauthenticated",
            "sign-in update needed",
            "authentication required",
            "invalid authentication credentials",
            "authentication expired",
            "oauth session expired or revoked",
            "invalid_client",
            "unauthorized_client",
            "credentials are invalid",
            "token revoked",
        ],
    ) || code == "401"
    {
        return mk(FailureClass::AuthInvalid, FailureAction::Disable);
    }
    if is_model_unavailable(&low) {
        return mk(FailureClass::ModelUnavailable, FailureAction::Deliver);
    }
    if contains_any(&low, &["content safety", "blocked by content", "safety filters"]) {
        return mk(FailureClass::ContentBlocked, FailureAction::Deliver);
    }
    if contains_any(
        &low,
        &[
            "out of credits",
            "credits balance is too low",
            "credits balance too low",
            "prepaid balance",
            "spend cap",
            "spend-cap",
            "no active subscription",
            "subscription has expired",
            "subscription expired",
            "requires a subscription",
            "failed to select license",
            "not entitled",
            "billing account",
            "billing is not enabled",
            "billing not enabled",
            "billing disabled",
            "check your billing",
        ],
    ) {
        return mk(
            FailureClass::Subscription,
            FailureAction::Cooldown { secs: reset.unwrap_or(COOLDOWN_SUBSCRIPTION_DEFAULT) },
        );
    }
    let quota_words = contains_any(
        &low,
        &[
            "quota",
            "resource_exhausted",
            "resource exhausted",
            "usage limit",
            "too many requests",
            "rate limit",
            "rate-limit",
            "ratelimit",
            "exhausted your capacity",
            "quotaresetdelay",
        ],
    ) || code == "429"
        || low.contains("code 429");
    if quota_words {
        let long_quota = contains_any(
            &low,
            &["individual quota", "quota reached", "quota exceeded", "quota exhausted", "quota_exhausted", "quotafailure", "exhausted your capacity", "quotaresetdelay", "usage limit", "5-hour", "five-hour", "5 hour", "weekly", "daily", "per day"],
        );
        if long_quota {
            let (default, scope) = if low.contains("weekly") {
                (COOLDOWN_WEEKLY_DEFAULT, QuotaScope::Weekly)
            } else if low.contains("daily") || low.contains("per day") {
                (COOLDOWN_DAILY_DEFAULT, QuotaScope::Daily)
            } else if low.contains("5-hour") || low.contains("five-hour") || low.contains("5 hour") {
                (COOLDOWN_QUOTA_DEFAULT, QuotaScope::FiveHour)
            } else {
                (COOLDOWN_QUOTA_DEFAULT, QuotaScope::Unknown)
            };
            return Classified {
                class: FailureClass::QuotaExhausted,
                action: FailureAction::Cooldown { secs: reset.unwrap_or(default).max(60) },
                reset_secs: reset,
                quota_scope: Some(scope),
            };
        }
        return mk(
            FailureClass::RateLimited,
            FailureAction::Cooldown { secs: reset.unwrap_or(COOLDOWN_RATE_DEFAULT).max(30) },
        );
    }
    if contains_any(
        &low,
        &[
            "model_capacity_exhausted",
            "no capacity",
            "capacity exhausted",
            "at capacity",
            "insufficient capacity",
            "overloaded",
            "service unavailable",
            "code = unavailable",
            "status: unavailable",
            "\"unavailable\"",
            "code 503",
            "code 500",
            "code 502",
            "code 504",
            "internal error",
            "model unavailable",
        ],
    ) || matches!(code.as_str(), "500" | "502" | "503" | "504")
    {
        return mk(
            FailureClass::Capacity,
            FailureAction::Cooldown { secs: reset.unwrap_or(COOLDOWN_CAPACITY_DEFAULT) },
        );
    }
    if contains_any(
        &low,
        &[
            "request too large",
            "trajectory not found",
            "prompt is too long",
            "context length",
            "too many tokens",
            "invalid_argument",
            "invalid argument",
            "code 400",
        ],
    ) || code == "400"
    {
        return mk(FailureClass::ContextProblem, FailureAction::Deliver);
    }
    if contains_any(
        &low,
        &[
            "no such host",
            "dial tcp",
            "i/o timeout",
            "connection refused",
            "connection reset",
            "network is unreachable",
            "network is down",
            "tls handshake",
            "temporary failure in name resolution",
            "broken pipe",
            "http2: client connection lost",
            "network error",
            "inference connection failed",
        ],
    ) {
        return mk(FailureClass::Network, FailureAction::RetrySame { delay_s: 8 });
    }
    if code == "403" || low.contains("permission_denied") || low.contains("code 403") {
        // 403 without a ToS phrase: project/model access. Treat as account-scoped, cool down.
        return mk(FailureClass::Subscription, FailureAction::Cooldown { secs: reset.unwrap_or(3600) });
    }
    let crashed = contains_any(&low, &["panic:", "sigsegv", "fatal error:", "goroutine ", "agent execution terminated due to error", "exited without an answer"])
        || exit_code.is_some_and(|c| c < 0)
        || (!had_result && exit_code.is_some_and(|c| c != 0));
    if crashed {
        return mk(FailureClass::Crash, FailureAction::RetrySame { delay_s: 3 });
    }
    mk(FailureClass::Other, FailureAction::Deliver)
}

// ---------------------------------------------------------------------------
// Persisted model
// ---------------------------------------------------------------------------

/// Rolling window durations for per-account usage ledger.
pub const WINDOW_5H_SECS: i64 = 5 * 3600;
pub const WINDOW_WEEK_SECS: i64 = 7 * 86_400;
/// Default cooldown (seconds) when the pool-wide severe incident safety breaker trips.
pub const POOL_BREAKER_COOLDOWN_SECS: i64 = 3600;

/// High-level preset for gentle, anti-ban account pool behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountPolicyPreset {
    #[default]
    StrictSafe,
    Balanced,
}

impl AccountPolicyPreset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StrictSafe => "strict_safe",
            Self::Balanced => "balanced",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::StrictSafe => "strict_safe (gentle)",
            Self::Balanced => "balanced",
        }
    }
}

impl std::str::FromStr for AccountPolicyPreset {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "strict_safe" | "strict-safe" | "strict" | "safe" | "gentle" => Ok(Self::StrictSafe),
            "balanced" | "normal" | "standard" => Ok(Self::Balanced),
            other => Err(BridgeError::Config(format!(
                "invalid ACCT_POLICY_PRESET '{other}' (expected strict_safe or balanced)"
            ))),
        }
    }
}

/// Configurable account health, pacing, 1% weekly reserve, and pool breaker policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountPolicy {
    #[serde(default)]
    pub preset: AccountPolicyPreset,
    /// Percentage of **weekly** quota to keep untouched (`1.0` = park at 99% weekly usage).
    /// Never applied to 5-hour rolling windows.
    #[serde(default = "default_weekly_reserve_pct")]
    pub weekly_reserve_pct: f64,
    /// Optional default weekly effective-token ceiling per account (`0` = auto-calibrate / per-account).
    #[serde(default)]
    pub default_weekly_token_budget: u64,
    /// Weekly usage percentage where gentle pacing starts scaling up (default 75%).
    #[serde(default = "default_soft_throttle_pct")]
    pub soft_throttle_start_pct: f64,
    /// Weekly usage percentage where fresher accounts are preferred over sticky affinity (default 90%).
    #[serde(default = "default_prefer_fresher_pct")]
    pub prefer_fresher_pct: f64,
    /// Maximum simultaneous runs allowed on a single account.
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency_per_account: u32,
    /// Minimum breathing gap (seconds) between consecutive runs on the same account.
    #[serde(default)]
    pub min_gap_secs: u64,
    /// Soft delay (seconds) before failing over to the next account.
    #[serde(default)]
    pub switch_delay_secs: u64,
    /// Maximum engine failover attempts per turn (1..=8).
    #[serde(default = "default_max_attempts")]
    pub max_failover_attempts: usize,
    /// Number of severe incidents (ToS ban / verification challenge / ineligible) inside
    /// `pool_breaker_window_secs` that trips the pool-wide safety pause (`0` = disabled).
    #[serde(default)]
    pub pool_breaker_threshold: u32,
    /// Sliding window (seconds) for the pool-wide severe incident breaker.
    #[serde(default = "default_breaker_window_secs")]
    pub pool_breaker_window_secs: u64,
    /// Cooldown duration (seconds) when the pool-wide safety breaker trips.
    #[serde(default = "default_breaker_cooldown_secs")]
    pub pool_breaker_cooldown_secs: u64,
}

fn default_weekly_reserve_pct() -> f64 {
    1.0
}
fn default_soft_throttle_pct() -> f64 {
    75.0
}
fn default_prefer_fresher_pct() -> f64 {
    90.0
}
fn default_max_concurrency() -> u32 {
    2
}
fn default_max_attempts() -> usize {
    8
}
fn default_breaker_window_secs() -> u64 {
    900
}
fn default_breaker_cooldown_secs() -> u64 {
    POOL_BREAKER_COOLDOWN_SECS as u64
}

impl Default for AccountPolicy {
    /// Neutral backwards-compatible default for bare `AccountStore::open` (production `main.rs`
    /// hydrates `Config::account_policy()`, which defaults to [`Self::strict_safe()`]).
    fn default() -> Self {
        Self {
            preset: AccountPolicyPreset::Balanced,
            weekly_reserve_pct: default_weekly_reserve_pct(),
            default_weekly_token_budget: 0,
            soft_throttle_start_pct: default_soft_throttle_pct(),
            prefer_fresher_pct: default_prefer_fresher_pct(),
            max_concurrency_per_account: default_max_concurrency(),
            min_gap_secs: 0,
            switch_delay_secs: 0,
            max_failover_attempts: default_max_attempts(),
            pool_breaker_threshold: 0,
            pool_breaker_window_secs: default_breaker_window_secs(),
            pool_breaker_cooldown_secs: default_breaker_cooldown_secs(),
        }
    }
}

impl AccountPolicy {
    /// Obsessive anti-ban gentle preset: 1 concurrent run/account, 8s breathing gap, 3s failover
    /// delay, 1% weekly reserve, max 4 failover attempts, and pool breaker after 2 severe hits/15m.
    pub fn strict_safe() -> Self {
        Self {
            preset: AccountPolicyPreset::StrictSafe,
            weekly_reserve_pct: 1.0,
            default_weekly_token_budget: 0,
            soft_throttle_start_pct: 75.0,
            prefer_fresher_pct: 90.0,
            max_concurrency_per_account: 1,
            min_gap_secs: 8,
            switch_delay_secs: 3,
            max_failover_attempts: 4,
            pool_breaker_threshold: 2,
            pool_breaker_window_secs: 900,
            pool_breaker_cooldown_secs: default_breaker_cooldown_secs(),
        }
    }

    /// Balanced preset: up to 2 concurrent runs/account, 2s gap, 1s switch delay, 1% weekly reserve.
    pub fn balanced() -> Self {
        Self {
            preset: AccountPolicyPreset::Balanced,
            weekly_reserve_pct: 1.0,
            default_weekly_token_budget: 0,
            soft_throttle_start_pct: 80.0,
            prefer_fresher_pct: 92.0,
            max_concurrency_per_account: 2,
            min_gap_secs: 2,
            switch_delay_secs: 1,
            max_failover_attempts: 6,
            pool_breaker_threshold: 3,
            pool_breaker_window_secs: 900,
            pool_breaker_cooldown_secs: default_breaker_cooldown_secs(),
        }
    }

    pub fn from_preset(preset: AccountPolicyPreset) -> Self {
        match preset {
            AccountPolicyPreset::StrictSafe => Self::strict_safe(),
            AccountPolicyPreset::Balanced => Self::balanced(),
        }
    }

    pub fn sanitized(mut self) -> Self {
        if !self.weekly_reserve_pct.is_finite() {
            self.weekly_reserve_pct = 1.0;
        }
        self.weekly_reserve_pct = self.weekly_reserve_pct.clamp(0.0, 25.0);
        if !self.soft_throttle_start_pct.is_finite() {
            self.soft_throttle_start_pct = 75.0;
        }
        self.soft_throttle_start_pct = self.soft_throttle_start_pct.clamp(30.0, 98.0);
        if !self.prefer_fresher_pct.is_finite() {
            self.prefer_fresher_pct = 90.0;
        }
        self.prefer_fresher_pct = self
            .prefer_fresher_pct
            .clamp(self.soft_throttle_start_pct, 99.5);
        self.max_concurrency_per_account = self.max_concurrency_per_account.clamp(1, 8);
        self.min_gap_secs = self.min_gap_secs.min(300);
        self.switch_delay_secs = self.switch_delay_secs.min(120);
        self.max_failover_attempts = self.max_failover_attempts.clamp(1, 8);
        self.pool_breaker_window_secs = self.pool_breaker_window_secs.clamp(60, 86_400);
        if self.pool_breaker_cooldown_secs == 0 {
            self.pool_breaker_cooldown_secs = default_breaker_cooldown_secs();
        }
        self.pool_breaker_cooldown_secs = self.pool_breaker_cooldown_secs.clamp(60, 86_400);
        self
    }

    /// Weekly usage % ceiling where an account soft-parks to preserve the weekly reserve.
    pub fn weekly_stop_pct(&self) -> f64 {
        (100.0 - self.weekly_reserve_pct.clamp(0.0, 25.0)).max(50.0)
    }
}

/// Extract `(input_tokens, output_tokens, cache_read_tokens, effective_total)` from an engine `usage` JSON object.
pub fn extract_usage_tokens(usage: &Value) -> (u64, u64, u64, u64) {
    let Some(obj) = usage.as_object() else {
        return (0, 0, 0, 0);
    };
    let read_u64 = |keys: &[&str]| -> u64 {
        keys.iter()
            .find_map(|k| obj.get(*k).and_then(Value::as_u64))
            .unwrap_or(0)
    };
    let inp = read_u64(&["input_tokens", "prompt_tokens"]);
    let out = read_u64(&["output_tokens", "completion_tokens"]);
    let cache = read_u64(&["cache_read_tokens", "cached_tokens", "cache_read_input_tokens"]);
    let total_field = read_u64(&["total_tokens"]);
    // Weight cached reads lightly (1/10) so prompt-cache hits don't falsely inflate weekly usage.
    let computed = inp.saturating_add(out).saturating_add(cache / 10);
    let effective = if computed > 0 { computed } else { total_field };
    (inp, out, cache, effective)
}

/// Human-compact token count (`14.2k`, `2.35M`).
pub fn format_tokens_compact(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.2}M", (n as f64) / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", (n as f64) / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Per-account rolling 5-hour and 7-day (weekly) usage ledger.
///
/// The 1% reserve (`weekly_reserve_parked_until`) applies **strictly** to the weekly window,
/// never to the 5-hour rolling window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccountUsage {
    #[serde(default)]
    pub window_5h_start_ts: i64,
    #[serde(default)]
    pub tokens_5h: u64,
    #[serde(default)]
    pub runs_5h: u64,

    #[serde(default)]
    pub window_week_start_ts: i64,
    #[serde(default)]
    pub tokens_week: u64,
    #[serde(default)]
    pub input_tokens_week: u64,
    #[serde(default)]
    pub output_tokens_week: u64,
    #[serde(default)]
    pub cache_read_tokens_week: u64,
    #[serde(default)]
    pub runs_week: u64,

    /// Explicit owner-configured weekly effective-token ceiling for this account.
    #[serde(default)]
    pub weekly_budget_override: Option<u64>,
    /// Auto-calibrated weekly ceiling learned from observed `weekly` quota exhaustion.
    #[serde(default)]
    pub calibrated_weekly_budget: Option<u64>,
    /// Soft-park timestamp when weekly usage reaches `>= (100 - reserve_pct)%`.
    #[serde(default)]
    pub weekly_reserve_parked_until: Option<i64>,
    /// Timestamp when the last run finished on this account (drives soft pacing).
    #[serde(default)]
    pub last_run_end_ts: i64,
}

impl AccountUsage {
    /// Roll expired 5-hour and 7-day windows forward at `now`.
    pub fn roll_windows(&mut self, now: i64) {
        if self.window_5h_start_ts <= 0 || now.saturating_sub(self.window_5h_start_ts) >= WINDOW_5H_SECS {
            self.window_5h_start_ts = now;
            self.tokens_5h = 0;
            self.runs_5h = 0;
        }
        if self.window_week_start_ts <= 0 || now.saturating_sub(self.window_week_start_ts) >= WINDOW_WEEK_SECS {
            self.window_week_start_ts = now;
            self.tokens_week = 0;
            self.input_tokens_week = 0;
            self.output_tokens_week = 0;
            self.cache_read_tokens_week = 0;
            self.runs_week = 0;
            self.weekly_reserve_parked_until = None;
        } else if self.weekly_reserve_parked_until.is_some_and(|u| u <= now) {
            self.weekly_reserve_parked_until = None;
        }
    }

    pub fn effective_weekly_budget(&self, policy: &AccountPolicy) -> Option<u64> {
        self.weekly_budget_override
            .filter(|&b| b > 0)
            .or_else(|| self.calibrated_weekly_budget.filter(|&b| b > 0))
            .or_else(|| (policy.default_weekly_token_budget > 0).then_some(policy.default_weekly_token_budget))
    }

    pub fn weekly_reset_ts(&self, now: i64) -> i64 {
        let start = if self.window_week_start_ts > 0 {
            self.window_week_start_ts
        } else {
            now
        };
        start.saturating_add(WINDOW_WEEK_SECS)
    }

    /// Current weekly consumption percentage (`0.0..=100.0+`), if a weekly budget is known.
    pub fn weekly_used_pct_at(&self, now: i64, policy: &AccountPolicy) -> Option<f64> {
        let budget = self.effective_weekly_budget(policy)?;
        if self.window_week_start_ts > 0 && now.saturating_sub(self.window_week_start_ts) >= WINDOW_WEEK_SECS {
            return Some(0.0);
        }
        Some((self.tokens_week as f64) * 100.0 / (budget as f64))
    }

    /// True ONLY when weekly usage hit the weekly reserve ceiling (e.g. `>= 99.0%` for 1% reserve).
    /// Never triggered by 5-hour usage.
    pub fn is_weekly_reserved(&self, now: i64, policy: &AccountPolicy) -> bool {
        if policy.weekly_reserve_pct <= 0.0 {
            return false;
        }
        if self.window_week_start_ts > 0 && now.saturating_sub(self.window_week_start_ts) >= WINDOW_WEEK_SECS {
            return false;
        }
        if let Some(pct) = self.weekly_used_pct_at(now, policy) {
            return pct >= policy.weekly_stop_pct();
        }
        self.weekly_reserve_parked_until.is_some_and(|u| u > now)
    }

    /// Record usage tokens for a completed turn. Returns `true` if the account just entered
    /// weekly reserve parking (preserving the final `weekly_reserve_pct`%).
    pub fn add_turn(&mut self, now: i64, inp: u64, out: u64, cache: u64, effective: u64, policy: &AccountPolicy) -> bool {
        self.roll_windows(now);
        self.tokens_5h = self.tokens_5h.saturating_add(effective);
        self.runs_5h = self.runs_5h.saturating_add(1);
        self.tokens_week = self.tokens_week.saturating_add(effective);
        self.input_tokens_week = self.input_tokens_week.saturating_add(inp);
        self.output_tokens_week = self.output_tokens_week.saturating_add(out);
        self.cache_read_tokens_week = self.cache_read_tokens_week.saturating_add(cache);
        self.runs_week = self.runs_week.saturating_add(1);
        self.last_run_end_ts = now;

        if policy.weekly_reserve_pct > 0.0 {
            if let Some(pct) = self.weekly_used_pct_at(now, policy) {
                if pct >= policy.weekly_stop_pct() {
                    let until = self.weekly_reset_ts(now);
                    let newly_parked = self.weekly_reserve_parked_until.is_none_or(|u| u <= now);
                    self.weekly_reserve_parked_until = Some(until);
                    return newly_parked;
                }
            }
        }
        false
    }

    /// Auto-calibrate weekly budget & window alignment when a real `weekly` quota failure occurs.
    pub fn note_weekly_quota_hit(&mut self, now: i64, reset_secs: Option<u64>) {
        self.roll_windows(now);
        if self.tokens_week > 0 {
            self.calibrated_weekly_budget = Some(match self.calibrated_weekly_budget {
                Some(prev) => prev.min(self.tokens_week),
                None => self.tokens_week,
            });
        }
        if let Some(r) = reset_secs {
            let r_i64 = r.min(WINDOW_WEEK_SECS as u64) as i64;
            self.window_week_start_ts = (now + r_i64).saturating_sub(WINDOW_WEEK_SECS);
        }
    }

    /// Soft pacing wait (seconds) required before running another turn on this account.
    pub fn pacing_wait_at(&self, now: i64, policy: &AccountPolicy, consecutive_failures: u32) -> u64 {
        let base = policy.min_gap_secs;
        if base == 0 || self.last_run_end_ts <= 0 {
            return 0;
        }
        let mult = match self.weekly_used_pct_at(now, policy) {
            Some(pct) if pct >= policy.prefer_fresher_pct => 2.0,
            Some(pct) if pct >= policy.soft_throttle_start_pct => 1.5,
            _ => 1.0,
        };
        let fail_boost = if consecutive_failures > 0 { 1.5 } else { 1.0 };
        let target_gap = ((base as f64) * mult * fail_boost).ceil() as u64;
        let elapsed = now.saturating_sub(self.last_run_end_ts).max(0) as u64;
        target_gap.saturating_sub(elapsed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SevereIncident {
    pub ts: i64,
    pub account_id: String,
    pub class: String,
}

/// Pool-wide anti-cascade circuit breaker: pauses automatic rotation when multiple accounts
/// hit severe ToS / verification / eligibility errors within a short sliding window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PoolBreakerState {
    #[serde(default)]
    pub recent_severe: Vec<SevereIncident>,
    #[serde(default)]
    pub tripped_until_ts: Option<i64>,
    #[serde(default)]
    pub tripped_reason: Option<String>,
}

impl PoolBreakerState {
    pub fn active_at(&self, now: i64) -> Option<(i64, String)> {
        let until = self.tripped_until_ts?;
        if until > now {
            Some((
                until,
                self.tripped_reason
                    .clone()
                    .unwrap_or_else(|| "multiple severe account incidents".to_string()),
            ))
        } else {
            None
        }
    }

    pub fn record_severe(
        &mut self,
        now: i64,
        account_id: &str,
        class_label: &str,
        policy: &AccountPolicy,
    ) -> bool {
        if policy.pool_breaker_threshold == 0 {
            return false;
        }
        let win = policy.pool_breaker_window_secs as i64;
        self.recent_severe
            .retain(|e| e.account_id != account_id && now.saturating_sub(e.ts) <= win);
        self.recent_severe.push(SevereIncident {
            ts: now,
            account_id: account_id.to_string(),
            class: class_label.to_string(),
        });
        let distinct_accounts: HashSet<&str> = self
            .recent_severe
            .iter()
            .map(|e| e.account_id.as_str())
            .collect();
        if distinct_accounts.len() >= policy.pool_breaker_threshold as usize {
            let reason = format!(
                "{} accounts hit severe errors ({}) within {}m — pool auto-paused to protect remaining accounts",
                distinct_accounts.len(),
                class_label,
                (policy.pool_breaker_window_secs / 60).max(1)
            );
            let cd = policy.pool_breaker_cooldown_secs.clamp(60, 86_400) as i64;
            self.tripped_until_ts = Some(now + cd);
            self.tripped_reason = Some(reason);
            return true;
        }
        false
    }

    pub fn clear_account(&mut self, account_id: &str) {
        self.recent_severe.retain(|e| e.account_id != account_id);
    }

    pub fn clear(&mut self) {
        self.recent_severe.clear();
        self.tripped_until_ts = None;
        self.tripped_reason = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    #[default]
    Ok,
    Cooldown,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccountHealth {
    #[serde(default)]
    pub status: HealthStatus,
    #[serde(default)]
    pub class: Option<FailureClass>,
    #[serde(default)]
    pub quota_scope: Option<QuotaScope>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub until_ts: Option<i64>,
    #[serde(default)]
    pub last_ok_ts: Option<i64>,
    #[serde(default)]
    pub last_fail_ts: Option<i64>,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub runs: u64,
    #[serde(default)]
    pub failures: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub email: Option<String>,
    pub home: PathBuf,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub created_ts: i64,
    #[serde(default)]
    pub health: AccountHealth,
    /// Optional 1:1 sticky egress proxy ID (from `$STATE_DIR/proxies.json`).
    #[serde(default)]
    pub proxy_id: Option<String>,
    /// Per-account rolling 5-hour & 7-day usage ledger.
    #[serde(default)]
    pub usage: AccountUsage,
}

fn default_true() -> bool {
    true
}

impl Account {
    pub fn is_primary(&self) -> bool {
        self.id == PRIMARY_ACCOUNT_ID
    }
    pub fn token_path(&self) -> PathBuf {
        self.home.join(TOKEN_REL_PATH)
    }
    /// Available right now (enabled, not disabled, cooldown elapsed).
    pub fn available_at(&self, now: i64) -> bool {
        if !self.enabled {
            return false;
        }
        match self.health.status {
            HealthStatus::Ok => true,
            HealthStatus::Disabled => false,
            HealthStatus::Cooldown => self.health.until_ts.is_none_or(|u| u <= now),
        }
    }
    /// Available right now considering both health cooldowns AND the weekly 1% reserve policy.
    pub fn available_at_with_policy(&self, now: i64, policy: &AccountPolicy) -> bool {
        self.available_at(now) && !self.usage.is_weekly_reserved(now, policy)
    }
    /// Masked e-mail (`ab***@gmail.com`) for display.
    pub fn masked_email(&self) -> Option<String> {
        self.email.as_deref().map(mask_email)
    }
    /// `acc1 · ma…ei@gmail.com` (id always included so two similar labels never collide).
    pub fn display_name(&self) -> String {
        let l = self.label.trim();
        if l.is_empty() || l == self.id {
            self.id.clone()
        } else if self.is_primary() {
            l.to_string()
        } else {
            format!("{} · {}", self.id, l)
        }
    }
}

/// Masked e-mail for display: first two and last two characters of the local part
/// (`ma…ei@gmail.com`), so different addresses with the same prefix stay distinguishable.
pub fn mask_email(e: &str) -> String {
    match e.split_once('@') {
        Some((user, dom)) => {
            let chars: Vec<char> = user.chars().collect();
            if chars.len() <= 4 {
                let keep: String = chars.iter().take(1).collect();
                format!("{keep}…@{dom}")
            } else {
                let head: String = chars[..2].iter().collect();
                let tail: String = chars[chars.len() - 2..].iter().collect();
                format!("{head}…{tail}@{dom}")
            }
        }
        None => "***".to_string(),
    }
}

/// Old masking (`ab***@dom`), used to migrate auto-generated labels.
fn legacy_mask_email(e: &str) -> Option<String> {
    let (user, dom) = e.split_once('@')?;
    let keep: String = user.chars().take(2).collect();
    Some(format!("{keep}***@{dom}"))
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountsData {
    #[serde(default)]
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub next_seq: u32,
    /// Last account used per Telegram user (soft affinity / stickiness).
    #[serde(default)]
    pub affinity: BTreeMap<String, String>,
    /// Gentle account pacing, 1% weekly reserve & pool breaker policy.
    #[serde(default)]
    pub policy: AccountPolicy,
    /// True once the owner customized policy via `/accounts` UI (env defaults won't clobber it).
    #[serde(default)]
    pub policy_customized: bool,
    /// Pool-wide anti-cascade safety breaker state.
    #[serde(default)]
    pub breaker: PoolBreakerState,
}

/// Token presence check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenState {
    Missing,
    Invalid,
    Present { email: Option<String> },
}

/// Inspect a token file WITHOUT exposing its secrets (only checks structure + reads e-mail).
pub fn inspect_token(path: &Path) -> TokenState {
    let Ok(raw) = fs::read(path) else {
        return TokenState::Missing;
    };
    if raw.is_empty() {
        return TokenState::Missing;
    }
    let Ok(v) = serde_json::from_slice::<Value>(&raw) else {
        return TokenState::Invalid;
    };
    let has_refresh = v
        .get("token")
        .and_then(|t| t.get("refresh_token"))
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    let has_access = v
        .get("token")
        .and_then(|t| t.get("access_token"))
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if !(has_refresh || has_access) {
        return TokenState::Invalid;
    }
    let email = v
        .get("id_token_email")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    TokenState::Present { email }
}

// ---------------------------------------------------------------------------
// Shadow home
// ---------------------------------------------------------------------------

fn set_mode(path: &Path, mode: u32) {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.file_type().is_symlink() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
        }
    }
}

fn ensure_real_dir(path: &Path, mode: u32) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            fs::remove_file(path).map_err(|e| BridgeError::io(path.display().to_string(), e))?;
        } else if !meta.is_dir() {
            return Err(BridgeError::Validation(format!(
                "{} exists and is not a directory",
                path.display()
            )));
        }
    }
    fs::create_dir_all(path).map_err(|e| BridgeError::io(path.display().to_string(), e))?;
    set_mode(path, mode);
    Ok(())
}

/// Create/refresh a symlink `link -> target` without clobbering real files.
fn ensure_link(link: &Path, target: &Path) -> Result<()> {
    match fs::symlink_metadata(link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            if fs::read_link(link).ok().as_deref() == Some(target) {
                return Ok(());
            }
            fs::remove_file(link).map_err(|e| BridgeError::io(link.display().to_string(), e))?;
        }
        Ok(_) => return Ok(()), // real file/dir present: account-local, never clobber
        Err(_) => {}
    }
    symlink(target, link).map_err(|e| BridgeError::io(link.display().to_string(), e))?;
    Ok(())
}

/// Build or refresh a shadow `HOME` for an extra account.
///
/// Layout (`home` = `<accounts_root>/<id>/home`):
/// * `home/<entry>` -> `primary_home/<entry>` for every top-level entry except `.gemini`;
/// * `home/.gemini/<entry>` -> `primary_home/.gemini/<entry>` except `antigravity-cli`;
/// * `home/.gemini/antigravity-cli/<entry>` -> primary for everything except
///   [`PER_ACCOUNT_ENTRIES`] (token, caches, logs, summary DB...), which stay private.
///
/// `conversations/` and `brain/` are therefore SHARED, which is what makes
/// `--conversation <id>` resumable on any account.
pub fn ensure_shadow_home(home: &Path, primary_home: &Path) -> Result<()> {
    if home == primary_home {
        return Ok(());
    }
    ensure_real_dir(home, 0o700)?;
    if let Ok(rd) = fs::read_dir(primary_home) {
        for ent in rd.flatten() {
            let name = ent.file_name();
            if name == ".gemini" {
                continue;
            }
            let _ = ensure_link(&home.join(&name), &primary_home.join(&name));
        }
    }
    let g_home = home.join(".gemini");
    let g_primary = primary_home.join(".gemini");
    ensure_real_dir(&g_home, 0o700)?;
    if let Ok(rd) = fs::read_dir(&g_primary) {
        for ent in rd.flatten() {
            let name = ent.file_name();
            if name == "antigravity-cli" {
                continue;
            }
            let _ = ensure_link(&g_home.join(&name), &g_primary.join(&name));
        }
    }
    let c_home = g_home.join("antigravity-cli");
    let c_primary = g_primary.join("antigravity-cli");
    ensure_real_dir(&c_home, 0o700)?;
    // make sure shared dirs exist on the primary side so links are never dangling
    for shared in ["conversations", "brain"] {
        let p = c_primary.join(shared);
        if !p.exists() {
            let _ = fs::create_dir_all(&p);
        }
    }
    if let Ok(rd) = fs::read_dir(&c_primary) {
        for ent in rd.flatten() {
            let name = ent.file_name();
            let s = name.to_string_lossy();
            if PER_ACCOUNT_ENTRIES.contains(&s.as_ref()) {
                continue;
            }
            let _ = ensure_link(&c_home.join(&name), &c_primary.join(&name));
        }
    }
    set_mode(&c_home.join("antigravity-oauth-token"), 0o600);
    Ok(())
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Thread-safe persisted account pool (`accounts.json`, 0600).
pub struct AccountStore {
    path: PathBuf,
    root: PathBuf,
    primary_home: PathBuf,
    inner: RwLock<AccountsData>,
    in_flight: Mutex<HashMap<String, u32>>,
    /// Generation of the in-memory data / last generation written to disk.
    gen: std::sync::atomic::AtomicU64,
    saved_gen: Mutex<u64>,
    pick_lock: Mutex<()>,
}

impl AccountStore {
    /// Open (or create) the store. Ensures the implicit `primary` account exists.
    pub fn open(
        path: impl Into<PathBuf>,
        accounts_root: impl Into<PathBuf>,
        primary_home: impl Into<PathBuf>,
    ) -> Result<Self> {
        let path = path.into();
        let root = accounts_root.into();
        let primary_home = primary_home.into();
        let mut data: AccountsData = match fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw).unwrap_or_else(|e| {
                warn!(error = %e, "accounts.json unreadable; starting with an empty pool");
                AccountsData::default()
            }),
            Err(_) => AccountsData::default(),
        };
        if !data.accounts.iter().any(|a| a.id == PRIMARY_ACCOUNT_ID) {
            let email = match inspect_token(&primary_home.join(TOKEN_REL_PATH)) {
                TokenState::Present { email } => email,
                _ => None,
            };
            data.accounts.insert(
                0,
                Account {
                    id: PRIMARY_ACCOUNT_ID.to_string(),
                    label: "server login".to_string(),
                    email,
                    home: primary_home.clone(),
                    enabled: true,
                    priority: 0,
                    created_ts: now_ts(),
                    health: AccountHealth::default(),
                    proxy_id: None,
                    usage: AccountUsage::default(),
                },
            );
        }
        // migrate auto-generated labels from the old ambiguous mask
        for a in &mut data.accounts {
            if let Some(e) = a.email.clone() {
                if legacy_mask_email(&e).as_deref() == Some(a.label.trim()) {
                    a.label = mask_email(&e);
                }
            }
        }
        let store = Self {
            path,
            root,
            primary_home,
            inner: RwLock::new(data),
            in_flight: Mutex::new(HashMap::new()),
            gen: std::sync::atomic::AtomicU64::new(0),
            saved_gen: Mutex::new(0),
            pick_lock: Mutex::new(()),
        };
        store.save()?;
        Ok(store)
    }

    pub fn primary_home(&self) -> &Path {
        &self.primary_home
    }

    pub fn accounts_root(&self) -> &Path {
        &self.root
    }

    /// Shared conversations directory (all shadow homes link to it).
    pub fn shared_conversations_dir(&self) -> PathBuf {
        self.primary_home.join(CONVERSATIONS_REL_DIR)
    }

    /// Whether a conversation is resumable from the shared local store.
    pub fn conversation_exists(&self, cid: &str) -> bool {
        if cid.is_empty() || cid.contains('/') || cid.contains("..") {
            return false;
        }
        self.shared_conversations_dir().join(format!("{cid}.db")).is_file()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, AccountsData> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn save_locked(&self, data: &AccountsData) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(data).map_err(|e| BridgeError::json("accounts.json", e))?;
        atomic_write_bytes(&self.path, &bytes, 0o600)
    }

    fn save(&self) -> Result<()> {
        let g = self.read();
        self.save_locked(&g)
    }

    /// Apply `f` under the write lock, then persist **outside** it (readers are not blocked by
    /// the fsync). Writes are ordered by a generation counter so an older snapshot never
    /// overwrites a newer one.
    fn mutate<R>(&self, f: impl FnOnce(&mut AccountsData) -> Result<R>) -> Result<R> {
        let (out, bytes, gen) = {
            let mut g = self
                .inner
                .write()
                .map_err(|e| BridgeError::Internal(format!("accounts lock poisoned: {e}")))?;
            let out = f(&mut g)?;
            let bytes = serde_json::to_vec_pretty(&*g).map_err(|e| BridgeError::json("accounts.json", e))?;
            let gen = self.gen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            (out, bytes, gen)
        };
        let mut last = self.saved_gen.lock().unwrap_or_else(|e| e.into_inner());
        if gen > *last {
            if let Err(e) = atomic_write_bytes(&self.path, &bytes, 0o600) {
                warn!(error = %e, "accounts.json save failed (kept in memory; retried on next change)");
                return Err(e);
            }
            *last = gen;
        }
        Ok(out)
    }

    pub fn list(&self) -> Vec<Account> {
        let mut v = self.read().accounts.clone();
        v.sort_by_key(|a| (a.priority, a.created_ts));
        v
    }

    pub fn get(&self, id: &str) -> Option<Account> {
        self.read().accounts.iter().find(|a| a.id == id).cloned()
    }

    pub fn len(&self) -> usize {
        self.read().accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Create a new account slot with an isolated shadow home (no token yet => disabled
    /// until login completes).
    pub fn add_slot(&self, label: &str) -> Result<Account> {
        let acc = self.mutate(|d| {
            if d.accounts.len() >= MAX_ACCOUNTS {
                return Err(BridgeError::Validation(format!(
                    "account limit reached ({MAX_ACCOUNTS})"
                )));
            }
            let mut seq = d.next_seq.max(1);
            let mut id = format!("acc{seq}");
            while d.accounts.iter().any(|a| a.id == id) {
                seq += 1;
                id = format!("acc{seq}");
            }
            d.next_seq = seq + 1;
            let max_prio = d.accounts.iter().map(|a| a.priority).max().unwrap_or(0);
            let acc = Account {
                id: id.clone(),
                label: label.trim().chars().take(32).collect(),
                email: None,
                home: self.root.join(&id).join("home"),
                enabled: false,
                priority: max_prio + 1,
                created_ts: now_ts(),
                health: AccountHealth {
                    status: HealthStatus::Disabled,
                    class: Some(FailureClass::AuthInvalid),
                    detail: Some("waiting for sign-in".to_string()),
                    ..Default::default()
                },
                proxy_id: None,
                usage: AccountUsage::default(),
            };
            d.accounts.push(acc.clone());
            Ok(acc)
        })?;
        ensure_real_dir(&self.root, 0o700)?;
        ensure_real_dir(&self.root.join(&acc.id), 0o700)?;
        ensure_shadow_home(&acc.home, &self.primary_home)?;
        info!(id = %acc.id, "account slot created");
        Ok(acc)
    }

    /// Refresh a non-primary account's shadow home links (idempotent).
    pub fn prepare_home(&self, acc: &Account) -> Result<()> {
        if acc.is_primary() {
            return Ok(());
        }
        ensure_shadow_home(&acc.home, &self.primary_home)
    }

    /// Re-read the token after login; enable the account if a token is present.
    pub fn finish_login(&self, id: &str) -> Result<TokenState> {
        let acc = self
            .get(id)
            .ok_or_else(|| BridgeError::Validation(format!("unknown account {id}")))?;
        set_mode(&acc.token_path(), 0o600);
        let st = inspect_token(&acc.token_path());
        if let TokenState::Present { ref email } = st {
            let email = email.clone();
            self.mutate(|d| {
                if let Some(a) = d.accounts.iter_mut().find(|a| a.id == id) {
                    a.email = email.clone();
                    if a.label.trim().is_empty() {
                        if let Some(e) = email.as_deref() {
                            a.label = mask_email(e);
                        }
                    }
                    a.enabled = true;
                    a.health = AccountHealth {
                        runs: a.health.runs,
                        failures: a.health.failures,
                        ..Default::default()
                    };
                }
                Ok(())
            })?;
        }
        Ok(st)
    }

    /// Remove a non-primary account and its private directory.
    pub fn remove(&self, id: &str) -> Result<()> {
        if id == PRIMARY_ACCOUNT_ID {
            return Err(BridgeError::Validation(
                "the primary (server) account cannot be removed; disable it instead".to_string(),
            ));
        }
        let acc = self
            .get(id)
            .ok_or_else(|| BridgeError::Validation(format!("unknown account {id}")))?;
        if self.in_flight(id) > 0 {
            return Err(BridgeError::Validation(format!(
                "{id} is running a task right now; try again when it is idle"
            )));
        }
        self.mutate(|d| {
            d.accounts.retain(|a| a.id != id);
            d.affinity.retain(|_, v| v != id);
            d.breaker.clear_account(id);
            Ok(())
        })?;
        let dir = self.root.join(id);
        // Safety: only ever delete inside accounts_root; remove_dir_all does not follow
        // symlinks (it unlinks them), so shared primary data is never touched.
        if dir.starts_with(&self.root) && dir != self.root && acc.home.starts_with(&dir) {
            if let Err(e) = fs::remove_dir_all(&dir) {
                warn!(id, error = %e, "failed removing account dir");
            }
        }
        Ok(())
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        self.mutate(|d| {
            let a = d
                .accounts
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or_else(|| BridgeError::Validation(format!("unknown account {id}")))?;
            a.enabled = enabled;
            Ok(())
        })
    }

    pub fn rename(&self, id: &str, label: &str) -> Result<()> {
        self.mutate(|d| {
            let a = d
                .accounts
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or_else(|| BridgeError::Validation(format!("unknown account {id}")))?;
            a.label = label.trim().chars().take(32).collect();
            Ok(())
        })
    }

    /// Move an account one step earlier in the priority order.
    pub fn move_up(&self, id: &str) -> Result<()> {
        self.mutate(|d| {
            d.accounts.sort_by_key(|a| (a.priority, a.created_ts));
            if let Some(i) = d.accounts.iter().position(|a| a.id == id) {
                if i > 0 {
                    d.accounts.swap(i, i - 1);
                }
            }
            for (n, a) in d.accounts.iter_mut().enumerate() {
                a.priority = n as i32;
            }
            Ok(())
        })
    }

    /// Clear health (owner "reset"), re-checking the token for non-primary accounts.
    pub fn reset_health(&self, id: &str) -> Result<()> {
        let acc = self
            .get(id)
            .ok_or_else(|| BridgeError::Validation(format!("unknown account {id}")))?;
        let token_ok = matches!(inspect_token(&acc.token_path()), TokenState::Present { .. });
        self.mutate(|d| {
            if let Some(a) = d.accounts.iter_mut().find(|a| a.id == id) {
                let runs = a.health.runs;
                let failures = a.health.failures;
                a.health = if token_ok {
                    d.breaker.clear_account(id);
                    AccountHealth { runs, failures, ..Default::default() }
                } else {
                    AccountHealth {
                        status: HealthStatus::Disabled,
                        class: Some(FailureClass::AuthInvalid),
                        detail: Some("no sign-in token".to_string()),
                        runs,
                        failures,
                        ..Default::default()
                    }
                };
            }
            Ok(())
        })
    }

    pub fn policy(&self) -> AccountPolicy {
        self.read().policy.clone()
    }

    /// Apply env/config policy defaults unless the owner already customized policy via UI.
    pub fn init_policy_if_unset(&self, policy: AccountPolicy) -> Result<()> {
        let pol = policy.sanitized();
        self.mutate(|d| {
            if !d.policy_customized {
                d.policy = pol;
            }
            Ok(())
        })
    }

    /// Persist owner-updated account policy (marks `policy_customized = true`), re-evaluating
    /// weekly reserve parks and breaker state immediately.
    pub fn set_policy(&self, policy: AccountPolicy) -> Result<()> {
        let pol = policy.sanitized();
        let now = now_ts();
        self.mutate(|d| {
            for a in &mut d.accounts {
                a.usage.roll_windows(now);
                if pol.weekly_reserve_pct > 0.0
                    && a.usage
                        .weekly_used_pct_at(now, &pol)
                        .is_some_and(|pct| pct >= pol.weekly_stop_pct())
                {
                    a.usage.weekly_reserve_parked_until = Some(a.usage.weekly_reset_ts(now));
                } else if pol.weekly_reserve_pct <= 0.0
                    || a.usage
                        .weekly_used_pct_at(now, &pol)
                        .is_some_and(|pct| pct < pol.weekly_stop_pct())
                {
                    a.usage.weekly_reserve_parked_until = None;
                }
            }
            if pol.pool_breaker_threshold == 0
                || d.breaker.recent_severe.len() < pol.pool_breaker_threshold as usize
            {
                d.breaker.tripped_until_ts = None;
                d.breaker.tripped_reason = None;
            }
            d.policy = pol;
            d.policy_customized = true;
            Ok(())
        })
    }

    /// Clear any learned auto-calibrated weekly ceiling for account `id`.
    pub fn clear_calibrated_budget(&self, id: &str) -> Result<()> {
        let now = now_ts();
        self.mutate(|d| {
            let pol = d.policy.clone();
            let a = d
                .accounts
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or_else(|| BridgeError::Validation(format!("unknown account {id}")))?;
            a.usage.calibrated_weekly_budget = None;
            a.usage.roll_windows(now);
            if a.usage
                .weekly_used_pct_at(now, &pol)
                .is_none_or(|pct| pct < pol.weekly_stop_pct())
            {
                a.usage.weekly_reserve_parked_until = None;
            }
            Ok(())
        })
    }

    /// Bind or unbind a 1:1 sticky egress proxy ID for account `id`.
    pub fn set_account_proxy(&self, id: &str, proxy_id: Option<&str>) -> Result<()> {
        let clean = proxy_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
        self.mutate(|d| {
            let a = d
                .accounts
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or_else(|| BridgeError::Validation(format!("unknown account {id}")))?;
            a.proxy_id = clean;
            Ok(())
        })
    }

    /// Remove references to a deleted proxy ID from all accounts. Returns count updated.
    pub fn clear_proxy_bindings(&self, proxy_id: &str) -> Result<usize> {
        self.mutate(|d| {
            let mut n = 0usize;
            for a in &mut d.accounts {
                if a.proxy_id.as_deref() == Some(proxy_id) {
                    a.proxy_id = None;
                    n += 1;
                }
            }
            Ok(n)
        })
    }

    /// Set or clear an explicit per-account weekly effective-token ceiling.
    pub fn set_weekly_budget(&self, id: &str, budget: Option<u64>) -> Result<()> {
        let clean = budget.filter(|&b| b > 0);
        let now = now_ts();
        self.mutate(|d| {
            let pol = d.policy.clone();
            let a = d
                .accounts
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or_else(|| BridgeError::Validation(format!("unknown account {id}")))?;
            a.usage.weekly_budget_override = clean;
            a.usage.roll_windows(now);
            // Re-evaluate weekly reserve parking immediately after cap change.
            if a.usage.weekly_used_pct_at(now, &pol).is_some_and(|pct| pct >= pol.weekly_stop_pct()) {
                if pol.weekly_reserve_pct > 0.0 {
                    a.usage.weekly_reserve_parked_until = Some(a.usage.weekly_reset_ts(now));
                }
            } else {
                a.usage.weekly_reserve_parked_until = None;
            }
            Ok(())
        })
    }

    /// Record completed turn token usage into an account's 5-hour & 7-day ledgers.
    /// Returns `true` if this turn just crossed into the weekly reserve (preserving ≥`weekly_reserve_pct`%).
    pub fn record_usage(&self, id: &str, usage_val: &Value) -> bool {
        let (inp, out, cache, eff) = extract_usage_tokens(usage_val);
        let now = now_ts();
        self.mutate(|d| {
            let pol = d.policy.clone();
            if let Some(a) = d.accounts.iter_mut().find(|a| a.id == id) {
                let parked = a.usage.add_turn(now, inp, out, cache, eff, &pol);
                if parked {
                    warn!(
                        account = %id,
                        tokens_week = a.usage.tokens_week,
                        reserve_pct = pol.weekly_reserve_pct,
                        "account soft-parked to preserve weekly quota reserve"
                    );
                }
                return Ok(parked);
            }
            Ok(false)
        })
        .unwrap_or(false)
    }

    /// Mark the completion timestamp of a run (for gentle `min_gap_secs` pacing even when usage wasn't emitted).
    pub fn record_run_finished(&self, id: &str) {
        let now = now_ts();
        let _ = self.mutate(|d| {
            if let Some(a) = d.accounts.iter_mut().find(|a| a.id == id) {
                a.usage.last_run_end_ts = now;
            }
            Ok(())
        });
    }

    /// Seconds to wait politely before starting another run on `id` under current pacing policy.
    pub fn pacing_wait_secs(&self, id: &str) -> u64 {
        let now = now_ts();
        let g = self.read();
        let Some(a) = g.accounts.iter().find(|a| a.id == id) else {
            return 0;
        };
        a.usage.pacing_wait_at(now, &g.policy, a.health.consecutive_failures)
    }

    /// Active pool-wide safety breaker `(until_ts, reason)`, if tripped.
    pub fn breaker_status(&self) -> Option<(i64, String)> {
        let now = now_ts();
        self.read().breaker.active_at(now)
    }

    /// Clear the pool-wide safety breaker (owner acknowledgement).
    pub fn reset_breaker(&self) -> Result<()> {
        self.mutate(|d| {
            d.breaker.clear();
            Ok(())
        })
    }

    /// Count of enabled accounts currently soft-parked to protect their weekly reserve.
    pub fn weekly_reserved_count(&self) -> usize {
        let now = now_ts();
        let g = self.read();
        g.accounts
            .iter()
            .filter(|a| a.available_at(now) && a.usage.is_weekly_reserved(now, &g.policy))
            .count()
    }

    pub fn record_success(&self, id: &str, uid: Option<i64>) {
        let now = now_ts();
        let res = self.mutate(|d| {
            if let Some(a) = d.accounts.iter_mut().find(|a| a.id == id) {
                a.health.runs += 1;
                a.health.last_ok_ts = Some(now);
                a.health.consecutive_failures = 0;
                a.usage.last_run_end_ts = now;
                if a.health.status == HealthStatus::Cooldown {
                    a.health.status = HealthStatus::Ok;
                    a.health.until_ts = None;
                    a.health.class = None;
                    a.health.quota_scope = None;
                    a.health.detail = None;
                }
            }
            if let Some(u) = uid {
                d.affinity.insert(u.to_string(), id.to_string());
            }
            Ok(())
        });
        if let Err(e) = res {
            warn!(error = %e, "accounts: record_success save failed");
        }
    }

    /// Apply a classified failure to `id`'s health. Returns the resulting status.
    pub fn record_failure(&self, id: &str, c: &Classified, detail: &str) -> HealthStatus {
        let now = now_ts();
        let detail: String = detail.chars().take(300).collect();
        self.mutate(|d| {
            let pol = d.policy.clone();
            let Some(a) = d.accounts.iter_mut().find(|a| a.id == id) else {
                return Ok(HealthStatus::Ok);
            };
            a.health.runs += 1;
            a.health.failures += 1;
            a.health.last_fail_ts = Some(now);
            a.health.consecutive_failures = a.health.consecutive_failures.saturating_add(1);
            a.usage.last_run_end_ts = now;

            if c.class == FailureClass::QuotaExhausted && c.quota_scope == Some(QuotaScope::Weekly) {
                a.usage.note_weekly_quota_hit(now, c.reset_secs);
            }

            match c.action {
                FailureAction::Disable => {
                    a.health.status = HealthStatus::Disabled;
                    a.health.until_ts = None;
                    a.health.class = Some(c.class);
                    a.health.quota_scope = c.quota_scope;
                    a.health.detail = Some(detail.clone());
                }
                FailureAction::Cooldown { secs } => {
                    // escalate repeated short cooldowns
                    let factor = 1u64 << a.health.consecutive_failures.saturating_sub(1).min(4);
                    let secs = if matches!(c.class, FailureClass::QuotaExhausted | FailureClass::Subscription) {
                        secs
                    } else {
                        (secs.saturating_mul(factor)).min(6 * 3600)
                    };
                    a.health.status = HealthStatus::Cooldown;
                    a.health.until_ts = Some(now + secs as i64);
                    a.health.class = Some(c.class);
                    a.health.quota_scope = c.quota_scope;
                    a.health.detail = Some(detail.clone());
                }
                FailureAction::RetrySame { .. } | FailureAction::Deliver => {
                    if a.health.consecutive_failures >= 3 && c.class.is_account_scoped() {
                        a.health.status = HealthStatus::Cooldown;
                        a.health.until_ts = Some(now + COOLDOWN_CRASH_DEFAULT as i64);
                        a.health.class = Some(c.class);
                        a.health.quota_scope = c.quota_scope;
                        a.health.detail = Some(detail.clone());
                    }
                }
            }
            let resulting = a.health.status;

            // Pool-wide safety breaker for severe ToS / location / account-verification incidents
            let low_det = detail.to_ascii_lowercase();
            let severe = matches!(c.class, FailureClass::Banned | FailureClass::Ineligible)
                || (c.class == FailureClass::AuthInvalid
                    && contains_any(
                        &low_det,
                        &["verify your account", "validation_required", "account_disabled", "user_disabled"],
                    ));
            if severe
                && resulting == HealthStatus::Disabled
                && d.breaker.record_severe(now, id, c.class.label(), &pol)
            {
                warn!(
                    account = %id,
                    class = c.class.label(),
                    "pool safety breaker TRIPPED; pausing automatic failover"
                );
            }

            Ok(resulting)
        })
        .unwrap_or(HealthStatus::Ok)
    }

    /// Choose an account for `uid`, skipping `exclude` and accounts rejected by `allow`.
    /// Preference order:
    /// 1. respects pool safety breaker, weekly 1% reserve, and `max_concurrency_per_account`;
    /// 2. user's sticky account when healthy and below `prefer_fresher_pct` (or no fresher account exists);
    /// 3. otherwise least-loaded / freshest weekly usage / lowest pacing wait / priority.
    pub fn pick_with_filter<F>(&self, uid: i64, exclude: &HashSet<String>, allow: F) -> Option<Account>
    where
        F: Fn(&Account) -> bool,
    {
        let now = now_ts();
        let (cands, sticky, policy) = {
            let g = self.read();
            if g.breaker.active_at(now).is_some() {
                return None;
            }
            let pol = g.policy.clone();
            let c: Vec<Account> = g
                .accounts
                .iter()
                .filter(|a| !exclude.contains(&a.id) && a.available_at_with_policy(now, &pol) && allow(a))
                .cloned()
                .collect();
            (c, g.affinity.get(&uid.to_string()).cloned(), pol)
        };
        let mut usable = Vec::new();
        for a in cands {
            if !a.is_primary() && !matches!(inspect_token(&a.token_path()), TokenState::Present { .. }) {
                let c = Classified {
                    class: FailureClass::AuthInvalid,
                    action: FailureAction::Disable,
                    reset_secs: None,
                    quota_scope: None,
                };
                self.record_failure(&a.id, &c, "sign-in token missing");
                continue;
            }
            usable.push(a);
        }
        if usable.is_empty() {
            return None;
        }
        let load = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        let max_conc = policy.max_concurrency_per_account.max(1);
        let under_cap: Vec<Account> = usable
            .iter()
            .filter(|a| *load.get(&a.id).unwrap_or(&0) < max_conc)
            .cloned()
            .collect();
        if !under_cap.is_empty() {
            usable = under_cap;
        } else if policy.preset == AccountPolicyPreset::StrictSafe && max_conc == 1 {
            // In strict_safe single-concurrency mode, refuse piling a second live job onto a busy account.
            return None;
        }

        if let Some(s) = sticky {
            if let Some(a) = usable.iter().find(|a| a.id == s) {
                let sticky_pct = a.usage.weekly_used_pct_at(now, &policy).unwrap_or(0.0);
                let has_much_fresher = sticky_pct >= policy.prefer_fresher_pct
                    && usable.iter().any(|other| {
                        other.id != a.id
                            && other.usage.weekly_used_pct_at(now, &policy).unwrap_or(0.0)
                                + 5.0
                                < sticky_pct
                    });
                if !has_much_fresher {
                    return Some(a.clone());
                }
            }
        }
        usable.sort_by_key(|a| {
            let inf = *load.get(&a.id).unwrap_or(&0);
            let wk_bucket = a
                .usage
                .weekly_used_pct_at(now, &policy)
                .map(|p| (p / 10.0).floor().clamp(0.0, 10.0) as u32)
                .unwrap_or(0);
            let wait_s = a.usage.pacing_wait_at(now, &policy, a.health.consecutive_failures);
            (inf, wk_bucket, wait_s > 0, a.priority, a.created_ts)
        });
        usable.into_iter().next()
    }

    /// Choose an account for `uid`, skipping `exclude`.
    pub fn pick(&self, uid: i64, exclude: &HashSet<String>) -> Option<Account> {
        self.pick_with_filter(uid, exclude, |_| true)
    }

    /// The account `uid` would most likely run on next, without side effects:
    /// its sticky account when usable, otherwise the best available by priority.
    pub fn preferred_for(&self, uid: i64) -> Option<Account> {
        let now = now_ts();
        let g = self.read();
        if g.breaker.active_at(now).is_some() {
            return None;
        }
        let pol = &g.policy;
        let usable: Vec<&Account> = g
            .accounts
            .iter()
            .filter(|a| a.available_at_with_policy(now, pol))
            .collect();
        if let Some(s) = g.affinity.get(&uid.to_string()) {
            if let Some(a) = usable.iter().find(|a| &a.id == s) {
                return Some((*a).clone());
            }
        }
        let load = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = usable;
        v.sort_by_key(|a| (*load.get(&a.id).unwrap_or(&0), a.priority, a.created_ts));
        v.first().map(|a| (*a).clone())
    }

    /// Other accounts signed in with the same e-mail (case-insensitive) as `id`.
    pub fn duplicates_of(&self, id: &str) -> Vec<String> {
        let g = self.read();
        let Some(me) = g.accounts.iter().find(|a| a.id == id).and_then(|a| a.email.clone()) else {
            return Vec::new();
        };
        let me = me.trim().to_ascii_lowercase();
        g.accounts
            .iter()
            .filter(|a| a.id != id && a.email.as_deref().is_some_and(|e| e.trim().to_ascii_lowercase() == me))
            .map(|a| a.id.clone())
            .collect()
    }

    /// Groups of account ids that share one e-mail (each group has 2+ ids).
    pub fn duplicate_groups(&self) -> Vec<Vec<String>> {
        let mut by: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for a in self.list() {
            if let Some(e) = a.email.as_deref() {
                by.entry(e.trim().to_ascii_lowercase()).or_default().push(a.id.clone());
            }
        }
        by.into_values().filter(|v| v.len() > 1).collect()
    }

    /// `pick_with_filter` + `begin` atomically under `pick_lock`.
    pub fn pick_begin_with_filter<F>(&self, uid: i64, exclude: &HashSet<String>, allow: F) -> Option<Account>
    where
        F: Fn(&Account) -> bool,
    {
        let _serial = self.pick_lock.lock().unwrap_or_else(|e| e.into_inner());
        let a = self.pick_with_filter(uid, exclude, allow)?;
        self.begin(&a.id);
        Some(a)
    }

    /// Pick a specific pinned account under `pick_lock`, strictly enforcing breaker,
    /// weekly reserve policy, concurrency limit, token presence, and `allow` predicate.
    pub fn pick_pinned_begin_with_filter<F>(
        &self,
        id: &str,
        exclude: &HashSet<String>,
        allow: F,
    ) -> Option<Account>
    where
        F: Fn(&Account) -> bool,
    {
        let _serial = self.pick_lock.lock().unwrap_or_else(|e| e.into_inner());
        if exclude.contains(id) {
            return None;
        }
        let now = now_ts();
        let (acc, pol) = {
            let g = self.read();
            if g.breaker.active_at(now).is_some() {
                return None;
            }
            let a = g.accounts.iter().find(|a| a.id == id)?.clone();
            (a, g.policy.clone())
        };
        if !acc.available_at_with_policy(now, &pol) || !allow(&acc) {
            return None;
        }
        if !acc.is_primary() && !matches!(inspect_token(&acc.token_path()), TokenState::Present { .. }) {
            let c = Classified {
                class: FailureClass::AuthInvalid,
                action: FailureAction::Disable,
                reset_secs: None,
                quota_scope: None,
            };
            self.record_failure(&acc.id, &c, "sign-in token missing");
            return None;
        }
        let max_conc = pol.max_concurrency_per_account.max(1);
        if self.in_flight(&acc.id) >= max_conc {
            return None;
        }
        self.begin(&acc.id);
        Some(acc)
    }

    /// `pick` + `begin` as one step: the in-flight counter is taken under the same lock that
    /// ranks the candidates, so concurrent callers spread over accounts.
    pub fn pick_begin(&self, uid: i64, exclude: &HashSet<String>) -> Option<Account> {
        self.pick_begin_with_filter(uid, exclude, |_| true)
    }

    /// Like [`acquire_distinct`](Self::acquire_distinct) with an extra candidate filter (e.g. sticky proxy health).
    pub fn acquire_distinct_with_filter<F>(
        &self,
        uid: i64,
        exclude: &HashSet<String>,
        avoid: &HashSet<String>,
        allow: F,
    ) -> Option<Account>
    where
        F: Fn(&Account) -> bool,
    {
        let _serial = self.pick_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut ex = exclude.clone();
        ex.extend(avoid.iter().cloned());
        let a = self
            .pick_with_filter(uid, &ex, &allow)
            .or_else(|| self.pick_with_filter(uid, exclude, &allow))?;
        self.begin(&a.id);
        Some(a)
    }

    /// Like [`pick_begin`](Self::pick_begin) but prefers an account **not** in `avoid` (e.g. the
    /// accounts other parallel workers already hold). Falls back to the normal least-loaded
    /// pick only when no healthy account outside `avoid` is left.
    pub fn acquire_distinct(&self, uid: i64, exclude: &HashSet<String>, avoid: &HashSet<String>) -> Option<Account> {
        self.acquire_distinct_with_filter(uid, exclude, avoid, |_| true)
    }

    pub fn begin(&self, id: &str) {
        let mut g = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        *g.entry(id.to_string()).or_insert(0) += 1;
    }

    pub fn end(&self, id: &str) {
        let mut g = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = g.get_mut(id) {
            *v = v.saturating_sub(1);
        }
    }

    pub fn in_flight(&self, id: &str) -> u32 {
        *self
            .in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .unwrap_or(&0)
    }

    /// Earliest timestamp at which some enabled account leaves cooldown or weekly reserve.
    pub fn next_available_ts(&self) -> Option<i64> {
        let now = now_ts();
        let g = self.read();
        if let Some((until, _)) = g.breaker.active_at(now) {
            return Some(until);
        }
        let pol = &g.policy;
        let cooldown_min = g
            .accounts
            .iter()
            .filter(|a| a.enabled && a.health.status == HealthStatus::Cooldown)
            .filter_map(|a| a.health.until_ts)
            .min();
        let reserve_min = g
            .accounts
            .iter()
            .filter(|a| a.available_at(now) && a.usage.is_weekly_reserved(now, pol))
            .filter_map(|a| a.usage.weekly_reserve_parked_until.or_else(|| Some(a.usage.weekly_reset_ts(now))))
            .min();
        match (cooldown_min, reserve_min) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    /// Count of accounts currently available (respecting cooldowns, weekly reserve & pool breaker).
    pub fn available_count(&self) -> usize {
        let now = now_ts();
        let g = self.read();
        if g.breaker.active_at(now).is_some() {
            return 0;
        }
        let pol = &g.policy;
        g.accounts
            .iter()
            .filter(|a| a.available_at_with_policy(now, pol))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store(dir: &TempDir) -> (AccountStore, PathBuf) {
        let primary = dir.path().join("root");
        fs::create_dir_all(primary.join(".gemini/antigravity-cli/conversations")).unwrap();
        fs::create_dir_all(primary.join(".gemini/config")).unwrap();
        fs::create_dir_all(primary.join(".skillport")).unwrap();
        fs::write(primary.join(".gemini/GEMINI.md"), "x").unwrap();
        fs::write(primary.join(".gemini/antigravity-cli/settings.json"), "{}").unwrap();
        fs::write(
            primary.join(TOKEN_REL_PATH),
            r#"{"token":{"access_token":"a","refresh_token":"r"},"auth_method":"oauth","id_token_email":"primary@example.com"}"#,
        )
        .unwrap();
        let s = AccountStore::open(
            dir.path().join("state/accounts.json"),
            dir.path().join("state/accounts"),
            &primary,
        )
        .unwrap();
        (s, primary)
    }

    #[test]
    fn model_errors_labels_and_duplicates() {
        for m in [
            "Invalid model \"gemini-4-x\" (valid choices: a, b)",
            "The requested model was not found, or your project does not have access to it.",
            "no model is selected and the account has no default",
            "Unknown model ID: foo",
        ] {
            let c = classify_failure(m, Some("403"), Some(1), false);
            assert_eq!(c.class, FailureClass::ModelUnavailable, "{m}");
            assert_eq!(c.action, FailureAction::Deliver, "no cooldown for a model problem: {m}");
        }
        // narrowed keywords: tool text mentioning billing / unavailable is not an account fault
        assert_eq!(classify_failure("MCP tool error: billing report unavailable", None, Some(0), true).action, FailureAction::Deliver);
        assert_eq!(classify_failure("agy exited without an answer (empty output)", None, Some(0), false).class, FailureClass::Crash);
        assert_eq!(mask_email("mahdisoolei@gmail.com"), "ma…ei@gmail.com");
        assert_ne!(mask_email("mahdisoolei@gmail.com"), mask_email("mahdisoleimanian18@gmail.com"));
        let dir = tempfile::TempDir::new().unwrap();
        let prim = dir.path().join("root");
        fs::create_dir_all(prim.join(".gemini/antigravity-cli")).unwrap();
        let s = AccountStore::open(dir.path().join("a.json"), dir.path().join("acc"), &prim).unwrap();
        let mk = |email: &str| {
            let a = s.add_slot("").unwrap();
            let cli = a.home.join(".gemini/antigravity-cli");
            fs::create_dir_all(&cli).unwrap();
            fs::write(cli.join("antigravity-oauth-token"), format!(r#"{{"token":{{"refresh_token":"r"}},"id_token_email":"{email}"}}"#)).unwrap();
            s.finish_login(&a.id).unwrap();
            a.id
        };
        let a1 = mk("Same@x.io");
        let a2 = mk("same@x.io");
        let a3 = mk("other@x.io");
        assert_eq!(s.duplicates_of(&a1), vec![a2.clone()]);
        assert!(s.duplicates_of(&a3).is_empty());
        assert_eq!(s.duplicate_groups(), vec![vec![a1.clone(), a2.clone()]]);
        assert_eq!(s.get(&a1).unwrap().display_name(), format!("{a1} · S…@x.io"));
        // atomic pick + in-flight, remove refused while busy
        let x = s.pick_begin(1, &HashSet::new()).unwrap();
        assert_eq!(s.in_flight(&x.id), 1);
        if x.id != PRIMARY_ACCOUNT_ID {
            assert!(s.remove(&x.id).is_err());
        }
        s.end(&x.id);
        // distinct acquisition: avoid what siblings hold; fall back only when nothing else is free
        let all: HashSet<String> = s.list().into_iter().map(|a| a.id).collect();
        let mut avoid = all.clone();
        avoid.remove(&a3);
        let d = s.acquire_distinct(0, &HashSet::new(), &avoid).unwrap();
        assert_eq!(d.id, a3);
        let f = s.acquire_distinct(0, &HashSet::new(), &all).expect("falls back when all are held");
        s.end(&d.id);
        s.end(&f.id);
        assert!(s.remove(&a3).is_ok());
    }

    #[test]
    fn classify_known_agy_errors() {
        // transient startup WARN from the token cache must not disable an account
        let warn = "W1118 23:01:02.123 cache.go:157] Singleflight refresh failed: error getting token source: You are not logged into Antigravity.\nError: dial tcp: i/o timeout";
        assert_eq!(classify_failure(warn, None, Some(3), false).class, FailureClass::Network);
        assert_eq!(classify_failure("Verify your account to continue. https://accounts.google.com/signin/continue?x=1", None, Some(3), false).action, FailureAction::Disable);
        assert_eq!(classify_failure("Authentication expired. Please log back in.", None, Some(3), false).class, FailureClass::AuthInvalid);
        assert_eq!(classify_failure("You have exhausted your capacity on this model.", None, Some(3), false).class, FailureClass::QuotaExhausted);
        assert_eq!(classify_failure("Your AI credits balance is too low to continue.", None, Some(3), false).class, FailureClass::Subscription);
        assert_eq!(classify_failure("trajectory not found", None, Some(3), false).class, FailureClass::ContextProblem);
        assert_eq!(classify_failure("INVALID_ARGUMENT (code 400): bad", Some("400"), Some(3), false).action, FailureAction::Deliver);
        let ban = classify_failure("Permission denied (code 403): This service has been disabled in this account for violation of Terms of Service. Please submit an appeal", Some("403"), Some(1), false);
        assert_eq!(ban.class, FailureClass::Banned);
        assert_eq!(ban.action, FailureAction::Disable);

        let loc = classify_failure("You are not eligible for Antigravity, because it is not currently available in your location.", None, Some(1), false);
        assert_eq!(loc.class, FailureClass::Ineligible);
        assert_eq!(loc.action, FailureAction::Disable);

        let auth = classify_failure("authentication failed or timed out", None, Some(1), true);
        assert_eq!(auth.class, FailureClass::AuthInvalid);
        let auth2 = classify_failure("error getting token source: You are not logged into Antigravity.", None, Some(1), false);
        assert_eq!(auth2.class, FailureClass::AuthInvalid);
        let grant = classify_failure("oauth2: \"invalid_grant\" \"Token has been expired or revoked.\"", None, Some(1), false);
        assert_eq!(grant.class, FailureClass::AuthInvalid);

        let q = classify_failure("RESOURCE_EXHAUSTED (code 429): Individual quota reached. Resets in 3h20m.", Some("429"), Some(1), false);
        assert_eq!(q.class, FailureClass::QuotaExhausted);
        assert_eq!(q.action, FailureAction::Cooldown { secs: 3 * 3600 + 20 * 60 });

        let qd = classify_failure("RESOURCE_EXHAUSTED (code 429): Individual quota reached", None, Some(1), false);
        assert_eq!(qd.action, FailureAction::Cooldown { secs: COOLDOWN_QUOTA_DEFAULT });

        let wk = classify_failure("You have reached your weekly quota", None, Some(1), false);
        assert_eq!(wk.action, FailureAction::Cooldown { secs: COOLDOWN_WEEKLY_DEFAULT });

        let rl = classify_failure("429 Too Many Requests, retry after 45s", None, Some(1), false);
        assert_eq!(rl.class, FailureClass::RateLimited);
        assert_eq!(rl.action, FailureAction::Cooldown { secs: 45 });

        let cap = classify_failure("MODEL_CAPACITY_EXHAUSTED (code 503)", None, Some(1), false);
        assert_eq!(cap.class, FailureClass::Capacity);

        let credits = classify_failure("AI: Out of credits", None, Some(1), false);
        assert_eq!(credits.class, FailureClass::Subscription);

        let net = classify_failure("Post \"https://x\": dial tcp 1.2.3.4:443: i/o timeout", None, Some(1), false);
        assert_eq!(net.class, FailureClass::Network);
        assert!(matches!(net.action, FailureAction::RetrySame { .. }));

        let crash = classify_failure("panic: runtime error: index out of range", None, Some(2), false);
        assert_eq!(crash.class, FailureClass::Crash);
        let killed = classify_failure("", None, Some(-9), false);
        assert_eq!(killed.class, FailureClass::Crash);

        let safety = classify_failure("The response was blocked by content safety filters.", None, Some(1), true);
        assert_eq!(safety.action, FailureAction::Deliver);

        let ctxp = classify_failure("INVALID_ARGUMENT (code 400): prompt is too long", Some("400"), Some(1), false);
        assert_eq!(ctxp.class, FailureClass::ContextProblem);

        let other = classify_failure("something odd", None, Some(0), true);
        assert_eq!(other.class, FailureClass::Other);
        assert!(!other.class.is_account_scoped());
    }

    #[test]
    fn reset_hint_parsing() {
        assert_eq!(parse_reset_hint("individual quota reached. resets in 2h."), Some(7200));
        assert_eq!(parse_reset_hint("retry after 1.5s."), Some(2));
        assert_eq!(parse_reset_hint("quota resets in 2 hours and 5 minutes"), Some(7500));
        assert_eq!(parse_reset_hint("\"retrydelay\": \"34.2s\""), Some(35));
        assert_eq!(parse_reset_hint("try again in 1 day"), Some(86400));
        assert_eq!(parse_reset_hint("nothing here"), None);
        assert_eq!(parse_reset_hint("retry in a moment"), None);
    }

    #[test]
    fn primary_is_created_and_pool_persists() {
        let dir = TempDir::new().unwrap();
        let (s, primary) = store(&dir);
        let all = s.list();
        assert_eq!(all.len(), 1);
        assert!(all[0].is_primary());
        assert_eq!(all[0].home, primary);
        assert_eq!(all[0].email.as_deref(), Some("primary@example.com"));
        let mode = fs::metadata(dir.path().join("state/accounts.json")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(s);
        let s2 = AccountStore::open(dir.path().join("state/accounts.json"), dir.path().join("state/accounts"), &primary).unwrap();
        assert_eq!(s2.len(), 1);
        assert!(s2.remove(PRIMARY_ACCOUNT_ID).is_err());
    }

    #[test]
    fn shadow_home_shares_everything_but_credentials() {
        let dir = TempDir::new().unwrap();
        let (s, primary) = store(&dir);
        let a = s.add_slot("work").unwrap();
        assert!(!a.enabled);
        let h = &a.home;
        // top-level entries linked, .gemini is real
        assert!(fs::symlink_metadata(h.join(".skillport")).unwrap().file_type().is_symlink());
        assert!(!fs::symlink_metadata(h.join(".gemini")).unwrap().file_type().is_symlink());
        assert!(fs::symlink_metadata(h.join(".gemini/config")).unwrap().file_type().is_symlink());
        let cli = h.join(".gemini/antigravity-cli");
        assert!(!fs::symlink_metadata(&cli).unwrap().file_type().is_symlink());
        assert!(fs::symlink_metadata(cli.join("conversations")).unwrap().file_type().is_symlink());
        assert_eq!(fs::read_link(cli.join("conversations")).unwrap(), primary.join(".gemini/antigravity-cli/conversations"));
        assert!(fs::symlink_metadata(cli.join("settings.json")).unwrap().file_type().is_symlink());
        // the token is NOT shared
        assert!(!cli.join("antigravity-oauth-token").exists());
        let mode = fs::metadata(h).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);

        // pick skips the slot (no token) and disables it
        let picked = s.pick(1, &HashSet::new()).unwrap();
        assert!(picked.is_primary());

        // simulate a successful login
        fs::write(cli.join("antigravity-oauth-token"), r#"{"token":{"refresh_token":"r2"},"id_token_email":"second@example.com"}"#).unwrap();
        assert!(matches!(s.finish_login(&a.id).unwrap(), TokenState::Present { .. }));
        let a2 = s.get(&a.id).unwrap();
        assert!(a2.enabled);
        assert_eq!(a2.health.status, HealthStatus::Ok);
        assert_eq!(a2.masked_email().as_deref(), Some("se…nd@example.com"));
        let tmode = fs::metadata(cli.join("antigravity-oauth-token")).unwrap().permissions().mode() & 0o777;
        assert_eq!(tmode, 0o600);

        // refresh is idempotent and never clobbers the private token
        s.prepare_home(&a2).unwrap();
        assert!(cli.join("antigravity-oauth-token").is_file());
        assert!(!fs::symlink_metadata(cli.join("antigravity-oauth-token")).unwrap().file_type().is_symlink());

        // conversation visibility is shared
        fs::write(primary.join(".gemini/antigravity-cli/conversations/abc.db"), "x").unwrap();
        assert!(s.conversation_exists("abc"));
        assert!(cli.join("conversations/abc.db").is_file());
        assert!(!s.conversation_exists("../etc"));

        // remove deletes only the private dir; primary data survives
        s.remove(&a.id).unwrap();
        assert!(!dir.path().join("state/accounts").join(&a.id).exists());
        assert!(primary.join(".gemini/antigravity-cli/conversations/abc.db").is_file());
        assert!(primary.join(TOKEN_REL_PATH).is_file());
    }

    #[test]
    fn failover_selection_cooldown_and_stickiness() {
        let dir = TempDir::new().unwrap();
        let (s, _primary) = store(&dir);
        let mut ids = vec![PRIMARY_ACCOUNT_ID.to_string()];
        for n in 0..2 {
            let a = s.add_slot(&format!("a{n}")).unwrap();
            fs::write(a.token_path(), r#"{"token":{"refresh_token":"r"}}"#).unwrap();
            s.finish_login(&a.id).unwrap();
            ids.push(a.id);
        }
        // least-loaded / priority
        let p = s.pick(7, &HashSet::new()).unwrap();
        assert_eq!(p.id, ids[0]);
        s.begin(&ids[0]);
        let p2 = s.pick(8, &HashSet::new()).unwrap();
        assert_eq!(p2.id, ids[1], "concurrent user goes to the idle account");
        s.end(&ids[0]);

        // quota on primary -> cooldown, failover to next
        let q = classify_failure("RESOURCE_EXHAUSTED (code 429): Individual quota reached", None, Some(1), false);
        assert_eq!(s.record_failure(&ids[0], &q, "quota"), HealthStatus::Cooldown);
        let mut ex = HashSet::new();
        ex.insert(ids[0].clone());
        let n = s.pick(7, &ex).unwrap();
        assert_eq!(n.id, ids[1]);
        s.record_success(&n.id, Some(7));
        // sticky afterwards even without exclusions (primary is cooling down anyway)
        assert_eq!(s.pick(7, &HashSet::new()).unwrap().id, ids[1]);
        assert!(s.next_available_ts().is_some());

        // ban -> disabled
        let ban = classify_failure("disabled in this account for violation of Terms of Service", None, Some(1), false);
        assert_eq!(s.record_failure(&ids[1], &ban, "ban"), HealthStatus::Disabled);
        assert_eq!(s.pick(7, &HashSet::new()).unwrap().id, ids[2]);

        // everything down -> None
        s.record_failure(&ids[2], &ban, "ban");
        assert!(s.pick(7, &HashSet::new()).is_none());
        assert_eq!(s.available_count(), 0);

        // owner reset restores
        s.reset_health(&ids[2]).unwrap();
        assert_eq!(s.pick(7, &HashSet::new()).unwrap().id, ids[2]);

        // persisted health survives reopen
        let reopened = AccountStore::open(dir.path().join("state/accounts.json"), dir.path().join("state/accounts"), dir.path().join("root")).unwrap();
        assert_eq!(reopened.get(&ids[1]).unwrap().health.status, HealthStatus::Disabled);
        assert_eq!(reopened.get(&ids[0]).unwrap().health.status, HealthStatus::Cooldown);
    }

    #[test]
    fn weekly_one_percent_reserve_and_five_hour_separation() {
        let dir = TempDir::new().unwrap();
        let (s, _primary) = store(&dir);
        let a2 = s.add_slot("second").unwrap();
        fs::write(a2.token_path(), r#"{"token":{"refresh_token":"r"}}"#).unwrap();
        s.finish_login(&a2.id).unwrap();

        let mut pol = AccountPolicy::strict_safe();
        pol.weekly_reserve_pct = 1.0; // stop at 99% weekly
        pol.min_gap_secs = 10;
        s.set_policy(pol.clone()).unwrap();
        s.set_weekly_budget(PRIMARY_ACCOUNT_ID, Some(100_000)).unwrap();

        // Heavy 5-hour usage that is only 50% of weekly budget must NOT park the account!
        let parked1 = s.record_usage(
            PRIMARY_ACCOUNT_ID,
            &serde_json::json!({ "input_tokens": 40_000, "output_tokens": 10_000, "cache_read_tokens": 0 }),
        );
        assert!(!parked1);
        assert_eq!(s.get(PRIMARY_ACCOUNT_ID).unwrap().usage.tokens_5h, 50_000);
        assert_eq!(s.get(PRIMARY_ACCOUNT_ID).unwrap().usage.tokens_week, 50_000);
        assert_eq!(s.weekly_reserved_count(), 0);
        assert!(s.get(PRIMARY_ACCOUNT_ID).unwrap().available_at_with_policy(now_ts(), &pol));

        // Crossing 99% weekly (99,000 / 100,000) parks ONLY for the weekly reserve (preserving 1%)!
        let parked2 = s.record_usage(
            PRIMARY_ACCOUNT_ID,
            &serde_json::json!({ "input_tokens": 49_000, "output_tokens": 0 }),
        );
        assert!(parked2, "hitting 99% weekly must soft-park to preserve 1% weekly reserve");
        assert_eq!(s.weekly_reserved_count(), 1);
        assert!(!s.get(PRIMARY_ACCOUNT_ID).unwrap().available_at_with_policy(now_ts(), &pol));
        // Pool automatically routes to second account instead
        assert_eq!(s.pick(7, &HashSet::new()).unwrap().id, a2.id);

        // After 7 days elapse, weekly reserve automatically clears
        let next_week = now_ts() + WINDOW_WEEK_SECS + 5;
        assert!(s.get(PRIMARY_ACCOUNT_ID).unwrap().available_at_with_policy(next_week, &pol));

        // Auto-calibration on weekly quota hit learns ceiling cleanly
        s.record_usage(&a2.id, &serde_json::json!({ "input_tokens": 80_000, "output_tokens": 5_000 }));
        let wk_err = classify_failure("You have reached your weekly quota. Resets in 2d.", Some("429"), Some(1), false);
        assert_eq!(wk_err.quota_scope, Some(QuotaScope::Weekly));
        s.record_failure(&a2.id, &wk_err, "weekly quota");
        assert_eq!(s.get(&a2.id).unwrap().usage.calibrated_weekly_budget, Some(85_000));
    }

    #[test]
    fn pool_safety_breaker_strict_concurrency_and_proxy_filter() {
        let dir = TempDir::new().unwrap();
        let (s, _primary) = store(&dir);
        let a1 = s.add_slot("acc1").unwrap();
        let a2 = s.add_slot("acc2").unwrap();
        for a in [&a1, &a2] {
            fs::write(a.token_path(), r#"{"token":{"refresh_token":"r"}}"#).unwrap();
            s.finish_login(&a.id).unwrap();
        }
        s.set_policy(AccountPolicy::strict_safe()).unwrap();

        // Bind sticky proxy & verify filter can block unhealthy fail-closed proxy account
        s.set_account_proxy(PRIMARY_ACCOUNT_ID, Some("px1")).unwrap();
        let picked = s
            .pick_with_filter(1, &HashSet::new(), |a| a.proxy_id.as_deref() != Some("px1"))
            .unwrap();
        assert_eq!(picked.id, a1.id);

        // Strict concurrency = 1 refuses double-booking when all remaining accounts are busy
        s.begin(PRIMARY_ACCOUNT_ID);
        s.begin(&a1.id);
        s.begin(&a2.id);
        assert!(s.pick(9, &HashSet::new()).is_none());
        s.end(PRIMARY_ACCOUNT_ID);
        s.end(&a1.id);
        s.end(&a2.id);

        // Two distinct severe ToS bans within 15m trip the pool breaker & protect the 3rd account
        let ban = classify_failure("disabled in this account for violation of Terms of Service", Some("403"), Some(1), false);
        s.record_failure(PRIMARY_ACCOUNT_ID, &ban, "ToS");
        assert!(s.breaker_status().is_none());
        s.record_failure(&a1.id, &ban, "ToS");
        assert!(s.breaker_status().is_some(), "breaker must trip after 2 severe hits");
        assert!(s.pick(9, &HashSet::new()).is_none(), "tripped breaker protects a2 from rotation");
        assert_eq!(s.available_count(), 0);

        // Owner clears breaker -> healthy a2 is usable again
        s.reset_breaker().unwrap();
        assert!(s.breaker_status().is_none());
        assert_eq!(s.pick(9, &HashSet::new()).unwrap().id, a2.id);

        // Clearing proxy bindings removes references cleanly
        assert_eq!(s.clear_proxy_bindings("px1").unwrap(), 1);
        assert!(s.get(PRIMARY_ACCOUNT_ID).unwrap().proxy_id.is_none());
    }

    #[test]
    fn safety_fixes_policy_reevaluation_breaker_reset_and_pinned_respects_policy() {
        let dir = TempDir::new().unwrap();
        let (s, _primary) = store(&dir);
        let a1 = s.add_slot("acc1").unwrap();
        let a2 = s.add_slot("acc2").unwrap();
        for a in [&a1, &a2] {
            fs::write(a.token_path(), r#"{"token":{"refresh_token":"r"}}"#).unwrap();
            s.finish_login(&a.id).unwrap();
        }

        // 1. Account parked under 5% weekly reserve un-parks immediately when reserve drops to 1% via set_policy
        let mut pol = AccountPolicy::strict_safe();
        pol.weekly_reserve_pct = 5.0;
        pol.default_weekly_token_budget = 100_000;
        s.set_policy(pol.clone()).unwrap();
        let parked = s.record_usage(
            PRIMARY_ACCOUNT_ID,
            &serde_json::json!({ "input_tokens": 96_000, "output_tokens": 0 }),
        );
        assert!(parked);
        assert!(s
            .pick_pinned_begin_with_filter(PRIMARY_ACCOUNT_ID, &HashSet::new(), |_| true)
            .is_none());

        pol.weekly_reserve_pct = 1.0; // stop threshold raises from 95% -> 99%
        s.set_policy(pol.clone()).unwrap();
        let picked_pin = s
            .pick_pinned_begin_with_filter(PRIMARY_ACCOUNT_ID, &HashSet::new(), |_| true)
            .expect("lowering reserve must immediately un-park primary");
        assert_eq!(picked_pin.id, PRIMARY_ACCOUNT_ID);
        // Max concurrency = 1 refuses second pinned pick while first is in-flight
        assert!(s
            .pick_pinned_begin_with_filter(PRIMARY_ACCOUNT_ID, &HashSet::new(), |_| true)
            .is_none());
        s.end(PRIMARY_ACCOUNT_ID);

        // 2. reset_health clears stale severe breaker incidents for the reset account
        let ban = classify_failure(
            "disabled in this account for violation of Terms of Service",
            Some("403"),
            Some(1),
            false,
        );
        s.record_failure(PRIMARY_ACCOUNT_ID, &ban, "ToS");
        s.reset_health(PRIMARY_ACCOUNT_ID).unwrap();
        s.record_failure(&a1.id, &ban, "ToS");
        assert!(
            s.breaker_status().is_none(),
            "reset_health must purge stale incident from breaker window so next failure doesn't false-trip"
        );
    }
}
