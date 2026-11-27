//! Core domain types, typed config, atomic persistence, ACL, outbox, and health tracking.

pub mod accounts;
pub mod acl;
pub mod atomic;
pub mod config;
pub mod error;
pub mod health;
pub mod outbox;
pub mod proxies;
pub mod security;
pub mod store;
pub mod telemetry;
pub mod text;
pub mod tg;

pub use accounts::{AccountPolicy, AccountPolicyPreset, AccountUsage, QuotaScope};
pub use acl::{
    AclData, AclStore, AclUser, BulkTarget, McpDecision, McpRequest, McpRequestStatus, Perms,
    RolePreset, RoleTier, UserFilter, UserStatus, DEFAULT_START_NOTIFY_COOLDOWN_SECS,
    MAX_MCP_REQUESTS, PERM_KEYS, ROLE_PRESETS, TOUCH_SAVE_INTERVAL_SECS,
};
pub use atomic::{atomic_write_bytes, atomic_write_json, atomic_write_text};
pub use config::{redact_proxy_url, Config, EngineKind, ProxyMode, TransportMode};
pub use error::{BridgeError, Result};
pub use health::{HealthSnapshot, HealthTracker};
pub use outbox::{
    dedupe_key, full_jitter, full_jitter_with, OutQueue, OutboxItem, DEFAULT_MAX_AGE_SECS,
};
pub use proxies::{
    validate_proxy_url, ProxiesData, ProxyEntry, ProxyEntryHealth, ProxyFallbackPolicy,
    ProxyHealthStatus, ProxyRegistry, ResolvedProxy, MAX_PROXIES,
};
pub use security::{
    scan_file_for_secrets, scan_secret_leaks, KeyedTokenBucket, RateLimitResult, SecretFinding,
    DEFAULT_MAX_BUCKET_KEYS, DEFAULT_MAX_SECRET_SCAN_BYTES,
};
pub use store::{
    SessionEntry, StateData, StateStore, UserState, MAX_HISTORY_ENTRIES, MAX_HISTORY_TITLE_CHARS,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
