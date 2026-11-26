//! Thread-safe JSON-backed Access Control List (ACL) store with owner immunity,
//! permission presets, batch selection/operations, and idempotent MCP approval queue.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::RwLock;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use crate::atomic::atomic_write_json;
use crate::error::{BridgeError, Result};
use crate::tg::User;

/// Supported fine-grained modular permission keys (13 modules).
pub const PERM_KEYS: [&str; 13] = [
    "dashboard_access",
    "models_switch",
    "uncensored",
    "grok",
    "settings_access",
    "status_net",
    "widgets",
    "skills_manage",
    "mcp_manage",
    "root_access",
    "parallel",
    "automations",
    "sandbox_exec",
];

/// Debounce interval for `touch_user` disk persistence when metadata has not changed.
pub const TOUCH_SAVE_INTERVAL_SECS: f64 = 60.0;

/// Default cooldown between unapproved `/start` notifications to the owner.
pub const DEFAULT_START_NOTIFY_COOLDOWN_SECS: u64 = 300;

/// Maximum number of retained MCP approval requests (evicting resolved oldest first).
pub const MAX_MCP_REQUESTS: usize = 100;

/// Named role presets for quick permission configuration.
pub const ROLE_PRESETS: [(&str, Perms); 3] = [
    (
        "std",
        Perms {
            dashboard_access: false,
            models_switch: false,
            uncensored: false,
            grok: false,
            settings_access: false,
            status_net: false,
            widgets: false,
            skills_manage: false,
            mcp_manage: false,
            root_access: false,
            parallel: false,
            automations: false,
            sandbox_exec: false,
        },
    ),
    (
        "dev",
        Perms {
            dashboard_access: true,
            models_switch: true,
            uncensored: true,
            grok: true,
            settings_access: true,
            status_net: true,
            widgets: false,
            skills_manage: true,
            mcp_manage: true,
            root_access: false,
            parallel: false,
            automations: false,
            sandbox_exec: true,
        },
    ),
    (
        "full",
        Perms {
            dashboard_access: true,
            models_switch: true,
            uncensored: true,
            grok: true,
            settings_access: true,
            status_net: true,
            widgets: true,
            skills_manage: true,
            mcp_manage: true,
            root_access: true,
            parallel: true,
            automations: true,
            sandbox_exec: true,
        },
    ),
];

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// User approval lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    #[default]
    Pending,
    Approved,
    Blocked,
}

impl UserStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Blocked => "blocked",
        }
    }
}

impl fmt::Display for UserStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for UserStatus {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "blocked" => Ok(Self::Blocked),
            other => Err(BridgeError::Validation(format!("Invalid status: '{other}'"))),
        }
    }
}

/// Explicit three-tier RBAC hierarchy: `User < Admin < Owner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleTier {
    #[default]
    User,
    Admin,
    Owner,
}

impl RoleTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    pub fn badge(&self) -> &'static str {
        match self {
            Self::User => "👤",
            Self::Admin => "🛡",
            Self::Owner => "★",
        }
    }

    /// Parses only delegable non-owner tiers (`"user"` or `"admin"`).
    pub fn parse_non_owner(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "user" => Ok(Self::User),
            "admin" => Ok(Self::Admin),
            "owner" => Err(BridgeError::PermissionDenied(
                "Cannot assign owner tier".into(),
            )),
            other => Err(BridgeError::Validation(format!("Unknown tier: '{other}'"))),
        }
    }
}

impl fmt::Display for RoleTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RoleTier {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "user" => Ok(Self::User),
            "admin" => Ok(Self::Admin),
            "owner" => Ok(Self::Owner),
            other => Err(BridgeError::Validation(format!("Unknown tier: '{other}'"))),
        }
    }
}

/// Role permission presets (`"std"`, `"dev"`, `"full"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolePreset {
    Std,
    Dev,
    Full,
}

impl RolePreset {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Std => "std",
            Self::Dev => "dev",
            Self::Full => "full",
        }
    }

    pub fn perms(self) -> Perms {
        match self {
            Self::Std => Perms::user_default(),
            Self::Dev => Perms {
                dashboard_access: true,
                models_switch: true,
                uncensored: true,
                grok: true,
                settings_access: true,
                status_net: true,
                widgets: false,
                skills_manage: true,
                mcp_manage: true,
                root_access: false,
                parallel: false,
                automations: false,
                sandbox_exec: true,
            },
            Self::Full => Perms::admin_default(),
        }
    }
}

impl fmt::Display for RolePreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RolePreset {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "std" => Ok(Self::Std),
            "dev" => Ok(Self::Dev),
            "full" => Ok(Self::Full),
            other => Err(BridgeError::Validation(format!("Unknown preset: '{other}'"))),
        }
    }
}

/// Target selector for bulk ACL mutations (always excludes owner).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BulkTarget {
    Selected,
    Pending,
    ApprovedNonOwner,
    AllNonOwner,
}

impl BulkTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::Pending => "pending",
            Self::ApprovedNonOwner => "approved_non_owner",
            Self::AllNonOwner => "all_non_owner",
        }
    }
}

impl FromStr for BulkTarget {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "selected" => Ok(Self::Selected),
            "pending" => Ok(Self::Pending),
            "approved_non_owner" => Ok(Self::ApprovedNonOwner),
            "all_non_owner" => Ok(Self::AllNonOwner),
            other => Err(BridgeError::Validation(format!(
                "Invalid bulk target: '{other}'"
            ))),
        }
    }
}

/// Filter for `AclStore::list_users`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserFilter {
    #[default]
    All,
    Approved,
    Pending,
    Blocked,
}

impl FromStr for UserFilter {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "all" => Ok(Self::All),
            "approved" => Ok(Self::Approved),
            "pending" => Ok(Self::Pending),
            "blocked" => Ok(Self::Blocked),
            other => Err(BridgeError::Validation(format!(
                "Invalid status filter: '{other}'"
            ))),
        }
    }
}

/// Owner decision on a pending MCP installation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpDecision {
    Approved,
    Rejected,
}

impl FromStr for McpDecision {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            other => Err(BridgeError::Validation(format!(
                "Invalid decision: '{other}'"
            ))),
        }
    }
}

/// Lifecycle status of an MCP request in `acl.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpRequestStatus {
    Pending,
    Approved,
    Rejected,
}

/// Per-user modular capability flags (12 modules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Perms {
    /// May open the Dashboard (`/menu`) and view sessions (`/resume`).
    #[serde(default)]
    pub dashboard_access: bool,
    /// May open and switch primary AGY models (`/model`).
    #[serde(default)]
    pub models_switch: bool,
    /// May use Venice Uncensored chat/agent (`/uncensored`, `/uagent`).
    #[serde(default)]
    pub uncensored: bool,
    /// May use Grok panel/chat/agent (`/grok`, `/gagent`, excluding Owner-only OAuth).
    #[serde(default)]
    pub grok: bool,
    /// May change operational preferences (`/settings`, `/mode`, `/effort`, `/agent`, `/cwd`, `/trace`, `/changelog`).
    #[serde(default)]
    pub settings_access: bool,
    /// May inspect system health, network proxy, and read-only cron status (`/status`, `/net`, `/cron`).
    #[serde(default)]
    pub status_net: bool,
    /// May browse interactive widgets (`/widget`, `wmenu:*`).
    #[serde(default)]
    pub widgets: bool,
    /// May browse and manage skills (`/skills`).
    #[serde(default)]
    pub skills_manage: bool,
    /// May view and manage MCP servers (`/mcp`).
    #[serde(default)]
    pub mcp_manage: bool,
    /// May execute OS/root operations (bash `run_command`, outside-workspace `/cwd`, `skip_permissions`, `retry:all`).
    #[serde(default)]
    pub root_access: bool,
    /// May use Parallel mode (`/parallel`).
    #[serde(default)]
    pub parallel: bool,
    /// May create scheduled automations (`/auto`).
    #[serde(default)]
    pub automations: bool,
    /// May execute sandboxed shell/PTY/`execute_code` commands inside the Linux `bubblewrap` sandbox (no host root).
    #[serde(default)]
    pub sandbox_exec: bool,
}

impl Perms {
    /// Full privileges granted unconditionally to the owner.
    pub fn owner() -> Self {
        Self {
            dashboard_access: true,
            models_switch: true,
            uncensored: true,
            grok: true,
            settings_access: true,
            status_net: true,
            widgets: true,
            skills_manage: true,
            mcp_manage: true,
            root_access: true,
            parallel: true,
            automations: true,
            sandbox_exec: true,
        }
    }

    /// Default privileges for an Admin tier account (full dashboard + root_access; owner may still revoke any key).
    pub fn admin_default() -> Self {
        Self::owner()
    }

    /// Default privileges for a regular User tier account (all dashboard modules & root disabled).
    pub fn user_default() -> Self {
        Self::default()
    }

    pub fn get(&self, perm: &str) -> Option<bool> {
        match perm {
            "dashboard_access" => Some(self.dashboard_access),
            "models_switch" => Some(self.models_switch),
            "uncensored" => Some(self.uncensored),
            "grok" => Some(self.grok),
            "settings_access" => Some(self.settings_access),
            "status_net" => Some(self.status_net),
            "widgets" => Some(self.widgets),
            "skills_manage" => Some(self.skills_manage),
            "mcp_manage" => Some(self.mcp_manage),
            "root_access" => Some(self.root_access),
            "parallel" => Some(self.parallel),
            "automations" => Some(self.automations),
            "sandbox_exec" => Some(self.sandbox_exec),
            _ => None,
        }
    }

    /// Sets or toggles (`val == None`) a permission flag, returning the new boolean value.
    pub fn set(&mut self, perm: &str, val: Option<bool>) -> Result<bool> {
        let slot = match perm {
            "dashboard_access" => &mut self.dashboard_access,
            "models_switch" => &mut self.models_switch,
            "uncensored" => &mut self.uncensored,
            "grok" => &mut self.grok,
            "settings_access" => &mut self.settings_access,
            "status_net" => &mut self.status_net,
            "widgets" => &mut self.widgets,
            "skills_manage" => &mut self.skills_manage,
            "mcp_manage" => &mut self.mcp_manage,
            "root_access" => &mut self.root_access,
            "parallel" => &mut self.parallel,
            "automations" => &mut self.automations,
            "sandbox_exec" => &mut self.sandbox_exec,
            _ => {
                return Err(BridgeError::Validation(format!(
                    "Invalid permission: '{perm}'"
                )))
            }
        };
        *slot = val.unwrap_or(!*slot);
        Ok(*slot)
    }
}

/// Persisted ACL user record matching Python `acl.json` schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AclUser {
    pub uid: i64,
    pub status: UserStatus,
    pub role: String,
    pub perms: Perms,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub language_code: Option<String>,
    #[serde(default)]
    pub is_premium: bool,
    pub first_seen: f64,
    pub last_seen: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_start_notify_ts: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_by: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_at: Option<f64>,
}

impl AclUser {
    /// Returns the parsed [`RoleTier`] for this ACL record.
    pub fn tier(&self) -> RoleTier {
        match self.role.trim().to_ascii_lowercase().as_str() {
            "owner" => RoleTier::Owner,
            "admin" => RoleTier::Admin,
            _ => RoleTier::User,
        }
    }
}

/// Persisted MCP installation approval request matching Python `acl.json` schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpRequest {
    pub req_id: String,
    pub status: McpRequestStatus,
    pub uid: i64,
    pub user_label: String,
    pub chat_id: i64,
    pub spec_text: String,
    pub created_at: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<f64>,
}

/// Top-level JSON structure of `acl.json`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AclData {
    #[serde(default)]
    pub users: BTreeMap<String, AclUser>,
    #[serde(default)]
    pub selected: Vec<i64>,
    #[serde(default)]
    pub suppressed_seeds: Vec<i64>,
    #[serde(default)]
    pub mcp_requests: BTreeMap<String, McpRequest>,
}

struct AclInner {
    data: AclData,
    last_touch_save: BTreeMap<i64, f64>,
}

/// Default cap on persisted `Pending` stranger records in `acl.json` (anti `/start` spam).
pub const DEFAULT_MAX_PENDING_USERS: usize = 100;

/// Minimum interval (seconds) between disk flushes for repeated `/start` attempts by an already-known
/// `Pending` or `Blocked` stranger (prevents `fsync` disk thrashing under `/start` spam).
const START_SPAM_SAVE_DEBOUNCE_SECS: f64 = 60.0;

/// Thread-safe JSON-backed ACL store.
pub struct AclStore {
    path: PathBuf,
    owner_id: i64,
    owner_ids: HashSet<i64>,
    start_notify_cooldown: u64,
    max_pending: std::sync::atomic::AtomicUsize,
    inner: RwLock<AclInner>,
}

impl AclStore {
    /// Opens `acl.json`, sanitizes/heals corrupt data, enforces owner immunity,
    /// seeds `seed_allowed` users (unless suppressed), and persists if modified.
    pub fn open(
        path: impl Into<PathBuf>,
        owner_id: i64,
        seed_allowed: &[i64],
        start_notify_cooldown: u64,
    ) -> Result<Self> {
        let path = path.into();
        let now = now_secs();
        let (inner, dirty) = load_and_sanitize(&path, owner_id, seed_allowed, now)?;
        if dirty {
            atomic_write_json(&path, &inner.data, true)?;
        }
        Ok(Self {
            path,
            owner_id,
            owner_ids: HashSet::from([owner_id]),
            start_notify_cooldown,
            max_pending: std::sync::atomic::AtomicUsize::new(DEFAULT_MAX_PENDING_USERS),
            inner: RwLock::new(inner),
        })
    }

    /// Registers additional owner IDs (e.g. from comma-separated `OWNER_ID` or `OWNER_IDS`).
    /// Each extra owner is granted `RoleTier::Owner` immunity and `Approved` status.
    pub fn with_extra_owners(mut self, extra: &[i64]) -> Self {
        for &uid in extra {
            if uid > 0 {
                self.owner_ids.insert(uid);
            }
        }
        if let Ok(mut guard) = self.inner.write() {
            let now = now_secs();
            let mut dirty = false;
            for &uid in &self.owner_ids {
                if uid == self.owner_id {
                    continue;
                }
                let key = uid.to_string();
                let needs_init = guard.data.users.get(&key).is_none_or(|u| {
                    u.status != UserStatus::Approved || u.tier() != RoleTier::Owner
                });
                if needs_init {
                    let entry = guard.data.users.entry(key).or_insert_with(|| AclUser {
                        uid,
                        status: UserStatus::Approved,
                        role: "owner".to_string(),
                        perms: Perms::owner(),
                        username: None,
                        first_name: None,
                        last_name: None,
                        language_code: None,
                        is_premium: false,
                        first_seen: now,
                        last_seen: now,
                        last_start_notify_ts: None,
                        status_by: Some(self.owner_id),
                        status_at: Some(now),
                    });
                    entry.status = UserStatus::Approved;
                    entry.role = "owner".to_string();
                    entry.perms = Perms::owner();
                    dirty = true;
                }
                if guard.data.selected.iter().any(|&x| x == uid) {
                    guard.data.selected.retain(|&x| x != uid);
                    dirty = true;
                }
            }
            if dirty {
                let _ = atomic_write_json(&self.path, &guard.data, true);
            }
        }
        self
    }

    /// Override the maximum number of persisted `Pending` stranger records (`ACL_MAX_PENDING`).
    pub fn set_max_pending(&self, max_pending: usize) {
        self.max_pending
            .store(max_pending.clamp(10, 5000), std::sync::atomic::Ordering::Relaxed);
    }

    pub fn max_pending(&self) -> usize {
        self.max_pending.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn owner_id(&self) -> i64 {
        self.owner_id
    }

    pub fn is_owner(&self, uid: i64) -> bool {
        self.owner_ids.contains(&uid)
    }

    /// Returns `true` for any owner or any user with `status == Approved`.
    pub fn is_approved(&self, uid: i64) -> bool {
        if self.is_owner(uid) {
            return true;
        }
        let Ok(guard) = self.inner.read() else {
            return false;
        };
        guard
            .data
            .users
            .get(&uid.to_string())
            .is_some_and(|u| u.status == UserStatus::Approved)
    }

    /// Returns the set of all approved user IDs (always includes all owners).
    pub fn approved_ids(&self) -> HashSet<i64> {
        let mut out = self.owner_ids.clone();
        let Ok(guard) = self.inner.read() else {
            return out;
        };
        for rec in guard.data.users.values() {
            if rec.status == UserStatus::Approved {
                out.insert(rec.uid);
            }
        }
        out
    }

    /// Returns a cloned snapshot of `uid`'s ACL record if present.
    pub fn get_user(&self, uid: i64) -> Option<AclUser> {
        let Ok(guard) = self.inner.read() else {
            return None;
        };
        guard.data.users.get(&uid.to_string()).cloned()
    }

    /// Updates user metadata and `last_seen`, saving immediately on new user / metadata change
    /// or after `> 60s` since the last save for that user.
    pub fn touch_user(&self, user: &User) -> Result<AclUser> {
        self.touch_user_at(user, now_secs())
    }

    /// Deterministic timestamp variant of [`Self::touch_user`].
    pub fn touch_user_at(&self, user: &User, now: f64) -> Result<AclUser> {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;
        let (rec, should_save) = touch_user_locked(&mut guard, self.owner_id, user, now);
        if should_save {
            atomic_write_json(&self.path, &guard.data, true)?;
        }
        Ok(rec)
    }

    /// Records an unapproved `/start` attempt, returning `(record, should_notify_owner)`.
    /// Approved users and owner only refresh metadata (`should_notify = false`).
    /// Blocked users refresh metadata and `last_seen` (`should_notify = false`).
    pub fn record_start_attempt(&self, user: &User) -> Result<(AclUser, bool)> {
        self.record_start_attempt_at(user, now_secs())
    }

    /// Deterministic timestamp variant of [`Self::record_start_attempt`].
    pub fn record_start_attempt_at(&self, user: &User, now: f64) -> Result<(AclUser, bool)> {
        let uid = user.id;
        let ukey = uid.to_string();
        let meta = UserMeta::from_tg(user);

        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;

        let already_approved = uid == self.owner_id
            || guard
                .data
                .users
                .get(&ukey)
                .is_some_and(|r| r.status == UserStatus::Approved);

        if already_approved {
            let (rec, should_save) = touch_user_locked(&mut guard, self.owner_id, user, now);
            if should_save {
                atomic_write_json(&self.path, &guard.data, true)?;
            }
            return Ok((rec, false));
        }

        let existing_status = guard.data.users.get(&ukey).map(|r| r.status);
        let is_new = existing_status.is_none();
        let is_blocked = existing_status == Some(UserStatus::Blocked);

        if is_new {
            let pending_count = guard
                .data
                .users
                .values()
                .filter(|r| r.status == UserStatus::Pending)
                .count();
            let cap = self.max_pending();
            if pending_count >= cap {
                warn!(
                    uid,
                    pending_count,
                    cap,
                    "ACL pending stranger cap reached; dropping new /start without disk write"
                );
                let ephemeral =
                    make_user_record(uid, UserStatus::Pending, "user", Perms::default(), now, &meta);
                return Ok((ephemeral, false));
            }
        }

        let last_save = guard.last_touch_save.get(&uid).copied().unwrap_or(0.0);
        let save_due = (now - last_save) >= START_SPAM_SAVE_DEBOUNCE_SECS;

        let rec = guard
            .data
            .users
            .entry(ukey.clone())
            .or_insert_with(|| make_user_record(uid, UserStatus::Pending, "user", Perms::default(), now, &meta));

        meta.apply_to(rec);
        rec.last_seen = now;

        if is_blocked {
            let snapshot = rec.clone();
            if save_due {
                guard.last_touch_save.insert(uid, now);
                atomic_write_json(&self.path, &guard.data, true)?;
            }
            return Ok((snapshot, false));
        }

        rec.status = UserStatus::Pending;
        let cooldown = self.start_notify_cooldown as f64;
        let should_notify = match rec.last_start_notify_ts {
            None => true,
            Some(last) => (now - last) >= cooldown,
        };
        if should_notify {
            rec.last_start_notify_ts = Some(now);
        }
        let snapshot = rec.clone();
        if is_new || should_notify || save_due {
            guard.last_touch_save.insert(uid, now);
            atomic_write_json(&self.path, &guard.data, true)?;
        }
        Ok((snapshot, should_notify))
    }

    /// Sets a non-owner user's approval status, optionally recording `by_uid` and applying a preset.
    pub fn set_status(
        &self,
        uid: i64,
        status: UserStatus,
        by_uid: Option<i64>,
        preset: Option<RolePreset>,
    ) -> Result<AclUser> {
        self.set_status_at(uid, status, by_uid, preset, now_secs())
    }

    /// Deterministic timestamp variant of [`Self::set_status`].
    pub fn set_status_at(
        &self,
        uid: i64,
        status: UserStatus,
        by_uid: Option<i64>,
        preset: Option<RolePreset>,
        now: f64,
    ) -> Result<AclUser> {
        if uid == self.owner_id {
            return Err(BridgeError::PermissionDenied(
                "Cannot modify owner status".into(),
            ));
        }
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;

        let ukey = uid.to_string();
        if !guard.data.users.contains_key(&ukey) {
            guard.data.users.insert(
                ukey.clone(),
                make_user_record(
                    uid,
                    UserStatus::Pending,
                    "user",
                    Perms::default(),
                    now,
                    &UserMeta::default(),
                ),
            );
        }

        if let Some(rec) = guard.data.users.get_mut(&ukey) {
            apply_status_to_record(rec, status, by_uid, preset, now);
        }
        if status == UserStatus::Approved {
            guard.data.suppressed_seeds.retain(|&x| x != uid);
        }

        let snapshot = guard
            .data
            .users
            .get(&ukey)
            .cloned()
            .ok_or_else(|| BridgeError::Internal("missing user after insert".into()))?;
        atomic_write_json(&self.path, &guard.data, true)?;
        Ok(snapshot)
    }

    /// Returns the effective [`RoleTier`] for `uid` (`Owner` for `owner_id`, stored tier for non-owners).
    pub fn tier_of(&self, uid: i64) -> RoleTier {
        if uid == self.owner_id {
            return RoleTier::Owner;
        }
        let Ok(guard) = self.inner.read() else {
            return RoleTier::User;
        };
        guard
            .data
            .users
            .get(&uid.to_string())
            .map(AclUser::tier)
            .filter(|t| *t != RoleTier::Owner)
            .unwrap_or(RoleTier::User)
    }

    /// Returns `true` if `uid` is an approved Admin (or the Owner).
    pub fn is_admin(&self, uid: i64) -> bool {
        if uid == self.owner_id {
            return true;
        }
        let Ok(guard) = self.inner.read() else {
            return false;
        };
        guard
            .data
            .users
            .get(&uid.to_string())
            .is_some_and(|rec| rec.status == UserStatus::Approved && rec.tier() == RoleTier::Admin)
    }

    /// Only the Owner may manage user tiers, permissions, approvals, or receive Owner alerts.
    pub fn can_manage_users(&self, uid: i64) -> bool {
        self.is_owner(uid)
    }

    /// Changes a non-owner user's [`RoleTier`] (`User` or `Admin`), optionally applying tier defaults.
    pub fn set_tier(&self, uid: i64, tier: RoleTier, apply_defaults: bool) -> Result<AclUser> {
        if uid == self.owner_id {
            return Err(BridgeError::PermissionDenied(
                "Cannot modify owner tier".into(),
            ));
        }
        if tier == RoleTier::Owner {
            return Err(BridgeError::PermissionDenied(
                "Cannot assign owner tier to another user".into(),
            ));
        }
        let now = now_secs();
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;

        let ukey = uid.to_string();
        let rec = guard.data.users.entry(ukey).or_insert_with(|| {
            make_user_record(
                uid,
                UserStatus::Pending,
                "user",
                Perms::default(),
                now,
                &UserMeta::default(),
            )
        });
        rec.role = tier.as_str().to_string();
        if apply_defaults {
            rec.perms = match tier {
                RoleTier::Admin => Perms::admin_default(),
                RoleTier::User => Perms::user_default(),
                RoleTier::Owner => Perms::owner(),
            };
        }
        let snapshot = rec.clone();
        atomic_write_json(&self.path, &guard.data, true)?;
        Ok(snapshot)
    }

    /// Checks whether `uid` effectively holds `perm` (owner always `true`; blocked/pending always `false`).
    pub fn has_perm(&self, uid: i64, perm: &str) -> bool {
        if uid == self.owner_id {
            return true;
        }
        let Ok(guard) = self.inner.read() else {
            return false;
        };
        let Some(rec) = guard.data.users.get(&uid.to_string()) else {
            return false;
        };
        if rec.status != UserStatus::Approved {
            return false;
        }
        rec.perms.get(perm).unwrap_or(false)
    }

    /// Sets (or toggles when `val == None`) a permission bit for a non-owner user.
    pub fn set_perm(&self, uid: i64, perm: &str, val: Option<bool>) -> Result<AclUser> {
        if uid == self.owner_id {
            return Err(BridgeError::PermissionDenied(
                "Cannot modify owner permissions".into(),
            ));
        }
        if !PERM_KEYS.contains(&perm) {
            return Err(BridgeError::Validation(format!(
                "Invalid permission: '{perm}'"
            )));
        }
        let now = now_secs();
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;

        let ukey = uid.to_string();
        let rec = guard.data.users.entry(ukey).or_insert_with(|| {
            make_user_record(
                uid,
                UserStatus::Pending,
                "user",
                Perms::default(),
                now,
                &UserMeta::default(),
            )
        });
        rec.perms.set(perm, val)?;
        let snapshot = rec.clone();
        atomic_write_json(&self.path, &guard.data, true)?;
        Ok(snapshot)
    }

    /// Applies a named [`RolePreset`] to a non-owner user.
    pub fn apply_preset(&self, uid: i64, preset: RolePreset) -> Result<AclUser> {
        if uid == self.owner_id {
            return Err(BridgeError::PermissionDenied(
                "Cannot apply preset to owner".into(),
            ));
        }
        let now = now_secs();
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;

        let ukey = uid.to_string();
        let rec = guard.data.users.entry(ukey).or_insert_with(|| {
            make_user_record(
                uid,
                UserStatus::Pending,
                "user",
                Perms::default(),
                now,
                &UserMeta::default(),
            )
        });
        rec.perms = preset.perms();
        let snapshot = rec.clone();
        atomic_write_json(&self.path, &guard.data, true)?;
        Ok(snapshot)
    }

    /// Removes a non-owner user and suppresses future re-seeding from `ALLOWED_USER_IDS`.
    pub fn remove_user(&self, uid: i64) -> Result<bool> {
        if uid == self.owner_id {
            return Err(BridgeError::PermissionDenied("Cannot remove owner".into()));
        }
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;

        let existed = guard.data.users.remove(&uid.to_string()).is_some();
        guard.last_touch_save.remove(&uid);
        guard.data.selected.retain(|&x| x != uid);
        if !existed {
            return Ok(false);
        }
        if !guard.data.suppressed_seeds.contains(&uid) {
            guard.data.suppressed_seeds.push(uid);
        }
        atomic_write_json(&self.path, &guard.data, true)?;
        Ok(true)
    }

    /// Lists users matching `filter`, sorted: owner first, then pending, approved, blocked
    /// (within each bucket: descending `last_seen`, descending `first_seen`, ascending `uid`).
    pub fn list_users(&self, filter: UserFilter) -> Vec<AclUser> {
        let Ok(guard) = self.inner.read() else {
            return Vec::new();
        };
        let mut items: Vec<AclUser> = guard
            .data
            .users
            .values()
            .filter(|rec| match filter {
                UserFilter::All => true,
                UserFilter::Approved => rec.status == UserStatus::Approved,
                UserFilter::Pending => rec.status == UserStatus::Pending,
                UserFilter::Blocked => rec.status == UserStatus::Blocked,
            })
            .cloned()
            .collect();

        let owner_id = self.owner_id;
        items.sort_by(|a, b| {
            let bucket = |u: &AclUser| -> u8 {
                if u.uid == owner_id {
                    0
                } else {
                    match u.status {
                        UserStatus::Pending => 1,
                        UserStatus::Approved => 2,
                        UserStatus::Blocked => 3,
                    }
                }
            };
            bucket(a)
                .cmp(&bucket(b))
                .then_with(|| (-a.last_seen).total_cmp(&(-b.last_seen)))
                .then_with(|| (-a.first_seen).total_cmp(&(-b.first_seen)))
                .then_with(|| a.uid.cmp(&b.uid))
        });
        items
    }

    /// Toggles selection state of `uid` (owner can never be selected; returns `false`).
    pub fn toggle_select(&self, uid: i64) -> Result<bool> {
        if uid == self.owner_id {
            return Ok(false);
        }
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;
        let new_state = if let Some(pos) = guard.data.selected.iter().position(|&x| x == uid) {
            guard.data.selected.remove(pos);
            false
        } else {
            guard.data.selected.push(uid);
            true
        };
        atomic_write_json(&self.path, &guard.data, true)?;
        Ok(new_state)
    }

    /// Adds or removes multiple non-owner `uids` in `selected`, returning total selected count.
    pub fn select_many(&self, uids: &[i64], selected: bool) -> Result<usize> {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;
        let old = guard.data.selected.clone();
        if selected {
            let mut seen: HashSet<i64> = guard.data.selected.iter().copied().collect();
            for &uid in uids {
                if uid == self.owner_id || !seen.insert(uid) {
                    continue;
                }
                guard.data.selected.push(uid);
            }
        } else {
            let remove_set: HashSet<i64> = uids
                .iter()
                .copied()
                .filter(|&u| u != self.owner_id)
                .collect();
            guard.data.selected.retain(|u| !remove_set.contains(u));
        }
        if guard.data.selected != old {
            atomic_write_json(&self.path, &guard.data, true)?;
        }
        Ok(guard.data.selected.len())
    }

    /// Clears all selected non-owner UIDs and returns how many were cleared.
    pub fn clear_selection(&self) -> Result<usize> {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;
        let count = guard.data.selected.len();
        if count > 0 {
            guard.data.selected.clear();
            atomic_write_json(&self.path, &guard.data, true)?;
        }
        Ok(count)
    }

    /// Returns a cloned list of currently selected UIDs.
    pub fn selected_uids(&self) -> Vec<i64> {
        let Ok(guard) = self.inner.read() else {
            return Vec::new();
        };
        guard.data.selected.clone()
    }

    /// Bulk-updates status (and optionally preset) for a [`BulkTarget`], never touching the owner.
    pub fn bulk_set_status(
        &self,
        target: BulkTarget,
        status: UserStatus,
        preset: Option<RolePreset>,
        by_uid: Option<i64>,
    ) -> Result<Vec<i64>> {
        let now = now_secs();
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;

        let uids = resolve_bulk_targets_locked(&guard.data, self.owner_id, target);
        let mut modified = Vec::with_capacity(uids.len());
        for uid in uids {
            if let Some(rec) = guard.data.users.get_mut(&uid.to_string()) {
                apply_status_to_record(rec, status, by_uid, preset, now);
                if status == UserStatus::Approved {
                    guard.data.suppressed_seeds.retain(|&x| x != uid);
                }
                modified.push(uid);
            }
        }
        if !modified.is_empty() {
            atomic_write_json(&self.path, &guard.data, true)?;
        }
        Ok(modified)
    }

    /// Bulk-sets a single permission flag for a [`BulkTarget`], never touching the owner.
    pub fn bulk_set_perm(&self, target: BulkTarget, perm: &str, val: bool) -> Result<Vec<i64>> {
        if !PERM_KEYS.contains(&perm) {
            return Err(BridgeError::Validation(format!(
                "Invalid permission: '{perm}'"
            )));
        }
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;

        let uids = resolve_bulk_targets_locked(&guard.data, self.owner_id, target);
        let mut modified = Vec::with_capacity(uids.len());
        for uid in uids {
            if let Some(rec) = guard.data.users.get_mut(&uid.to_string()) {
                rec.perms.set(perm, Some(val))?;
                modified.push(uid);
            }
        }
        if !modified.is_empty() {
            atomic_write_json(&self.path, &guard.data, true)?;
        }
        Ok(modified)
    }

    /// Bulk-applies a [`RolePreset`] to a [`BulkTarget`], never touching the owner.
    pub fn bulk_apply_preset(&self, target: BulkTarget, preset: RolePreset) -> Result<Vec<i64>> {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;

        let uids = resolve_bulk_targets_locked(&guard.data, self.owner_id, target);
        let mut modified = Vec::with_capacity(uids.len());
        for uid in uids {
            if let Some(rec) = guard.data.users.get_mut(&uid.to_string()) {
                rec.perms = preset.perms();
                modified.push(uid);
            }
        }
        if !modified.is_empty() {
            atomic_write_json(&self.path, &guard.data, true)?;
        }
        Ok(modified)
    }

    /// Bulk-changes non-owner [`RoleTier`] (`User` or `Admin`), optionally applying tier defaults.
    pub fn bulk_set_tier(
        &self,
        target: BulkTarget,
        tier: RoleTier,
        apply_defaults: bool,
    ) -> Result<Vec<i64>> {
        if tier == RoleTier::Owner {
            return Err(BridgeError::PermissionDenied(
                "Cannot assign owner tier in bulk".into(),
            ));
        }
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;

        let uids = resolve_bulk_targets_locked(&guard.data, self.owner_id, target);
        let mut modified = Vec::with_capacity(uids.len());
        for uid in uids {
            if let Some(rec) = guard.data.users.get_mut(&uid.to_string()) {
                rec.role = tier.as_str().to_string();
                if apply_defaults {
                    rec.perms = match tier {
                        RoleTier::Admin => Perms::admin_default(),
                        RoleTier::User => Perms::user_default(),
                        RoleTier::Owner => Perms::owner(),
                    };
                }
                modified.push(uid);
            }
        }
        if !modified.is_empty() {
            atomic_write_json(&self.path, &guard.data, true)?;
        }
        Ok(modified)
    }

    /// Creates a new pending MCP request, evicting resolved-oldest entries first at the 100-item cap.
    pub fn create_mcp_request(
        &self,
        uid: i64,
        user_label: impl Into<String>,
        chat_id: i64,
        spec_text: impl Into<String>,
    ) -> Result<McpRequest> {
        self.create_mcp_request_at(uid, user_label, chat_id, spec_text, now_secs())
    }

    /// Deterministic timestamp variant of [`Self::create_mcp_request`].
    pub fn create_mcp_request_at(
        &self,
        uid: i64,
        user_label: impl Into<String>,
        chat_id: i64,
        spec_text: impl Into<String>,
        now: f64,
    ) -> Result<McpRequest> {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;

        while guard.data.mcp_requests.len() >= MAX_MCP_REQUESTS {
            let victim = guard
                .data
                .mcp_requests
                .iter()
                .min_by(|(ka, a), (kb, b)| {
                    let pa = u8::from(a.status == McpRequestStatus::Pending);
                    let pb = u8::from(b.status == McpRequestStatus::Pending);
                    pa.cmp(&pb)
                        .then_with(|| a.created_at.total_cmp(&b.created_at))
                        .then_with(|| ka.cmp(kb))
                })
                .map(|(k, _)| k.clone());
            match victim {
                Some(k) => {
                    guard.data.mcp_requests.remove(&k);
                }
                None => break,
            }
        }

        let mut req_id = random_req_id();
        while guard.data.mcp_requests.contains_key(&req_id) {
            req_id = random_req_id();
        }

        let req = McpRequest {
            req_id: req_id.clone(),
            status: McpRequestStatus::Pending,
            uid,
            user_label: user_label.into(),
            chat_id,
            spec_text: spec_text.into(),
            created_at: now,
            resolved_by: None,
            resolved_at: None,
        };
        guard.data.mcp_requests.insert(req_id, req.clone());
        atomic_write_json(&self.path, &guard.data, true)?;
        Ok(req)
    }

    /// Looks up an MCP request by ID.
    pub fn get_mcp_request(&self, req_id: &str) -> Option<McpRequest> {
        let Ok(guard) = self.inner.read() else {
            return None;
        };
        guard.data.mcp_requests.get(req_id).cloned()
    }

    /// Returns the number of stored MCP requests.
    pub fn mcp_request_count(&self) -> usize {
        let Ok(guard) = self.inner.read() else {
            return 0;
        };
        guard.data.mcp_requests.len()
    }

    /// Idempotently resolves a pending MCP request. Returns `Ok(None)` if missing or already resolved.
    pub fn resolve_mcp_request(
        &self,
        req_id: &str,
        decision: McpDecision,
        by_uid: i64,
    ) -> Result<Option<McpRequest>> {
        self.resolve_mcp_request_at(req_id, decision, by_uid, now_secs())
    }

    /// Deterministic timestamp variant of [`Self::resolve_mcp_request`].
    pub fn resolve_mcp_request_at(
        &self,
        req_id: &str,
        decision: McpDecision,
        by_uid: i64,
        now: f64,
    ) -> Result<Option<McpRequest>> {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("acl write lock poisoned: {e}")))?;

        let Some(req) = guard.data.mcp_requests.get_mut(req_id) else {
            return Ok(None);
        };
        if req.status != McpRequestStatus::Pending {
            return Ok(None);
        }
        req.status = match decision {
            McpDecision::Approved => McpRequestStatus::Approved,
            McpDecision::Rejected => McpRequestStatus::Rejected,
        };
        req.resolved_by = Some(by_uid);
        req.resolved_at = Some(now);
        let snapshot = req.clone();
        atomic_write_json(&self.path, &guard.data, true)?;
        Ok(Some(snapshot))
    }
}

#[derive(Default)]
struct UserMeta {
    username: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    language_code: Option<String>,
    is_premium: bool,
}

impl UserMeta {
    fn from_tg(user: &User) -> Self {
        Self {
            username: user.username.clone(),
            first_name: if user.first_name.is_empty() {
                None
            } else {
                Some(user.first_name.clone())
            },
            last_name: user.last_name.clone(),
            language_code: user.language_code.clone(),
            is_premium: user.is_premium.unwrap_or(false),
        }
    }

    fn differs_from(&self, rec: &AclUser) -> bool {
        rec.username != self.username
            || rec.first_name != self.first_name
            || rec.last_name != self.last_name
            || rec.language_code != self.language_code
            || rec.is_premium != self.is_premium
    }

    fn apply_to(&self, rec: &mut AclUser) {
        rec.username.clone_from(&self.username);
        rec.first_name.clone_from(&self.first_name);
        rec.last_name.clone_from(&self.last_name);
        rec.language_code.clone_from(&self.language_code);
        rec.is_premium = self.is_premium;
    }
}

fn make_user_record(
    uid: i64,
    status: UserStatus,
    role: &str,
    perms: Perms,
    now: f64,
    meta: &UserMeta,
) -> AclUser {
    AclUser {
        uid,
        status,
        role: role.to_string(),
        perms,
        username: meta.username.clone(),
        first_name: meta.first_name.clone(),
        last_name: meta.last_name.clone(),
        language_code: meta.language_code.clone(),
        is_premium: meta.is_premium,
        first_seen: now,
        last_seen: now,
        last_start_notify_ts: None,
        status_by: None,
        status_at: None,
    }
}

fn touch_user_locked(
    guard: &mut AclInner,
    owner_id: i64,
    user: &User,
    now: f64,
) -> (AclUser, bool) {
    let uid = user.id;
    let ukey = uid.to_string();
    let meta = UserMeta::from_tg(user);

    if let Some(rec) = guard.data.users.get_mut(&ukey) {
        let meta_changed = meta.differs_from(rec);
        if meta_changed {
            meta.apply_to(rec);
        }
        let prev_last_seen = rec.last_seen;
        rec.last_seen = now;
        if uid == owner_id {
            rec.status = UserStatus::Approved;
            rec.role = "owner".to_string();
            rec.perms = Perms::owner();
        }
        let last_saved = guard
            .last_touch_save
            .get(&uid)
            .copied()
            .unwrap_or(prev_last_seen);
        let should_save = meta_changed || (now - last_saved) > TOUCH_SAVE_INTERVAL_SECS;
        let snapshot = rec.clone();
        if should_save {
            guard.last_touch_save.insert(uid, now);
        }
        (snapshot, should_save)
    } else {
        let is_owner = uid == owner_id;
        let rec = make_user_record(
            uid,
            if is_owner {
                UserStatus::Approved
            } else {
                UserStatus::Pending
            },
            if is_owner { "owner" } else { "user" },
            if is_owner {
                Perms::owner()
            } else {
                Perms::default()
            },
            now,
            &meta,
        );
        guard.data.users.insert(ukey, rec.clone());
        guard.last_touch_save.insert(uid, now);
        (rec, true)
    }
}

fn apply_status_to_record(
    rec: &mut AclUser,
    status: UserStatus,
    by_uid: Option<i64>,
    preset: Option<RolePreset>,
    now: f64,
) {
    rec.status = status;
    if let Some(by) = by_uid {
        rec.status_by = Some(by);
        rec.status_at = Some(now);
    }
    if let Some(p) = preset {
        rec.perms = p.perms();
    }
}

fn resolve_bulk_targets_locked(data: &AclData, owner_id: i64, target: BulkTarget) -> Vec<i64> {
    match target {
        BulkTarget::Selected => data
            .selected
            .iter()
            .copied()
            .filter(|&uid| uid != owner_id && data.users.contains_key(&uid.to_string()))
            .collect(),
        BulkTarget::Pending => data
            .users
            .values()
            .filter(|rec| rec.uid != owner_id && rec.status == UserStatus::Pending)
            .map(|rec| rec.uid)
            .collect(),
        BulkTarget::ApprovedNonOwner => data
            .users
            .values()
            .filter(|rec| rec.uid != owner_id && rec.status == UserStatus::Approved)
            .map(|rec| rec.uid)
            .collect(),
        BulkTarget::AllNonOwner => data
            .users
            .values()
            .filter(|rec| rec.uid != owner_id)
            .map(|rec| rec.uid)
            .collect(),
    }
}

fn random_req_id() -> String {
    let mut bytes = [0_u8; 5];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn parse_i64_value(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn parse_f64_value(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64().filter(|x| x.is_finite()),
        Value::String(s) => s.trim().parse::<f64>().ok().filter(|x| x.is_finite()),
        _ => None,
    }
}

fn parse_opt_string(v: Option<&Value>, dirty: &mut bool) -> Option<String> {
    match v {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => {
            *dirty = true;
            Some(other.to_string())
        }
    }
}

fn load_and_sanitize(
    path: &Path,
    owner_id: i64,
    seed_allowed: &[i64],
    now: f64,
) -> Result<(AclInner, bool)> {
    let mut dirty = false;
    let loaded_obj = match std::fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(Value::Object(map)) => map,
            Ok(_) => {
                warn!(path = %path.display(), "acl.json root is not an object; recovering");
                dirty = true;
                serde_json::Map::new()
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "corrupt acl.json; recovering");
                dirty = true;
                serde_json::Map::new()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            dirty = true;
            serde_json::Map::new()
        }
        Err(e) => return Err(BridgeError::io(format!("read {}", path.display()), e)),
    };

    let mut data = AclData::default();
    let mut last_touch_save = BTreeMap::new();

    if let Some(raw_users_val) = loaded_obj.get("users") {
        if let Some(raw_users) = raw_users_val.as_object() {
            for (key, val) in raw_users {
                let Some(rec_obj) = val.as_object() else {
                    dirty = true;
                    continue;
                };
                let uid = rec_obj
                    .get("uid")
                    .and_then(parse_i64_value)
                    .or_else(|| key.trim().parse::<i64>().ok());
                let Some(uid) = uid else {
                    dirty = true;
                    continue;
                };

                let status = match rec_obj.get("status").and_then(Value::as_str) {
                    Some(s) => match s.parse::<UserStatus>() {
                        Ok(st) => st,
                        Err(_) => {
                            dirty = true;
                            UserStatus::Pending
                        }
                    },
                    None => {
                        dirty = true;
                        UserStatus::Pending
                    }
                };

                let role = match rec_obj.get("role").and_then(Value::as_str) {
                    Some(r) if uid == owner_id => {
                        if r != "owner" {
                            dirty = true;
                        }
                        "owner".to_string()
                    }
                    Some(r) => match r.trim().to_ascii_lowercase().as_str() {
                        "admin" => {
                            if r != "admin" {
                                dirty = true;
                            }
                            "admin".to_string()
                        }
                        "user" => {
                            if r != "user" {
                                dirty = true;
                            }
                            "user".to_string()
                        }
                        _ => {
                            dirty = true;
                            "user".to_string()
                        }
                    },
                    None => {
                        dirty = true;
                        if uid == owner_id {
                            "owner".to_string()
                        } else {
                            "user".to_string()
                        }
                    }
                };

                let perms = match rec_obj.get("perms").and_then(Value::as_object) {
                    Some(pm) => Perms {
                        dashboard_access: pm
                            .get("dashboard_access")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        models_switch: pm
                            .get("models_switch")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        uncensored: pm
                            .get("uncensored")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        grok: pm.get("grok").and_then(Value::as_bool).unwrap_or(false),
                        settings_access: pm
                            .get("settings_access")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        status_net: pm
                            .get("status_net")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        widgets: pm.get("widgets").and_then(Value::as_bool).unwrap_or(false),
                        skills_manage: pm
                            .get("skills_manage")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        mcp_manage: pm
                            .get("mcp_manage")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        root_access: pm
                            .get("root_access")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        parallel: pm
                            .get("parallel")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        automations: pm
                            .get("automations")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        sandbox_exec: pm
                            .get("sandbox_exec")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    },
                    None => Perms::default(),
                };

                let first_seen = rec_obj
                    .get("first_seen")
                    .and_then(parse_f64_value)
                    .unwrap_or(now);
                let last_seen = rec_obj
                    .get("last_seen")
                    .and_then(parse_f64_value)
                    .unwrap_or(now);

                let norm = AclUser {
                    uid,
                    status,
                    role,
                    perms,
                    username: parse_opt_string(rec_obj.get("username"), &mut dirty),
                    first_name: parse_opt_string(rec_obj.get("first_name"), &mut dirty),
                    last_name: parse_opt_string(rec_obj.get("last_name"), &mut dirty),
                    language_code: parse_opt_string(rec_obj.get("language_code"), &mut dirty),
                    is_premium: rec_obj
                        .get("is_premium")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    first_seen,
                    last_seen,
                    last_start_notify_ts: rec_obj
                        .get("last_start_notify_ts")
                        .and_then(parse_f64_value),
                    status_by: rec_obj.get("status_by").and_then(parse_i64_value),
                    status_at: rec_obj.get("status_at").and_then(parse_f64_value),
                };

                last_touch_save.insert(uid, norm.last_seen);
                data.users.insert(uid.to_string(), norm);
            }
        } else {
            dirty = true;
        }
    }

    let mut seen_suppressed = HashSet::new();
    if let Some(raw_sup) = loaded_obj.get("suppressed_seeds") {
        if let Some(arr) = raw_sup.as_array() {
            for item in arr {
                let Some(uid) = parse_i64_value(item) else {
                    dirty = true;
                    continue;
                };
                if uid == owner_id || !seen_suppressed.insert(uid) {
                    dirty = true;
                    continue;
                }
                data.suppressed_seeds.push(uid);
            }
        } else {
            dirty = true;
        }
    }

    let mut seen_selected = HashSet::new();
    if let Some(raw_sel) = loaded_obj.get("selected") {
        if let Some(arr) = raw_sel.as_array() {
            for item in arr {
                let Some(uid) = parse_i64_value(item) else {
                    dirty = true;
                    continue;
                };
                if uid == owner_id || !seen_selected.insert(uid) {
                    dirty = true;
                    continue;
                }
                data.selected.push(uid);
            }
        } else {
            dirty = true;
        }
    }

    if let Some(raw_reqs) = loaded_obj.get("mcp_requests") {
        if let Some(map) = raw_reqs.as_object() {
            for (rid, rval) in map {
                match serde_json::from_value::<McpRequest>(rval.clone()) {
                    Ok(req) => {
                        data.mcp_requests.insert(rid.clone(), req);
                    }
                    Err(_) => {
                        dirty = true;
                    }
                }
            }
        } else {
            dirty = true;
        }
    }

    // Enforce owner immunity invariants unconditionally.
    let owner_key = owner_id.to_string();
    match data.users.get_mut(&owner_key) {
        None => {
            data.users.insert(
                owner_key,
                make_user_record(
                    owner_id,
                    UserStatus::Approved,
                    "owner",
                    Perms::owner(),
                    now,
                    &UserMeta::default(),
                ),
            );
            last_touch_save.insert(owner_id, now);
            dirty = true;
        }
        Some(owner_rec) => {
            if owner_rec.status != UserStatus::Approved
                || owner_rec.role != "owner"
                || owner_rec.perms != Perms::owner()
            {
                owner_rec.status = UserStatus::Approved;
                owner_rec.role = "owner".to_string();
                owner_rec.perms = Perms::owner();
                dirty = true;
            }
        }
    }

    // Seed allowed users unless already present or suppressed.
    for &uid in seed_allowed {
        if uid == owner_id {
            continue;
        }
        let ukey = uid.to_string();
        if !data.users.contains_key(&ukey) && !seen_suppressed.contains(&uid) {
            data.users.insert(
                ukey,
                make_user_record(
                    uid,
                    UserStatus::Approved,
                    "user",
                    Perms::default(),
                    now,
                    &UserMeta::default(),
                ),
            );
            last_touch_save.insert(uid, now);
            dirty = true;
        }
    }

    Ok((
        AclInner {
            data,
            last_touch_save,
        },
        dirty,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::{Arc, Barrier};
    use tempfile::TempDir;

    const OWNER_ID: i64 = 1_000_000_001;

    fn make_tg_user(uid: i64, username: Option<&str>, first_name: &str) -> User {
        User {
            id: uid,
            is_bot: false,
            first_name: first_name.to_string(),
            last_name: None,
            username: username.map(ToString::to_string),
            language_code: Some("en".to_string()),
            is_premium: Some(false),
        }
    }

    #[test]
    fn constants_and_seeding_with_0600_mode() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acl.json");
        let acl = AclStore::open(&path, OWNER_ID, &[OWNER_ID, 1001, 1002], 300).unwrap();

        assert_eq!(
            PERM_KEYS,
            [
                "dashboard_access",
                "models_switch",
                "uncensored",
                "grok",
                "settings_access",
                "status_net",
                "widgets",
                "skills_manage",
                "mcp_manage",
                "root_access",
                "parallel",
                "automations",
                "sandbox_exec"
            ]
        );
        assert_eq!(ROLE_PRESETS.len(), 3);
        assert!(path.exists());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        assert!(acl.is_owner(OWNER_ID));
        assert!(!acl.is_owner(1001));
        assert!(acl.is_approved(OWNER_ID));
        assert!(acl.is_approved(1001));
        assert!(acl.is_approved(1002));
        assert_eq!(
            acl.approved_ids(),
            HashSet::from([OWNER_ID, 1001, 1002])
        );

        let owner = acl.get_user(OWNER_ID).unwrap();
        assert_eq!(owner.status, UserStatus::Approved);
        assert_eq!(owner.role, "owner");
        assert_eq!(owner.perms, Perms::owner());

        let u1 = acl.get_user(1001).unwrap();
        assert_eq!(u1.status, UserStatus::Approved);
        assert_eq!(u1.role, "user");
        assert_eq!(u1.perms, Perms::default());
    }

    #[test]
    fn corrupt_json_and_owner_tampering_recovery() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acl.json");
        std::fs::write(&path, "{broken json").unwrap();

        let acl = AclStore::open(&path, OWNER_ID, &[2001], 300).unwrap();
        assert!(acl.is_approved(OWNER_ID));
        assert!(acl.is_approved(2001));

        // Tamper persisted owner + selected + suppressed_seeds on disk
        let mut raw: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        raw["users"][OWNER_ID.to_string()]["status"] = serde_json::json!("blocked");
        raw["users"][OWNER_ID.to_string()]["role"] = serde_json::json!("user");
        raw["users"][OWNER_ID.to_string()]["perms"] = serde_json::json!({
            "skills_manage": false,
            "mcp_manage": false,
            "root_access": false
        });
        raw["selected"] = serde_json::json!([OWNER_ID, 2001, 2001]);
        raw["suppressed_seeds"] = serde_json::json!([OWNER_ID, 3001, 3001]);
        std::fs::write(&path, serde_json::to_string(&raw).unwrap()).unwrap();

        let reloaded = AclStore::open(&path, OWNER_ID, &[3001], 300).unwrap();
        let owner = reloaded.get_user(OWNER_ID).unwrap();
        assert_eq!(owner.status, UserStatus::Approved);
        assert_eq!(owner.role, "owner");
        assert_eq!(owner.perms, Perms::owner());
        assert_eq!(reloaded.selected_uids(), vec![2001]);
        assert!(!reloaded.is_approved(3001));
    }

    #[test]
    fn owner_protection_invariants() {
        let dir = TempDir::new().unwrap();
        let acl = AclStore::open(dir.path().join("acl.json"), OWNER_ID, &[101], 300).unwrap();

        assert!(matches!(
            acl.set_status(OWNER_ID, UserStatus::Blocked, None, None),
            Err(BridgeError::PermissionDenied(_))
        ));
        assert!(matches!(
            acl.set_status(OWNER_ID, UserStatus::Pending, None, None),
            Err(BridgeError::PermissionDenied(_))
        ));
        assert!(matches!(
            acl.set_perm(OWNER_ID, "root_access", Some(false)),
            Err(BridgeError::PermissionDenied(_))
        ));
        assert!(matches!(
            acl.apply_preset(OWNER_ID, RolePreset::Std),
            Err(BridgeError::PermissionDenied(_))
        ));
        assert!(matches!(
            acl.remove_user(OWNER_ID),
            Err(BridgeError::PermissionDenied(_))
        ));

        assert!(!acl.toggle_select(OWNER_ID).unwrap());
        assert!(!acl.selected_uids().contains(&OWNER_ID));
        assert_eq!(acl.select_many(&[OWNER_ID, 101], true).unwrap(), 1);
        assert_eq!(acl.selected_uids(), vec![101]);

        for target in [
            BulkTarget::Selected,
            BulkTarget::Pending,
            BulkTarget::ApprovedNonOwner,
            BulkTarget::AllNonOwner,
        ] {
            assert!(
                !acl.bulk_set_status(target, UserStatus::Blocked, None, None)
                    .unwrap()
                    .contains(&OWNER_ID)
            );
            assert!(
                !acl.bulk_set_perm(target, "root_access", false)
                    .unwrap()
                    .contains(&OWNER_ID)
            );
            assert!(
                !acl.bulk_apply_preset(target, RolePreset::Std)
                    .unwrap()
                    .contains(&OWNER_ID)
            );
        }

        assert!(acl.is_approved(OWNER_ID));
        for perm in PERM_KEYS {
            assert!(acl.has_perm(OWNER_ID, perm));
        }
    }

    #[test]
    fn touch_user_60s_debounce_and_immediate_save_on_meta_change() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acl.json");
        let acl = AclStore::open(&path, OWNER_ID, &[], 300).unwrap();
        let ino0 = std::fs::metadata(&path).unwrap().ino();

        // New user -> saves immediately (new inode via atomic persist)
        let mut u = make_tg_user(3001, Some("alice"), "Alice");
        u.is_premium = Some(true);
        let rec1 = acl.touch_user_at(&u, 1000.0).unwrap();
        assert_eq!(rec1.uid, 3001);
        assert_eq!(rec1.status, UserStatus::Pending);
        assert_eq!(rec1.first_seen, 1000.0);
        assert_eq!(rec1.last_seen, 1000.0);
        assert!(rec1.is_premium);
        let ino1 = std::fs::metadata(&path).unwrap().ino();
        assert_ne!(ino1, ino0);

        // Within 60s and same metadata -> updates memory, does NOT save
        let rec2 = acl.touch_user_at(&u, 1030.0).unwrap();
        assert_eq!(rec2.last_seen, 1030.0);
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino1);

        // Still <= 60s since last save (1055 - 1000 = 55) -> does NOT save
        acl.touch_user_at(&u, 1055.0).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino1);

        // Exactly 60s (1060 - 1000 = 60, not > 60) -> still does NOT save
        acl.touch_user_at(&u, 1060.0).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino1);

        // > 60s since last save (1061 - 1000 = 61) -> saves
        let rec3 = acl.touch_user_at(&u, 1061.0).unwrap();
        assert_eq!(rec3.last_seen, 1061.0);
        let ino2 = std::fs::metadata(&path).unwrap().ino();
        assert_ne!(ino2, ino1);

        // Within 60s, metadata changed -> saves immediately
        u.username = Some("alice_new".to_string());
        let rec4 = acl.touch_user_at(&u, 1070.0).unwrap();
        assert_eq!(rec4.username.as_deref(), Some("alice_new"));
        let ino3 = std::fs::metadata(&path).unwrap().ino();
        assert_ne!(ino3, ino2);
    }

    #[test]
    fn record_start_attempt_300s_cooldown_and_blocked_behavior() {
        let dir = TempDir::new().unwrap();
        let acl = AclStore::open(dir.path().join("acl.json"), OWNER_ID, &[4001], 300).unwrap();

        let (rec1, notify1) = acl
            .record_start_attempt_at(&make_tg_user(5001, Some("stranger"), "Bob"), 100.0)
            .unwrap();
        assert_eq!(rec1.status, UserStatus::Pending);
        assert_eq!(rec1.last_start_notify_ts, Some(100.0));
        assert!(notify1);

        // Within cooldown -> no notify, updates metadata
        let (rec2, notify2) = acl
            .record_start_attempt_at(&make_tg_user(5001, Some("stranger2"), "Bob"), 250.0)
            .unwrap();
        assert_eq!(rec2.username.as_deref(), Some("stranger2"));
        assert_eq!(rec2.last_seen, 250.0);
        assert!(!notify2);

        // Exactly at cooldown boundary (400 - 100 == 300) -> notifies
        let (rec3, notify3) = acl
            .record_start_attempt_at(&make_tg_user(5001, Some("stranger2"), "Bob"), 400.0)
            .unwrap();
        assert_eq!(rec3.last_start_notify_ts, Some(400.0));
        assert!(notify3);

        // Blocked user -> updates last_seen, never notifies
        acl.set_status(5001, UserStatus::Blocked, Some(OWNER_ID), None)
            .unwrap();
        let (rec4, notify4) = acl
            .record_start_attempt_at(&make_tg_user(5001, Some("stranger2"), "Bob"), 900.0)
            .unwrap();
        assert_eq!(rec4.status, UserStatus::Blocked);
        assert_eq!(rec4.last_seen, 900.0);
        assert!(!notify4);

        // Approved user & owner -> never notify
        let (rec_app, notify_app) = acl
            .record_start_attempt_at(&make_tg_user(4001, Some("seeded"), "Seed"), 950.0)
            .unwrap();
        assert_eq!(rec_app.status, UserStatus::Approved);
        assert!(!notify_app);

        let (rec_own, notify_own) = acl
            .record_start_attempt_at(&make_tg_user(OWNER_ID, Some("owner"), "Owner"), 950.0)
            .unwrap();
        assert_eq!(rec_own.status, UserStatus::Approved);
        assert!(!notify_own);
    }

    #[test]
    fn status_perms_presets_and_seed_suppression() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acl.json");
        let acl = AclStore::open(&path, OWNER_ID, &[6001, 6002], 300).unwrap();

        assert!(!acl.has_perm(6001, "skills_manage"));
        assert!(!acl.has_perm(6001, "mcp_manage"));
        assert!(!acl.has_perm(6001, "root_access"));

        // Toggle & explicit set
        acl.set_perm(6001, "skills_manage", None).unwrap();
        assert!(acl.has_perm(6001, "skills_manage"));
        acl.set_perm(6001, "skills_manage", None).unwrap();
        assert!(!acl.has_perm(6001, "skills_manage"));
        acl.set_perm(6001, "mcp_manage", Some(true)).unwrap();
        assert!(acl.has_perm(6001, "mcp_manage"));

        // Blocking suppresses effective permissions
        acl.set_status(6001, UserStatus::Blocked, Some(OWNER_ID), None)
            .unwrap();
        assert!(!acl.is_approved(6001));
        assert!(!acl.has_perm(6001, "mcp_manage"));

        // Reload preserves blocked status
        let acl2 = AclStore::open(&path, OWNER_ID, &[6001, 6002], 300).unwrap();
        assert_eq!(acl2.get_user(6001).unwrap().status, UserStatus::Blocked);
        assert!(acl2.is_approved(6002));

        // Removing seeded user suppresses re-seeding across restarts
        assert!(acl2.remove_user(6002).unwrap());
        assert!(!acl2.remove_user(6002).unwrap());
        assert!(acl2.get_user(6002).is_none());

        let acl3 = AclStore::open(&path, OWNER_ID, &[6001, 6002], 300).unwrap();
        assert!(acl3.get_user(6002).is_none());

        // Approving clears suppression & applies preset
        let approved = acl3
            .set_status(6002, UserStatus::Approved, Some(OWNER_ID), Some(RolePreset::Dev))
            .unwrap();
        assert_eq!(approved.status, UserStatus::Approved);
        assert_eq!(approved.perms, RolePreset::Dev.perms());
        assert!(acl3.has_perm(6002, "skills_manage"));
        assert!(acl3.has_perm(6002, "mcp_manage"));
        assert!(!acl3.has_perm(6002, "root_access"));

        acl3.apply_preset(6002, RolePreset::Full).unwrap();
        assert!(acl3.has_perm(6002, "root_access"));

        assert!(matches!(
            acl3.set_perm(6002, "bad_perm", Some(true)),
            Err(BridgeError::Validation(_))
        ));
    }

    #[test]
    fn list_users_sorting_and_filtering() {
        let dir = TempDir::new().unwrap();
        let acl = AclStore::open(dir.path().join("acl.json"), OWNER_ID, &[], 300).unwrap();

        acl.set_status_at(10, UserStatus::Blocked, None, None, 110.0)
            .unwrap();
        acl.set_status_at(20, UserStatus::Approved, None, None, 120.0)
            .unwrap();
        acl.record_start_attempt_at(&make_tg_user(30, None, "OldPending"), 130.0)
            .unwrap();
        acl.record_start_attempt_at(&make_tg_user(31, None, "NewPending"), 140.0)
            .unwrap();

        let all: Vec<i64> = acl.list_users(UserFilter::All).into_iter().map(|u| u.uid).collect();
        assert_eq!(all, vec![OWNER_ID, 31, 30, 20, 10]);
        let pending: Vec<i64> = acl
            .list_users(UserFilter::Pending)
            .into_iter()
            .map(|u| u.uid)
            .collect();
        assert_eq!(pending, vec![31, 30]);
        let approved: Vec<i64> = acl
            .list_users(UserFilter::Approved)
            .into_iter()
            .map(|u| u.uid)
            .collect();
        assert_eq!(approved, vec![OWNER_ID, 20]);
        let blocked: Vec<i64> = acl
            .list_users(UserFilter::Blocked)
            .into_iter()
            .map(|u| u.uid)
            .collect();
        assert_eq!(blocked, vec![10]);
    }

    #[test]
    fn batch_selection_and_bulk_operations() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acl.json");
        let acl = AclStore::open(&path, OWNER_ID, &[201, 202], 300).unwrap();
        acl.record_start_attempt(&make_tg_user(301, None, "P1"))
            .unwrap();
        acl.record_start_attempt(&make_tg_user(302, None, "P2"))
            .unwrap();
        acl.set_status(401, UserStatus::Blocked, None, None).unwrap();

        assert!(acl.toggle_select(301).unwrap());
        assert!(!acl.toggle_select(301).unwrap());
        assert_eq!(acl.select_many(&[OWNER_ID, 301, 302], true).unwrap(), 2);
        assert_eq!(acl.selected_uids(), vec![301, 302]);

        let reloaded = AclStore::open(&path, OWNER_ID, &[], 300).unwrap();
        assert_eq!(reloaded.selected_uids(), vec![301, 302]);
        assert_eq!(reloaded.select_many(&[301], false).unwrap(), 1);
        assert_eq!(reloaded.selected_uids(), vec![302]);
        assert_eq!(reloaded.clear_selection().unwrap(), 1);
        assert!(reloaded.selected_uids().is_empty());
        assert_eq!(reloaded.clear_selection().unwrap(), 0);

        let mod_pending: HashSet<i64> = reloaded
            .bulk_set_status(
                BulkTarget::Pending,
                UserStatus::Approved,
                Some(RolePreset::Dev),
                Some(OWNER_ID),
            )
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(mod_pending, HashSet::from([301, 302]));
        assert!(reloaded.has_perm(301, "mcp_manage"));
        assert!(!reloaded.has_perm(301, "root_access"));

        let mod_perm: HashSet<i64> = reloaded
            .bulk_set_perm(BulkTarget::ApprovedNonOwner, "root_access", true)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(mod_perm, HashSet::from([201, 202, 301, 302]));
        assert!(reloaded.has_perm(201, "root_access"));

        let mod_preset: HashSet<i64> = reloaded
            .bulk_apply_preset(BulkTarget::ApprovedNonOwner, RolePreset::Std)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(mod_preset, HashSet::from([201, 202, 301, 302]));
        assert!(!reloaded.has_perm(201, "root_access"));
        assert!(reloaded.has_perm(OWNER_ID, "root_access"));

        reloaded.select_many(&[401, 201], true).unwrap();
        let mod_sel: HashSet<i64> = reloaded
            .bulk_set_status(BulkTarget::Selected, UserStatus::Approved, None, None)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(mod_sel, HashSet::from([401, 201]));
        assert!(reloaded.is_approved(401));

        let mod_all: HashSet<i64> = reloaded
            .bulk_set_status(BulkTarget::AllNonOwner, UserStatus::Blocked, None, None)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(mod_all, HashSet::from([201, 202, 301, 302, 401]));
        assert!(reloaded.is_approved(OWNER_ID));
    }

    #[test]
    fn mcp_request_queue_idempotency_and_100_cap_eviction() {
        let dir = TempDir::new().unwrap();
        let acl = AclStore::open(dir.path().join("acl.json"), OWNER_ID, &[], 300).unwrap();

        let req = acl
            .create_mcp_request_at(201, "@alice (201)", 201, "Install filesystem MCP", 1000.0)
            .unwrap();
        assert_eq!(req.req_id.len(), 10);
        assert_eq!(req.status, McpRequestStatus::Pending);
        assert_eq!(acl.get_mcp_request(&req.req_id).as_ref(), Some(&req));
        assert!(acl.get_mcp_request("nonexistent").is_none());

        let resolved = acl
            .resolve_mcp_request_at(&req.req_id, McpDecision::Approved, OWNER_ID, 1005.0)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.status, McpRequestStatus::Approved);
        assert_eq!(resolved.resolved_by, Some(OWNER_ID));
        assert_eq!(resolved.resolved_at, Some(1005.0));

        // Duplicate resolves are idempotent -> None
        assert!(acl
            .resolve_mcp_request(&req.req_id, McpDecision::Approved, OWNER_ID)
            .unwrap()
            .is_none());
        assert!(acl
            .resolve_mcp_request(&req.req_id, McpDecision::Rejected, OWNER_ID)
            .unwrap()
            .is_none());
        assert!(acl
            .resolve_mcp_request("missing", McpDecision::Rejected, OWNER_ID)
            .unwrap()
            .is_none());

        // Cap at 100, evicting resolved entries before pending ones
        let mut recent_pending = Vec::new();
        for i in 0..120 {
            let r = acl
                .create_mcp_request_at(201, "alice", 201, format!("spec-{i}"), 1010.0 + i as f64)
                .unwrap();
            if i >= 100 {
                recent_pending.push(r.req_id);
            }
        }
        assert_eq!(acl.mcp_request_count(), 100);
        assert!(acl.get_mcp_request(&req.req_id).is_none());
        for pid in recent_pending {
            assert!(acl.get_mcp_request(&pid).is_some());
        }
    }

    #[test]
    fn thread_safety_and_concurrent_mcp_resolve() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acl.json");
        let acl = Arc::new(AclStore::open(&path, OWNER_ID, &[7001], 300).unwrap());
        let req = acl
            .create_mcp_request(7001, "u7001", 7001, "concurrent mcp")
            .unwrap();

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for idx in 0..8_i64 {
            let a = Arc::clone(&acl);
            let b = Arc::clone(&barrier);
            let rid = req.req_id.clone();
            handles.push(std::thread::spawn(move || {
                b.wait();
                a.touch_user(&make_tg_user(
                    8000 + idx,
                    Some(&format!("user{idx}")),
                    &format!("U{idx}"),
                ))
                .unwrap();
                a.set_perm(7001, "skills_manage", Some(idx % 2 == 1))
                    .unwrap();
                a.resolve_mcp_request(&rid, McpDecision::Approved, OWNER_ID)
                    .unwrap()
                    .is_some()
            }));
        }

        let winners: usize = handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum();
        assert_eq!(winners, 1);
        assert!(acl.is_approved(OWNER_ID));

        let loaded: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(loaded["users"][OWNER_ID.to_string()].is_object());
    }

    #[test]
    fn three_tier_rbac_admin_defaults_modular_revocation_and_legacy_migration() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acl.json");

        // Simulate legacy 5-perm acl.json with a tampered "owner" string on a non-owner UID
        let legacy = serde_json::json!({
            "version": 1,
            "selected": [],
            "suppressed_seeds": [],
            "mcp_requests": {},
            "users": {
                OWNER_ID.to_string(): {
                    "uid": OWNER_ID,
                    "status": "approved",
                    "role": "owner",
                    "perms": {"skills_manage": true, "mcp_manage": true, "root_access": true},
                    "first_seen": 1.0,
                    "last_seen": 1.0
                },
                "201": {
                    "uid": 201,
                    "status": "approved",
                    "role": "user",
                    "perms": {"skills_manage": true, "mcp_manage": true, "root_access": true},
                    "first_seen": 1.0,
                    "last_seen": 1.0
                },
                "202": {
                    "uid": 202,
                    "status": "approved",
                    "role": "owner",
                    "perms": {},
                    "first_seen": 1.0,
                    "last_seen": 1.0
                }
            }
        });
        std::fs::write(&path, serde_json::to_string(&legacy).unwrap()).unwrap();

        let acl = AclStore::open(&path, OWNER_ID, &[], 300).unwrap();
        assert_eq!(acl.tier_of(OWNER_ID), RoleTier::Owner);
        assert!(acl.can_manage_users(OWNER_ID));

        // Legacy user 201 does NOT get dashboard_access implicitly
        assert_eq!(acl.tier_of(201), RoleTier::User);
        assert!(!acl.is_admin(201));
        assert!(!acl.can_manage_users(201));
        assert!(!acl.has_perm(201, "dashboard_access"));
        assert!(!acl.has_perm(201, "uncensored"));
        assert!(acl.has_perm(201, "root_access"));

        // Tampered non-owner "owner" normalized back to User
        assert_eq!(acl.tier_of(202), RoleTier::User);
        assert!(!acl.is_owner(202));

        // Promote 202 to Admin with defaults -> gets all 12 flags including dashboard_access & root_access
        let adm = acl.set_tier(202, RoleTier::Admin, true).unwrap();
        assert_eq!(adm.tier(), RoleTier::Admin);
        assert!(acl.is_admin(202));
        assert!(!acl.can_manage_users(202));
        for k in PERM_KEYS {
            assert!(acl.has_perm(202, k), "admin default should include {k}");
        }

        // Owner modularly revokes specific flags from Admin without demoting Admin tier
        acl.set_perm(202, "root_access", Some(false)).unwrap();
        acl.set_perm(202, "mcp_manage", Some(false)).unwrap();
        assert_eq!(acl.tier_of(202), RoleTier::Admin);
        assert!(acl.is_admin(202));
        assert!(!acl.has_perm(202, "root_access"));
        assert!(!acl.has_perm(202, "mcp_manage"));
        assert!(acl.has_perm(202, "dashboard_access"));

        // Owner grants a custom User dashboard_access + uncensored only
        acl.set_perm(201, "dashboard_access", Some(true)).unwrap();
        acl.set_perm(201, "uncensored", Some(true)).unwrap();
        assert_eq!(acl.tier_of(201), RoleTier::User);
        assert!(acl.has_perm(201, "dashboard_access"));
        assert!(acl.has_perm(201, "uncensored"));
        assert!(!acl.has_perm(201, "models_switch"));

        // Cannot assign Owner tier via set_tier / bulk_set_tier or demote Owner
        assert!(matches!(
            acl.set_tier(202, RoleTier::Owner, true),
            Err(BridgeError::PermissionDenied(_))
        ));
        assert!(matches!(
            acl.set_tier(OWNER_ID, RoleTier::Admin, true),
            Err(BridgeError::PermissionDenied(_))
        ));
        assert!(matches!(
            acl.bulk_set_tier(BulkTarget::AllNonOwner, RoleTier::Owner, true),
            Err(BridgeError::PermissionDenied(_))
        ));

        // Bulk demote back to User with defaults strips all modules
        let changed = acl
            .bulk_set_tier(BulkTarget::ApprovedNonOwner, RoleTier::User, true)
            .unwrap();
        assert!(changed.contains(&201));
        assert!(changed.contains(&202));
        assert!(!acl.is_admin(202));
        assert!(!acl.has_perm(202, "dashboard_access"));
        assert!(!acl.has_perm(201, "root_access"));
    }

    #[test]
    fn pending_cap_and_start_spam_debounce_prevent_disk_thrash() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("acl.json");
        let acl = AclStore::open(&path, OWNER_ID, &[], 300).unwrap();
        acl.set_max_pending(10);

        // Fill up to the 10-pending cap
        for i in 0..10i64 {
            let (_, notify) = acl
                .record_start_attempt_at(&make_tg_user(7000 + i, None, "P"), 1000.0 + i as f64)
                .unwrap();
            assert!(notify);
        }
        assert_eq!(acl.list_users(UserFilter::Pending).len(), 10);

        // 11th brand-new stranger is dropped cleanly without inflating acl.json
        let (ephemeral, notify11) = acl
            .record_start_attempt_at(&make_tg_user(7999, Some("spammer"), "S"), 1020.0)
            .unwrap();
        assert!(!notify11);
        assert_eq!(ephemeral.uid, 7999);
        assert!(acl.get_user(7999).is_none());
        assert_eq!(acl.list_users(UserFilter::Pending).len(), 10);

        // Repeated /start from existing pending stranger within 60s must NOT rewrite acl.json
        let disk_before = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let (_, notify_repeat) = acl
            .record_start_attempt_at(&make_tg_user(7000, None, "P"), 1015.0)
            .unwrap();
        assert!(!notify_repeat);
        assert!(
            !path.exists(),
            "debounced repeat /start must not thrash disk with fsync"
        );

        // Same for blocked user spamming /start within 60s
        std::fs::write(&path, &disk_before).unwrap();
        acl.set_status_at(7000, UserStatus::Blocked, Some(OWNER_ID), None, 1020.0)
            .unwrap();
        // Record one debounced hit at 1100.0 (saves), then spam at 1105.0 (must NOT save)
        let _ = acl
            .record_start_attempt_at(&make_tg_user(7000, None, "P"), 1100.0)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        let (_, notify_blk) = acl
            .record_start_attempt_at(&make_tg_user(7000, None, "P"), 1105.0)
            .unwrap();
        assert!(!notify_blk);
        assert!(
            !path.exists(),
            "blocked /start spam within debounce window must not rewrite acl.json"
        );
    }
}
