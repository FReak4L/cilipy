//! Persistent Cron & Sync scheduler (`$STATE_DIR/cron_jobs.json`) supporting
//! both 5-field POSIX cron and 6/7-field `cron::Schedule` expressions.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use agy_core::atomic::atomic_write_json;
use agy_core::config::Config;
use agy_core::health::HealthTracker;
use agy_core::{BridgeError, Result};
use agy_ext::engines::{parse_mcp_list, parse_models, run_cmd};
use agy_ext::mcp_client::redact_secrets_in_text;
use agy_ext::mcp_config::list_mcp_servers;
use agy_ext::memory::memory_overview;
use chrono::{DateTime, Utc};
use cron::Schedule;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::watch;
use tracing::{info, warn};

/// 7 days in seconds for inbox garbage collection.
pub const INBOX_GC_MAX_AGE_SECS: u64 = 7 * 24 * 3600; // 604_800s

/// Built-in job identifiers.
pub const JOB_MODELS_SYNC: &str = "models_sync";
pub const JOB_MCP_HEALTH_SYNC: &str = "mcp_health_sync";
pub const JOB_MEMORY_CACHE_SYNC: &str = "memory_cache_sync";
pub const JOB_INBOX_GC: &str = "inbox_gc";

/// Execution status of a scheduled cron job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CronJobStatus {
    Idle,
    Running,
    Ok,
    Error,
    Disabled,
}

impl CronJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Running => "running",
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Disabled => "disabled",
        }
    }
}

/// Persisted state and telemetry for a single cron job in `cron_jobs.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CronJobRecord {
    pub id: String,
    pub description: String,
    pub schedule: String,
    pub enabled: bool,
    pub status: CronJobStatus,
    #[serde(default)]
    pub last_run_at: Option<f64>,
    #[serde(default)]
    pub next_run_at: Option<f64>,
    #[serde(default)]
    pub last_duration_ms: Option<u64>,
    #[serde(default)]
    pub run_count: u64,
    #[serde(default)]
    pub fail_count: u64,
    #[serde(default)]
    pub last_summary: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

/// Secret-free MCP health snapshot cached by `mcp_health_sync`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpHealthServerSummary {
    pub name: String,
    #[serde(rename = "type")]
    pub server_type: String,
    pub enabled: bool,
    pub cli_status: Option<String>,
}

/// Sanitized MCP health overview cached by [`CronScheduler`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpHealthSummary {
    pub ts: f64,
    pub total_configured: usize,
    pub enabled_configured: usize,
    pub cli_rows_count: usize,
    pub servers: Vec<McpHealthServerSummary>,
    pub cli_error: Option<String>,
}

/// Sanitized AI-Memory cache overview updated by `memory_cache_sync`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryCacheSummary {
    pub ts: f64,
    pub ok: bool,
    pub total: u64,
    pub recent_24h: u64,
    pub types: BTreeMap<String, u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CronStoreFile {
    #[serde(default)]
    jobs: Vec<CronJobRecord>,
}

struct BuiltinSpec {
    id: &'static str,
    description: &'static str,
    schedule: &'static str,
}

const BUILTIN_SPECS: [BuiltinSpec; 4] = [
    BuiltinSpec {
        id: JOB_MODELS_SYNC,
        description: "Refresh cached agy models list into models.json",
        schedule: "0 */6 * * *",
    },
    BuiltinSpec {
        id: JOB_MCP_HEALTH_SYNC,
        description: "Refresh sanitized MCP server configuration and CLI status",
        schedule: "*/15 * * * *",
    },
    BuiltinSpec {
        id: JOB_MEMORY_CACHE_SYNC,
        description: "Refresh AI-Memory summary metrics",
        schedule: "*/10 * * * *",
    },
    BuiltinSpec {
        id: JOB_INBOX_GC,
        description: "Remove expired files older than 7 days from inbox directory",
        schedule: "15 4 * * *",
    },
];

fn posix_to_cron_dow(d: u32) -> u32 {
    if d.is_multiple_of(7) {
        1
    } else {
        d + 1
    }
}

fn normalize_posix_dow_token(token: &str) -> Result<String> {
    if token.is_empty() {
        return Err(BridgeError::Cron("empty day-of-week token".into()));
    }
    let (base, step_opt) = match token.split_once('/') {
        Some((b, s)) => (b, Some(s)),
        None => (token, None),
    };
    if base == "*" || base == "?" || base.chars().any(|c| c.is_ascii_alphabetic()) {
        return Ok(token.to_string());
    }

    let step: usize = match step_opt {
        Some(s) => s
            .parse::<usize>()
            .ok()
            .filter(|&v| v > 0)
            .ok_or_else(|| BridgeError::Cron(format!("invalid cron step '{s}'")))?,
        None => 1,
    };

    let days: Vec<u32> = if let Some((a_raw, b_raw)) = base.split_once('-') {
        let a = a_raw
            .parse::<u32>()
            .map_err(|_| BridgeError::Cron(format!("invalid day-of-week '{a_raw}'")))?;
        let b = b_raw
            .parse::<u32>()
            .map_err(|_| BridgeError::Cron(format!("invalid day-of-week '{b_raw}'")))?;
        if a > 7 || b > 7 || a > b {
            return Err(BridgeError::Cron(format!("invalid day-of-week range '{base}'")));
        }
        (a..=b).step_by(step).map(posix_to_cron_dow).collect()
    } else {
        let d = base
            .parse::<u32>()
            .map_err(|_| BridgeError::Cron(format!("invalid day-of-week '{base}'")))?;
        if d > 7 {
            return Err(BridgeError::Cron(format!("invalid day-of-week '{base}'")));
        }
        if step_opt.is_some() {
            if d == 7 {
                vec![posix_to_cron_dow(7)]
            } else {
                (d..=6).step_by(step).map(posix_to_cron_dow).collect()
            }
        } else {
            vec![posix_to_cron_dow(d)]
        }
    };

    let unique: BTreeSet<u32> = days.into_iter().collect();
    Ok(unique
        .into_iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(","))
}

fn normalize_posix_dow_field(field: &str) -> Result<String> {
    let mut parts = Vec::new();
    for tok in field.split(',') {
        parts.push(normalize_posix_dow_token(tok)?);
    }
    Ok(parts.join(","))
}

/// Normalize a 5-field POSIX cron expression (by prepending `"0 "` seconds and aligning
/// Sunday=0/7 -> 1..=7) or pass through a 6/7-field `cron::Schedule` expression, returning
/// the validated [`Schedule`].
pub fn parse_cron_schedule(expr: &str) -> Result<Schedule> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Err(BridgeError::Cron("cron expression cannot be empty".into()));
    }

    let normalized = if trimmed.eq_ignore_ascii_case("@midnight") {
        "0 0 0 * * *".to_string()
    } else if trimmed.starts_with('@') {
        trimmed.to_string()
    } else {
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        match fields.len() {
            5 => {
                let dow = normalize_posix_dow_field(fields[4])?;
                format!("0 {} {} {} {} {}", fields[0], fields[1], fields[2], fields[3], dow)
            }
            6 | 7 => fields.join(" "),
            other => {
                return Err(BridgeError::Cron(format!(
                    "expected 5, 6, or 7 cron fields, got {other} in '{trimmed}'"
                )));
            }
        }
    };

    Schedule::from_str(&normalized)
        .map_err(|e| BridgeError::Cron(format!("invalid cron schedule '{expr}': {e}")))
}

fn next_fire_epoch(expr: &str, after: DateTime<Utc>) -> Result<Option<f64>> {
    let sched = parse_cron_schedule(expr)?;
    Ok(sched
        .after(&after)
        .next()
        .map(|dt| dt.timestamp_millis() as f64 / 1000.0))
}

fn dt_to_epoch(dt: DateTime<Utc>) -> f64 {
    dt.timestamp_millis() as f64 / 1000.0
}

/// Persistent Cron & Sync scheduler managing the 4 built-in maintenance jobs.
pub struct CronScheduler {
    cfg: Arc<Config>,
    health: Arc<HealthTracker>,
    state_path: PathBuf,
    jobs: RwLock<Vec<CronJobRecord>>,
    running_ids: StdMutex<HashSet<String>>,
    persist_lock: StdMutex<()>,
    mcp_cache: RwLock<Option<McpHealthSummary>>,
    memory_cache: RwLock<Option<MemoryCacheSummary>>,
}

impl CronScheduler {
    /// Load or initialize `$STATE_DIR/cron_jobs.json`, validate schedules, compute next run times,
    /// and publish initial telemetry to [`HealthTracker`].
    pub fn new(cfg: Arc<Config>, health: Arc<HealthTracker>) -> Result<Self> {
        let state_path = cfg.cron_jobs_path();
        let now = Utc::now();
        let records = load_and_reconcile_jobs(&state_path, now)?;
        atomic_write_json(&state_path, &CronStoreFile { jobs: records.clone() }, true)?;

        let sched = Self {
            cfg,
            health,
            state_path,
            jobs: RwLock::new(records),
            running_ids: StdMutex::new(HashSet::new()),
            persist_lock: StdMutex::new(()),
            mcp_cache: RwLock::new(None),
            memory_cache: RwLock::new(None),
        };
        sched.sync_health_snapshot();
        Ok(sched)
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// Return a cloned list of all registered cron jobs.
    pub fn list_jobs(&self) -> Vec<CronJobRecord> {
        match self.jobs.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Look up a single job by ID.
    pub fn get_job(&self, id: &str) -> Option<CronJobRecord> {
        self.list_jobs().into_iter().find(|j| j.id == id)
    }

    /// Cached MCP health summary produced by `mcp_health_sync`.
    pub fn cached_mcp_health(&self) -> Option<McpHealthSummary> {
        match self.mcp_cache.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Cached AI-Memory metrics produced by `memory_cache_sync`.
    pub fn cached_memory_summary(&self) -> Option<MemoryCacheSummary> {
        match self.memory_cache.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Enable or disable a cron job, persist `cron_jobs.json`, and update `HealthTracker`.
    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<CronJobRecord> {
        let now = Utc::now();
        let updated = {
            let mut guard = self
                .jobs
                .write()
                .map_err(|e| BridgeError::Internal(format!("cron write lock poisoned: {e}")))?;
            let Some(rec) = guard.iter_mut().find(|j| j.id == id) else {
                return Err(BridgeError::NotFound(format!("Unknown cron job: {id}")));
            };
            rec.enabled = enabled;
            if enabled {
                if rec.status == CronJobStatus::Disabled {
                    rec.status = CronJobStatus::Idle;
                }
                rec.next_run_at = next_fire_epoch(&rec.schedule, now)?;
            } else {
                rec.status = CronJobStatus::Disabled;
                rec.next_run_at = None;
            }
            rec.clone()
        };

        self.persist_jobs()?;
        self.sync_health_snapshot();
        Ok(updated)
    }

    /// Execute a cron job immediately (regardless of schedule), updating telemetry and `cron_jobs.json`.
    pub async fn run_now(&self, id: &str) -> Result<CronJobRecord> {
        self.execute_job_at(id, Utc::now()).await
    }

    /// Compact JSON summary suitable for `/cron` UI and `health.json`.
    pub fn summary_json(&self) -> Value {
        let jobs = self.list_jobs();
        let arr: Vec<Value> = jobs
            .iter()
            .map(|j| {
                json!({
                    "id": j.id,
                    "schedule": j.schedule,
                    "enabled": j.enabled,
                    "status": j.status,
                    "last_run_at": j.last_run_at,
                    "next_run_at": j.next_run_at,
                    "last_duration_ms": j.last_duration_ms,
                    "run_count": j.run_count,
                    "fail_count": j.fail_count,
                    "last_summary": j.last_summary,
                    "last_error": j.last_error,
                })
            })
            .collect();
        Value::Array(arr)
    }

    /// Check all enabled jobs due at or before `now`, execute them, and return IDs that ran.
    pub async fn tick_at(&self, now: DateTime<Utc>) -> Vec<String> {
        let now_ts = dt_to_epoch(now);
        let due_ids: Vec<String> = self
            .list_jobs()
            .into_iter()
            .filter(|j| j.enabled && j.next_run_at.is_some_and(|nxt| nxt <= now_ts))
            .map(|j| j.id)
            .collect();

        let mut executed = Vec::new();
        for id in due_ids {
            match self.execute_job_at(&id, now).await {
                Ok(_) => executed.push(id),
                Err(err) => {
                    warn!(job_id = %id, error = %err, "scheduled cron tick failed");
                }
            }
        }
        executed
    }

    /// Run the background scheduler loop until `shutdown` becomes `true`.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        self.sync_health_snapshot();
        if !self.cfg.cron_enabled {
            info!("cron scheduler disabled via CRON_ENABLED=false");
            loop {
                if *shutdown.borrow() {
                    return;
                }
                if shutdown.changed().await.is_err() {
                    return;
                }
            }
        }

        let interval = Duration::from_secs(10);
        loop {
            if *shutdown.borrow() {
                break;
            }
            self.tick_at(Utc::now()).await;
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }

    async fn execute_job_at(&self, id: &str, now: DateTime<Utc>) -> Result<CronJobRecord> {
        {
            let jobs = self.list_jobs();
            if !jobs.iter().any(|j| j.id == id) {
                return Err(BridgeError::NotFound(format!("Unknown cron job: {id}")));
            }
        }

        {
            let mut inflight = self.running_ids.lock().unwrap_or_else(|e| e.into_inner());
            if !inflight.insert(id.to_string()) {
                return Err(BridgeError::Cron(format!("cron job '{id}' is already running")));
            }
        }

        struct InflightCleanup<'a> {
            set: &'a StdMutex<HashSet<String>>,
            id: String,
        }
        impl Drop for InflightCleanup<'_> {
            fn drop(&mut self) {
                let mut g = self.set.lock().unwrap_or_else(|e| e.into_inner());
                g.remove(&self.id);
            }
        }
        let _cleanup = InflightCleanup {
            set: &self.running_ids,
            id: id.to_string(),
        };

        // Mark Running
        {
            let mut guard = self
                .jobs
                .write()
                .map_err(|e| BridgeError::Internal(format!("cron write lock poisoned: {e}")))?;
            if let Some(rec) = guard.iter_mut().find(|j| j.id == id) {
                rec.status = CronJobStatus::Running;
            }
        }
        self.sync_health_snapshot();

        let started = Instant::now();
        let outcome = match id {
            JOB_MODELS_SYNC => self.run_models_sync().await,
            JOB_MCP_HEALTH_SYNC => self.run_mcp_health_sync().await,
            JOB_MEMORY_CACHE_SYNC => self.run_memory_cache_sync().await,
            JOB_INBOX_GC => self.run_inbox_gc().await,
            other => Err(BridgeError::NotFound(format!("Unknown cron job: {other}"))),
        };
        let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let finished_ts = dt_to_epoch(now);

        let updated = {
            let mut guard = self
                .jobs
                .write()
                .map_err(|e| BridgeError::Internal(format!("cron write lock poisoned: {e}")))?;
            let Some(rec) = guard.iter_mut().find(|j| j.id == id) else {
                return Err(BridgeError::NotFound(format!("Unknown cron job: {id}")));
            };
            rec.last_run_at = Some(finished_ts);
            rec.last_duration_ms = Some(duration_ms);
            rec.run_count = rec.run_count.saturating_add(1);
            rec.next_run_at = if rec.enabled {
                next_fire_epoch(&rec.schedule, now).ok().flatten()
            } else {
                None
            };

            match &outcome {
                Ok(summary) => {
                    rec.status = if rec.enabled {
                        CronJobStatus::Ok
                    } else {
                        CronJobStatus::Disabled
                    };
                    rec.last_summary = Some(redact_secrets_in_text(summary));
                    rec.last_error = None;
                }
                Err(err) => {
                    rec.fail_count = rec.fail_count.saturating_add(1);
                    rec.status = if rec.enabled {
                        CronJobStatus::Error
                    } else {
                        CronJobStatus::Disabled
                    };
                    rec.last_error = Some(redact_secrets_in_text(&err.to_string()));
                }
            }
            rec.clone()
        };

        {
            let mut inflight = self.running_ids.lock().unwrap_or_else(|e| e.into_inner());
            inflight.remove(id);
        }

        self.persist_jobs()?;
        self.sync_health_snapshot();

        match outcome {
            Ok(summary) => {
                info!(job = id, duration_ms, summary = %summary, "cron job completed");
                Ok(updated)
            }
            Err(err) => {
                warn!(job = id, duration_ms, error = %redact_secrets_in_text(&err.to_string()), "cron job failed");
                Ok(updated)
            }
        }
    }

    async fn run_models_sync(&self) -> Result<String> {
        let agy_bin = self.cfg.agy_bin.to_string_lossy().to_string();
        let cwd = self.effective_cwd();
        let args = vec![agy_bin, "models".to_string()];
        let (rc, stdout, stderr) = run_cmd(&args, cwd, 30.0).await?;
        if rc != 0 {
            let err_clean = redact_secrets_in_text(stderr.trim());
            return Err(BridgeError::Cron(format!(
                "agy models exited with code {rc}: {err_clean}"
            )));
        }
        let models = parse_models(&stdout);
        if models.is_empty() {
            return Ok("models=0 (kept existing cache)".to_string());
        }
        let models_path = self.cfg.state_dir.join("models.json");
        atomic_write_json(&models_path, &models, true)?;
        Ok(format!("models={} synced", models.len()))
    }

    async fn run_mcp_health_sync(&self) -> Result<String> {
        let configured = list_mcp_servers(&self.cfg.mcp_config_path)?;
        let total_configured = configured.len();
        let enabled_configured = configured.iter().filter(|s| s.enabled).count();

        let mut cli_rows = Vec::new();
        let mut cli_error: Option<String> = None;

        let agy_exists = self.cfg.agy_bin.components().count() == 1 || self.cfg.agy_bin.is_file();
        if agy_exists {
            let agy_bin = self.cfg.agy_bin.to_string_lossy().to_string();
            let args = vec![agy_bin, "mcp".to_string(), "list".to_string()];
            match run_cmd(&args, self.effective_cwd(), 30.0).await {
                Ok((0, stdout, _)) => {
                    cli_rows = parse_mcp_list(&stdout);
                }
                Ok((rc, _, stderr)) => {
                    cli_error = Some(redact_secrets_in_text(&format!(
                        "exit {rc}: {}",
                        stderr.trim()
                    )));
                }
                Err(err) => {
                    cli_error = Some(redact_secrets_in_text(&err.to_string()));
                }
            }
        }

        let servers: Vec<McpHealthServerSummary> = configured
            .iter()
            .map(|srv| {
                let cli_status = cli_rows
                    .iter()
                    .find(|r| r.name == srv.name)
                    .map(|r| r.status.clone());
                McpHealthServerSummary {
                    name: srv.name.clone(),
                    server_type: srv.server_type.clone(),
                    enabled: srv.enabled,
                    cli_status,
                }
            })
            .collect();

        let summary = McpHealthSummary {
            ts: dt_to_epoch(Utc::now()),
            total_configured,
            enabled_configured,
            cli_rows_count: cli_rows.len(),
            servers,
            cli_error: cli_error.clone(),
        };

        if let Ok(mut guard) = self.mcp_cache.write() {
            *guard = Some(summary);
        }

        Ok(match cli_error {
            Some(e) => format!(
                "configured={total_configured} enabled={enabled_configured} cli_err={e}"
            ),
            None => format!(
                "configured={total_configured} enabled={enabled_configured} cli={}",
                cli_rows.len()
            ),
        })
    }

    async fn run_memory_cache_sync(&self) -> Result<String> {
        let bin_path = &self.cfg.ai_memory_mcp_bin;
        if bin_path.components().count() > 1 && !bin_path.exists() {
            return Ok("ai-memory binary absent; skipped".to_string());
        }
        let bin_str = bin_path.to_string_lossy().to_string();
        let ov = tokio::time::timeout(
            Duration::from_secs(30),
            memory_overview(&bin_str, "", None, 10),
        )
        .await
        .map_err(|_| BridgeError::Cron("memory_overview timed out".into()))?;

        let err_sanitized = ov.error.as_deref().map(redact_secrets_in_text);
        let summary = MemoryCacheSummary {
            ts: dt_to_epoch(Utc::now()),
            ok: ov.ok,
            total: ov.total,
            recent_24h: ov.recent_24h,
            types: ov.types.clone(),
            error: err_sanitized.clone(),
        };
        if let Ok(mut guard) = self.memory_cache.write() {
            *guard = Some(summary);
        }

        if let Some(err) = err_sanitized {
            return Err(BridgeError::Cron(format!("memory_overview failed: {err}")));
        }
        Ok(format!(
            "total={} recent_24h={} types={}",
            ov.total,
            ov.recent_24h,
            ov.types.len()
        ))
    }

    async fn run_inbox_gc(&self) -> Result<String> {
        let roots = vec![
            self.cfg.inbox_dir(),
            self.cfg.outbox_dir(),
            self.cfg.agy_workspace.join(".parallel"),
        ];
        tokio::task::spawn_blocking(move || -> Result<String> {
            let now = SystemTime::now();
            let mut removed = 0usize;
            let mut freed_bytes = 0u64;
            let mut existing_roots = 0usize;

            for root in roots {
                if !root.is_dir() {
                    continue;
                }
                existing_roots += 1;
                let mut stack = vec![root.clone()];
                let mut dirs_visited = Vec::new();

                while let Some(dir) = stack.pop() {
                    let entries = match std::fs::read_dir(&dir) {
                        Ok(it) => it,
                        Err(_) => continue,
                    };
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let Ok(meta) = std::fs::symlink_metadata(&path) else {
                            continue;
                        };
                        if meta.file_type().is_symlink() {
                            continue;
                        }
                        if meta.is_dir() {
                            dirs_visited.push(path.clone());
                            stack.push(path);
                        } else if meta.is_file() {
                            let Ok(modified) = meta.modified() else {
                                continue;
                            };
                            let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
                            if age.as_secs() >= INBOX_GC_MAX_AGE_SECS {
                                let size = meta.len();
                                if std::fs::remove_file(&path).is_ok() {
                                    removed += 1;
                                    freed_bytes = freed_bytes.saturating_add(size);
                                }
                            }
                        }
                    }
                }
                // Prune empty expired subdirectories bottom-up (never removing root itself).
                dirs_visited.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
                for d in dirs_visited {
                    if d != root {
                        let _ = std::fs::remove_dir(&d);
                    }
                }
            }

            if existing_roots == 0 {
                return Ok("inbox/outbox absent; removed=0".to_string());
            }
            Ok(format!("removed={removed} freed_bytes={freed_bytes}"))
        })
        .await
        .map_err(|e| BridgeError::Cron(format!("inbox_gc task join failed: {e}")))?
    }

    fn effective_cwd(&self) -> Option<&Path> {
        if self.cfg.agy_workspace.is_dir() {
            Some(self.cfg.agy_workspace.as_path())
        } else {
            Some(Path::new("/tmp"))
        }
    }

    fn persist_jobs(&self) -> Result<()> {
        let _guard = self.persist_lock.lock().unwrap_or_else(|e| e.into_inner());
        let snapshot = self.list_jobs();
        atomic_write_json(&self.state_path, &CronStoreFile { jobs: snapshot }, true)
    }

    fn sync_health_snapshot(&self) {
        self.health.set_cron_jobs(Some(self.summary_json()));
    }
}

fn load_and_reconcile_jobs(path: &Path, now: DateTime<Utc>) -> Result<Vec<CronJobRecord>> {
    let existing_map: BTreeMap<String, CronJobRecord> = match std::fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<CronStoreFile>(&raw) {
            Ok(file) => file.jobs.into_iter().map(|j| (j.id.clone(), j)).collect(),
            Err(err) => {
                warn!(path = %path.display(), error = %err, "corrupt cron_jobs.json; rebuilding defaults");
                BTreeMap::new()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(e) => return Err(BridgeError::io(format!("read {}", path.display()), e)),
    };

    let mut out = Vec::with_capacity(BUILTIN_SPECS.len());
    for spec in &BUILTIN_SPECS {
        if let Some(mut rec) = existing_map.get(spec.id).cloned() {
            rec.description = spec.description.to_string();
            if parse_cron_schedule(&rec.schedule).is_err() {
                rec.schedule = spec.schedule.to_string();
            }
            if rec.status == CronJobStatus::Running {
                rec.status = if rec.enabled {
                    CronJobStatus::Idle
                } else {
                    CronJobStatus::Disabled
                };
            }
            if rec.enabled {
                rec.next_run_at = next_fire_epoch(&rec.schedule, now)?;
            } else {
                rec.status = CronJobStatus::Disabled;
                rec.next_run_at = None;
            }
            out.push(rec);
        } else {
            let next_run_at = next_fire_epoch(spec.schedule, now)?;
            out.push(CronJobRecord {
                id: spec.id.to_string(),
                description: spec.description.to_string(),
                schedule: spec.schedule.to_string(),
                enabled: true,
                status: CronJobStatus::Idle,
                last_run_at: None,
                next_run_at,
                last_duration_ms: None,
                run_count: 0,
                fail_count: 0,
                last_summary: None,
                last_error: None,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agy_ext::engines::ModelInfo;
    use chrono::TimeZone;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    fn make_test_cfg(dir: &TempDir) -> Config {
        Config {
            bot_token: "123:SECRET_TOKEN".to_string(),
            state_dir: dir.path().join("state"),
            agy_workspace: dir.path().join("ws"),
            agy_bin: dir.path().join("bin/agy"),
            mcp_config_path: dir.path().join("mcp_config.json"),
            ai_memory_mcp_bin: dir.path().join("bin/ai-memory-mcp"),
            ..Default::default()
        }
    }

    #[test]
    fn parse_cron_accepts_5_and_6_field_and_posix_dow() {
        for expr in [
            "*/15 * * * *",
            "0 */6 * * *",
            "15 4 * * *",
            "0 0 * * 0",
            "0 9 * * 1-5",
            "0 9 * * 5-7",
            "0 0 12 * * MON-FRI",
            "0 */15 * * * *",
            "@daily",
        ] {
            assert!(parse_cron_schedule(expr).is_ok(), "failed on {expr}");
        }

        // Verify Sunday=0 in 5-field POSIX fires on Sunday (2026-11-22 is Sunday)
        let sun_sched = parse_cron_schedule("30 9 * * 0").unwrap();
        let sat = Utc.with_ymd_and_hms(2026, 11, 21, 9, 0, 0).unwrap();
        let next = sun_sched.after(&sat).next().unwrap();
        assert_eq!(next, Utc.with_ymd_and_hms(2026, 11, 22, 9, 30, 0).unwrap());

        assert!(parse_cron_schedule("").is_err());
        assert!(parse_cron_schedule("* * *").is_err());
        assert!(parse_cron_schedule("99 * * * *").is_err());
    }

    #[tokio::test]
    async fn cron_models_mcp_memory_inbox_and_persistence() {
        let dir = TempDir::new().unwrap();
        let mut cfg = make_test_cfg(&dir);
        std::fs::create_dir_all(&cfg.state_dir).unwrap();
        std::fs::create_dir_all(&cfg.agy_workspace).unwrap();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();

        // Mock `agy` script supporting `models` and `mcp list`
        let agy_script = cfg.agy_bin.clone();
        std::fs::write(
            &agy_script,
            "#!/bin/sh\nif [ \"$1\" = \"models\" ]; then\n  printf 'm1\\tClaude Sonnet\\nm2\\tGemini Pro\\n'\n  exit 0\nfi\nif [ \"$1\" = \"mcp\" ] && [ \"$2\" = \"list\" ]; then\n  printf 'NAME TYPE STATUS CMD\\nsrv1 stdio enabled /usr/bin/node\\n'\n  exit 0\nfi\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&agy_script, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Write mcp_config.json containing sensitive env secrets
        std::fs::write(
            &cfg.mcp_config_path,
            r#"{"mcpServers":{"srv1":{"command":"node","env":{"API_KEY":"super-secret-xyz","MODE":"prod"}}}}"#,
        )
        .unwrap();

        // Prepare inbox with 1 old file (>7 days), 1 fresh file, 1 subdir, 1 outside target symlink
        let inbox = cfg.inbox_dir();
        let sub = inbox.join("u1");
        std::fs::create_dir_all(&sub).unwrap();
        let old_file = sub.join("old.txt");
        let fresh_file = sub.join("fresh.txt");
        let outside_file = dir.path().join("outside_keep.txt");
        std::fs::write(&old_file, b"stale").unwrap();
        std::fs::write(&fresh_file, b"keep").unwrap();
        std::fs::write(&outside_file, b"must_not_delete").unwrap();
        let link_path = sub.join("link.txt");
        symlink(&outside_file, &link_path).unwrap();

        // Backdate old_file mtime by 8 days using `touch -d`
        let status = std::process::Command::new("touch")
            .args(["-d", "8 days ago"])
            .arg(&old_file)
            .status()
            .unwrap();
        assert!(status.success());

        cfg.cron_enabled = true;
        let cfg = Arc::new(cfg);
        let health = Arc::new(HealthTracker::new(cfg.health_path()));
        let sched = CronScheduler::new(Arc::clone(&cfg), Arc::clone(&health)).unwrap();

        assert_eq!(sched.list_jobs().len(), 4);
        assert!(cfg.cron_jobs_path().exists());
        assert_eq!(
            std::fs::metadata(cfg.cron_jobs_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        // 1. models_sync writes Vec<ModelInfo> directly
        let r_models = sched.run_now(JOB_MODELS_SYNC).await.unwrap();
        assert_eq!(r_models.status, CronJobStatus::Ok);
        let models_raw = std::fs::read_to_string(cfg.state_dir.join("models.json")).unwrap();
        let parsed_models: Vec<ModelInfo> = serde_json::from_str(&models_raw).unwrap();
        assert_eq!(parsed_models.len(), 2);
        assert_eq!(parsed_models[0].id, "m1");
        assert_eq!(parsed_models[1].name, "Gemini Pro");

        // 2. mcp_health_sync redacts secrets
        let r_mcp = sched.run_now(JOB_MCP_HEALTH_SYNC).await.unwrap();
        assert_eq!(r_mcp.status, CronJobStatus::Ok);
        let mcp_sum = sched.cached_mcp_health().unwrap();
        assert_eq!(mcp_sum.total_configured, 1);
        assert_eq!(mcp_sum.cli_rows_count, 1);
        let mcp_json = serde_json::to_string(&mcp_sum).unwrap();
        assert!(!mcp_json.contains("super-secret-xyz"));

        // 3. memory_cache_sync skips cleanly when binary absent
        let r_mem = sched.run_now(JOB_MEMORY_CACHE_SYNC).await.unwrap();
        assert_eq!(r_mem.status, CronJobStatus::Ok);
        assert!(r_mem.last_summary.as_deref().unwrap().contains("skipped"));

        // 4. inbox_gc removes ONLY old_file
        let r_gc = sched.run_now(JOB_INBOX_GC).await.unwrap();
        assert_eq!(r_gc.status, CronJobStatus::Ok);
        assert!(!old_file.exists());
        assert!(fresh_file.exists());
        assert!(outside_file.exists());
        assert!(sub.is_dir());

        // 5. set_enabled & persistence across reload
        let disabled = sched.set_enabled(JOB_INBOX_GC, false).unwrap();
        assert!(!disabled.enabled);
        assert_eq!(disabled.status, CronJobStatus::Disabled);
        assert!(disabled.next_run_at.is_none());

        let reloaded = CronScheduler::new(Arc::clone(&cfg), Arc::clone(&health)).unwrap();
        let gc_reloaded = reloaded.get_job(JOB_INBOX_GC).unwrap();
        assert!(!gc_reloaded.enabled);
        assert_eq!(gc_reloaded.run_count, 1);
        assert!(health.snapshot().cron_jobs.is_some());

        // 6. tick_at fires due jobs in the future
        let future = Utc::now() + chrono::Duration::hours(7);
        let ran = reloaded.tick_at(future).await;
        assert!(ran.contains(&JOB_MODELS_SYNC.to_string()));
        assert!(!ran.contains(&JOB_INBOX_GC.to_string())); // disabled
    }
}
