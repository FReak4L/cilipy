//! Per-account model catalogs.
//!
//! Each Antigravity account can expose a different model list. The list comes from
//! `agy models` run under that account's `HOME`. Verified on the server: that command makes
//! only `loadCodeAssist` and `fetchAvailableModels` calls and no `generateContent`, so it does
//! not start a turn or spend quota.
//! Storage: the `primary` account uses `$STATE_DIR/models.json` (the existing cache); every
//! other account uses `$STATE_DIR/accounts/<id>/models.json` (0600).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::SystemTime;

use agy_core::accounts::{Account, PRIMARY_ACCOUNT_ID};
use agy_core::config::Config;
use agy_ext::engines::{parse_models, run_cmd_env, ModelInfo};
use dashmap::DashMap;
use tracing::{info, warn};

/// Re-fetch an account's list when it is older than this.
pub const MODELS_MAX_AGE_SECS: u64 = 6 * 3600;

fn models_cache() -> &'static DashMap<PathBuf, (Option<SystemTime>, Vec<ModelInfo>)> {
    static CACHE: OnceLock<DashMap<PathBuf, (Option<SystemTime>, Vec<ModelInfo>)>> =
        OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

pub fn models_path(state_dir: &Path, account_id: &str) -> PathBuf {
    if account_id == PRIMARY_ACCOUNT_ID {
        state_dir.join("models.json")
    } else {
        state_dir.join("accounts").join(account_id).join("models.json")
    }
}

/// Mtime-checked in-memory cached load of per-account models (avoids repeated disk I/O
/// on dashboard and model-label renders while staying immediately fresh on updates).
pub fn load(state_dir: &Path, account_id: &str) -> Vec<ModelInfo> {
    let path = models_path(state_dir, account_id);
    let mtime = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok());
    let cache = models_cache();
    if let Some(entry) = cache.get(&path) {
        if entry.0 == mtime {
            return entry.1.clone();
        }
    }
    let parsed = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<Vec<ModelInfo>>(&raw).ok())
        .unwrap_or_default();
    if cache.len() >= 128 {
        cache.clear();
    }
    cache.insert(path, (mtime, parsed.clone()));
    parsed
}

pub fn age_secs(state_dir: &Path, account_id: &str) -> Option<u64> {
    let m = std::fs::metadata(models_path(state_dir, account_id)).ok()?.modified().ok()?;
    SystemTime::now().duration_since(m).ok().map(|d| d.as_secs())
}

pub fn is_stale(state_dir: &Path, account_id: &str) -> bool {
    age_secs(state_dir, account_id).is_none_or(|a| a > MODELS_MAX_AGE_SECS)
}

/// Run `agy models` as `account` and persist the list. Returns the fresh list. The cached
/// list is kept if the command fails or prints nothing.
pub async fn refresh(cfg: &Config, account: &Account) -> Vec<ModelInfo> {
    refresh_with_proxy(cfg, account, None).await
}

/// Run `agy models` as `account`, optionally routed through its sticky egress proxy URL.
pub async fn refresh_with_proxy(
    cfg: &Config,
    account: &Account,
    proxy_url: Option<&str>,
) -> Vec<ModelInfo> {
    let args = vec![cfg.agy_bin.to_string_lossy().into_owned(), "models".to_string()];
    let mut env = vec![("HOME".to_string(), account.home.to_string_lossy().into_owned())];
    if let Some(px) = proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
        for k in [
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "ALL_PROXY",
            "https_proxy",
            "http_proxy",
            "all_proxy",
        ] {
            env.push((k.to_string(), px.to_string()));
        }
        for k in ["NO_PROXY", "no_proxy"] {
            env.push((k.to_string(), "127.0.0.1,localhost,::1".to_string()));
        }
    }
    match run_cmd_env(&args, Some(&cfg.agy_workspace), 45.0, &env).await {
        Ok((0, out, _)) => {
            let models = parse_models(&out);
            if models.is_empty() {
                warn!(account = %account.id, "agy models returned no models");
                return load(&cfg.state_dir, &account.id);
            }
            let path = models_path(&cfg.state_dir, &account.id);
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Err(e) = agy_core::atomic::atomic_write_json(&path, &models, true) {
                warn!(account = %account.id, error = %e, "failed to persist account models");
            } else {
                let mtime = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok());
                models_cache().insert(path, (mtime, models.clone()));
            }
            info!(account = %account.id, count = models.len(), "account models refreshed");
            models
        }
        Ok((rc, _, err)) => {
            let tail: String = err.chars().rev().take(200).collect::<String>().chars().rev().collect();
            warn!(account = %account.id, rc, err = %tail.replace('\n', " "), "agy models failed");
            load(&cfg.state_dir, &account.id)
        }
        Err(e) => {
            warn!(account = %account.id, error = %e, "agy models spawn failed");
            load(&cfg.state_dir, &account.id)
        }
    }
}

/// The cached list, refreshed first when it is missing.
pub async fn ensure(cfg: &Config, account: &Account) -> Vec<ModelInfo> {
    let cur = load(&cfg.state_dir, &account.id);
    if cur.is_empty() {
        return refresh(cfg, account).await;
    }
    cur
}

/// User-triggered refresh throttle: at most one `agy models` per account per minute
/// (the owner is not throttled).
pub fn may_refresh_now(account_id: &str, is_owner: bool) -> bool {
    static LAST: std::sync::Mutex<Option<std::collections::HashMap<String, std::time::Instant>>> = std::sync::Mutex::new(None);
    if is_owner {
        return true;
    }
    let mut g = LAST.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(Default::default);
    let now = std::time::Instant::now();
    if m.get(account_id).is_some_and(|t| now.duration_since(*t) < std::time::Duration::from_secs(60)) {
        return false;
    }
    m.insert(account_id.to_string(), now);
    true
}

/// True when agy rejected the requested model (unknown or not available for this account).
pub fn is_model_unavailable_error(msg: &str) -> bool {
    agy_core::accounts::is_model_unavailable(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_error_detection() {
        assert!(is_model_unavailable_error("Error: model \"x\" cannot be resolved. Available models: a, b"));
        assert!(is_model_unavailable_error("The requested model was not found, or your project does not have access to it."));
        assert!(!is_model_unavailable_error("RESOURCE_EXHAUSTED (code 429): Individual quota reached"));
        assert!(is_model_unavailable_error("Invalid model \"gemini-4-x\" (valid choices: a, b)"));
        assert!(is_model_unavailable_error("failed to resolve model \"x\": model not found"));
        assert!(is_model_unavailable_error("no model is selected and the account has no default"));
        assert!(is_model_unavailable_error("models.defaultLabel \"X\" references an unknown model"));
    }

    #[test]
    fn per_account_paths() {
        let d = Path::new("/s");
        assert_eq!(models_path(d, "primary"), PathBuf::from("/s/models.json"));
        assert_eq!(models_path(d, "acc2"), PathBuf::from("/s/accounts/acc2/models.json"));
    }

    #[test]
    fn load_caches_and_invalidates_on_file_update() {
        let td = tempfile::TempDir::new().unwrap();
        let p = models_path(td.path(), "primary");
        std::fs::write(&p, r#"[{"id":"m1","name":"Model 1"}]"#).unwrap();
        let first = load(td.path(), "primary");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].id, "m1");
        // Overwrite with a distinct mtime (sleep 20ms or touch)
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&p, r#"[{"id":"m1","name":"Model 1"},{"id":"m2","name":"Model 2"}]"#).unwrap();
        let second = load(td.path(), "primary");
        assert_eq!(second.len(), 2);
        assert_eq!(second[1].id, "m2");
    }
}
