//! Read-only, zero-ban-risk local quota & activity collector (adapted from
//! `IMYin/google-ultra-maximizer` `agy_quota_probe.py`).
//!
//! Collection priority (strictly local, zero unofficial cloud OAuth scraping):
//! 1. Authoritative token windows from `AccountStore` (`accounts.json` — handled by caller).
//! 2. Read-only 24h step/conversation activity counts via `/usr/bin/sqlite3 -readonly -json`
//!    against `<home>/.gemini/antigravity-cli/conversation_summaries.db` (`PRAGMA busy_timeout=1000`,
//!    2s hard timeout, graceful `None` when absent).
//! 3. Opportunistic loopback-only (`127.0.0.1` / `::1`, `no_proxy()`, `<= 1s` timeout)
//!    Language Server Connect-RPC status check if `~/.gemini/*/daemon/hub_*.json` lists a live PID.
//!    Tokens / CSRF headers are NEVER persisted or logged.
//!
//! All probes are cached for 60s in memory (`DashMap`) so `/quota` and the `telemetry` widget
//! stay instant (<1ms on cache hit).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::process::Command;
use url::Url;

/// In-memory probe cache TTL (60 seconds).
pub const PROBE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Hard timeout for local `/usr/bin/sqlite3 -readonly -json` queries.
const SQLITE_TIMEOUT: Duration = Duration::from_secs(2);

/// Hard timeout for opportunistic loopback Connect-RPC probe.
const LS_RPC_TIMEOUT: Duration = Duration::from_secs(1);

/// Sanitized local probe output (zero tokens, zero CSRF secrets, zero raw emails).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalProbeSummary {
    pub steps_24h: Option<u64>,
    pub conversations_24h: Option<u64>,
    pub ls_rpc_live: bool,
    pub ls_plan_tier: Option<String>,
}

struct CachedProbe {
    at: Instant,
    summary: LocalProbeSummary,
}

fn probe_cache() -> &'static Mutex<HashMap<String, CachedProbe>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedProbe>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Clear the in-memory 60s probe cache (used when owner taps "Refresh").
pub fn invalidate_probe_cache() {
    probe_cache().lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Strictly validate that a URL points ONLY to loopback (`127.0.0.1` or `::1` or `localhost`)
/// over `http` or `https`, with no embedded credentials, preventing SSRF if a daemon discovery
/// file is tampered with.
pub fn is_strict_loopback_url(raw: &str) -> bool {
    let Ok(u) = Url::parse(raw.trim()) else {
        return false;
    };
    if !matches!(u.scheme(), "http" | "https") {
        return false;
    }
    if !u.username().is_empty() || u.password().is_some() {
        return false;
    }
    matches!(
        u.host_str(),
        Some("127.0.0.1") | Some("::1") | Some("[::1]") | Some("localhost")
    )
}

/// Read 24-hour conversation/step activity counts from `conversation_summaries.db` using
/// `/usr/bin/sqlite3 -readonly -json` (WAL-safe, zero new Cargo crates, 2s timeout).
pub async fn query_sqlite_activity_24h(db_path: &Path) -> Option<(u64, u64)> {
    let canon = std::fs::canonicalize(db_path).ok()?;
    if !canon.is_file() {
        return None;
    }
    let sqlite_bin = if Path::new("/usr/bin/sqlite3").is_file() {
        "/usr/bin/sqlite3"
    } else {
        "sqlite3"
    };
    let since = agy_core::text::now_unix().saturating_sub(86_400);
    let sql = format!(
        "SELECT COUNT(*) AS convs, COALESCE(SUM(step_count), 0) AS steps \
         FROM conversation_summaries \
         WHERE CAST(strftime('%s', substr(last_modified_time, 1, 19)) AS INTEGER) >= {since};"
    );
    let child = Command::new(sqlite_bin)
        .arg("-readonly")
        .arg("-json")
        .arg("-cmd")
        .arg(".timeout 1000")
        .arg(&canon)
        .arg(&sql)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;

    let out = tokio::time::timeout(SQLITE_TIMEOUT, child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout).ok()?;
    let row = rows.first()?;
    let convs = row.get("convs").and_then(Value::as_u64).unwrap_or(0);
    let steps = row.get("steps").and_then(Value::as_u64).unwrap_or(0);
    Some((convs, steps))
}

#[cfg(unix)]
fn pid_is_alive(pid: i32) -> bool {
    if pid <= 1 {
        return false;
    }
    Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(not(unix))]
fn pid_is_alive(_pid: i32) -> bool {
    false
}

/// Discover a live loopback daemon discovery JSON under `<home>/.gemini/*/daemon/hub_*.json`.
fn find_live_daemon_endpoint(home: &Path) -> Option<(String, Option<String>)> {
    let gemini_dir = home.join(".gemini");
    let entries = std::fs::read_dir(gemini_dir).ok()?;
    for entry in entries.flatten() {
        let daemon_dir = entry.path().join("daemon");
        let Ok(d_entries) = std::fs::read_dir(daemon_dir) else {
            continue;
        };
        for df in d_entries.flatten() {
            let name = df.file_name();
            let s = name.to_string_lossy();
            if !s.starts_with("hub_") || !s.ends_with(".json") {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(df.path()) else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            let pid = v.get("pid").and_then(Value::as_i64).unwrap_or(0) as i32;
            if !pid_is_alive(pid) {
                continue;
            }
            let Some(port) = v
                .get("https_port")
                .or_else(|| v.get("http_port"))
                .or_else(|| v.get("port"))
                .and_then(Value::as_u64)
            else {
                continue;
            };
            let scheme = if v.get("https_port").and_then(Value::as_u64).is_some() {
                "https"
            } else {
                "http"
            };
            let url = format!("{scheme}://127.0.0.1:{port}");
            if !is_strict_loopback_url(&url) {
                continue;
            }
            let csrf = v
                .get("csrf_token")
                .or_else(|| v.get("csrfToken"))
                .and_then(Value::as_str)
                .map(str::to_string);
            return Some((url, csrf));
        }
    }
    None
}

/// Opportunistic loopback-only Connect-RPC probe (`<= 1s`, `no_proxy()`, no redirects). Never logs CSRF tokens.
async fn probe_local_ls_rpc(home: &Path) -> (bool, Option<String>) {
    let Some((base_url, csrf)) = find_live_daemon_endpoint(home) else {
        return (false, None);
    };
    if !is_strict_loopback_url(&base_url) {
        return (false, None);
    }
    let endpoint = format!(
        "{base_url}/exa.language_server_pb.LanguageServerService/GetUserStatus"
    );
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(LS_RPC_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .build()
    else {
        return (false, None);
    };
    let mut req = client
        .post(&endpoint)
        .header("content-type", "application/json")
        .header("connect-protocol-version", "1")
        .body("{}");
    if let Some(tok) = csrf.as_deref() {
        req = req.header("x-codeium-csrf-token", tok);
    }
    let Ok(resp) = req.send().await else {
        return (false, None);
    };
    if !resp.status().is_success() {
        return (false, None);
    }
    let tier = resp
        .json::<Value>()
        .await
        .ok()
        .and_then(|v| {
            v.pointer("/userStatus/planStatus/planInfo/planName")
                .or_else(|| v.pointer("/planStatus/planInfo/planName"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    (true, tier)
}

/// Collect cached (60s TTL) read-only local activity + opportunistic loopback LS probe for `home`.
pub async fn probe_account_home_cached(
    cache_key: &str,
    home: &Path,
    force_refresh: bool,
) -> LocalProbeSummary {
    if !force_refresh {
        let g = probe_cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = g.get(cache_key) {
            if hit.at.elapsed() < PROBE_CACHE_TTL {
                return hit.summary.clone();
            }
        }
    }

    let db_path = home.join(".gemini/antigravity-cli/conversation_summaries.db");
    let (sqlite_res, (ls_live, ls_tier)) = tokio::join!(
        query_sqlite_activity_24h(&db_path),
        probe_local_ls_rpc(home),
    );
    let summary = LocalProbeSummary {
        conversations_24h: sqlite_res.map(|(c, _)| c),
        steps_24h: sqlite_res.map(|(_, s)| s),
        ls_rpc_live: ls_live,
        ls_plan_tier: ls_tier,
    };

    {
        let mut g = probe_cache().lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= 128 {
            g.retain(|_, v| v.at.elapsed() < PROBE_CACHE_TTL);
        }
        g.insert(
            cache_key.to_string(),
            CachedProbe {
                at: Instant::now(),
                summary: summary.clone(),
            },
        );
    }
    summary
}

/// Collect read-only 24h step counts and loopback LS liveness across multiple `(account_id, home)` pairs.
pub async fn collect_pool_local_probes(
    homes: &[(String, PathBuf)],
    force_refresh: bool,
) -> (HashMap<String, u64>, bool, Option<u64>) {
    let mut steps_map = HashMap::new();
    let mut any_ls_live = false;
    let mut total_steps: Option<u64> = None;

    let mut handles = Vec::with_capacity(homes.len());
    for (id, home) in homes {
        let id_c = id.clone();
        let home_c = home.clone();
        let key = Arc::new(format!("{id_c}:{}", home_c.display()));
        handles.push(tokio::spawn(async move {
            let sum = probe_account_home_cached(&key, &home_c, force_refresh).await;
            (id_c, sum)
        }));
    }

    for h in handles {
        if let Ok((id, sum)) = h.await {
            if sum.ls_rpc_live {
                any_ls_live = true;
            }
            if let Some(st) = sum.steps_24h {
                steps_map.insert(id, st);
                total_steps = Some(total_steps.unwrap_or(0).saturating_add(st));
            }
        }
    }

    (steps_map, any_ls_live, total_steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn loopback_guard_rejects_remote_and_invalid_urls() {
        assert!(is_strict_loopback_url("http://127.0.0.1:42100"));
        assert!(is_strict_loopback_url("https://127.0.0.1:8443"));
        assert!(is_strict_loopback_url("http://[::1]:42100"));
        assert!(is_strict_loopback_url("http://localhost:9000"));
        assert!(!is_strict_loopback_url("https://google.com:443"));
        assert!(!is_strict_loopback_url("http://169.254.169.254/latest"));
        assert!(!is_strict_loopback_url("file:///etc/passwd"));
        assert!(!is_strict_loopback_url("ftp://127.0.0.1:21"));
        assert!(!is_strict_loopback_url("http://user:pass@127.0.0.1:42100"));
        assert!(!is_strict_loopback_url("http://user@127.0.0.1:42100"));
    }

    #[tokio::test]
    async fn sqlite_readonly_probe_reads_24h_steps_and_handles_missing_db() {
        let td = TempDir::new().unwrap();
        assert!(query_sqlite_activity_24h(&td.path().join("missing.db"))
            .await
            .is_none());

        if !Path::new("/usr/bin/sqlite3").is_file() {
            return;
        }
        let db = td.path().join("conversation_summaries.db");
        let init_sql = "PRAGMA journal_mode=WAL; \
             CREATE TABLE conversation_summaries (conversation_id TEXT PRIMARY KEY, step_count INTEGER NOT NULL DEFAULT 0, last_modified_time DATETIME NOT NULL); \
             INSERT INTO conversation_summaries VALUES ('c1', 12, datetime('now') || '.123456+00:00'); \
             INSERT INTO conversation_summaries VALUES ('c2', 8, datetime('now', '-2 hours') || '.654321+00:00'); \
             INSERT INTO conversation_summaries VALUES ('old', 99, datetime('now', '-3 days') || '.000000+00:00');";
        let st = Command::new("/usr/bin/sqlite3")
            .arg(&db)
            .arg(init_sql)
            .status()
            .await
            .unwrap();
        assert!(st.success());

        let (convs, steps) = query_sqlite_activity_24h(&db)
            .await
            .expect("sqlite3 readonly query must succeed on WAL db");
        assert_eq!(convs, 2);
        assert_eq!(steps, 20);
    }

    #[tokio::test]
    async fn probe_cache_returns_cached_summary_within_ttl() {
        let td = TempDir::new().unwrap();
        let key = format!("test-cache-{}", td.path().display());
        invalidate_probe_cache();
        let first = probe_account_home_cached(&key, td.path(), false).await;
        assert!(!first.ls_rpc_live);
        assert!(first.steps_24h.is_none());
        assert!(probe_cache().lock().unwrap().contains_key(&key));
        let second = probe_account_home_cached(&key, td.path(), false).await;
        assert_eq!(second.steps_24h, first.steps_24h);
    }
}
