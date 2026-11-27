//! Shared anti-DDoS rate limiting (bounded token buckets) and secret-leak scanning
//! for HTTP endpoints, Telegram updates, and outbox file delivery.

use std::collections::HashMap;
use std::hash::Hash;
use std::io::Read;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use regex::Regex;
use url::Url;

/// Maximum number of distinct keys retained in a single [`KeyedTokenBucket`] before
/// evicting stale / oldest entries (protects against IP-spray OOM attacks).
pub const DEFAULT_MAX_BUCKET_KEYS: usize = 4096;

/// Default maximum bytes read from a single outbox text file during secret scanning (2 MiB).
pub const DEFAULT_MAX_SECRET_SCAN_BYTES: usize = 2 * 1024 * 1024;

/// Extensions treated as binary media/archives that are skipped by text secret scanning.
const BINARY_SKIP_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "webp", "gif", "bmp", "ico", "heic", "avif",
    "mp4", "mov", "mkv", "webm", "avi",
    "mp3", "m4a", "wav", "ogg", "opus", "flac", "aac",
    "pdf", "zip", "gz", "tgz", "bz2", "xz", "zst", "tar", "7z", "rar",
    "woff", "woff2", "ttf", "otf", "eot",
    "exe", "dll", "so", "dylib", "wasm", "sqlite", "db",
];

fn now_secs() -> f64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_secs_f64()
}

/// Outcome of a rate-limit admission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub retry_after_secs: u64,
    pub remaining: u32,
}

#[derive(Debug, Clone)]
struct BucketState {
    tokens: f64,
    last_refill: f64,
    last_seen: f64,
}

/// Memory-bounded, keyed token-bucket rate limiter.
///
/// Setting `rate_per_min == 0` disables rate limiting (always allows).
struct BucketInner<K> {
    rate_per_min: u32,
    rate_per_sec: f64,
    burst: f64,
    map: HashMap<K, BucketState>,
}

pub struct KeyedTokenBucket<K> {
    max_keys: usize,
    inner: Mutex<BucketInner<K>>,
}

impl<K: Eq + Hash + Clone> KeyedTokenBucket<K> {
    /// Construct a limiter allowing `rate_per_min` sustained tokens/min with initial `burst`.
    pub fn new(rate_per_min: u32, burst: u32, max_keys: usize) -> Self {
        let rate_per_sec = f64::from(rate_per_min) / 60.0;
        let effective_burst = if rate_per_min == 0 {
            0.0
        } else {
            f64::from(burst.max(1))
        };
        Self {
            max_keys: max_keys.max(64),
            inner: Mutex::new(BucketInner {
                rate_per_min,
                rate_per_sec,
                burst: effective_burst,
                map: HashMap::new(),
            }),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .rate_per_sec
            > 0.0
    }

    pub fn rate_per_min(&self) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .rate_per_min
    }

    /// Dynamically adjust the limiter rate and burst (e.g. from `/limits`).
    pub fn set_rate(&self, rate_per_min: u32, burst: u32) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.rate_per_min = rate_per_min;
        g.rate_per_sec = f64::from(rate_per_min) / 60.0;
        g.burst = if rate_per_min == 0 {
            0.0
        } else {
            f64::from(burst.max(1))
        };
        if rate_per_min == 0 {
            g.map.clear();
        }
    }

    /// Check admission for `key` consuming `cost` tokens using wall-clock time.
    pub fn check(&self, key: K, cost: u32) -> RateLimitResult {
        self.check_at(key, cost, 1.0, now_secs())
    }

    /// Check admission for `key` with an optional capacity/rate multiplier (e.g. `3.0` for owner).
    pub fn check_scaled(&self, key: K, cost: u32, scale: f64) -> RateLimitResult {
        self.check_at(key, cost, scale, now_secs())
    }

    /// Deterministic timestamp variant of [`Self::check_scaled`] for unit tests.
    pub fn check_at(&self, key: K, cost: u32, scale: f64, now: f64) -> RateLimitResult {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.rate_per_sec <= 0.0 {
            return RateLimitResult {
                allowed: true,
                retry_after_secs: 0,
                remaining: u32::MAX,
            };
        }

        let mult = if scale.is_finite() && scale > 0.0 {
            scale
        } else {
            1.0
        };
        let eff_rate = g.rate_per_sec * mult;
        let eff_burst = (g.burst * mult).max(1.0);
        let need = f64::from(cost.max(1));

        let max_keys = self.max_keys;
        let map = &mut g.map;
        if !map.contains_key(&key) && map.len() >= max_keys {
            // Evict entries idle for > 120s first; if still at cap, evict oldest quarter.
            map.retain(|_, st| (now - st.last_seen) < 120.0);
            if map.len() >= max_keys {
                let mut ages: Vec<(K, f64)> =
                    map.iter().map(|(k, v)| (k.clone(), v.last_seen)).collect();
                ages.sort_by(|a, b| a.1.total_cmp(&b.1));
                let drop_n = (max_keys / 4).max(1);
                for (old_k, _) in ages.into_iter().take(drop_n) {
                    map.remove(&old_k);
                }
            }
        }

        let st = map.entry(key).or_insert_with(|| BucketState {
            tokens: eff_burst,
            last_refill: now,
            last_seen: now,
        });

        let elapsed = (now - st.last_refill).max(0.0);
        if elapsed > 0.0 {
            st.tokens = (st.tokens + elapsed * eff_rate).min(eff_burst);
            st.last_refill = now;
        }
        st.last_seen = now;

        if st.tokens >= need {
            st.tokens -= need;
            RateLimitResult {
                allowed: true,
                retry_after_secs: 0,
                remaining: st.tokens.floor().max(0.0) as u32,
            }
        } else {
            let deficit = (need - st.tokens).max(0.0);
            let wait = (deficit / eff_rate).ceil().max(1.0) as u64;
            RateLimitResult {
                allowed: false,
                retry_after_secs: wait,
                remaining: 0,
            }
        }
    }

    /// Number of currently tracked keys (for diagnostics/tests).
    pub fn tracked_keys(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .len()
    }
}

/// Classification of a suspected secret leak (never carries the raw secret value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFinding {
    pub kind: &'static str,
    pub count: usize,
}

struct SecretPattern {
    kind: &'static str,
    re: Regex,
}

fn secret_patterns() -> &'static [SecretPattern] {
    static PATS: OnceLock<Vec<SecretPattern>> = OnceLock::new();
    PATS.get_or_init(|| {
        let defs: &[(&'static str, &str)] = &[
            (
                "private_key",
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
            ),
            (
                "telegram_bot_token",
                r"\b[0-9]{8,11}:[A-Za-z0-9_-]{30,50}\b",
            ),
            (
                "openai_or_anthropic_key",
                r"\b(?:sk-proj-|sk-ant-|sk-live-|sk-svcacct-)[A-Za-z0-9_-]{20,}\b",
            ),
            (
                "xai_api_key",
                r"\bxai-[A-Za-z0-9_-]{24,}\b",
            ),
            (
                "google_api_key",
                r"\bAIza[0-9A-Za-z_-]{35}\b",
            ),
            (
                "google_oauth_token",
                r"\bya29\.[0-9A-Za-z_-]{24,}\b",
            ),
            (
                "github_token",
                r"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|gho_[A-Za-z0-9]{30,})\b",
            ),
            (
                "aws_access_key",
                r"\bAKIA[0-9A-Z]{16}\b",
            ),
            (
                "slack_token",
                r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b",
            ),
            (
                "proxy_credentials",
                r"(?i)\b(?:https?|socks5h?)://[^\s:@/]{2,}:[^\s@/]{4,}@[^\s/]+",
            ),
        ];
        defs.iter()
            .filter_map(|(kind, pat)| Regex::new(pat).ok().map(|re| SecretPattern { kind, re }))
            .collect()
    })
}

fn is_placeholder_proxy_match(m: &str) -> bool {
    let clean = m.trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | ',' | ';' | ')' | ']' | '}'));
    let low = clean.to_ascii_lowercase();
    if low.contains("[redacted]@") || low.contains("***@") {
        return true;
    }
    // Source-code templates & variable interpolations are NOT leaked credentials:
    // e.g. Python f"http://{user}:{password}@{host}:{port}", JS `http://${u}:${p}@${h}`,
    // PHP/Bash `http://$user:$pass@$host`, printf `http://%s:%s@%s`, docs `http://<user>:<pass>@<host>`.
    if clean.contains('{')
        || clean.contains('}')
        || clean.contains('$')
        || clean.contains('<')
        || clean.contains('>')
        || clean.contains("%s")
        || clean.contains("%(")
        || clean.contains("'+")
        || clean.contains("\"+")
        || clean.contains("'.")
        || clean.contains("\".")
    {
        return true;
    }
    if let Ok(u) = Url::parse(clean) {
        let user = u.username().to_ascii_lowercase();
        let pass = u.password().unwrap_or("").to_ascii_lowercase();
        let host = u.host_str().unwrap_or("").to_ascii_lowercase();
        let dummy_cred = matches!(
            (user.as_str(), pass.as_str()),
            ("user", "pass")
                | ("user", "password")
                | ("username", "password")
                | ("alice", "pass")
                | ("foo", "bar")
                | ("demo", "demo")
                | ("test", "test")
                | ("proxy", "proxy")
                | ("proxyuser", "proxypass")
        );
        let dummy_host = host == "example.com"
            || host == "example.org"
            || host.ends_with(".example")
            || host == "proxy.local"
            || host == "localhost"
            || host == "127.0.0.1"
            || host == "0.0.0.0"
            || host == "host";
        if dummy_cred || dummy_host {
            return true;
        }
    }
    false
}

/// Scan UTF-8 text content for suspected secret leaks plus configured runtime secret literals.
///
/// Never returns matched secret strings — only `(kind, count)`.
pub fn scan_secret_leaks(content: &str, extra_literals: &[&str]) -> Vec<SecretFinding> {
    let mut findings: Vec<SecretFinding> = Vec::new();

    // 1. Exact check against live runtime secrets (bot token, API keys, proxy passwords).
    let mut runtime_hits = 0usize;
    for lit in extra_literals {
        let s = lit.trim();
        if s.len() >= 10 && content.contains(s) {
            runtime_hits += 1;
        }
    }
    if runtime_hits > 0 {
        findings.push(SecretFinding {
            kind: "configured_runtime_secret",
            count: runtime_hits,
        });
    }

    // 2. High-confidence regex signatures.
    for pat in secret_patterns() {
        let count = if pat.kind == "proxy_credentials" {
            pat.re
                .find_iter(content)
                .filter(|m| !is_placeholder_proxy_match(m.as_str()))
                .count()
        } else {
            pat.re.find_iter(content).count()
        };
        if count > 0 {
            findings.push(SecretFinding {
                kind: pat.kind,
                count,
            });
        }
    }

    findings
}

/// Scan an outbox file on disk for suspected secret leaks.
///
/// Automatically skips binary media/archive extensions and files containing NUL bytes in their
/// first 512 bytes. Reads at most `max_scan_bytes`.
pub fn scan_file_for_secrets(
    path: &Path,
    max_scan_bytes: usize,
    extra_literals: &[&str],
) -> Vec<SecretFinding> {
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        let low = ext.to_ascii_lowercase();
        if BINARY_SKIP_EXTS.contains(&low.as_str()) {
            return Vec::new();
        }
    }

    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let cap = if max_scan_bytes == 0 {
        DEFAULT_MAX_SECRET_SCAN_BYTES
    } else {
        max_scan_bytes
    };
    let mut buf = Vec::new();
    let mut limited = file.take(cap as u64);
    if limited.read_to_end(&mut buf).is_err() || buf.is_empty() {
        return Vec::new();
    }

    let probe_len = buf.len().min(512);
    if buf[..probe_len].contains(&0) {
        return Vec::new();
    }

    let text = String::from_utf8_lossy(&buf);
    scan_secret_leaks(&text, extra_literals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn token_bucket_refills_scales_and_bounds_keys() {
        let rl = KeyedTokenBucket::<i64>::new(60, 3, 64); // 1 req/sec, burst 3
        assert!(rl.is_enabled());

        assert!(rl.check_at(10, 1, 1.0, 100.0).allowed);
        assert!(rl.check_at(10, 1, 1.0, 100.0).allowed);
        assert!(rl.check_at(10, 1, 1.0, 100.0).allowed);
        let denied = rl.check_at(10, 1, 1.0, 100.0);
        assert!(!denied.allowed);
        assert!(denied.retry_after_secs >= 1);

        // After 1.5s, 1 token refilled
        assert!(rl.check_at(10, 1, 1.0, 101.5).allowed);
        assert!(!rl.check_at(10, 1, 1.0, 101.5).allowed);

        // Scaled caller (e.g. owner 3x) gets larger burst
        for _ in 0..9 {
            assert!(rl.check_at(99, 1, 3.0, 100.0).allowed);
        }
        assert!(!rl.check_at(99, 1, 3.0, 100.0).allowed);

        // Key-spray eviction keeps memory bounded <= max_keys
        for ip in 1..=200i64 {
            let _ = rl.check_at(1000 + ip, 1, 1.0, 200.0 + (ip as f64) * 0.01);
        }
        assert!(rl.tracked_keys() <= 64);

        // Disabled limiter always allows
        let off = KeyedTokenBucket::<i64>::new(0, 1, 64);
        assert!(!off.is_enabled());
        assert!(off.check_at(1, 100, 1.0, 0.0).allowed);
    }

    #[test]
    fn secret_scanner_catches_real_secrets_and_ignores_benign_text_and_binaries() {
        let clean = "# Report\nproxy example: socks5h://user:pass@example.com:1080\nredacted: http://[REDACTED]@10.0.0.1:8080\n\
python_fstring: return f\"http://{user}:{password}@{host}:{port}\"\n\
js_template: const u = `socks5://${user}:${pass}@${host}:${port}`;\n\
php_var: $url = \"http://$user:$pass@$host:$port\";\n\
doc_placeholder: http://<user>:<pass>@<host>:<port>\n";
        assert!(scan_secret_leaks(clean, &["999999999:MyLiveBotTokenSecret1234567890"]).is_empty());

        let leaked = "BOT_TOKEN=123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789\n-----BEGIN OPENSSH PRIVATE KEY-----\nproxy=socks5h://prod:RealPass99@198.51.100.2:1080\n";
        let hits = scan_secret_leaks(leaked, &[]);
        let kinds: Vec<&str> = hits.iter().map(|h| h.kind).collect();
        assert!(kinds.contains(&"telegram_bot_token"));
        assert!(kinds.contains(&"private_key"));
        assert!(kinds.contains(&"proxy_credentials"));

        // Runtime literal match
        let custom = "secret=my-super-unique-webhook-secret-xyz";
        let rt_hits = scan_secret_leaks(custom, &["my-super-unique-webhook-secret-xyz"]);
        assert_eq!(rt_hits.len(), 1);
        assert_eq!(rt_hits[0].kind, "configured_runtime_secret");

        // File scan skips binary extensions and NUL-byte files
        let dir = TempDir::new().unwrap();
        let png = dir.path().join("photo.png");
        std::fs::write(&png, leaked.as_bytes()).unwrap();
        assert!(scan_file_for_secrets(&png, 65536, &[]).is_empty());

        let bin = dir.path().join("blob.dat");
        let mut raw = vec![0u8, 1, 2, 3];
        raw.extend_from_slice(leaked.as_bytes());
        std::fs::write(&bin, raw).unwrap();
        assert!(scan_file_for_secrets(&bin, 65536, &[]).is_empty());

        let env_file = dir.path().join("dump.env");
        std::fs::write(&env_file, leaked).unwrap();
        assert!(!scan_file_for_secrets(&env_file, 65536, &[]).is_empty());
    }
}
