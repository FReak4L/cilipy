//! Headless relay of the interactive `agy` Google OAuth sign-in for an isolated account
//! `HOME` (used by the Telegram `/accounts` "Add account" flow).
//!
//! `agy` 1.5.x has no non-interactive login subcommand: running `agy` without a token shows
//! a TUI ("Select login method" -> "1. Google OAuth"), prints an
//! `https://accounts.google.com/o/oauth2/auth?...` PKCE URL (also as an OSC-8 hyperlink) and
//! waits for the user to paste the authorization code. We drive that TUI through
//! util-linux `script` (a PTY) and relay URL out / code in.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use agy_core::error::{BridgeError, Result};
use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tracing::{info, warn};

use crate::engines::agy_env;
use crate::mcp_client::{configure_new_session, redact_secrets_in_text, signal_process_group};

const MAX_BUF: usize = 256 * 1024;

fn osc8_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\x1b\]8;[^;\x07\x1b]*;(https://accounts\.google\.com/o/oauth2/[^\x07\x1b\s]+)")
            .expect("valid regex")
    })
}

fn ansi_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b\[[0-9;?<>=]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
            .expect("valid regex")
    })
}

fn plain_url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"https://accounts\.google\.com/o/oauth2/auth\?[A-Za-z0-9%&=_.+\-~:/]+?state=[A-Za-z0-9_\-]+")
            .expect("valid regex")
    })
}

/// Strip ANSI CSI/OSC sequences.
pub fn strip_ansi(s: &str) -> String {
    ansi_re().replace_all(s, "").into_owned()
}

/// Extract the Google OAuth URL from raw TUI output (OSC-8 link first, then the wrapped
/// plain-text rendering with line breaks removed).
pub fn extract_oauth_url(raw: &str) -> Option<String> {
    let mut best: Option<String> = None;
    for cap in osc8_re().captures_iter(raw) {
        let u = cap[1].to_string();
        if u.contains("state=") && best.as_ref().is_none_or(|b| u.len() > b.len()) {
            best = Some(u);
        }
    }
    if best.is_some() {
        return best;
    }
    let plain = strip_ansi(raw);
    // the TUI wraps the URL over several indented lines: join everything without whitespace
    let joined: String = plain
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control() && *c != '│')
        .collect();
    plain_url_re().find(&joined).map(|m| m.as_str().to_string())
}

/// Basic sanity check for a pasted OAuth authorization code.
pub fn valid_auth_code(code: &str) -> bool {
    let c = code.trim();
    (8..=512).contains(&c.len())
        && c
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "/_-.%~=+".contains(ch))
}

/// A running interactive login session.
pub struct LoginSession {
    pub account_id: String,
    pub home: PathBuf,
    child: tokio::sync::Mutex<Option<Child>>,
    stdin: tokio::sync::Mutex<Option<ChildStdin>>,
    pgid: Option<libc::pid_t>,
    buf: Arc<Mutex<String>>,
}

impl LoginSession {
    /// Spawn `agy` under a PTY with `HOME=home`, cwd `home`.
    pub fn spawn(agy_bin: &str, home: &Path, account_id: &str) -> Result<Arc<Self>> {
        Self::spawn_with_proxy(agy_bin, home, account_id, None)
    }

    /// Spawn `agy` under a PTY with `HOME=home`, optionally bound to a sticky egress proxy URL.
    pub fn spawn_with_proxy(
        agy_bin: &str,
        home: &Path,
        account_id: &str,
        proxy_url: Option<&str>,
    ) -> Result<Arc<Self>> {
        let script = which_script().ok_or_else(|| {
            BridgeError::Process("script".into(), "util-linux `script` not found".into())
        })?;
        let inner = format!(
            "stty cols 240 rows 60 2>/dev/null; exec {}",
            shell_words::quote(agy_bin)
        );
        let mut env = agy_env();
        env.insert("HOME".into(), home.to_string_lossy().into_owned());
        env.insert("TERM".into(), "xterm-256color".into());
        env.remove("NO_COLOR");
        if let Some(px) = proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
            for k in [
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "ALL_PROXY",
                "https_proxy",
                "http_proxy",
                "all_proxy",
            ] {
                env.insert(k.into(), px.to_string());
            }
            for k in ["NO_PROXY", "no_proxy"] {
                env.insert(k.into(), "127.0.0.1,localhost,::1".into());
            }
        }
        let mut cmd = Command::new(script);
        cmd.args(["-q", "-f", "-e", "-c", &inner, "/dev/null"])
            .current_dir(home)
            .env_clear()
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        configure_new_session(&mut cmd);
        let mut child = cmd
            .spawn()
            .map_err(|e| BridgeError::Process("script".into(), format!("spawn failed: {e}")))?;
        let pgid = child.id().and_then(|p| libc::pid_t::try_from(p).ok());
        let stdin = child.stdin.take();
        let buf = Arc::new(Mutex::new(String::new()));
        for out in [
            child.stdout.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
            child.stderr.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let b = Arc::clone(&buf);
            tokio::spawn(async move {
                let mut r = out;
                let mut chunk = [0u8; 8192];
                loop {
                    match r.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let s = String::from_utf8_lossy(&chunk[..n]);
                            let mut g = b.lock().unwrap_or_else(|e| e.into_inner());
                            g.push_str(&s);
                            if g.len() > MAX_BUF {
                                let cut = g.len() - MAX_BUF;
                                let cut = (cut..g.len()).find(|i| g.is_char_boundary(*i)).unwrap_or(0);
                                g.drain(..cut);
                            }
                        }
                    }
                }
            });
        }
        info!(account = account_id, "agy login session started");
        Ok(Arc::new(Self {
            account_id: account_id.to_string(),
            home: home.to_path_buf(),
            child: tokio::sync::Mutex::new(Some(child)),
            stdin: tokio::sync::Mutex::new(stdin),
            pgid,
            buf,
        }))
    }

    fn snapshot(&self) -> String {
        self.buf.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Redacted, ANSI-stripped tail of the TUI output for diagnostics.
    pub fn tail(&self, max_chars: usize) -> String {
        let plain = strip_ansi(&self.snapshot());
        let lines: Vec<&str> = plain
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.chars().all(|c| "▄▀█ ─".contains(c)))
            .collect();
        let joined = lines.join("\n");
        let n = joined.chars().count();
        let t: String = joined.chars().skip(n.saturating_sub(max_chars)).collect();
        // never echo OAuth URLs/codes back into logs or chat
        let t = plain_url_re().replace_all(&t, "<oauth-url>").into_owned();
        redact_secrets_in_text(&t)
    }

    async fn write(&self, bytes: &[u8]) -> Result<()> {
        let mut g = self.stdin.lock().await;
        let Some(stdin) = g.as_mut() else {
            return Err(BridgeError::Process("agy".into(), "login stdin closed".into()));
        };
        stdin
            .write_all(bytes)
            .await
            .map_err(|e| BridgeError::Process("agy".into(), format!("write failed: {e}")))?;
        let _ = stdin.flush().await;
        Ok(())
    }

    /// Drive the TUI until the OAuth URL is printed. Picks "Google OAuth" (option 1).
    pub async fn wait_for_url(&self, timeout: Duration) -> Result<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut chose = false;
        loop {
            let raw = self.snapshot();
            if let Some(u) = extract_oauth_url(&raw) {
                return Ok(u);
            }
            let plain = strip_ansi(&raw);
            if !chose && (plain.contains("Select login method") || plain.contains("Google OAuth")) {
                tokio::time::sleep(Duration::from_millis(400)).await;
                self.write(b"\r").await?;
                chose = true;
            }
            if self.exited().await {
                return Err(BridgeError::Process(
                    "agy".into(),
                    format!("login TUI exited early: {}", self.tail(600)),
                ));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(BridgeError::Process(
                    "agy".into(),
                    format!("no sign-in URL within {}s: {}", timeout.as_secs(), self.tail(600)),
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Paste the authorization code and press Enter.
    pub async fn submit_code(&self, code: &str) -> Result<()> {
        let c = code.trim();
        if !valid_auth_code(c) {
            return Err(BridgeError::Validation("authorization code looks invalid".into()));
        }
        self.write(c.as_bytes()).await?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        self.write(b"\r").await
    }

    /// Returns `true` if the underlying login TUI child has exited.
    pub async fn is_exited(&self) -> bool {
        self.exited().await
    }

    async fn exited(&self) -> bool {
        let mut g = self.child.lock().await;
        match g.as_mut() {
            Some(ch) => matches!(ch.try_wait(), Ok(Some(_))),
            None => true,
        }
    }

    /// Stop the TUI: Ctrl-C twice, then SIGTERM/SIGKILL to the `script` session, and kill
    /// any `agy` left in that `HOME` (the PTY child lives in its own session).
    pub async fn stop(&self) {
        let _ = self.write(b"\x03").await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = self.write(b"\x03").await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(pg) = self.pgid {
            signal_process_group(pg, libc::SIGTERM);
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
        if let Some(pg) = self.pgid {
            signal_process_group(pg, libc::SIGKILL);
        }
        {
            let mut g = self.child.lock().await;
            if let Some(mut ch) = g.take() {
                let _ = ch.start_kill();
                let _ = tokio::time::timeout(Duration::from_secs(3), ch.wait()).await;
            }
        }
        *self.stdin.lock().await = None;
        kill_strays_for_home(&self.home);
        info!(account = %self.account_id, "agy login session stopped");
    }
}

fn which_script() -> Option<PathBuf> {
    ["/usr/bin/script", "/bin/script"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// Kill any process whose environment has `HOME=<home>` (only used for login cleanup;
/// shadow homes are unique per account so this cannot hit unrelated processes).
pub fn kill_strays_for_home(home: &Path) {
    let needle = format!("HOME={}", home.display());
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return;
    };
    let me = std::process::id();
    for ent in rd.flatten() {
        let Ok(pid) = ent.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(env) = std::fs::read(ent.path().join("environ")) else {
            continue;
        };
        if env.split(|b| *b == 0).any(|kv| kv == needle.as_bytes()) {
            if let Ok(p) = libc::pid_t::try_from(pid) {
                // SAFETY: plain kill(2) on a concrete pid owned by this (root) service.
                let rc = unsafe { libc::kill(p, libc::SIGKILL) };
                if rc == 0 {
                    warn!(pid, "killed leftover login process");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_extraction_from_osc8_and_wrapped_text() {
        let url = "https://accounts.google.com/o/oauth2/auth?access_type=offline&client_id=x.apps.googleusercontent.com&code_challenge=abc&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fantigravity.google%2Foauth-callback&response_type=code&scope=openid&state=Zz_9-x";
        let osc = format!("\x1b[34;4m\x1b]8;id=jk1;{url}\x1b\\Click here\x1b]8;;\x1b\\");
        assert_eq!(extract_oauth_url(&osc).as_deref(), Some(url));
        let wrapped = format!(
            " Open the URL below in your browser:\n ────\n {}\n {}\n ────\n",
            &url[..90],
            &url[90..]
        );
        assert_eq!(extract_oauth_url(&wrapped).as_deref(), Some(url));
        assert!(extract_oauth_url("nothing").is_none());
    }

    #[test]
    fn auth_code_validation() {
        assert!(valid_auth_code("4/0AVGzR1A-abcdefghijk_LMNOP"));
        assert!(!valid_auth_code("short"));
        assert!(!valid_auth_code("has space inside code"));
        assert!(!valid_auth_code("rm -rf /; echo"));
    }

    #[tokio::test]
    async fn fake_tui_relay_end_to_end() {
        let dir = tempfile::TempDir::new().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
        let fake = dir.path().join("fake-agy.sh");
        std::fs::write(
            &fake,
            "#!/bin/bash\nprintf ' Select login method:\\n > 1. Google OAuth\\n'\nread -r _choice\nprintf 'Open the URL below:\\n\\033]8;id=a;https://accounts.google.com/o/oauth2/auth?client_id=c&state=S1\\033\\\\link\\033]8;;\\033\\\\\\n paste code:\\n'\nread -r code\nprintf '{\"token\":{\"refresh_token\":\"%s\"},\"id_token_email\":\"x@y.z\"}' \"$code\" > \"$HOME/.gemini/antigravity-cli/antigravity-oauth-token\"\necho signed-in\nsleep 30\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let s = LoginSession::spawn(fake.to_str().unwrap(), &home, "accT").unwrap();
        let url = s.wait_for_url(Duration::from_secs(15)).await.unwrap();
        assert!(url.ends_with("state=S1"), "{url}");
        s.submit_code("4/0ABCDEFGHIJ_test").await.unwrap();
        let tok = home.join(".gemini/antigravity-cli/antigravity-oauth-token");
        for _ in 0..50 {
            if tok.is_file() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let txt = std::fs::read_to_string(&tok).unwrap();
        assert!(txt.contains("4/0ABCDEFGHIJ_test"));
        assert!(!s.tail(500).contains("state=S1"));
        s.stop().await;
        // no process with this HOME survives
        tokio::time::sleep(Duration::from_millis(300)).await;
        let needle = format!("HOME={}", home.display());
        let alive = std::fs::read_dir("/proc").unwrap().flatten().any(|e| {
            std::fs::read(e.path().join("environ"))
                .map(|env| env.split(|b| *b == 0).any(|kv| kv == needle.as_bytes()))
                .unwrap_or(false)
        });
        assert!(!alive, "login processes leaked");
    }

    /// Manual check against a real captured agy login screen:
    /// `AGY_LOGIN_FIXTURE=/path/to/raw cargo test -p agy-ext real_capture -- --ignored`
    #[test]
    #[ignore]
    fn real_capture_url_extraction() {
        let p = std::env::var("AGY_LOGIN_FIXTURE").expect("AGY_LOGIN_FIXTURE");
        let raw = String::from_utf8_lossy(&std::fs::read(p).unwrap()).to_string();
        let osc = extract_oauth_url(&raw).expect("url");
        // simulate a terminal without OSC-8 hyperlinks: drop the whole link sequences
        let plain_only: String = Regex::new(r"\x1b\]8;[^\x07\x1b]*(\x07|\x1b\\)")
            .unwrap()
            .replace_all(&raw, "")
            .to_string();
        assert!(!plain_only.contains("\x1b]8;"));
        let wrapped = extract_oauth_url(&plain_only).expect("wrapped url");
        assert_eq!(osc, wrapped, "OSC8 and wrapped-text extraction must agree");
        assert!(osc.starts_with("https://accounts.google.com/") && osc.contains("state=") && osc.contains("redirect_uri="));
        assert!(!osc.chars().any(|c| c.is_whitespace() || !c.is_ascii()));
        println!("url_len={} host_ok=true", osc.len());
    }

}
