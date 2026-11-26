//! Hardened shell execution backend with:
//! - Zero-`SIGPIPE` full-pipe draining into a bounded [`HeadTailRingBuffer`] (preserves BOTH
//!   initial headers and trailing compiler/test errors!)
//! - Partial stdout/stderr preservation on timeout (never discards output before SIGKILL)
//! - Humanized UNIX signal diagnostics (`SIGKILL` -> likely OOM/timeout, `SIGSEGV`, etc.)
//! - Zero-daemon Linux OS isolation via `bubblewrap` (`bwrap`) with minimal safe `/etc` allowlist,
//!   dropped capabilities (`--cap-drop ALL`), PID/IPC/UTS/user namespaces, and RW write mount
//!   restricted strictly to the canonical workspace root (falling back to `unshare` or fail-closed).

use std::collections::VecDeque;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::mcp_client::{
    configure_new_session, redact_secrets_in_text, signal_process_group, ProcessGroupGuard,
};

/// Canonical secret, systemd, and dynamic-linker variables stripped from ALL child subprocesses
/// (`agy`, `bash`, `bwrap`, `tmux`, `python3`, stdio MCPs).
pub const STRIPPED_ENV_KEYS: &[&str] = &[
    "BOT_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "VENICE_API_KEY",
    "WEBHOOK_SECRET",
    "WEBAPP_SECRET",
    "PROXY_URLS",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "XAI_API_KEY",
    "GROK_API_KEY",
    "DATABASE_URL",
    "MEMORY_DB_URL",
    "NOTIFY_SOCKET",
    "WATCHDOG_PID",
    "WATCHDOG_USEC",
    "WATCHDOG_FD",
    "LISTEN_PID",
    "LISTEN_FDS",
    "LISTEN_FDNAMES",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
];

/// Default head bytes retained per stream (16 KiB).
pub const DEFAULT_HEAD_BYTES: usize = 16 * 1024;
/// Default tail bytes retained per stream (48 KiB).
pub const DEFAULT_TAIL_BYTES: usize = 48 * 1024;
/// Maximum command timeout permitted for `run_command` (10 minutes).
pub const MAX_COMMAND_TIMEOUT_SECS: u64 = 600;
/// Default timeout for `run_command` (60s).
pub const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 60;

/// Bounded head + tail byte accumulator that NEVER stops reading its pipe (preventing `SIGPIPE`)
/// and retains both leading context and trailing compiler/test errors.
#[derive(Debug, Clone)]
pub struct HeadTailRingBuffer {
    head: Vec<u8>,
    tail: VecDeque<u8>,
    head_cap: usize,
    tail_cap: usize,
    omitted_bytes: usize,
    total_bytes: usize,
}

impl HeadTailRingBuffer {
    pub fn new(head_cap: usize, tail_cap: usize) -> Self {
        Self {
            head: Vec::with_capacity(head_cap.min(16 * 1024)),
            tail: VecDeque::with_capacity(tail_cap.min(32 * 1024)),
            head_cap,
            tail_cap,
            omitted_bytes: 0,
            total_bytes: 0,
        }
    }

    pub fn push(&mut self, mut chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        self.total_bytes = self.total_bytes.saturating_add(chunk.len());

        // Fill head first
        if self.head.len() < self.head_cap {
            let take = (self.head_cap - self.head.len()).min(chunk.len());
            self.head.extend_from_slice(&chunk[..take]);
            chunk = &chunk[take..];
        }
        if chunk.is_empty() {
            return;
        }

        if self.tail_cap == 0 {
            self.omitted_bytes = self.omitted_bytes.saturating_add(chunk.len());
            return;
        }

        // If incoming chunk alone exceeds tail_cap, everything currently in tail plus the leading
        // part of chunk is omitted.
        if chunk.len() >= self.tail_cap {
            let drop_incoming = chunk.len() - self.tail_cap;
            self.omitted_bytes = self
                .omitted_bytes
                .saturating_add(self.tail.len())
                .saturating_add(drop_incoming);
            self.tail.clear();
            self.tail.extend(&chunk[drop_incoming..]);
            return;
        }

        let needed = self.tail.len() + chunk.len();
        if needed > self.tail_cap {
            let evict = needed - self.tail_cap;
            self.tail.drain(..evict);
            self.omitted_bytes = self.omitted_bytes.saturating_add(evict);
        }
        self.tail.extend(chunk);
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn omitted_bytes(&self) -> usize {
        self.omitted_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.total_bytes == 0
    }

    pub fn render_lossy(&self) -> String {
        if self.total_bytes == 0 {
            return String::new();
        }
        let tail_slice: Vec<u8> = self.tail.iter().copied().collect();
        if self.omitted_bytes == 0 {
            let mut combined = Vec::with_capacity(self.head.len() + tail_slice.len());
            combined.extend_from_slice(&self.head);
            combined.extend_from_slice(&tail_slice);
            return String::from_utf8_lossy(&combined).into_owned();
        }
        let head_s = String::from_utf8_lossy(&self.head);
        let tail_s = String::from_utf8_lossy(&tail_slice);
        format!(
            "{head_s}\n\n... [omitted {} bytes of middle output; {} bytes total] ...\n\n{tail_s}",
            self.omitted_bytes, self.total_bytes
        )
    }
}

/// True when an environment variable name matches a sensitive credential, linker, or systemd key.
pub fn is_sensitive_env_key(key: &str) -> bool {
    if STRIPPED_ENV_KEYS.contains(&key) {
        return true;
    }
    let up = key.to_ascii_uppercase();
    up.contains("TOKEN")
        || up.contains("SECRET")
        || up.contains("PASSWORD")
        || up.contains("PASSWD")
        || up.contains("API_KEY")
        || up.contains("PRIVATE_KEY")
        || up.contains("CREDENTIALS")
        || up.starts_with("WATCHDOG_")
        || up.starts_with("LD_")
}

/// Remove all sensitive bridge/systemd/linker keys (both exact list and heuristic patterns) from a [`Command`].
pub fn scrub_command_env(cmd: &mut Command) {
    for key in STRIPPED_ENV_KEYS {
        cmd.env_remove(key);
    }
    for (k, _) in std::env::vars() {
        if is_sensitive_env_key(&k) {
            cmd.env_remove(k);
        }
    }
}

/// Human-readable diagnosis for UNIX termination signals (inspired by Hermes `terminal`).
pub fn humanize_signal(sig: i32) -> &'static str {
    match sig {
        2 => "SIGINT (interrupted)",
        6 => "SIGABRT (aborted — assertion or panic)",
        9 => "SIGKILL (killed — likely OOM killer, cgroup limit, or timeout)",
        11 => "SIGSEGV (segmentation fault)",
        13 => "SIGPIPE (broken pipe)",
        15 => "SIGTERM (terminated)",
        24 => "SIGXCPU (CPU time limit exceeded)",
        25 => "SIGXFSZ (file size limit exceeded)",
        _ => "terminated by signal",
    }
}

/// Detect `/usr/bin/bwrap` (bubblewrap) once per process.
pub fn bwrap_binary_path() -> Option<&'static Path> {
    static BWRAP: OnceLock<Option<PathBuf>> = OnceLock::new();
    BWRAP
        .get_or_init(|| {
            for candidate in ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"] {
                let p = Path::new(candidate);
                if p.is_file() {
                    return Some(p.to_path_buf());
                }
            }
            None
        })
        .as_deref()
}

/// Detect `/usr/bin/unshare` once per process.
pub fn unshare_binary_path() -> Option<&'static Path> {
    static UNSHARE: OnceLock<Option<PathBuf>> = OnceLock::new();
    UNSHARE
        .get_or_init(|| {
            for candidate in ["/usr/bin/unshare", "/bin/unshare"] {
                let p = Path::new(candidate);
                if p.is_file() {
                    return Some(p.to_path_buf());
                }
            }
            None
        })
        .as_deref()
}

/// Safe read-only `/etc` entries mounted inside `bwrap` (deliberately excludes `/etc/agy-telegram`,
/// `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/ssh`, `/etc/systemd`).
const BWRAP_SAFE_ETC_ENTRIES: &[&str] = &[
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/passwd",
    "/etc/group",
    "/etc/localtime",
    "/etc/timezone",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/alternatives",
    "/etc/gitconfig",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/mime.types",
];

/// Read-only system and toolchain mounts exposed inside `bwrap` (no host secrets).
const BWRAP_SAFE_RO_DIRS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/root/.rustup",
    "/root/.cargo/bin",
];

/// Options controlling how a shell command is executed.
#[derive(Debug, Clone)]
pub struct ExecOptions {
    pub command: String,
    pub cwd: PathBuf,
    pub workspace_root: PathBuf,
    pub timeout_secs: u64,
    pub allow_root: bool,
    pub force_sandbox: bool,
    pub allow_network: bool,
    pub extra_ro_binds: Vec<(PathBuf, PathBuf)>,
    pub extra_rw_binds: Vec<(PathBuf, PathBuf)>,
    pub extra_env: Vec<(String, String)>,
    pub head_bytes: usize,
    pub tail_bytes: usize,
}

impl ExecOptions {
    pub fn for_shell(
        command: impl Into<String>,
        cwd: PathBuf,
        workspace_root: PathBuf,
        timeout_secs: u64,
        allow_root: bool,
    ) -> Self {
        Self {
            command: command.into(),
            cwd,
            workspace_root,
            timeout_secs: timeout_secs.clamp(5, MAX_COMMAND_TIMEOUT_SECS),
            allow_root,
            force_sandbox: !allow_root,
            allow_network: true,
            extra_ro_binds: Vec::new(),
            extra_rw_binds: Vec::new(),
            extra_env: Vec::new(),
            head_bytes: DEFAULT_HEAD_BYTES,
            tail_bytes: DEFAULT_TAIL_BYTES,
        }
    }
}

/// Structured outcome of a command run.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub sandboxed: bool,
    pub backend: &'static str,
    pub stdout: String,
    pub stderr: String,
    pub stdout_total_bytes: usize,
    pub stderr_total_bytes: usize,
    pub elapsed_ms: u128,
}

impl ExecOutcome {
    /// Format a redacted, high-signal summary for the LLM agent.
    pub fn format_for_agent(&self) -> String {
        let mut out = String::new();
        let mode_tag = if self.sandboxed {
            format!("[sandbox:{}] ", self.backend)
        } else {
            format!("[{}] ", self.backend)
        };

        if self.timed_out {
            out.push_str(&format!(
                "{mode_tag}TIMED OUT after {:.1}s (process group terminated; partial output preserved below)\n",
                self.elapsed_ms as f64 / 1000.0
            ));
        } else if let Some(sig) = self.signal {
            out.push_str(&format!(
                "{mode_tag}Terminated by signal {sig}: {} ({:.2}s)\n",
                humanize_signal(sig),
                self.elapsed_ms as f64 / 1000.0
            ));
        } else {
            let code = self.exit_code.unwrap_or(-1);
            let extra = if code == 137 {
                " (exit 137 = SIGKILL, likely OOM or killed)"
            } else if code == 139 {
                " (exit 139 = SIGSEGV)"
            } else if code == 143 {
                " (exit 143 = SIGTERM)"
            } else {
                ""
            };
            out.push_str(&format!(
                "{mode_tag}Exit code: {code}{extra} ({:.2}s)\n",
                self.elapsed_ms as f64 / 1000.0
            ));
        }

        let stdout_s = redact_secrets_in_text(&self.stdout);
        let stderr_s = redact_secrets_in_text(&self.stderr);
        if !stdout_s.is_empty() {
            out.push_str("STDOUT:\n");
            out.push_str(&stdout_s);
            if !stdout_s.ends_with('\n') {
                out.push('\n');
            }
        }
        if !stderr_s.is_empty() {
            out.push_str("STDERR:\n");
            out.push_str(&stderr_s);
            if !stderr_s.ends_with('\n') {
                out.push('\n');
            }
        }
        if stdout_s.is_empty() && stderr_s.is_empty() {
            out.push_str("(no output)\n");
        }
        out
    }
}

/// Build an argv vector (`[bwrap, ...args, --, bash, -c, wrapped_cmd]`) for bubblewrap execution.
///
/// Used both by [`run_exec_command`] and by [`crate::pty_manager`] so sandboxed PTY sessions get
/// identical Linux namespace isolation.
pub fn build_bwrap_argv(
    workspace_root: &Path,
    cwd: &Path,
    allow_network: bool,
    extra_ro_binds: &[(PathBuf, PathBuf)],
    extra_rw_binds: &[(PathBuf, PathBuf)],
    inner_argv: &[String],
) -> std::result::Result<Vec<String>, String> {
    let Some(bwrap) = bwrap_binary_path() else {
        return Err("bubblewrap (bwrap) binary not found".to_string());
    };
    let canon_ws = std::fs::canonicalize(workspace_root)
        .map_err(|e| format!("cannot canonicalize workspace {}: {e}", workspace_root.display()))?;
    let canon_cwd = std::fs::canonicalize(cwd).unwrap_or_else(|_| canon_ws.clone());
    let effective_cwd = if canon_cwd.starts_with(&canon_ws) {
        canon_cwd
    } else {
        canon_ws.clone()
    };

    let mut args: Vec<String> = Vec::with_capacity(96);
    args.push(bwrap.to_string_lossy().into_owned());

    // System & toolchain read-only mounts
    for dir in BWRAP_SAFE_RO_DIRS {
        if Path::new(dir).exists() {
            args.push("--ro-bind-try".into());
            args.push((*dir).into());
            args.push((*dir).into());
        }
    }

    // Minimal safe /etc allowlist (zero access to /etc/agy-telegram, /etc/shadow, /etc/ssh)
    for etc_item in BWRAP_SAFE_ETC_ENTRIES {
        if Path::new(etc_item).exists() {
            args.push("--ro-bind-try".into());
            args.push((*etc_item).into());
            args.push((*etc_item).into());
        }
    }

    // Isolated ephemeral /tmp, /proc, /dev, and fresh /var/tmp
    args.extend([
        "--tmpfs".into(),
        "/tmp".into(),
        "--dir".into(),
        "/var".into(),
        "--tmpfs".into(),
        "/var/tmp".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
    ]);

    // Read-write workspace mount ONLY at its canonical path
    let ws_str = canon_ws.to_string_lossy().into_owned();
    args.push("--bind".into());
    args.push(ws_str.clone());
    args.push(ws_str.clone());

    for (src, dst) in extra_ro_binds {
        if src.exists() {
            args.push("--ro-bind".into());
            args.push(src.to_string_lossy().into_owned());
            args.push(dst.to_string_lossy().into_owned());
        }
    }
    for (src, dst) in extra_rw_binds {
        if src.exists() {
            args.push("--bind".into());
            args.push(src.to_string_lossy().into_owned());
            args.push(dst.to_string_lossy().into_owned());
        }
    }

    args.push("--chdir".into());
    args.push(effective_cwd.to_string_lossy().into_owned());

    // Namespaces + non-root uid/gid + capability drop + TIOCSTI guard + orphan cleanup
    args.push("--unshare-all".into());
    if allow_network {
        args.push("--share-net".into());
    }
    args.extend([
        "--uid".into(),
        "65534".into(),
        "--gid".into(),
        "65534".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--new-session".into(),
        "--die-with-parent".into(),
        "--clearenv".into(),
        "--setenv".into(),
        "HOME".into(),
        "/tmp".into(),
        "--setenv".into(),
        "TMPDIR".into(),
        "/tmp".into(),
        "--setenv".into(),
        "TERM".into(),
        "xterm-256color".into(),
        "--setenv".into(),
        "LANG".into(),
        "C.UTF-8".into(),
        "--setenv".into(),
        "NO_COLOR".into(),
        "1".into(),
        "--setenv".into(),
        "PATH".into(),
        "/root/.cargo/bin:/usr/local/bin:/usr/bin:/bin".into(),
        "--setenv".into(),
        "RUSTUP_HOME".into(),
        "/root/.rustup".into(),
        "--setenv".into(),
        "CARGO_HOME".into(),
        "/tmp/.cargo".into(),
        "--".into(),
    ]);
    args.extend(inner_argv.iter().cloned());
    Ok(args)
}

async fn drain_stream_into_ring<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    buf: Arc<Mutex<HeadTailRingBuffer>>,
) {
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                let mut g = buf.lock().unwrap_or_else(|e| e.into_inner());
                g.push(&chunk[..n]);
            }
            Err(_) => break,
        }
    }
}

/// Execute a command with full-pipe draining (`HeadTailRingBuffer`), timeout partial output
/// preservation, secret env scrubbing, and `bubblewrap` OS isolation when sandboxed.
pub async fn run_exec_command(opts: &ExecOptions) -> ExecOutcome {
    let started = Instant::now();
    let timeout_secs = opts.timeout_secs.clamp(5, MAX_COMMAND_TIMEOUT_SECS);
    let use_sandbox = opts.force_sandbox || !opts.allow_root;

    let (mut cmd, backend_label): (Command, &'static str) = if use_sandbox {
        // Wrap shell payload with ulimit guard (max 128 procs, 256 MiB file write) inside bwrap
        let inner = vec![
            "/bin/bash".to_string(),
            "-c".to_string(),
            "ulimit -u 128 -f 262144 2>/dev/null; exec /bin/bash -c \"$1\"".to_string(),
            "--".to_string(),
            opts.command.clone(),
        ];
        match build_bwrap_argv(
            &opts.workspace_root,
            &opts.cwd,
            opts.allow_network,
            &opts.extra_ro_binds,
            &opts.extra_rw_binds,
            &inner,
        ) {
            Ok(argv) => {
                let mut c = Command::new(&argv[0]);
                c.args(&argv[1..]);
                (c, "bwrap")
            }
            Err(bwrap_err) => {
                // Non-root callers MUST fail closed if no OS isolation backend exists!
                if !opts.allow_root {
                    if let Some(unshare) = unshare_binary_path() {
                        let mut c = Command::new(unshare);
                        c.args(["--pid", "--fork", "--uts", "--ipc"]);
                        if !opts.allow_network {
                            c.arg("--net");
                        }
                        c.args([
                            "--",
                            "/bin/bash",
                            "-c",
                            "ulimit -u 128 -f 262144 2>/dev/null; exec /bin/bash -c \"$1\"",
                            "--",
                            &opts.command,
                        ]);
                        c.current_dir(&opts.cwd);
                        (c, "unshare")
                    } else {
                        return ExecOutcome {
                            exit_code: Some(126),
                            signal: None,
                            timed_out: false,
                            sandboxed: true,
                            backend: "none",
                            stdout: String::new(),
                            stderr: format!(
                                "Sandbox unavailable (fail-closed): {bwrap_err}; install bubblewrap."
                            ),
                            stdout_total_bytes: 0,
                            stderr_total_bytes: 0,
                            elapsed_ms: started.elapsed().as_millis(),
                        };
                    }
                } else {
                    let mut c = Command::new("/bin/bash");
                    c.arg("-c").arg(&opts.command).current_dir(&opts.cwd);
                    (c, "host-fallback")
                }
            }
        }
    } else {
        let mut c = Command::new("/bin/bash");
        c.arg("-c").arg(&opts.command).current_dir(&opts.cwd);
        (c, "host")
    };

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    scrub_command_env(&mut cmd);
    if !use_sandbox {
        // Ensure /root/.cargo/bin & /root/.local/bin are reachable for host coding builds
        let existing_path = std::env::var("PATH").unwrap_or_default();
        let prefix = "/root/.cargo/bin:/root/.local/bin:/usr/local/bin:/usr/bin:/bin";
        let full_path = if existing_path.is_empty() {
            prefix.to_string()
        } else {
            format!("{prefix}:{existing_path}")
        };
        cmd.env("PATH", full_path);
    }
    for (k, v) in &opts.extra_env {
        if !STRIPPED_ENV_KEYS.contains(&k.as_str()) {
            cmd.env(k, v);
        }
    }
    configure_new_session(&mut cmd);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ExecOutcome {
                exit_code: Some(127),
                signal: None,
                timed_out: false,
                sandboxed: use_sandbox,
                backend: backend_label,
                stdout: String::new(),
                stderr: format!("Error spawning command ({backend_label}): {e}"),
                stdout_total_bytes: 0,
                stderr_total_bytes: 0,
                elapsed_ms: started.elapsed().as_millis(),
            };
        }
    };

    let mut pg_guard = ProcessGroupGuard::new(child.id());

    let out_buf = Arc::new(Mutex::new(HeadTailRingBuffer::new(
        opts.head_bytes,
        opts.tail_bytes,
    )));
    let err_buf = Arc::new(Mutex::new(HeadTailRingBuffer::new(
        opts.head_bytes / 2,
        opts.tail_bytes / 2,
    )));

    let out_task = child
        .stdout
        .take()
        .map(|r| tokio::spawn(drain_stream_into_ring(r, Arc::clone(&out_buf))));
    let err_task = child
        .stderr
        .take()
        .map(|r| tokio::spawn(drain_stream_into_ring(r, Arc::clone(&err_buf))));

    let (exit_code, signal, timed_out) =
        match tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait()).await {
            Ok(Ok(status)) => {
                pg_guard.disarm();
                if let Some(t) = out_task {
                    let _ = tokio::time::timeout(Duration::from_secs(2), t).await;
                }
                if let Some(t) = err_task {
                    let _ = tokio::time::timeout(Duration::from_secs(2), t).await;
                }
                (status.code(), status.signal(), false)
            }
            Ok(Err(e)) => {
                if let Some(pg) = pg_guard.pgid() {
                    signal_process_group(pg, libc::SIGKILL);
                }
                let _ = child.wait().await;
                pg_guard.disarm();
                if let Some(t) = out_task {
                    t.abort();
                }
                if let Some(t) = err_task {
                    t.abort();
                }
                let mut g = err_buf.lock().unwrap_or_else(|e| e.into_inner());
                g.push(format!("\nError waiting for child: {e}").as_bytes());
                (Some(-1), None, false)
            }
            Err(_) => {
                // Timeout: gracefully SIGTERM then SIGKILL process group, and WAIT briefly
                // for pipe tasks to flush buffered partial output rather than discarding it!
                if let Some(pg) = pg_guard.pgid() {
                    signal_process_group(pg, libc::SIGTERM);
                    if tokio::time::timeout(Duration::from_millis(400), child.wait())
                        .await
                        .is_err()
                    {
                        signal_process_group(pg, libc::SIGKILL);
                        let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
                    }
                }
                if matches!(child.try_wait(), Ok(Some(_))) {
                    pg_guard.disarm();
                }
                if let Some(mut t) = out_task {
                    if tokio::time::timeout(Duration::from_millis(250), &mut t)
                        .await
                        .is_err()
                    {
                        t.abort();
                    }
                }
                if let Some(mut t) = err_task {
                    if tokio::time::timeout(Duration::from_millis(250), &mut t)
                        .await
                        .is_err()
                    {
                        t.abort();
                    }
                }
                (None, Some(libc::SIGKILL), true)
            }
        };

    let (stdout, stdout_total_bytes) = {
        let g = out_buf.lock().unwrap_or_else(|e| e.into_inner());
        (g.render_lossy(), g.total_bytes())
    };
    let (stderr, stderr_total_bytes) = {
        let g = err_buf.lock().unwrap_or_else(|e| e.into_inner());
        (g.render_lossy(), g.total_bytes())
    };

    ExecOutcome {
        exit_code,
        signal,
        timed_out,
        sandboxed: use_sandbox,
        backend: backend_label,
        stdout,
        stderr,
        stdout_total_bytes,
        stderr_total_bytes,
        elapsed_ms: started.elapsed().as_millis(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn head_tail_ring_preserves_head_and_tail_on_large_stream() {
        let mut ring = HeadTailRingBuffer::new(32, 32);
        ring.push(b"HEAD_MARKER_1234567890_ABCDEFGHI");
        for _ in 0..1000 {
            ring.push(b"middle_noise_line_0123456789\n");
        }
        ring.push(b"FINAL_COMPILER_ERROR_AT_TAIL!!!!");

        let rendered = ring.render_lossy();
        assert!(rendered.contains("HEAD_MARKER_1234567890"));
        assert!(rendered.contains("FINAL_COMPILER_ERROR_AT_TAIL!!!!"));
        assert!(rendered.contains("omitted"));
        assert!(ring.omitted_bytes() > 20_000);
    }

    #[tokio::test]
    async fn noisy_stdout_does_not_sigpipe_and_retains_tail_errors() {
        let dir = TempDir::new().unwrap();
        // Emit >500 KB of stdout then print a final tail marker and exit 0 (old code broke pipe -> SIGPIPE 141!)
        let cmd = "python3 -c \"print('FIRST_LINE'); [print('X'*200) for _ in range(3000)]; print('TAIL_ERROR_MARKER')\"";
        let opts = ExecOptions::for_shell(cmd, dir.path().to_path_buf(), dir.path().to_path_buf(), 20, true);
        let res = run_exec_command(&opts).await;
        assert_eq!(res.exit_code, Some(0), "command must not die from SIGPIPE: {:?}", res.stderr);
        assert!(res.stdout.contains("FIRST_LINE"));
        assert!(res.stdout.contains("TAIL_ERROR_MARKER"));
        assert!(res.stdout.contains("omitted"));
        assert!(res.stdout_total_bytes > 500_000);
    }

    #[tokio::test]
    async fn timeout_preserves_partial_stdout_output() {
        let dir = TempDir::new().unwrap();
        let cmd = "echo 'PARTIAL_BEFORE_TIMEOUT'; sleep 20";
        let mut opts = ExecOptions::for_shell(cmd, dir.path().to_path_buf(), dir.path().to_path_buf(), 5, true);
        opts.timeout_secs = 5;
        // Override directly for quick 1s timeout in test by calling with short command? Wait: clamp is 5s.
        // 5s is fine for one integration test; verify partial stdout survived!
        let res = run_exec_command(&opts).await;
        assert!(res.timed_out);
        assert!(
            res.stdout.contains("PARTIAL_BEFORE_TIMEOUT"),
            "partial stdout must be preserved on timeout, got: {:?}",
            res.stdout
        );
    }

    #[tokio::test]
    async fn bwrap_sandbox_isolates_host_secrets_and_allows_workspace_writes() {
        if bwrap_binary_path().is_none() {
            return;
        }
        let dir = TempDir::new().unwrap();
        let cmd = "id; grep CapEff /proc/self/status; ls /etc/agy-telegram 2>&1 || true; cat /etc/shadow 2>&1 || true; touch ws_ok.txt && echo WS_WRITE_OK";
        let mut opts = ExecOptions::for_shell(cmd, dir.path().to_path_buf(), dir.path().to_path_buf(), 15, false);
        opts.allow_network = false;
        let res = run_exec_command(&opts).await;
        assert_eq!(res.backend, "bwrap");
        assert!(res.sandboxed);
        assert_eq!(res.exit_code, Some(0), "stderr: {}", res.stderr);
        assert!(res.stdout.contains("uid=65534"));
        assert!(res.stdout.contains("CapEff:\t0000000000000000"));
        assert!(res.stdout.contains("WS_WRITE_OK"));
        assert!(!res.stdout.contains("BOT_TOKEN"));
        assert!(!res.stdout.contains("root:$"));
        assert!(dir.path().join("ws_ok.txt").exists());
    }
}
