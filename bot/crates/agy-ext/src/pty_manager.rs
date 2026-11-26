//! Persistent `tmux` PTY & background process session manager inspired by Hermes
//! `terminal(background=true, pty=true)` + `process_manage`.
//!
//! Uses a dedicated isolated tmux socket (`$STATE_DIR/tmux/agy-pty.sock`, `0700`), supports
//! `bubblewrap` sandboxing for non-root (`sandbox_exec`) sessions, tracks exact exit status via
//! per-session sentinel files, and auto-prunes stale completed sessions.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::exec_backend::{
    build_bwrap_argv, bwrap_binary_path, humanize_signal, scrub_command_env,
};
use crate::mcp_client::redact_secrets_in_text;

/// Maximum concurrent active tmux sessions per state dir.
const MAX_ACTIVE_SESSIONS: usize = 16;
/// Auto-prune completed session metadata older than 1 hour.
const STALE_SESSION_SECS: u64 = 3600;
/// Maximum lines returned by `capture-pane`.
const MAX_CAPTURE_LINES: usize = 400;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtySessionMeta {
    pub id: String,
    pub command_preview: String,
    pub cwd: String,
    pub sandboxed: bool,
    pub started_at: u64,
    pub exit_file: PathBuf,
    pub owner_tag: String,
}

#[derive(Debug, Clone)]
pub struct StartPtyRequest {
    pub command: String,
    pub cwd: PathBuf,
    pub workspace_root: PathBuf,
    pub allow_root: bool,
    pub force_sandbox: bool,
    pub owner_tag: String,
    pub session_name: Option<String>,
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn tmux_binary_path() -> Option<&'static Path> {
    static TMUX: OnceLock<Option<PathBuf>> = OnceLock::new();
    TMUX.get_or_init(|| {
        for p in ["/usr/bin/tmux", "/bin/tmux", "/usr/local/bin/tmux"] {
            let path = Path::new(p);
            if path.is_file() {
                return Some(path.to_path_buf());
            }
        }
        None
    })
    .as_deref()
}

fn tmux_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("tmux")
}

fn tmux_socket_path(state_dir: &Path) -> PathBuf {
    tmux_dir(state_dir).join("agy-pty.sock")
}

fn sessions_dir(state_dir: &Path) -> PathBuf {
    tmux_dir(state_dir).join("sessions")
}

fn ensure_tmux_dirs(state_dir: &Path) -> std::result::Result<(), String> {
    let dir = tmux_dir(state_dir);
    let sdir = sessions_dir(state_dir);
    std::fs::create_dir_all(&sdir).map_err(|e| format!("failed creating tmux state dir: {e}"))?;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::set_permissions(&sdir, std::fs::Permissions::from_mode(0o700));
    Ok(())
}

fn sanitize_session_id(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect();
    if cleaned.is_empty() {
        format!("pty_{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    } else {
        cleaned
    }
}

fn tmux_name(id: &str) -> String {
    format!("agy_{}", sanitize_session_id(id))
}

async fn run_tmux(state_dir: &Path, args: &[&str]) -> std::result::Result<(i32, String, String), String> {
    let Some(bin) = tmux_binary_path() else {
        return Err("tmux binary not installed on host".to_string());
    };
    let sock = tmux_socket_path(state_dir);
    let mut cmd = Command::new(bin);
    cmd.arg("-S")
        .arg(&sock)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    scrub_command_env(&mut cmd);

    let output = tokio::time::timeout(Duration::from_secs(10), cmd.output())
        .await
        .map_err(|_| "tmux command timed out".to_string())?
        .map_err(|e| format!("failed executing tmux: {e}"))?;
    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

fn meta_path(state_dir: &Path, id: &str) -> PathBuf {
    sessions_dir(state_dir).join(format!("{}.json", sanitize_session_id(id)))
}

fn load_meta(state_dir: &Path, id: &str) -> Option<PtySessionMeta> {
    let raw = std::fs::read_to_string(meta_path(state_dir, id)).ok()?;
    serde_json::from_str(&raw).ok()
}

fn save_meta(state_dir: &Path, meta: &PtySessionMeta) -> std::result::Result<(), String> {
    let path = meta_path(state_dir, &meta.id);
    let data = serde_json::to_vec_pretty(meta).map_err(|e| e.to_string())?;
    std::fs::write(&path, data).map_err(|e| format!("failed writing session meta: {e}"))?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

fn read_exit_code(exit_file: &Path) -> Option<i32> {
    std::fs::read_to_string(exit_file)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
}

fn format_exit_status(code: i32) -> String {
    if code > 128 && code <= 192 {
        let sig = code - 128;
        format!("exited({code}: signal {sig} - {})", humanize_signal(sig))
    } else {
        format!("exited({code})")
    }
}

async fn session_pane_alive(state_dir: &Path, id: &str) -> bool {
    let tname = tmux_name(id);
    matches!(
        run_tmux(state_dir, &["has-session", "-t", &tname]).await,
        Ok((0, _, _))
    )
}

async fn prune_stale_sessions(state_dir: &Path) {
    let sdir = sessions_dir(state_dir);
    let Ok(rd) = std::fs::read_dir(&sdir) else {
        return;
    };
    let now = now_unix_secs();
    for ent in rd.flatten() {
        let p = ent.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Ok(meta) = serde_json::from_str::<PtySessionMeta>(&raw) else {
            continue;
        };
        let done = read_exit_code(&meta.exit_file).is_some();
        if done && now.saturating_sub(meta.started_at) > STALE_SESSION_SECS {
            let _ = kill_session(state_dir, &meta.id).await;
        }
    }
}

fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Start a persistent PTY / background process inside an isolated `tmux` session.
pub async fn start_session(state_dir: &Path, req: &StartPtyRequest) -> std::result::Result<String, String> {
    if tmux_binary_path().is_none() {
        return Err("Error: tmux is not installed on this server.".to_string());
    }
    ensure_tmux_dirs(state_dir)?;
    prune_stale_sessions(state_dir).await;

    // Count active running sessions
    let mut active_count = 0usize;
    if let Ok(rd) = std::fs::read_dir(sessions_dir(state_dir)) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(raw) = std::fs::read_to_string(&p) {
                    if let Ok(m) = serde_json::from_str::<PtySessionMeta>(&raw) {
                        if read_exit_code(&m.exit_file).is_none() && session_pane_alive(state_dir, &m.id).await {
                            active_count += 1;
                        }
                    }
                }
            }
        }
    }
    if active_count >= MAX_ACTIVE_SESSIONS {
        return Err(format!(
            "Error: max active background/PTY sessions ({MAX_ACTIVE_SESSIONS}) reached. Kill finished or unused sessions with process_manage(action='kill')."
        ));
    }

    let id = req
        .session_name
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(sanitize_session_id)
        .unwrap_or_else(|| format!("pty_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
    let tname = tmux_name(&id);
    if session_pane_alive(state_dir, &id).await {
        return Err(format!(
            "Error: session '{id}' already exists. Pick another name or kill it first."
        ));
    }

    let exit_file = sessions_dir(state_dir).join(format!("{id}.rc"));
    let _ = std::fs::remove_file(&exit_file);
    let use_sandbox = req.force_sandbox || !req.allow_root;

    // Build wrapper script that runs the command (inside bwrap if sandboxed), writes exit code
    // to sentinel file, and leaves the pane alive (`remain-on-exit`) so output can always be polled!
    let exec_snippet = if use_sandbox {
        if bwrap_binary_path().is_none() {
            return Err("Error: bubblewrap (bwrap) unavailable for sandboxed PTY session.".to_string());
        }
        let inner = vec![
            "/bin/bash".to_string(),
            "-c".to_string(),
            "ulimit -u 128 -f 262144 2>/dev/null; exec /bin/bash -c \"$1\"".to_string(),
            "--".to_string(),
            req.command.clone(),
        ];
        let bwrap_argv = build_bwrap_argv(&req.workspace_root, &req.cwd, true, &[], &[], &inner)?;
        let quoted: Vec<String> = bwrap_argv.iter().map(|a| shell_single_quote(a)).collect();
        quoted.join(" ")
    } else {
        format!(
            "export PATH=\"/root/.cargo/bin:/root/.local/bin:/usr/local/bin:/usr/bin:/bin:$PATH\"; cd {} && /bin/bash -c {}",
            shell_single_quote(&req.cwd.to_string_lossy()),
            shell_single_quote(&req.command)
        )
    };

    let wrapper = format!(
        "{exec_snippet}; __rc=$?; printf '%d\\n' \"$__rc\" > {}; exit $__rc",
        shell_single_quote(&exit_file.to_string_lossy())
    );

    let cwd_str = req.cwd.to_string_lossy().into_owned();
    // Chain `set-option -p remain-on-exit on` atomically inside `new-session` so fast-exiting
    // commands never close the pane before output can be captured!
    let (code, _out, err) = run_tmux(
        state_dir,
        &[
            "new-session",
            "-d",
            "-s",
            &tname,
            "-x",
            "160",
            "-y",
            "48",
            "-c",
            &cwd_str,
            "/bin/bash",
            "-c",
            &wrapper,
            ";",
            "set-option",
            "-p",
            "-t",
            &tname,
            "remain-on-exit",
            "on",
            ";",
            "set-option",
            "-t",
            &tname,
            "history-limit",
            "4000",
        ],
    )
    .await?;
    if code != 0 {
        return Err(format!("Error starting tmux PTY session: {}", err.trim()));
    }

    let preview: String = req.command.chars().take(100).collect();
    let meta = PtySessionMeta {
        id: id.clone(),
        command_preview: preview,
        cwd: cwd_str,
        sandboxed: use_sandbox,
        started_at: now_unix_secs(),
        exit_file: exit_file.clone(),
        owner_tag: req.owner_tag.clone(),
    };
    save_meta(state_dir, &meta)?;

    // Give quick commands 350ms to emit initial output or finish immediately
    tokio::time::sleep(Duration::from_millis(350)).await;
    let initial = poll_session(state_dir, &id, 60).await.unwrap_or_default();

    Ok(format!(
        "Started background PTY session '{id}' (sandboxed={use_sandbox}).\n\
         Use process_manage(action='poll'|'wait'|'write'|'kill', session_id='{id}') to interact.\n\n{initial}"
    ))
}

/// List all known background/PTY sessions for `owner_tag` (or all if empty).
pub async fn list_sessions(state_dir: &Path, owner_tag: &str) -> String {
    let _ = ensure_tmux_dirs(state_dir);
    prune_stale_sessions(state_dir).await;
    let sdir = sessions_dir(state_dir);
    let Ok(rd) = std::fs::read_dir(&sdir) else {
        return "No background/PTY sessions.".to_string();
    };
    let now = now_unix_secs();
    let mut rows = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Ok(meta) = serde_json::from_str::<PtySessionMeta>(&raw) else {
            continue;
        };
        if !owner_tag.is_empty() && meta.owner_tag != owner_tag {
            continue;
        }
        let status = match read_exit_code(&meta.exit_file) {
            Some(rc) => format_exit_status(rc),
            None => {
                if session_pane_alive(state_dir, &meta.id).await {
                    "running".to_string()
                } else {
                    "stopped".to_string()
                }
            }
        };
        let age = now.saturating_sub(meta.started_at);
        let sb = if meta.sandboxed { "sandbox" } else { "host" };
        rows.push(format!(
            "- {} [{} | {} | {}s]: {}",
            meta.id, status, sb, age, meta.command_preview
        ));
    }
    rows.sort();
    if rows.is_empty() {
        "No background/PTY sessions.".to_string()
    } else {
        format!("Background/PTY sessions ({}):\n{}", rows.len(), rows.join("\n"))
    }
}

/// Capture recent terminal output and status for a session.
pub async fn poll_session(state_dir: &Path, id: &str, lines: usize) -> std::result::Result<String, String> {
    let clean_id = sanitize_session_id(id);
    let meta = load_meta(state_dir, &clean_id)
        .ok_or_else(|| format!("Error: session '{clean_id}' not found."))?;
    let tname = tmux_name(&clean_id);
    let cap_lines = lines.clamp(10, MAX_CAPTURE_LINES);
    let start_arg = format!("-{cap_lines}");

    let status = match read_exit_code(&meta.exit_file) {
        Some(rc) => format_exit_status(rc),
        None => {
            if session_pane_alive(state_dir, &clean_id).await {
                "running".to_string()
            } else {
                "stopped".to_string()
            }
        }
    };

    let (code, stdout, stderr) = run_tmux(
        state_dir,
        &["capture-pane", "-t", &tname, "-p", "-J", "-S", &start_arg],
    )
    .await?;

    let captured = if code == 0 {
        redact_secrets_in_text(stdout.trim_end())
    } else {
        format!("(pane unavailable: {})", stderr.trim())
    };
    let age = now_unix_secs().saturating_sub(meta.started_at);
    Ok(format!(
        "Session: {clean_id} | Status: {status} | Elapsed: {age}s\nOUTPUT (last {cap_lines} lines):\n{}",
        if captured.is_empty() { "(empty)" } else { &captured }
    ))
}

/// Wait up to `timeout_secs` (1..=180) for a session to exit, then return captured output.
pub async fn wait_session(
    state_dir: &Path,
    id: &str,
    timeout_secs: u64,
    lines: usize,
) -> std::result::Result<String, String> {
    let clean_id = sanitize_session_id(id);
    let meta = load_meta(state_dir, &clean_id)
        .ok_or_else(|| format!("Error: session '{clean_id}' not found."))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs.clamp(1, 180));
    loop {
        if read_exit_code(&meta.exit_file).is_some() {
            break;
        }
        if !session_pane_alive(state_dir, &clean_id).await {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    poll_session(state_dir, &clean_id, lines).await
}

/// Send input text (and optional Enter or Ctrl-C) to a running PTY session.
pub async fn write_session(
    state_dir: &Path,
    id: &str,
    input: &str,
    send_enter: bool,
    ctrl_c: bool,
) -> std::result::Result<String, String> {
    let clean_id = sanitize_session_id(id);
    let _meta = load_meta(state_dir, &clean_id)
        .ok_or_else(|| format!("Error: session '{clean_id}' not found."))?;
    let tname = tmux_name(&clean_id);

    if ctrl_c {
        let (code, _, err) = run_tmux(state_dir, &["send-keys", "-t", &tname, "C-c"]).await?;
        if code != 0 {
            return Err(format!("Error sending Ctrl-C to '{clean_id}': {}", err.trim()));
        }
    }
    if !input.is_empty() {
        let (code, _, err) = run_tmux(state_dir, &["send-keys", "-t", &tname, "-l", input]).await?;
        if code != 0 {
            return Err(format!("Error writing to '{clean_id}': {}", err.trim()));
        }
    }
    if send_enter {
        let _ = run_tmux(state_dir, &["send-keys", "-t", &tname, "Enter"]).await;
    }

    tokio::time::sleep(Duration::from_millis(250)).await;
    poll_session(state_dir, &clean_id, 60).await
}

/// Kill a tmux session and remove its metadata & exit sentinel.
pub async fn kill_session(state_dir: &Path, id: &str) -> std::result::Result<String, String> {
    let clean_id = sanitize_session_id(id);
    let tname = tmux_name(&clean_id);
    let _ = run_tmux(state_dir, &["kill-session", "-t", &tname]).await;
    if let Some(meta) = load_meta(state_dir, &clean_id) {
        let _ = std::fs::remove_file(&meta.exit_file);
    }
    let _ = std::fs::remove_file(meta_path(state_dir, &clean_id));
    Ok(format!("Killed and cleaned up session '{clean_id}'."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn tmux_background_session_wait_poll_write_and_kill() {
        if tmux_binary_path().is_none() {
            return;
        }
        let dir = TempDir::new().unwrap();
        let state = dir.path().join("state");
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();

        // 1. Background job that completes and writes exit code
        let start_out = start_session(
            &state,
            &StartPtyRequest {
                command: "echo 'HELLO_BG_PTY'; sleep 0.2; exit 0".into(),
                cwd: ws.clone(),
                workspace_root: ws.clone(),
                allow_root: true,
                force_sandbox: false,
                owner_tag: "test".into(),
                session_name: Some("build1".into()),
            },
        )
        .await
        .unwrap();
        assert!(start_out.contains("build1"));

        let waited = wait_session(&state, "build1", 10, 50).await.unwrap();
        assert!(waited.contains("exited(0)"), "got: {waited}");
        assert!(waited.contains("HELLO_BG_PTY"), "got: {waited}");

        let listed = list_sessions(&state, "test").await;
        assert!(listed.contains("build1"));

        // 2. Interactive PTY session receiving input + Ctrl-C + kill
        let _ = start_session(
            &state,
            &StartPtyRequest {
                command: "cat".into(),
                cwd: ws.clone(),
                workspace_root: ws.clone(),
                allow_root: true,
                force_sandbox: false,
                owner_tag: "test".into(),
                session_name: Some("repl1".into()),
            },
        )
        .await
        .unwrap();

        let wrote = write_session(&state, "repl1", "PING_PTY_42", true, false)
            .await
            .unwrap();
        assert!(wrote.contains("PING_PTY_42"), "got: {wrote}");

        let killed = kill_session(&state, "repl1").await.unwrap();
        assert!(killed.contains("repl1"));
        let _ = kill_session(&state, "build1").await;
    }
}
