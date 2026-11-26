//! CLI mode dispatcher, `--check` pre-flight diagnostics, `--health` probe,
//! and atomic self-update / rollback with ELF & pre-flight verification.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agy_core::atomic::atomic_write_bytes;
use agy_core::config::Config;
use agy_core::health::HealthSnapshot;
use agy_core::{BridgeError, ProxyMode as CoreProxyMode, Result};
use agy_ext::mcp_client::redact_secrets_in_text;
use agy_net::{NetConfig, ProxyMode as NetProxyMode, ProxyPool, ProxyRouteConfig};
use serde_json::{json, Value};
use tempfile::NamedTempFile;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const MAX_HEALTH_AGE_SECS: f64 = 120.0;
const SELF_UPDATE_CHECK_TIMEOUT: Duration = Duration::from_secs(30);

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// CLI operational mode parsed from process arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliMode {
    Run,
    Check,
    Health,
    BenchAb,
    SelfUpdate(PathBuf),
    Rollback,
    Version,
    McpUncensored,
    McpSkillhub,
    McpOpenhands,
    UpdatesCheck,
    UpdatesApply(String),
}

/// Parse CLI arguments (excluding `argv[0]`) into a typed [`CliMode`].
pub fn parse_cli_args(args: &[String]) -> Result<CliMode> {
    if args.is_empty() {
        return Ok(CliMode::Run);
    }

    let first = args[0].as_str();
    match first {
        "--check" if args.len() == 1 => Ok(CliMode::Check),
        "--health" if args.len() == 1 => Ok(CliMode::Health),
        "--bench-ab" if args.len() == 1 => Ok(CliMode::BenchAb),
        "--rollback" if args.len() == 1 => Ok(CliMode::Rollback),
        "--version" | "-V" if args.len() == 1 => Ok(CliMode::Version),
        "--mcp-uncensored" | "mcp-uncensored" if args.len() == 1 => Ok(CliMode::McpUncensored),
        "--mcp-skillhub" | "mcp-skillhub" if args.len() == 1 => Ok(CliMode::McpSkillhub),
        "--mcp-openhands" | "mcp-openhands" if args.len() == 1 => Ok(CliMode::McpOpenhands),
        "--updates-check" if args.len() == 1 => Ok(CliMode::UpdatesCheck),
        "--updates-apply" => {
            let scope = args.get(1).map(|s| s.trim().to_string()).unwrap_or_else(|| "all".into());
            if args.len() > 2 || scope.is_empty() {
                return Err(BridgeError::Validation(
                    "--updates-apply takes at most one scope (hub|skills|mcps|all)".into(),
                ));
            }
            Ok(CliMode::UpdatesApply(scope))
        }
        "--self-update" => {
            if args.len() != 2 || args[1].trim().is_empty() {
                return Err(BridgeError::Validation(
                    "--self-update requires a non-empty binary path".into(),
                ));
            }
            Ok(CliMode::SelfUpdate(PathBuf::from(args[1].trim())))
        }
        other if other.starts_with("--self-update=") => {
            if args.len() != 1 {
                return Err(BridgeError::Validation(
                    "unexpected extra arguments after --self-update".into(),
                ));
            }
            let path = other.trim_start_matches("--self-update=").trim();
            if path.is_empty() {
                return Err(BridgeError::Validation(
                    "--self-update= requires a non-empty binary path".into(),
                ));
            }
            Ok(CliMode::SelfUpdate(PathBuf::from(path)))
        }
        other => Err(BridgeError::Validation(format!(
            "unsupported CLI arguments starting with '{other}'"
        ))),
    }
}

/// Parse CLI mode from `std::env::args()`.
pub fn parse_cli_from_env() -> Result<CliMode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    parse_cli_args(&args)
}

/// Explicitly convert `agy_core::ProxyMode` to `agy_net::ProxyMode`.
pub fn to_net_proxy_mode(mode: CoreProxyMode) -> NetProxyMode {
    match mode {
        CoreProxyMode::Failover => NetProxyMode::Failover,
        CoreProxyMode::RoundRobin => NetProxyMode::RoundRobin,
        CoreProxyMode::Race => NetProxyMode::Race,
    }
}

/// Construct a [`ProxyPool`] from [`Config`] proxy settings without mutating network sockets.
pub fn build_proxy_pool_from_config(cfg: &Config) -> Result<ProxyPool> {
    let routes = if cfg.proxy_urls.is_empty() {
        vec![ProxyRouteConfig::direct()]
    } else {
        ProxyRouteConfig::parse_list(&cfg.proxy_urls.join(","))?
    };
    let net_cfg = NetConfig {
        force_ipv4: cfg.force_ipv4,
        routes,
        proxy_mode: to_net_proxy_mode(cfg.proxy_mode),
        ..Default::default()
    };
    ProxyPool::new(net_cfg)
}

/// Run pre-flight checks (`cfg.validate()`, `state_dir` RW probe, `mcp_config.json` syntax,
/// [`ProxyPool`] construction, and `widget_check_hook`) without printing secrets.
pub fn evaluate_check<F>(cfg: &Config, widget_check_hook: F) -> Result<Value>
where
    F: FnOnce() -> Result<Value>,
{
    cfg.validate()?;

    std::fs::create_dir_all(&cfg.state_dir).map_err(|e| {
        BridgeError::io(format!("create state_dir {}", cfg.state_dir.display()), e)
    })?;
    let mut probe = NamedTempFile::new_in(&cfg.state_dir).map_err(|e| {
        BridgeError::io(
            format!("rw probe create in {}", cfg.state_dir.display()),
            e,
        )
    })?;
    probe
        .write_all(b"agy-check")
        .and_then(|_| probe.flush())
        .map_err(|e| {
            BridgeError::io(format!("rw probe write in {}", cfg.state_dir.display()), e)
        })?;
    drop(probe);

    let mcp_config_status = if cfg.mcp_config_path.exists() {
        let raw = std::fs::read_to_string(&cfg.mcp_config_path).map_err(|e| {
            BridgeError::io(
                format!("read mcp_config {}", cfg.mcp_config_path.display()),
                e,
            )
        })?;
        let parsed: Value = serde_json::from_str(&raw).map_err(|e| {
            BridgeError::json(
                format!("parse mcp_config {}", cfg.mcp_config_path.display()),
                e,
            )
        })?;
        let Some(obj) = parsed.as_object() else {
            return Err(BridgeError::Validation(
                "mcp_config.json root must be a JSON object".into(),
            ));
        };
        if let Some(srvs) = obj.get("mcpServers") {
            if !srvs.is_object() && !srvs.is_null() {
                return Err(BridgeError::Validation(
                    "mcp_config.json 'mcpServers' must be a JSON object".into(),
                ));
            }
        }
        "ok"
    } else {
        "absent"
    };

    let pool = build_proxy_pool_from_config(cfg)?;
    let pool_snap = pool.snapshot();
    let route_labels: Vec<String> = pool_snap.routes.into_iter().map(|r| r.label).collect();

    let widgets = widget_check_hook()?;

    Ok(json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "transport": cfg.tg_transport.as_str(),
        "engine": cfg.agy_engine.as_str(),
        "state_dir": cfg.state_dir,
        "state_dir_rw": true,
        "mcp_config": mcp_config_status,
        "proxy_mode": pool_snap.mode,
        "proxy_routes": route_labels,
        "widgets": widgets,
    }))
}

/// Run [`evaluate_check`] and print the secret-free JSON report to stdout.
pub fn run_check<F>(cfg: &Config, widget_check_hook: F) -> Result<Value>
where
    F: FnOnce() -> Result<Value>,
{
    let report = evaluate_check(cfg, widget_check_hook)?;
    let pretty = serde_json::to_string_pretty(&report)
        .map_err(|e| BridgeError::json("serialize check report", e))?;
    println!("{pretty}");
    Ok(report)
}

/// Run local health verification (`$STATE_DIR/health.json` freshness + `stall_s` +
/// `127.0.0.1:<widget_port>/healthz` HTTP probe).
pub fn run_health(cfg: &Config) -> Result<Value> {
    run_health_at(cfg, now_secs())
}

/// Deterministic timestamp variant of [`run_health`].
pub fn run_health_at(cfg: &Config, now: f64) -> Result<Value> {
    let health_path = cfg.health_path();
    let raw = std::fs::read_to_string(&health_path).map_err(|e| {
        BridgeError::Updater(format!(
            "cannot read health file {}: {e}",
            health_path.display()
        ))
    })?;
    let snap: HealthSnapshot = serde_json::from_str(&raw)
        .map_err(|e| BridgeError::Updater(format!("invalid health.json: {e}")))?;

    let age = now - snap.ts;
    if !age.is_finite() || age.abs() > MAX_HEALTH_AGE_SECS {
        return Err(BridgeError::Updater(format!(
            "health.json is stale or skewed (age={age:.1}s, limit=±{MAX_HEALTH_AGE_SECS:.0}s)"
        )));
    }
    if !snap.stall_s.is_finite() || snap.stall_s >= cfg.wd_hard {
        return Err(BridgeError::Updater(format!(
            "bridge polling stalled (stall_s={:.1}s >= wd_hard={:.1}s)",
            snap.stall_s, cfg.wd_hard
        )));
    }

    probe_local_healthz(cfg.widget_port)?;

    Ok(json!({
        "ok": true,
        "age_s": (age * 10.0).round() / 10.0,
        "stall_s": snap.stall_s,
        "mode": snap.mode,
        "updates": snap.updates,
        "widget_healthz": "ok",
    }))
}

fn probe_local_healthz(port: u16) -> Result<()> {
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|e| BridgeError::Updater(format!("invalid healthz addr: {e}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| {
        BridgeError::Updater(format!("healthz TCP connect to 127.0.0.1:{port} failed: {e}"))
    })?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));

    let req = format!(
        "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).map_err(|e| {
        BridgeError::Updater(format!("healthz write failed: {e}"))
    })?;

    let mut buf = [0u8; 4096];
    let n = loop {
        match stream.read(&mut buf) {
            Ok(n) => break n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(BridgeError::Updater(format!("healthz read failed: {e}")));
            }
        }
    };
    let head = String::from_utf8_lossy(&buf[..n]);
    let status_line = head.lines().next().unwrap_or("");
    let status_code = status_line.split_whitespace().nth(1);
    if !status_line.starts_with("HTTP/1.") || status_code != Some("200") {
        return Err(BridgeError::Updater(format!(
            "healthz HTTP probe returned unexpected status: '{status_line}'"
        )));
    }
    Ok(())
}

fn verify_elf_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).map_err(|e| {
        BridgeError::Updater(format!("{label} {} not accessible: {e}", path.display()))
    })?;
    if !meta.is_file() {
        return Err(BridgeError::Updater(format!(
            "{label} {} is not a regular file",
            path.display()
        )));
    }
    let bytes = std::fs::read(path)
        .map_err(|e| BridgeError::io(format!("read {label} {}", path.display()), e))?;
    if bytes.len() < 4 || &bytes[..4] != ELF_MAGIC {
        return Err(BridgeError::Updater(format!(
            "{label} {} is not a valid ELF binary",
            path.display()
        )));
    }
    Ok(bytes)
}

fn run_preflight_check_cmd(staged_bin: &Path) -> Result<()> {
    let mut child = Command::new(staged_bin)
        .arg("--check")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            BridgeError::Updater(format!(
                "failed to execute {} --check: {e}",
                staged_bin.display()
            ))
        })?;

    // Drain stderr concurrently so `--check` can never deadlock on a full pipe buffer.
    let stderr_handle = child.stderr.take().map(|mut se| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match se.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let rem = 16_384usize.saturating_sub(buf.len());
                        if rem > 0 {
                            buf.extend_from_slice(&chunk[..n.min(rem)]);
                        }
                    }
                }
            }
            buf
        })
    });

    let deadline = Instant::now() + SELF_UPDATE_CHECK_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let err_buf = stderr_handle
                    .and_then(|h| h.join().ok())
                    .unwrap_or_default();
                if status.success() {
                    return Ok(());
                }
                let err_txt = redact_secrets_in_text(
                    &String::from_utf8_lossy(&err_buf).chars().take(400).collect::<String>(),
                );
                return Err(BridgeError::Updater(format!(
                    "staged binary --check failed (exit={:?}): {}",
                    status.code(),
                    err_txt.trim()
                )));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(h) = stderr_handle {
                        let _ = h.join();
                    }
                    return Err(BridgeError::Updater(
                        "staged binary --check timed out after 30s".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(h) = stderr_handle {
                    let _ = h.join();
                }
                return Err(BridgeError::Updater(format!(
                    "waiting on staged binary --check failed: {e}"
                )));
            }
        }
    }
}

/// Atomically replace `active_bin` with `staged_bin` after verifying ELF magic and
/// passing `staged_bin --check`. Backs up existing `active_bin` to `backup_dir`
/// (`agy-telegram.<ts>.bak` + `agy-telegram.latest.bak`) before swapping.
pub fn atomic_self_update(
    staged_bin: &Path,
    active_bin: &Path,
    backup_dir: &Path,
) -> Result<PathBuf> {
    let staged_bytes = verify_elf_file(staged_bin, "staged_bin")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(staged_bin) {
            let mode = meta.permissions().mode();
            if mode & 0o111 == 0 {
                let mut perms = meta.permissions();
                perms.set_mode(mode | 0o755);
                let _ = std::fs::set_permissions(staged_bin, perms);
            }
        }
    }
    run_preflight_check_cmd(staged_bin)?;

    std::fs::create_dir_all(backup_dir)
        .map_err(|e| BridgeError::io(format!("create backup_dir {}", backup_dir.display()), e))?;

    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let ts_bak = backup_dir.join(format!("agy-telegram.{ts_ms}.bak"));
    let latest_bak = backup_dir.join("agy-telegram.latest.bak");

    if active_bin.exists() {
        let mut active_file = File::open(active_bin)
            .map_err(|e| BridgeError::io(format!("open active_bin {}", active_bin.display()), e))?;
        let mut active_bytes = Vec::new();
        active_file
            .read_to_end(&mut active_bytes)
            .map_err(|e| BridgeError::io(format!("read active_bin {}", active_bin.display()), e))?;
        atomic_write_bytes(&ts_bak, &active_bytes, 0o755)?;
        atomic_write_bytes(&latest_bak, &active_bytes, 0o755)?;
    }

    atomic_write_bytes(active_bin, &staged_bytes, 0o755)?;
    Ok(if ts_bak.exists() { ts_bak } else { latest_bak })
}

/// Atomically restore `active_bin` from `backup_dir/agy-telegram.latest.bak` with mode `0o755`.
pub fn rollback_binary(active_bin: &Path, backup_dir: &Path) -> Result<PathBuf> {
    let latest_bak = backup_dir.join("agy-telegram.latest.bak");
    let backup_bytes = verify_elf_file(&latest_bak, "backup_bin")?;
    atomic_write_bytes(active_bin, &backup_bytes, 0o755)?;
    Ok(active_bin.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agy_core::health::HealthTracker;
    use axum::routing::get;
    use axum::Router;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    fn compile_c_elf(dir: &Path, name: &str, exit_code: i32, marker: &str) -> PathBuf {
        let src = dir.join(format!("{name}.c"));
        let out = dir.join(name);
        let code = format!(
            "#include <string.h>\n#include <stdio.h>\nint main(int argc, char **argv) {{\n  if (argc > 1 && strcmp(argv[1], \"--check\") == 0) {{ return {exit_code}; }}\n  printf(\"{marker}\\n\");\n  return 0;\n}}\n"
        );
        std::fs::write(&src, code).unwrap();
        let st = Command::new("cc")
            .arg(&src)
            .arg("-o")
            .arg(&out)
            .status()
            .unwrap();
        assert!(st.success(), "cc failed compiling test ELF");
        out
    }

    #[test]
    fn cli_mode_parser_variants_and_validation() {
        assert_eq!(parse_cli_args(&[]).unwrap(), CliMode::Run);
        assert_eq!(parse_cli_args(&["--check".into()]).unwrap(), CliMode::Check);
        assert_eq!(parse_cli_args(&["--health".into()]).unwrap(), CliMode::Health);
        assert_eq!(parse_cli_args(&["--bench-ab".into()]).unwrap(), CliMode::BenchAb);
        assert_eq!(parse_cli_args(&["--rollback".into()]).unwrap(), CliMode::Rollback);
        assert_eq!(parse_cli_args(&["--version".into()]).unwrap(), CliMode::Version);
        assert_eq!(parse_cli_args(&["-V".into()]).unwrap(), CliMode::Version);
        assert_eq!(
            parse_cli_args(&["--updates-check".into()]).unwrap(),
            CliMode::UpdatesCheck
        );
        assert_eq!(
            parse_cli_args(&["--updates-apply".into()]).unwrap(),
            CliMode::UpdatesApply("all".into())
        );
        assert_eq!(
            parse_cli_args(&["--updates-apply".into(), "skills".into()]).unwrap(),
            CliMode::UpdatesApply("skills".into())
        );
        assert_eq!(
            parse_cli_args(&["--self-update".into(), "/tmp/new".into()]).unwrap(),
            CliMode::SelfUpdate(PathBuf::from("/tmp/new"))
        );
        assert_eq!(
            parse_cli_args(&["--self-update=/tmp/new2".into()]).unwrap(),
            CliMode::SelfUpdate(PathBuf::from("/tmp/new2"))
        );

        assert!(parse_cli_args(&["--self-update".into()]).is_err());
        assert!(parse_cli_args(&["--self-update=".into()]).is_err());
        assert!(parse_cli_args(&["--bogus".into()]).is_err());
    }

    #[test]
    fn evaluate_check_validates_and_redacts_secrets() {
        let dir = TempDir::new().unwrap();
        let mcp_path = dir.path().join("mcp.json");
        std::fs::write(
            &mcp_path,
            r#"{"mcpServers":{"demo":{"command":"node","env":{"KEY":"secret_val_999"}}}}"#,
        )
        .unwrap();

        let cfg = Config {
            bot_token: "999:SUPER_SECRET_BOT_TOKEN".into(),
            state_dir: dir.path().join("state"),
            mcp_config_path: mcp_path,
            proxy_urls: vec!["http://alice:proxyPass123@127.0.0.1:8080".into()],
            proxy_mode: CoreProxyMode::Race,
            ..Default::default()
        };

        let report = evaluate_check(&cfg, || Ok(json!({"builtins": 4}))).unwrap();
        assert_eq!(report["ok"], json!(true));
        assert_eq!(report["mcp_config"], json!("ok"));
        assert_eq!(report["widgets"]["builtins"], json!(4));
        let txt = serde_json::to_string(&report).unwrap();
        assert!(!txt.contains("SUPER_SECRET_BOT_TOKEN"));
        assert!(!txt.contains("proxyPass123"));
        assert!(!txt.contains("alice"));
        assert!(!txt.contains("secret_val_999"));

        // Invalid MCP JSON fails check
        std::fs::write(&cfg.mcp_config_path, "{broken").unwrap();
        assert!(evaluate_check(&cfg, || Ok(json!({}))).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_health_checks_freshness_stall_and_http_healthz() {
        let dir = TempDir::new().unwrap();
        let app = Router::new().route("/healthz", get(|| async { "ok" }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let cfg = Config {
            bot_token: "1:t".into(),
            state_dir: dir.path().join("state"),
            widget_port: addr.port(),
            wd_hard: 300.0,
            ..Default::default()
        };
        std::fs::create_dir_all(&cfg.state_dir).unwrap();
        let health = HealthTracker::new_at(cfg.health_path(), 1000.0);
        health.write_at(1005.0).unwrap();

        let cfg_probe = cfg.clone();
        let ok = tokio::task::spawn_blocking(move || run_health_at(&cfg_probe, 1020.0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ok["ok"], json!(true));
        assert_eq!(ok["widget_healthz"], json!("ok"));

        // Stale health.json (> 120s) fails
        let cfg_stale = cfg.clone();
        assert!(
            tokio::task::spawn_blocking(move || run_health_at(&cfg_stale, 1200.0))
                .await
                .unwrap()
                .is_err()
        );

        // High stall_s >= wd_hard fails
        health.set_last_poll_ok(500.0);
        health.write_at(1000.0).unwrap();
        let cfg_stall = cfg.clone();
        assert!(
            tokio::task::spawn_blocking(move || run_health_at(&cfg_stall, 1010.0))
                .await
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn atomic_self_update_verifies_elf_and_preflight_then_swaps_and_rolls_back() {
        let dir = TempDir::new().unwrap();
        let build_dir = dir.path().join("build");
        let backup_dir = dir.path().join("backups");
        std::fs::create_dir_all(&build_dir).unwrap();

        let active_bin = dir.path().join("agy-telegram");
        let old_elf = compile_c_elf(&build_dir, "old_bin", 0, "v1");
        std::fs::copy(&old_elf, &active_bin).unwrap();
        std::fs::set_permissions(&active_bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        // 1. Non-ELF staged binary rejected without mutating active_bin
        let fake_bin = build_dir.join("not_elf");
        std::fs::write(&fake_bin, b"#!/bin/sh\nexit 0\n").unwrap();
        assert!(atomic_self_update(&fake_bin, &active_bin, &backup_dir).is_err());
        assert_eq!(std::fs::read(&active_bin).unwrap(), std::fs::read(&old_elf).unwrap());
        assert!(!backup_dir.join("agy-telegram.latest.bak").exists());

        // 2. ELF binary failing `--check` rejected without mutating active_bin
        let bad_elf = compile_c_elf(&build_dir, "bad_elf", 2, "bad");
        assert!(atomic_self_update(&bad_elf, &active_bin, &backup_dir).is_err());
        assert_eq!(std::fs::read(&active_bin).unwrap(), std::fs::read(&old_elf).unwrap());
        assert!(!backup_dir.join("agy-telegram.latest.bak").exists());

        // 3. Valid ELF passing `--check` atomically replaces active_bin and creates backups
        let new_elf = compile_c_elf(&build_dir, "new_elf", 0, "v2");
        let ts_bak = atomic_self_update(&new_elf, &active_bin, &backup_dir).unwrap();
        assert!(ts_bak.exists());
        assert!(backup_dir.join("agy-telegram.latest.bak").exists());
        assert_eq!(std::fs::read(&active_bin).unwrap(), std::fs::read(&new_elf).unwrap());
        assert_eq!(
            std::fs::metadata(&active_bin).unwrap().permissions().mode() & 0o777,
            0o755
        );

        let out_v2 = Command::new(&active_bin).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out_v2.stdout).trim(), "v2");

        // 4. Rollback restores v1 atomically
        rollback_binary(&active_bin, &backup_dir).unwrap();
        assert_eq!(std::fs::read(&active_bin).unwrap(), std::fs::read(&old_elf).unwrap());
        let out_v1 = Command::new(&active_bin).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out_v1.stdout).trim(), "v1");
    }
}
