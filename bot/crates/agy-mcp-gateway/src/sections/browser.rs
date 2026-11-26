//! Section 10: Hybrid Fast & Interactive Browser Automation (`/mcp/s/browser`).
//!
//! Combines two complementary engines to keep RAM minimal on a 4 GB VPS while supporting
//! full interactive workflows (login, forms, product creation, file upload, screenshots):
//! - **Moli** (`/root/.local/bin/moli`): ~73 MB single-process Rust browser for fast reads & on-demand screenshots.
//! - **agent-browser** (`/usr/bin/agent-browser`): Rust daemon + Chrome headless with `@e1` accessibility refs
//!   (70-90% fewer tokens than screenshots) and persistent login profiles under `$STATE_DIR/browser_profiles/`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::process::Command;
use url::Url;

use crate::auth::AuthenticatedPrincipal;
use crate::config::SectionId;
use crate::policy::ToolRisk;
use crate::registry::{make_annotations, ToolSpec};
use crate::sanitize::is_forbidden_path;

pub const DEFAULT_MOLI_BIN: &str = "/root/.local/bin/moli";
pub const DEFAULT_AGENT_BROWSER_BIN: &str = "/usr/bin/agent-browser";
pub const DEFAULT_CHROME_BIN: &str = "/root/.agent-browser/browsers/chrome-158.0.8127.88/chrome";
pub const DEFAULT_BROWSER_CFG: &str = "/root/agy-stack/config/mcp/agent-browser.json";

pub fn browser_tool_specs() -> Vec<ToolSpec> {
    let ro = make_annotations(true, false, true, true);
    let wr = make_annotations(false, true, false, true);
    vec![
        ToolSpec {
            name: "browser_fast_read".to_string(),
            section: SectionId::Browser,
            risk: ToolRisk::ReadOnly,
            untrusted_output: true,
            description: "Ultra-fast, low-RAM (~73 MB) headless page reader powered by Moli (Rust + V8). Extracts semantic_tree_text or markdown after JS execution.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "format": {"type": "string", "enum": ["semantic_tree_text", "markdown", "html"], "default": "semantic_tree_text"},
                    "wait": {"type": "string", "default": "done", "description": "done | load | networkidle | ms:<n>"}
                },
                "required": ["url"]
            }),
            annotations: ro.clone(),
            keywords: vec!["browser".into(), "moli".into(), "read".into(), "webpage".into(), "scrape".into()],
        },
        ToolSpec {
            name: "browser_fast_screenshot".to_string(),
            section: SectionId::Browser,
            risk: ToolRisk::Write,
            untrusted_output: false,
            description: "Capture a quick viewport screenshot using Moli's on-demand layout renderer and save to a workspace path.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "output_path": {"type": "string", "description": "Relative or workspace-absolute .png path"}
                },
                "required": ["url", "output_path"]
            }),
            annotations: wr.clone(),
            keywords: vec!["browser".into(), "moli".into(), "screenshot".into()],
        },
        ToolSpec {
            name: "browser_open".to_string(),
            section: SectionId::Browser,
            risk: ToolRisk::Write,
            untrusted_output: true,
            description: "Open a URL in a stateful interactive Chrome headless session via agent-browser (supports persistent login profiles & isolated sessions).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "session": {"type": "string", "default": "default", "description": "Session name (alphanumeric/_/-)"},
                    "profile": {"type": "string", "description": "Optional persistent profile name under browser_profiles/ so login cookies survive restarts"}
                },
                "required": ["url"]
            }),
            annotations: wr.clone(),
            keywords: vec!["browser".into(), "open".into(), "login".into(), "session".into(), "agent-browser".into()],
        },
        ToolSpec {
            name: "browser_snapshot".to_string(),
            section: SectionId::Browser,
            risk: ToolRisk::ReadOnly,
            untrusted_output: true,
            description: "Get a token-efficient interactive accessibility tree with element refs (@e1, @e2, ...) for clicking, filling forms, and uploading files.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session": {"type": "string", "default": "default"},
                    "interactive_only": {"type": "boolean", "default": true}
                }
            }),
            annotations: ro.clone(),
            keywords: vec!["browser".into(), "snapshot".into(), "refs".into(), "a11y".into()],
        },
        ToolSpec {
            name: "browser_click".to_string(),
            section: SectionId::Browser,
            risk: ToolRisk::Write,
            untrusted_output: true,
            description: "Click an element by @eN ref (from browser_snapshot) or CSS/text selector.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Element ref (e.g. '@e1') or CSS selector"},
                    "session": {"type": "string", "default": "default"}
                },
                "required": ["target"]
            }),
            annotations: wr.clone(),
            keywords: vec!["browser".into(), "click".into(), "button".into()],
        },
        ToolSpec {
            name: "browser_fill".to_string(),
            section: SectionId::Browser,
            risk: ToolRisk::Write,
            untrusted_output: true,
            description: "Clear and fill an input/textarea by @eN ref or CSS selector (e.g. product title, price, description, login credentials).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "value": {"type": "string"},
                    "session": {"type": "string", "default": "default"}
                },
                "required": ["target", "value"]
            }),
            annotations: wr.clone(),
            keywords: vec!["browser".into(), "fill".into(), "form".into(), "input".into(), "product".into()],
        },
        ToolSpec {
            name: "browser_press".to_string(),
            section: SectionId::Browser,
            risk: ToolRisk::Write,
            untrusted_output: true,
            description: "Press a keyboard key (Enter, Tab, Escape, ArrowDown) or select a dropdown option.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["press", "select"], "default": "press"},
                    "key_or_target": {"type": "string", "description": "Key name for 'press' (e.g. 'Enter'), or @ref/selector for 'select'"},
                    "value": {"type": "string", "description": "Option value when action='select'"},
                    "session": {"type": "string", "default": "default"}
                },
                "required": ["key_or_target"]
            }),
            annotations: wr.clone(),
            keywords: vec!["browser".into(), "key".into(), "select".into(), "enter".into()],
        },
        ToolSpec {
            name: "browser_upload".to_string(),
            section: SectionId::Browser,
            risk: ToolRisk::Write,
            untrusted_output: true,
            description: "Upload a file (e.g. product image) from the workspace into a file input element (@eN ref or selector).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "file_path": {"type": "string"},
                    "session": {"type": "string", "default": "default"}
                },
                "required": ["target", "file_path"]
            }),
            annotations: wr.clone(),
            keywords: vec!["browser".into(), "upload".into(), "image".into(), "file".into()],
        },
        ToolSpec {
            name: "browser_wait".to_string(),
            section: SectionId::Browser,
            risk: ToolRisk::ReadOnly,
            untrusted_output: true,
            description: "Wait for an element, text, URL pattern, or networkidle in the active browser session.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Selector/@ref, or '--text \"Saved\"', or '--load networkidle'"},
                    "session": {"type": "string", "default": "default"}
                },
                "required": ["target"]
            }),
            annotations: ro,
            keywords: vec!["browser".into(), "wait".into()],
        },
        ToolSpec {
            name: "browser_screenshot".to_string(),
            section: SectionId::Browser,
            risk: ToolRisk::Write,
            untrusted_output: false,
            description: "Take a screenshot of the current page in agent-browser and save inside workspace/outbox.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "output_path": {"type": "string"},
                    "full_page": {"type": "boolean", "default": false},
                    "session": {"type": "string", "default": "default"}
                },
                "required": ["output_path"]
            }),
            annotations: wr.clone(),
            keywords: vec!["browser".into(), "screenshot".into(), "visual".into()],
        },
        ToolSpec {
            name: "browser_eval".to_string(),
            section: SectionId::Browser,
            risk: ToolRisk::HighRiskExec,
            untrusted_output: true,
            description: "Evaluate a JavaScript expression inside the active page context (HighRiskExec: subject to HITL for non-owner keys).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "expression": {"type": "string"},
                    "session": {"type": "string", "default": "default"}
                },
                "required": ["expression"]
            }),
            annotations: make_annotations(false, true, false, true),
            keywords: vec!["browser".into(), "eval".into(), "javascript".into()],
        },
        ToolSpec {
            name: "browser_session".to_string(),
            section: SectionId::Browser,
            risk: ToolRisk::Write,
            untrusted_output: false,
            description: "Manage browser sessions to preserve login cookies or free server RAM: url, title, close, close_all, list_profiles.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["url", "title", "close", "close_all", "list_profiles"]},
                    "session": {"type": "string", "default": "default"}
                },
                "required": ["action"]
            }),
            annotations: wr,
            keywords: vec!["browser".into(), "session".into(), "close".into(), "profile".into()],
        },
    ]
}

fn sanitize_ident(raw: &str, fallback: &str) -> String {
    let clean: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(40)
        .collect();
    if clean.is_empty() {
        fallback.to_string()
    } else {
        clean
    }
}

/// Strict SSRF protection for remote browser requests.
pub fn validate_browser_url(raw_url: &str, is_owner: bool) -> std::result::Result<String, String> {
    let trimmed = raw_url.trim();
    let parsed = Url::parse(trimmed).map_err(|e| format!("Invalid URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "Forbidden URL scheme '{other}'. Only http:// and https:// are allowed."
            ));
        }
    }
    let Some(host) = parsed.host_str() else {
        return Err("URL missing host".to_string());
    };
    let host_l = host.trim_matches(['[', ']']).to_ascii_lowercase();

    // Cloud metadata endpoints are ALWAYS blocked even for Owner
    if host_l == "169.254.169.254" || host_l == "metadata.google.internal" {
        return Err("Access to cloud metadata endpoint is forbidden".to_string());
    }
    if !is_owner {
        if host_l == "localhost"
            || host_l.ends_with(".local")
            || host_l.ends_with(".internal")
        {
            return Err(format!("SSRF guard: private/local host '{host_l}' blocked"));
        }
        if let Ok(ip) = host_l.parse::<IpAddr>() {
            let blocked = match ip {
                IpAddr::V4(v4) => {
                    v4.is_loopback()
                        || v4.is_private()
                        || v4.is_link_local()
                        || v4.is_unspecified()
                }
                IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
            };
            if blocked {
                return Err(format!("SSRF guard: non-public IP '{ip}' blocked"));
            }
        }
    }
    Ok(parsed.to_string())
}

fn resolve_workspace_file(workspace: &Path, raw: &str, is_owner: bool) -> std::result::Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("File path must not be empty".to_string());
    }
    if is_forbidden_path(trimmed) {
        return Err("Access to protected credential path is forbidden".to_string());
    }
    let candidate = if Path::new(trimmed).is_absolute() {
        PathBuf::from(trimmed)
    } else {
        workspace.join(trimmed)
    };
    let ws_canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    // Ensure parent exists for new screenshot outputs, and check confinement for non-owners
    if let Some(parent) = candidate.parent() {
        let _ = std::fs::create_dir_all(parent);
        if let Ok(p_canon) = std::fs::canonicalize(parent) {
            if !is_owner && !p_canon.starts_with(&ws_canon) {
                return Err(format!(
                    "Path '{}' is outside workspace confinement",
                    candidate.display()
                ));
            }
        }
    }
    Ok(candidate)
}

async fn run_cmd_bounded(
    bin: &str,
    args: &[String],
    envs: &[(&str, String)],
    timeout_secs: u64,
) -> std::result::Result<Vec<u8>, String> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn '{bin}': {e}"))?;
    let out = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output())
        .await
        .map_err(|_| format!("Browser command timed out after {timeout_secs}s"))?
        .map_err(|e| format!("Browser execution failed: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(format!(
            "Command failed (exit {:?}): {} {}",
            out.status.code(),
            stderr.trim(),
            stdout.trim()
        ));
    }
    Ok(out.stdout)
}

fn moli_bin() -> String {
    std::env::var("MOLI_BIN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_MOLI_BIN.to_string())
}

fn agent_browser_bin() -> String {
    std::env::var("AGENT_BROWSER_BIN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_AGENT_BROWSER_BIN.to_string())
}

fn agent_browser_envs(state_dir: &Path) -> Vec<(&'static str, String)> {
    let sock_dir = state_dir.join("browser_sockets");
    let _ = std::fs::create_dir_all(&sock_dir);
    let mut envs = vec![
        ("HOME", "/root".to_string()),
        ("AGENT_BROWSER_SOCKET_DIR", sock_dir.to_string_lossy().into_owned()),
    ];
    if Path::new(DEFAULT_CHROME_BIN).exists() {
        envs.push((
            "AGENT_BROWSER_EXECUTABLE_PATH",
            DEFAULT_CHROME_BIN.to_string(),
        ));
    }
    if Path::new(DEFAULT_BROWSER_CFG).exists() {
        envs.push(("AGENT_BROWSER_CONFIG", DEFAULT_BROWSER_CFG.to_string()));
    }
    envs
}

pub async fn call_browser_tool(
    principal: &AuthenticatedPrincipal,
    state_dir: &Path,
    workspace: &Path,
    tool: &str,
    args: &Value,
) -> std::result::Result<Value, String> {
    let envs = agent_browser_envs(state_dir);
    let session = sanitize_ident(
        args.get("session").and_then(Value::as_str).unwrap_or("default"),
        "default",
    );

    match tool {
        "browser_fast_read" => {
            let raw_url = args
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| "url is required".to_string())?;
            let safe_url = validate_browser_url(raw_url, principal.is_owner)?;
            let fmt = match args
                .get("format")
                .and_then(Value::as_str)
                .unwrap_or("semantic_tree_text")
            {
                "markdown" => "markdown",
                "html" => "html",
                _ => "semantic_tree_text",
            };
            let wait = args
                .get("wait")
                .and_then(Value::as_str)
                .unwrap_or("done");
            let wait_clean = match wait {
                "load" | "domcontentloaded" | "networkidle" | "done" => wait.to_string(),
                other if other.starts_with("ms:") => other.to_string(),
                _ => "done".to_string(),
            };
            let cmd_args = vec![
                "fetch".to_string(),
                "--dump".to_string(),
                fmt.to_string(),
                "--wait".to_string(),
                wait_clean,
                safe_url.clone(),
            ];
            let stdout = run_cmd_bounded(&moli_bin(), &cmd_args, &[], 35).await?;
            let text = String::from_utf8_lossy(&stdout).into_owned();
            Ok(json!({
                "engine": "moli",
                "url": safe_url,
                "format": fmt,
                "text": text
            }))
        }
        "browser_fast_screenshot" => {
            let raw_url = args
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| "url is required".to_string())?;
            let safe_url = validate_browser_url(raw_url, principal.is_owner)?;
            let out_raw = args
                .get("output_path")
                .and_then(Value::as_str)
                .ok_or_else(|| "output_path is required".to_string())?;
            let out_path = resolve_workspace_file(workspace, out_raw, principal.is_owner)?;
            let cmd_args = vec![
                "fetch".to_string(),
                "--layout".to_string(),
                "--dump".to_string(),
                "screenshot".to_string(),
                safe_url.clone(),
            ];
            let png_bytes = run_cmd_bounded(&moli_bin(), &cmd_args, &[], 40).await?;
            std::fs::write(&out_path, &png_bytes)
                .map_err(|e| format!("Failed to save screenshot: {e}"))?;
            Ok(json!({
                "engine": "moli",
                "url": safe_url,
                "saved_path": out_path.display().to_string(),
                "bytes": png_bytes.len()
            }))
        }
        "browser_open" => {
            let raw_url = args
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| "url is required".to_string())?;
            let safe_url = validate_browser_url(raw_url, principal.is_owner)?;
            let mut cmd_args = vec!["--session".to_string(), session];
            if let Some(prof) = args.get("profile").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                let p_name = sanitize_ident(prof, "default");
                let p_dir = state_dir.join("browser_profiles").join(p_name);
                let _ = std::fs::create_dir_all(&p_dir);
                cmd_args.push("--profile".to_string());
                cmd_args.push(p_dir.to_string_lossy().into_owned());
            }
            cmd_args.push("open".to_string());
            cmd_args.push(safe_url);
            let out = run_cmd_bounded(&agent_browser_bin(), &cmd_args, &envs, 45).await?;
            Ok(json!({"text": String::from_utf8_lossy(&out).trim()}))
        }
        "browser_snapshot" => {
            let inter = args
                .get("interactive_only")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let mut cmd_args = vec!["--session".to_string(), session, "snapshot".to_string()];
            if inter {
                cmd_args.push("-i".to_string());
            }
            let out = run_cmd_bounded(&agent_browser_bin(), &cmd_args, &envs, 25).await?;
            Ok(json!({"text": String::from_utf8_lossy(&out).into_owned()}))
        }
        "browser_click" => {
            let target = args
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| "target is required".to_string())?;
            let cmd_args = vec![
                "--session".to_string(),
                session,
                "click".to_string(),
                target.to_string(),
            ];
            let out = run_cmd_bounded(&agent_browser_bin(), &cmd_args, &envs, 25).await?;
            Ok(json!({"text": String::from_utf8_lossy(&out).trim()}))
        }
        "browser_fill" => {
            let target = args
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| "target is required".to_string())?;
            let value = args
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| "value is required".to_string())?;
            let cmd_args = vec![
                "--session".to_string(),
                session,
                "fill".to_string(),
                target.to_string(),
                value.to_string(),
            ];
            let out = run_cmd_bounded(&agent_browser_bin(), &cmd_args, &envs, 25).await?;
            Ok(json!({"text": String::from_utf8_lossy(&out).trim()}))
        }
        "browser_press" => {
            let action = args.get("action").and_then(Value::as_str).unwrap_or("press");
            let kt = args
                .get("key_or_target")
                .and_then(Value::as_str)
                .ok_or_else(|| "key_or_target is required".to_string())?;
            let mut cmd_args = vec!["--session".to_string(), session];
            if action == "select" {
                let val = args
                    .get("value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "value is required for action='select'".to_string())?;
                cmd_args.push("select".to_string());
                cmd_args.push(kt.to_string());
                cmd_args.push(val.to_string());
            } else {
                cmd_args.push("press".to_string());
                cmd_args.push(kt.to_string());
            }
            let out = run_cmd_bounded(&agent_browser_bin(), &cmd_args, &envs, 25).await?;
            Ok(json!({"text": String::from_utf8_lossy(&out).trim()}))
        }
        "browser_upload" => {
            let target = args
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| "target is required".to_string())?;
            let fraw = args
                .get("file_path")
                .and_then(Value::as_str)
                .ok_or_else(|| "file_path is required".to_string())?;
            let safe_file = resolve_workspace_file(workspace, fraw, principal.is_owner)?;
            if !safe_file.exists() {
                return Err(format!("Upload file not found: {}", safe_file.display()));
            }
            let cmd_args = vec![
                "--session".to_string(),
                session,
                "upload".to_string(),
                target.to_string(),
                safe_file.to_string_lossy().into_owned(),
            ];
            let out = run_cmd_bounded(&agent_browser_bin(), &cmd_args, &envs, 35).await?;
            Ok(json!({"text": String::from_utf8_lossy(&out).trim()}))
        }
        "browser_wait" => {
            let target = args
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| "target is required".to_string())?;
            let mut cmd_args = vec!["--session".to_string(), session, "wait".to_string()];
            if let Some(txt) = target.strip_prefix("--text ") {
                cmd_args.push("--text".to_string());
                cmd_args.push(txt.trim_matches('"').to_string());
            } else if let Some(load) = target.strip_prefix("--load ") {
                cmd_args.push("--load".to_string());
                cmd_args.push(load.trim().to_string());
            } else {
                cmd_args.push(target.to_string());
            }
            let out = run_cmd_bounded(&agent_browser_bin(), &cmd_args, &envs, 35).await?;
            Ok(json!({"text": String::from_utf8_lossy(&out).trim()}))
        }
        "browser_screenshot" => {
            let out_raw = args
                .get("output_path")
                .and_then(Value::as_str)
                .ok_or_else(|| "output_path is required".to_string())?;
            let full_page = args
                .get("full_page")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let out_path = resolve_workspace_file(workspace, out_raw, principal.is_owner)?;
            let mut cmd_args = vec!["--session".to_string(), session, "screenshot".to_string()];
            if full_page {
                cmd_args.push("--full".to_string());
            }
            cmd_args.push(out_path.to_string_lossy().into_owned());
            let out = run_cmd_bounded(&agent_browser_bin(), &cmd_args, &envs, 30).await?;
            Ok(json!({
                "saved_path": out_path.display().to_string(),
                "output": String::from_utf8_lossy(&out).trim()
            }))
        }
        "browser_eval" => {
            let expr = args
                .get("expression")
                .and_then(Value::as_str)
                .ok_or_else(|| "expression is required".to_string())?;
            let cmd_args = vec![
                "--session".to_string(),
                session,
                "eval".to_string(),
                expr.to_string(),
            ];
            let out = run_cmd_bounded(&agent_browser_bin(), &cmd_args, &envs, 25).await?;
            Ok(json!({"text": String::from_utf8_lossy(&out).trim()}))
        }
        "browser_session" => {
            let action = args
                .get("action")
                .and_then(Value::as_str)
                .ok_or_else(|| "action is required".to_string())?;
            match action {
                "url" => {
                    let out = run_cmd_bounded(
                        &agent_browser_bin(),
                        &["--session".into(), session, "get".into(), "url".into()],
                        &envs,
                        15,
                    )
                    .await?;
                    Ok(json!({"url": String::from_utf8_lossy(&out).trim()}))
                }
                "title" => {
                    let out = run_cmd_bounded(
                        &agent_browser_bin(),
                        &["--session".into(), session, "get".into(), "title".into()],
                        &envs,
                        15,
                    )
                    .await?;
                    Ok(json!({"title": String::from_utf8_lossy(&out).trim()}))
                }
                "close" => {
                    let out = run_cmd_bounded(
                        &agent_browser_bin(),
                        &["--session".into(), session, "close".into()],
                        &envs,
                        15,
                    )
                    .await?;
                    Ok(json!({"closed": true, "output": String::from_utf8_lossy(&out).trim()}))
                }
                "close_all" => {
                    let out = run_cmd_bounded(
                        &agent_browser_bin(),
                        &["close".into(), "--all".into()],
                        &envs,
                        15,
                    )
                    .await?;
                    Ok(json!({"closed_all": true, "output": String::from_utf8_lossy(&out).trim()}))
                }
                "list_profiles" => {
                    let dir = state_dir.join("browser_profiles");
                    let mut profs = Vec::new();
                    if let Ok(rd) = std::fs::read_dir(&dir) {
                        for ent in rd.flatten() {
                            if ent.path().is_dir() {
                                profs.push(ent.file_name().to_string_lossy().into_owned());
                            }
                        }
                    }
                    profs.sort();
                    Ok(json!({"profiles": profs}))
                }
                other => Err(format!("unknown browser_session action: {other}")),
            }
        }
        other => Err(format!("unknown browser tool: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssrf_guard_blocks_metadata_and_private_ips_for_non_owners() {
        assert!(validate_browser_url("https://example.com/shop", false).is_ok());
        assert!(validate_browser_url("http://169.254.169.254/latest/meta-data/", false).is_err());
        assert!(validate_browser_url("http://169.254.169.254/latest/meta-data/", true).is_err());
        assert!(validate_browser_url("http://127.0.0.1:8787/healthz", false).is_err());
        assert!(validate_browser_url("http://192.168.1.1/admin", false).is_err());
        assert!(validate_browser_url("file:///etc/passwd", true).is_err());
    }
}
