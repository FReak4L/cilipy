//! Venice Uncensored OpenAI-compatible engine, autonomous agent execution (via `agent_runtime`),
//! model catalog with uncensored filtering, and upgraded standalone stdio MCP server.

use std::path::{Path, PathBuf};
use std::time::Duration;

use agy_core::atomic::atomic_write_json;
use agy_core::error::{BridgeError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::watch;
use tracing::{info, warn};

pub use crate::agent_runtime::ThreeStageMode;
use crate::agent_runtime::{
    run_openai_agent_turn, AgentTurnConfig, StaticBearerProvider, DEFAULT_JOB_TIMEOUT_SECS,
    DEFAULT_MAX_AGENT_STEPS,
};
use crate::engines::{JobResult, ProgressCallback};
use crate::mcp_client::redact_secrets_in_text;

pub const DEFAULT_VENICE_API_BASE: &str = "https://api.example.com/v1";
/// Must be provided via `VENICE_API_KEY` env var (never hardcoded in source).
pub const DEFAULT_VENICE_API_KEY: &str = "";
pub const DEFAULT_UNCENSORED_MODEL: &str = "veniceai/deepseek-v4-1-flash-1017-uncensored";
pub const MAX_AGENT_STEPS: usize = DEFAULT_MAX_AGENT_STEPS;

/// Maximum custom system prompt size persisted per user (64 KiB — verified on Venice API).
pub const MAX_CUSTOM_SYSPROMPT_BYTES: usize = 64 * 1024;

/// Strong system prompt instructing the uncensored model to act as a pro OpenHands autonomous coding agent.
pub const UNCENSORED_AGENT_SYSTEM_PROMPT: &str = "\
You are an action-first, autonomous OpenHands-grade Uncensored AI software engineering agent on an Ubuntu server.\n\
Core Pro Coding & Speed Tools (35 live tools):\n\
- Programmatic Batching (5-10x FASTER): execute_code / <agy_exec> (Python 3 Unix-socket RPC with 24 agy_tools functions, up to 150 calls in ONE turn, 300s timeout — collapse multi-file reads/greps/edits/git/MCP/verify into 1 turn!)\n\
- Chunked Contract-First Assembly (NO standalone fragments!): assemble_slots / <agy_slot name=\"...\"> (write complete skeleton with `# <<<AGY_SLOT:id>>>` markers first, then stream 3-5 or up to 10 integrated code chunks with instant syntax validation after EVERY chunk)\n\
- Codebase Architecture & Diffs: repo_map (Aider-style .gitignore-aware structural symbol map of an entire repo or unpacked .zip in 1 call!), diff_files (unified Myers diff + executable non-comment diff stats for hunk-by-hunk self-review), glob_files, find_symbols, grep_files, list_dir, git_ops\n\
- Code Editing & Rollback: batch_read (up to 20 files concurrently), multi_edit (up to 25 surgical edits w/ undo_edit rollback), file_editor (view, create, str_replace, insert, undo_edit), read_file, write_file (append=true), patch_file\n\
- Planning & Project Packs: task_tracker (plan/update/view), think, finish, code_to_md (.zip/dir -> .md), md_to_code (.md -> disk), verify_project (auto-detect Rust/Python/TS/Go/PHP/Bash -> PASS or errors.md)\n\
- Shell & Persistent PTYs: run_command (bash, builds, tests, timeout 600s, background/pty tmux, bubblewrap sandbox), process_manage\n\
- Vision, Memory, Skills & MCPs: inspect_image, web_search & fetch_url (search-v3), memory_search & memory_store (ai-memory), search_skills/load_skill/skillhub_*, list_mcp_servers, discover_mcp_tools (inspect ANY MCP server's live tools & parameter schemas before calling!), call_mcp_tool (up to 50/turn: context7, gortex, graphify, search-v3, openhands, ai-memory, skillport, skillhub)\n\
Execution & Code-Quality Discipline:\n\
1. ACT IMMEDIATELY & NEVER STOP EARLY: Never stall in planning mode, never ask the user to paste attached files, and never ask permission when the user asked you to inspect/analyze/fix/improve/test/send code. Emit independent read/search calls together in ONE turn or use <agy_exec>.\n\
2. COMPLETE FILE & ZIP ANALYSIS: When the user attaches code files or `.zip` archives, read EVERY attached file completely (do NOT guess from a preview; use `read_file`, `code_to_md`, or `<agy_exec>`). For `.zip` archives (including nested `.zip` files), ALWAYS use Python `zipfile` via `<agy_exec>` / `run_command` (or `code_to_md`) — `unzip`/`zip` CLIs are NOT installed, and NEVER call `read_file` on binary `.zip` files.\n\
3. REAL EXECUTABLE CODE CHANGES — NO COSMETIC OR COMMENT-ONLY REWRITES: NEVER just rename a file or add a giant wall of header/changelog comments without meaningfully improving the actual executable code logic. Keep comments brief and surgical. NEVER emit lazy omission placeholders (`// ... rest unchanged`, `// TODO: implement`). Preserve ALL existing public functions, classes, and methods unless explicitly asked to delete them.\n\
4. LARGE-FILE & MULTI-CHUNK INTEGRATION: For large existing files (>10 KiB), copy input to `outbox/.../` and apply surgical edits via `<agy_exec>`, `patch_file`, or `multi_edit`. For new large modules, write the full skeleton with `# <<<AGY_SLOT:id>>>` markers first, then fill each slot across 3-5 (up to 10) focused `<agy_slot name=\"id\">` chunks (`2-5 KiB` each) — NEVER output disconnected standalone snippets!\n\
5. MANDATORY OUTBOX DELIVERY & REAL VERIFICATION: Always write complete, verified improved file(s) directly inside the exact `outbox/.../` directory given in the prompt (keep temporary scratch/test files in workspace cwd so outbox contains ONLY final deliverables). Before finishing, ALWAYS re-check with `grep_files`/`read_file` that every requested fix actually landed in the target `outbox/` file AND run a real linter/runtime check (`php -l` + `php -r` smoke test for PHP, `python3 -m py_compile` + assertions for Python, `node --check` for JS, `bash -n` for Bash) on that exact file.\n\
6. ZERO GUESSING & NO LOOPS: Verify every claim with fresh tool output. Never repeat a failing call twice; inspect errors, roll back bad edits with undo_edit if needed, and never reveal secrets/keys.";

pub const UNCENSORED_CHAT_SYSTEM_PROMPT: &str = "\
You are an uncensored AI assistant running via Venice. Be direct, thorough, accurate, and concise. \
Never fabricate file contents, command outputs, or URLs; if something cannot be verified without tools, state that clearly. \
Keep continuity with verified facts from earlier turns in this conversation.";

/// Return a safe maximum completion token limit matched to the specific Venice model's capabilities.
pub fn model_max_tokens(model: &str) -> u32 {
    let low = clean_model_id(model).to_ascii_lowercase();
    if low.contains("role-play") {
        4_096
    } else if low.contains("venice-uncensored-1-2")
        || low.contains("gemma-4")
        || low.contains("gemma4")
        || low.contains("e2ee-gemma")
    {
        8_192
    } else {
        16_384
    }
}

/// Ordered verified healthy `veniceai/*` failover models when the selected model fails
/// (403 Cloudflare, 429 rate-limit, 5xx, timeout, or empty completion).
pub fn fallback_failover_chain(primary: &str) -> Vec<String> {
    let cur = clean_model_id(primary);
    let candidates = [
        "veniceai/deepseek-v4-1-flash-1017-uncensored",
        "veniceai/glm-5-3-flash-uncensored",
        "veniceai/deepseek-v4-1-flash-uncensored",
        "veniceai/gemma-4-uncensored",
        "veniceai/venice-uncensored-1-2",
    ];
    candidates
        .iter()
        .filter(|&&m| !m.eq_ignore_ascii_case(&cur))
        .map(|&m| m.to_string())
        .collect()
}

/// Per-user custom system prompt file path (`$STATE_DIR/uncensored_sysprompts/<uid>.txt`).
pub fn uncensored_sysprompt_path(state_dir: &Path, uid: i64) -> PathBuf {
    state_dir
        .join("uncensored_sysprompts")
        .join(format!("{uid}.txt"))
}

/// Load a user's saved full custom system prompt for Venice Uncensored (no 6KB truncation).
pub fn load_custom_sysprompt(state_dir: &Path, uid: i64) -> Option<String> {
    let p = uncensored_sysprompt_path(state_dir, uid);
    std::fs::read_to_string(&p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Save a user's full custom system prompt (up to 64 KiB, atomic 0600 write).
pub fn save_custom_sysprompt(state_dir: &Path, uid: i64, text: &str) -> Result<usize> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(BridgeError::Validation(
            "System prompt must not be empty.".to_string(),
        ));
    }
    if trimmed.len() > MAX_CUSTOM_SYSPROMPT_BYTES {
        return Err(BridgeError::Validation(format!(
            "System prompt exceeds {} KiB limit ({} bytes).",
            MAX_CUSTOM_SYSPROMPT_BYTES / 1024,
            trimmed.len()
        )));
    }
    let p = uncensored_sysprompt_path(state_dir, uid);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| BridgeError::io("creating uncensored_sysprompts dir", e))?;
    }
    let tmp = p.with_extension("txt.tmp");
    std::fs::write(&tmp, trimmed.as_bytes())
        .map_err(|e| BridgeError::io("writing uncensored sysprompt tmp", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &p)
        .map_err(|e| BridgeError::io("renaming uncensored sysprompt", e))?;
    Ok(trimmed.len())
}

/// Remove a user's saved custom system prompt for Venice Uncensored.
pub fn clear_custom_sysprompt(state_dir: &Path, uid: i64) -> bool {
    let p = uncensored_sysprompt_path(state_dir, uid);
    if p.exists() {
        std::fs::remove_file(&p).is_ok()
    } else {
        false
    }
}

/// Enrich a Telegram bridge prompt with full attachment metadata and safe inline content so
/// uploaded files (including `.zip` archives and multi-file batches) are never incomplete or missed.
/// - In **Chat mode** (`agent_mode == false`): packs attachments via `code_to_md` up to 120 KiB
///   because Chat mode has no local file-reading tools.
/// - In **Agent mode** (`agent_mode == true`): appends a lean manifest (path, size, lines/files)
///   and safely inlines compact files up to 12 KiB total (keeping Step 1 lean for large files like
///   27 KB+ PHP/code while guiding the agent to read them via `read_file` / `code_to_md`).
pub async fn enrich_prompt_with_attachments(
    prompt: &str,
    attachments: &[PathBuf],
    agent_mode: bool,
) -> String {
    if attachments.is_empty() {
        return prompt.to_string();
    }
    let inline_budget: usize = if agent_mode { 12 * 1024 } else { 72 * 1024 };
    let mut used_bytes = 0usize;
    let mut manifest_lines = Vec::new();
    let mut inline_sections = Vec::new();

    for path in attachments {
        let fname = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("attachment");
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                manifest_lines.push(format!("- `{}` (unreadable: {e})", path.display()));
                continue;
            }
        };
        let size = meta.len();
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_media = matches!(
            ext.as_str(),
            "png" | "jpg" | "jpeg" | "webp" | "gif" | "mp4" | "mov" | "mp3" | "ogg" | "wav" | "pdf"
        );
        if is_media {
            manifest_lines.push(format!(
                "- `{}` ({size} B, media `{ext}` — use `inspect_image` for images)",
                path.display()
            ));
            continue;
        }

        let mut opts = crate::code_to_md::PackOptions::new(path.clone());
        opts.include_line_numbers = true;
        opts.include_symbols = true;
        opts.max_total_bytes = crate::code_to_md::DEFAULT_MAX_TOTAL_BYTES;

        match crate::code_to_md::pack_to_markdown(&opts).await {
            Ok(packed) => {
                let mut rec_note = String::new();
                if crate::code_to_md::is_zip_archive(path) {
                    if let Ok(rec) = crate::code_to_md::inspect_zip_recursive(path, 2).await {
                        let clipped: String = rec.markdown_overview.chars().take(2400).collect();
                        rec_note = format!("\n  ↳ Recursive ZIP Layout:\n    {}", clipped.replace('\n', "\n    "));
                    }
                }
                manifest_lines.push(format!(
                    "- `{}` ({}, {size} B, {} file(s), {} lines){rec_note}",
                    path.display(),
                    packed.source_kind,
                    packed.included_files,
                    packed.total_lines
                ));
                if packed.skipped_files == 0 && used_bytes + packed.markdown.len() <= inline_budget {
                    used_bytes += packed.markdown.len();
                    inline_sections.push(format!(
                        "#### Attached `{fname}` (`{}`)\n{}",
                        path.display(),
                        packed.markdown
                    ));
                } else if !agent_mode {
                    let rem = inline_budget.saturating_sub(used_bytes);
                    if rem > 1024 {
                        let mut end = rem.min(packed.markdown.len());
                        while end > 0 && !packed.markdown.is_char_boundary(end) {
                            end -= 1;
                        }
                        used_bytes += end;
                        inline_sections.push(format!(
                            "#### Attached `{fname}` (`{}` — truncated to budget)\n{}\n... [truncated]",
                            path.display(),
                            &packed.markdown[..end]
                        ));
                    }
                } else {
                    let preview_lines: String = packed
                        .markdown
                        .lines()
                        .take(35)
                        .collect::<Vec<_>>()
                        .join("\n");
                    manifest_lines.push(format!(
                        "  ↳ Large attachment ({} bytes packed); read completely with `<agy_exec>` / `code_to_md(path=\"{}\")` / `read_file`.\n  Preview:\n```\n{}\n```",
                        packed.markdown.len(),
                        path.display(),
                        preview_lines
                    ));
                }
            }
            Err(e) => {
                manifest_lines.push(format!(
                    "- `{}` ({size} B; inspect with `read_file`/`run_command`; pack note: {e})",
                    path.display()
                ));
            }
        }
    }

    let mut out = String::with_capacity(prompt.len() + used_bytes + 512);
    out.push_str(prompt);
    out.push_str("\n\n=== VERIFIED ATTACHMENT MANIFEST ===\n");
    out.push_str(&manifest_lines.join("\n"));
    if !inline_sections.is_empty() {
        out.push_str("\n\n=== ATTACHED FILE CONTENTS (COMPLETE) ===\n");
        out.push_str(&inline_sections.join("\n\n"));
    }
    out
}

/// Model info from Venice API filtered for `uncensored`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UncensoredModel {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub context_length: Option<u64>,
    #[serde(default)]
    pub tool_calling: bool,
}

pub fn uncensored_models_path(state_dir: &Path) -> PathBuf {
    state_dir.join("uncensored_models.json")
}

pub fn load_cached_uncensored_models(state_dir: &Path) -> Vec<UncensoredModel> {
    let p = uncensored_models_path(state_dir);
    if let Ok(raw) = std::fs::read_to_string(&p) {
        if let Ok(list) = serde_json::from_str::<Vec<UncensoredModel>>(&raw) {
            let healthy: Vec<UncensoredModel> = list
                .into_iter()
                .filter(|m| {
                    let low = m.id.to_ascii_lowercase();
                    !low.starts_with("venice-web/")
                        && !low.starts_with("ven/")
                        && !low.starts_with("hanz/")
                })
                .collect();
            if !healthy.is_empty() {
                return healthy;
            }
        }
    }
    fallback_uncensored_models()
}

pub fn save_cached_uncensored_models(state_dir: &Path, models: &[UncensoredModel]) -> Result<()> {
    let p = uncensored_models_path(state_dir);
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    atomic_write_json(&p, &models, true)
}

/// Fallback list if network/API is completely down.
pub fn fallback_uncensored_models() -> Vec<UncensoredModel> {
    vec![
        UncensoredModel {
            id: "veniceai/deepseek-v4-1-flash-1017-uncensored".to_string(),
            name: "DeepSeek V4 1 Flash 1017 Uncensored".to_string(),
            context_length: Some(1_000_000),
            tool_calling: true,
        },
        UncensoredModel {
            id: "veniceai/glm-5-3-flash-uncensored".to_string(),
            name: "GLM 5.3 Flash Uncensored".to_string(),
            context_length: Some(1_048_576),
            tool_calling: true,
        },
        UncensoredModel {
            id: "veniceai/gemma-4-uncensored".to_string(),
            name: "Gemma 4 Uncensored".to_string(),
            context_length: Some(256_000),
            tool_calling: true,
        },
        UncensoredModel {
            id: "veniceai/venice-uncensored-1-2".to_string(),
            name: "Venice Uncensored 1.2".to_string(),
            context_length: Some(128_000),
            tool_calling: true,
        },
        UncensoredModel {
            id: "veniceai/venice-uncensored-role-play".to_string(),
            name: "Venice Uncensored Role Play".to_string(),
            context_length: Some(128_000),
            tool_calling: true,
        },
    ]
}

/// Fetch live models from `{api_base}/models` and filter strictly for `uncensored` models.
pub async fn fetch_uncensored_models(api_base: &str, api_key: &str) -> Result<Vec<UncensoredModel>> {
    if api_key.trim().is_empty() {
        return Err(BridgeError::Config(
            "VENICE_API_KEY is not configured".to_string(),
        ));
    }
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| BridgeError::Network(format!("venice HTTP client build failed: {e}")))?;

    let url = format!("{}/models", api_base.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .bearer_auth(api_key)
        .send()
        .await
        .map_err(|e| BridgeError::Network(format!("venice models request failed: {e}")))?;

    if !resp.status().is_success() {
        let code = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(BridgeError::Network(format!(
            "venice models HTTP {code}: {}",
            redact_secrets_in_text(&body).chars().take(300).collect::<String>()
        )));
    }

    let doc: Value = resp
        .json()
        .await
        .map_err(|e| BridgeError::Network(format!("venice models JSON parse failed: {e}")))?;

    let Some(data) = doc.get("data").and_then(Value::as_array) else {
        return Err(BridgeError::Validation(
            "venice models response missing 'data' array".to_string(),
        ));
    };

    let mut out = Vec::new();
    for item in data {
        let id = item.get("id").and_then(Value::as_str).unwrap_or("");
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(id);

        let id_low = id.to_ascii_lowercase();
        let name_low = name.to_ascii_lowercase();

        // Exclude known-broken Cloudflare-403 legacy web-scrape prefixes (`venice-web/`, `ven/`)
        // and unfunded third-party `hanz/` routes when healthy `veniceai/` models are available.
        if id_low.starts_with("venice-web/")
            || id_low.starts_with("ven/")
            || id_low.starts_with("hanz/")
        {
            continue;
        }

        let is_uncensored = id_low.contains("uncensored")
            || name_low.contains("uncensored")
            || id_low.contains("heretic")
            || item
                .get("traits")
                .and_then(Value::as_array)
                .is_some_and(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .any(|t| t.eq_ignore_ascii_case("uncensored"))
                });

        if !is_uncensored || id.is_empty() {
            continue;
        }

        let context_length = item
            .get("context_length")
            .or_else(|| item.get("max_context_length"))
            .and_then(Value::as_u64);

        let tool_calling = item
            .get("capabilities")
            .and_then(|c| c.get("tool_calling"))
            .and_then(Value::as_bool)
            .unwrap_or(true);

        out.push(UncensoredModel {
            id: id.to_string(),
            name: name.to_string(),
            context_length,
            tool_calling,
        });
    }

    if out.is_empty() {
        return Ok(fallback_uncensored_models());
    }

    out.sort_by_key(|a| a.name.to_ascii_lowercase());
    Ok(out)
}

/// Refresh models from Venice API and persist into `$STATE_DIR/uncensored_models.json`.
pub async fn refresh_uncensored_models(
    state_dir: &Path,
    api_base: &str,
    api_key: &str,
) -> Vec<UncensoredModel> {
    match fetch_uncensored_models(api_base, api_key).await {
        Ok(models) if !models.is_empty() => {
            if let Err(e) = save_cached_uncensored_models(state_dir, &models) {
                warn!(error = %e, "failed caching uncensored models");
            }
            models
        }
        Ok(_) => load_cached_uncensored_models(state_dir),
        Err(e) => {
            warn!(error = %e, "failed refreshing uncensored models from Venice");
            load_cached_uncensored_models(state_dir)
        }
    }
}

/// Ensure cached uncensored models exist, refreshing if file is missing or older than 6 hours.
pub async fn ensure_uncensored_models(
    state_dir: &Path,
    api_base: &str,
    api_key: &str,
) -> Vec<UncensoredModel> {
    let p = uncensored_models_path(state_dir);
    let stale = std::fs::metadata(&p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_none_or(|d| d > Duration::from_secs(6 * 3600));

    if !p.exists() || stale {
        return refresh_uncensored_models(state_dir, api_base, api_key).await;
    }
    load_cached_uncensored_models(state_dir)
}

/// Check if a model ID belongs to the Venice Uncensored engine.
pub fn is_uncensored_model(model: &str) -> bool {
    let low = model.to_ascii_lowercase();
    low.starts_with("veniceai/")
        || low.starts_with("uncensored:")
        || low.contains("uncensored")
        || low.contains("heretic")
}

/// Clean optional `uncensored:` prefix from model ID before sending to Venice API,
/// and automatically upgrade legacy broken `venice-web/` / `ven/` / unfunded `hanz/` routes
/// to healthy `veniceai/` equivalents.
pub fn clean_model_id(model: &str) -> String {
    let trimmed = model
        .trim()
        .strip_prefix("uncensored:")
        .unwrap_or(model.trim());
    let low = trimmed.to_ascii_lowercase();
    if low == "venice-web/venice-uncensored"
        || low == "venice-web/venice-uncensored-1.2"
        || low == "ven/venice-uncensored"
        || low == "ven/venice-uncensored-1.2"
        || low.starts_with("hanz/")
    {
        "veniceai/venice-uncensored-1-2".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Build a compact live roster of installed local skills and enabled MCP servers so DeepSeek/GLM/Gemma
/// models proactively discover and use skills & MCPs accurately without guessing names.
fn build_live_capabilities_roster(skills_dir: &Path, mcp_config_path: &Path) -> String {
    let mut parts = Vec::new();
    let mut skill_names: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(skills_dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() && p.join("SKILL.md").is_file() {
                if let Some(name) = ent.file_name().to_str() {
                    if !name.starts_with('.') {
                        skill_names.push(name.to_string());
                    }
                }
            }
        }
    }
    skill_names.sort();
    skill_names.truncate(24);
    if !skill_names.is_empty() {
        parts.push(format!(
            "- Installed Local Skills (call `load_skill` when relevant): {}",
            skill_names.join(", ")
        ));
    }
    if let Ok(srvs) = crate::mcp_config::list_mcp_servers(mcp_config_path) {
        let enabled: Vec<String> = srvs
            .into_iter()
            .filter(|s| s.enabled)
            .map(|s| s.name)
            .collect();
        if !enabled.is_empty() {
            parts.push(format!(
                "- Enabled MCP Servers (use `discover_mcp_tools` to inspect exact schemas before `call_mcp_tool`): {}",
                enabled.join(", ")
            ));
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("\n\n=== LIVE WORKSPACE SKILLS & MCP ROSTER ===\n{}", parts.join("\n"))
    }
}

/// Deterministic zero-NLP Trigger-Table + local `BM25F` SkillHub retriever (~0.3 ms CPU, zero tokens).
/// Selects 2–3 high-signal local/SkillHub rules matched to the detected codebase stack and prompt,
/// bounded under ~3.2 KiB so Stage 2 enriches the chat without bloating Venice context.
pub async fn retrieve_targeted_skills_brief(
    skills_dir: &Path,
    state_dir: &Path,
    detected_stack: &[String],
    user_prompt: &str,
    memory_text: &str,
) -> String {
    let mut sections: Vec<String> = Vec::new();
    let combined_low = format!(
        "{}\n{}\n{}",
        detected_stack.join(" "),
        user_prompt,
        memory_text.chars().take(1200).collect::<String>()
    )
    .to_ascii_lowercase();

    // 1. Trigger-Table Lazy Loading (ECC / strategic-compact style) over local installed skills
    const TRIGGER_TABLE: &[(&[&str], &str)] = &[
        (&["bug", "error", "fix", "fail", "باگ", "خطا", "اصلاح", "دیباگ"], "systematic-debugging"),
        (&["test", "verify", "assert", "تست", "بررسی", "lint"], "verification-before-completion"),
        (&["refactor", "edit", "chunk", "slot", "zip", "تغییر", "ارتقا", "بهبود"], "code-change-protocol"),
        (&["plan", "architecture", "stage", "معماری", "مرحله"], "writing-plans"),
    ];
    let mut selected_local: Vec<&'static str> = Vec::new();
    for (triggers, slug) in TRIGGER_TABLE {
        if triggers.iter().any(|t| combined_low.contains(t) || user_prompt.contains(t))
            && !selected_local.contains(slug)
        {
            selected_local.push(slug);
            if selected_local.len() >= 2 {
                break;
            }
        }
    }
    if selected_local.is_empty() {
        selected_local.push("code-change-protocol");
        selected_local.push("verification-before-completion");
    }

    for slug in &selected_local {
        let p = skills_dir.join(slug).join("SKILL.md");
        if let Ok(raw) = tokio::fs::read_to_string(&p).await {
            let trimmed: String = raw
                .lines()
                .filter(|l| !l.trim().is_empty())
                .take(14)
                .collect::<Vec<_>>()
                .join("\n");
            let clip: String = trimmed.chars().take(550).collect();
            if !clip.is_empty() {
                sections.push(format!("### Local Skill: `{slug}`\n{clip}"));
            }
        }
    }

    // 2. Deterministic BM25F SkillHub query (0.3ms local search, zero NLP!)
    let mut terms: Vec<String> = detected_stack
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| s.len() >= 2)
        .collect();
    const DOMAIN_KW: &[&str] = &[
        "refactoring", "security", "testing", "api", "async", "retry", "zip", "parsing",
        "performance", "architecture", "woocommerce", "wordpress", "telegram", "fastapi",
        "django", "flask", "cli", "error", "validation",
    ];
    for &kw in DOMAIN_KW {
        if combined_low.contains(kw) && !terms.iter().any(|t| t == kw) {
            terms.push(kw.to_string());
        }
        if terms.len() >= 5 {
            break;
        }
    }
    if terms.is_empty() {
        terms.push("coding".to_string());
        terms.push("testing".to_string());
    }
    let query = terms.join(" ");
    let idx = crate::skill_hub::hub_index_async(state_dir).await;
    if !idx.is_empty() {
        let q_clone = query.clone();
        let resp = tokio::task::spawn_blocking(move || idx.search(&q_clone, 3))
            .await
            .unwrap_or_else(|_| crate::skill_index::SearchResponse {
                hits: Vec::new(),
                total: 0,
                elapsed_us: 0,
                plan: String::new(),
                suggestions: Vec::new(),
            });
        for hit in resp.hits.iter().take(2) {
            let mut body_snip = String::new();
            for (ln, txt) in hit.snippets.iter().take(3) {
                body_snip.push_str(&format!("\n  L{ln}: {}", txt.chars().take(180).collect::<String>()));
            }
            let desc: String = hit.description.chars().take(180).collect();
            sections.push(format!(
                "### SkillHub Match ({}): `{}` (`{}`)\n- {desc}{body_snip}\n- Call `skillhub_get(id=\"{}\", max_chars=4000)` if full rules are needed.",
                hit.kind.as_str(),
                hit.name,
                hit.id,
                hit.id
            ));
        }
    }

    if sections.is_empty() {
        "Apply modular Contract-First architecture, explicit error handling, and real syntax/unit verification before finishing.".to_string()
    } else {
        let joined = format!(
            "Targeted Skills Brief (BM25F query: `{query}`):\n\n{}",
            sections.join("\n\n")
        );
        let clipped: String = joined.chars().take(3200).collect();
        clipped
    }
}

/// Execute a full multi-turn autonomous agent (or direct chat) turn against Venice Uncensored
/// with configurable [`ThreeStageMode`] (`Auto`, `Always`, `Off`).
#[allow(clippy::too_many_arguments)]
pub async fn run_uncensored_agent_with_stage(
    api_base: &str,
    api_key: &str,
    model: &str,
    user_prompt: &str,
    cwd: &Path,
    workspace_root: &Path,
    mcp_config_path: &Path,
    skills_dir: &Path,
    state_dir: &Path,
    session_key: Option<String>,
    allow_root: bool,
    allow_sandbox: bool,
    agent_mode: bool,
    max_steps_opt: Option<usize>,
    custom_system_prompt: Option<&str>,
    three_stage_mode: ThreeStageMode,
    on_progress: Option<ProgressCallback>,
    cancel: watch::Receiver<bool>,
) -> Result<JobResult> {
    let clean_model = clean_model_id(if model.trim().is_empty() {
        DEFAULT_UNCENSORED_MODEL
    } else {
        model
    });
    let provider = StaticBearerProvider {
        api_base: api_base.to_string(),
        api_key: api_key.to_string(),
        extra_headers: Vec::new(),
    };
    let live_roster = if agent_mode {
        build_live_capabilities_roster(skills_dir, mcp_config_path)
    } else {
        String::new()
    };
    let system_prompt = match custom_system_prompt.filter(|s| !s.trim().is_empty()) {
        Some(custom) if agent_mode => {
            // Preserve the user's FULL custom system prompt verbatim AND keep agent execution rules intact
            format!(
                "{custom}\n\n=== AGENT ENVIRONMENT & EXECUTION CAPABILITIES ===\n{UNCENSORED_AGENT_SYSTEM_PROMPT}{live_roster}"
            )
        }
        Some(custom) => custom.to_string(),
        None if agent_mode => format!("{UNCENSORED_AGENT_SYSTEM_PROMPT}{live_roster}"),
        None => UNCENSORED_CHAT_SYSTEM_PROMPT.to_string(),
    };
    let max_tokens = model_max_tokens(&clean_model);
    let cfg = AgentTurnConfig {
        engine_id: "uncensored".to_string(),
        model: clean_model,
        system_prompt,
        cwd: cwd.to_path_buf(),
        workspace_root: workspace_root.to_path_buf(),
        allow_root,
        allow_sandbox: allow_sandbox || allow_root,
        agent_mode,
        mcp_config_path: mcp_config_path.to_path_buf(),
        skills_dir: skills_dir.to_path_buf(),
        state_dir: state_dir.to_path_buf(),
        session_key,
        max_steps: max_steps_opt.unwrap_or(DEFAULT_MAX_AGENT_STEPS),
        max_tokens,
        job_timeout_secs: DEFAULT_JOB_TIMEOUT_SECS,
        proxy_url: None,
        three_stage_mode,
    };

    run_openai_agent_turn(&provider, &cfg, user_prompt, on_progress, cancel).await
}

/// Execute a full multi-turn autonomous agent (or direct chat) turn against Venice Uncensored.
#[allow(clippy::too_many_arguments)]
pub async fn run_uncensored_agent(
    api_base: &str,
    api_key: &str,
    model: &str,
    user_prompt: &str,
    cwd: &Path,
    workspace_root: &Path,
    mcp_config_path: &Path,
    skills_dir: &Path,
    state_dir: &Path,
    session_key: Option<String>,
    allow_root: bool,
    allow_sandbox: bool,
    agent_mode: bool,
    max_steps_opt: Option<usize>,
    custom_system_prompt: Option<&str>,
    on_progress: Option<ProgressCallback>,
    cancel: watch::Receiver<bool>,
) -> Result<JobResult> {
    run_uncensored_agent_with_stage(
        api_base,
        api_key,
        model,
        user_prompt,
        cwd,
        workspace_root,
        mcp_config_path,
        skills_dir,
        state_dir,
        session_key,
        allow_root,
        allow_sandbox,
        agent_mode,
        max_steps_opt,
        custom_system_prompt,
        ThreeStageMode::Auto,
        on_progress,
        cancel,
    )
    .await
}

fn normalize_verify_error_fingerprint(vres: &crate::code_to_md::VerifyResult) -> String {
    vres.checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| format!("{}|{}|{}", c.command.trim(), c.exit_code, c.output.trim()))
        .collect::<Vec<_>>()
        .join("\n---\n")
}

fn extract_primary_error_query(vres: &crate::code_to_md::VerifyResult) -> Option<String> {
    for c in vres.checks.iter().filter(|c| !c.passed) {
        if let Some(line) = c.output.lines().map(str::trim).find(|l| {
            !l.is_empty()
                && !l.starts_with('#')
                && !l.starts_with('|')
                && (l.contains("error")
                    || l.contains("Error")
                    || l.contains("SyntaxError")
                    || l.contains("FAILED")
                    || l.contains("cannot find")
                    || l.contains("undefined"))
        }) {
            let q: String = line.chars().take(140).collect();
            if !q.is_empty() {
                return Some(q);
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_uncensored_dev_loop(
    api_base: &str,
    api_key: &str,
    model: &str,
    project_dir: &Path,
    task: &str,
    commands: Vec<String>,
    run_tests: bool,
    max_iters: usize,
    search_on_error: bool,
    workspace: &Path,
    mcp_config: &Path,
    skills_dir: &Path,
    state_dir: &Path,
    cancel: watch::Receiver<bool>,
) -> std::result::Result<String, String> {
    if !project_dir.is_dir() {
        return Err(format!("project_dir does not exist: {}", project_dir.display()));
    }
    if task.trim().is_empty() {
        return Err("task must not be empty".to_string());
    }

    let strict_sys = "\
You are a precise code-editing engine operating via structured Markdown.\n\
Rules:\n\
1. Output ONLY the files you actually need to create or modify, each with:\n\
   ### `relative/path/to/file.ext`\n\
   ```lang\n\
   <complete, valid file contents>\n\
   ```\n\
2. NEVER add unnecessary files, helper demos, or boilerplate.\n\
3. NEVER alter unrelated algorithms, business logic, or existing behavior.\n\
4. Provide COMPLETE file contents for each modified file (no `...` placeholders).";

    let mut log = String::new();
    let mut last_errors_md: Option<String> = None;
    let mut last_error_fp: Option<String> = None;
    let mut last_error_query: Option<String> = None;
    let mut active_model = model.to_string();
    let mut escalated = false;
    let mut baseline_lines: Option<usize> = None;

    for iter in 1..=max_iters {
        let mut pack_opts = crate::code_to_md::PackOptions::new(project_dir.to_path_buf());
        pack_opts.include_line_numbers = false;
        let packed = crate::code_to_md::pack_to_markdown(&pack_opts).await?;
        if baseline_lines.is_none() {
            baseline_lines = Some(packed.total_lines);
        }

        let mut prompt = format!(
            "## Project Snapshot\n{}\n\n## Task\n{task}\n",
            packed.markdown
        );
        if let Some(ref err_md) = last_errors_md {
            prompt.push_str("\n## Previous Verification Errors (`errors.md`)\nFix ONLY these errors without breaking existing algorithms:\n");
            prompt.push_str(err_md);
            if search_on_error {
                if let Some(ref q) = last_error_query {
                    let search_res = crate::agent_runtime::invoke_configured_mcp(
                        mcp_config,
                        "search-v3",
                        "search_web_v3",
                        json!({ "query": q, "profile": "fast", "limit": 3 }),
                        12.0,
                        true,
                    )
                    .await;
                    if !search_res.starts_with("Error:") {
                        let snippet: String = search_res.chars().take(2000).collect();
                        prompt.push_str("\n## Live Web Search Context\n");
                        prompt.push_str(&snippet);
                        prompt.push('\n');
                    }
                }
            }
        }

        let res = run_uncensored_agent(
            api_base,
            api_key,
            &active_model,
            &prompt,
            project_dir,
            workspace,
            mcp_config,
            skills_dir,
            state_dir,
            None,
            true,
            true,
            false,
            Some(1),
            Some(strict_sys),
            None,
            cancel.clone(),
        )
        .await
        .map_err(|e| format!("iteration {iter} AI call failed: {e}"))?;

        if let Some(err) = res.error {
            return Err(format!("iteration {iter} AI error: {err}"));
        }

        if crate::code_to_md::parse_markdown_files(&res.text).is_empty() {
            if iter < max_iters {
                last_errors_md = Some(
                    "Your previous response contained no `### \\`rel/path\\`` fenced code blocks. Output ONLY the modified file(s) in `### \\`rel/path\\`` fenced code blocks."
                        .to_string(),
                );
                log.push_str(&format!(
                    "### Iteration {iter}/{max_iters} (`{active_model}`)\n- No file blocks returned; nudging format.\n\n"
                ));
                continue;
            }
            log.push_str(&format!(
                "### Iteration {iter}/{max_iters} (`{active_model}`)\n- AI returned no file edits:\n\n{}\n",
                res.text
            ));
            return Ok(log);
        }

        let unpack_res = crate::code_to_md::unpack_from_markdown(&crate::code_to_md::UnpackOptions {
            target_dir: project_dir.to_path_buf(),
            markdown: res.text,
            dry_run: false,
        })
        .await
        .map_err(|e| format!("iteration {iter} unpack failed: {e}"))?;

        let changed_files: Vec<String> = unpack_res
            .files
            .iter()
            .filter(|f| f.action == "created" || f.action == "updated")
            .map(|f| format!("{} ({})", f.rel_path, f.action))
            .collect();

        let mut vopts = crate::code_to_md::VerifyOptions::new(project_dir.to_path_buf());
        vopts.commands = commands.clone();
        vopts.run_tests = run_tests;
        let vres = crate::code_to_md::verify_project(&vopts).await?;

        // Anti-Goodhart check: warn if >40% of lines vanished on a non-trivial project
        let mut shrink_warn = String::new();
        if let Some(base_l) = baseline_lines.filter(|&l| l > 20) {
            let post_pack = crate::code_to_md::pack_to_markdown(&pack_opts).await.ok();
            if let Some(pp) = post_pack {
                if pp.total_lines * 10 < base_l * 6 {
                    shrink_warn = format!(
                        "\n- ⚠️ Anti-Goodhart warning: project lines dropped from {base_l} to {} (>40% shrinkage)",
                        pp.total_lines
                    );
                }
            }
        }

        log.push_str(&format!(
            "### Iteration {iter}/{max_iters} (`{active_model}`)\n- Files: created={}, updated={}, unchanged={}, skipped={}\n- Modified: {}\n- Verify: {}{shrink_warn}\n\n",
            unpack_res.created,
            unpack_res.updated,
            unpack_res.unchanged,
            unpack_res.skipped,
            if changed_files.is_empty() { "none".to_string() } else { changed_files.join(", ") },
            if vres.passed { "✅ PASS" } else { "❌ FAIL" }
        ));

        if vres.passed {
            log.push_str(&vres.errors_md);
            return Ok(log);
        }

        // Compare duration-free error fingerprint so identical failures actually trigger escalation/stop
        let cur_fp = normalize_verify_error_fingerprint(&vres);
        if last_error_fp.as_deref() == Some(cur_fp.as_str()) {
            const ESCALATE_MODEL: &str = "veniceai/glm-5-3-flash-uncensored";
            if !escalated && active_model != ESCALATE_MODEL && iter < max_iters {
                escalated = true;
                active_model = ESCALATE_MODEL.to_string();
                log.push_str("- 🔁 Identical error persisted; escalating to `veniceai/glm-5-3-flash-uncensored`.\n\n");
            } else {
                log.push_str("## Stopped Early (Identical Error Persisted)\n");
                log.push_str(&vres.errors_md);
                return Ok(log);
            }
        }
        last_error_fp = Some(cur_fp);
        last_error_query = extract_primary_error_query(&vres);
        last_errors_md = Some(vres.errors_md);
    }

    if let Some(err_md) = last_errors_md {
        log.push_str("## Final Unresolved Errors\n");
        log.push_str(&err_md);
    }
    Ok(log)
}

pub(crate) async fn prepend_packed_attachments(prompt: &str, targs: &Value, base_dir: &Path) -> String {
    let Some(arr) = targs.get("attach_paths").and_then(Value::as_array) else {
        return prompt.to_string();
    };
    let mut bundles = Vec::new();
    for item in arr {
        let Some(raw) = item.as_str().map(str::trim).filter(|s| !s.is_empty()) else {
            continue;
        };
        let p = PathBuf::from(raw);
        let target = if p.is_absolute() { p } else { base_dir.join(p) };
        let opts = crate::code_to_md::PackOptions::new(target);
        match crate::code_to_md::pack_to_markdown(&opts).await {
            Ok(res) => bundles.push(res.markdown),
            Err(e) => bundles.push(format!("<!-- Failed to pack {raw}: {e} -->")),
        }
    }
    if bundles.is_empty() {
        prompt.to_string()
    } else {
        format!("{}\n\n---\n\n{prompt}", bundles.join("\n\n---\n\n"))
    }
}

/// Standalone stdio JSON-RPC 2.0 MCP server (`agy-telegram --mcp-uncensored`) allowing
/// Antigravity or any MCP client to delegate tasks to Venice Uncensored models as an autonomous agent.
pub async fn run_mcp_uncensored_server() -> Result<()> {
    let api_base = std::env::var("VENICE_API_BASE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_VENICE_API_BASE.to_string());
    let api_key = std::env::var("VENICE_API_KEY").unwrap_or_default();
    let workspace = std::env::var("AGY_WORKSPACE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root/agy-workspace"));
    let state_dir = std::env::var("STATE_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/agy-telegram"));
    let mcp_config = std::env::var("MCP_CONFIG_PATH")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(crate::mcp_config::DEFAULT_MCP_CONFIG_PATH));
    let skills_dir = std::env::var("AGY_SKILLS_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root/.gemini/config/skills"));

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| BridgeError::io("reading mcp-uncensored stdin", e))?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };

        let id = req.get("id").cloned();
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

        if id.is_none() {
            continue;
        }
        let id = id.unwrap_or(Value::Null);

        let response = match method {
            "initialize" => {
                let req_ver = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("2024-11-05");
                let negotiated = match req_ver {
                    "2025-06-18" | "2025-03-26" | "2024-11-05" => req_ver,
                    _ => "2024-11-05",
                };
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": negotiated,
                        "capabilities": { "tools": { "listChanged": false } },
                        "serverInfo": { "name": "venice-uncensored", "version": "3.0.0" }
                    }
                })
            }
            "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
            "resources/list" => json!({ "jsonrpc": "2.0", "id": id, "result": { "resources": [] } }),
            "prompts/list" => json!({ "jsonrpc": "2.0", "id": id, "result": { "prompts": [] } }),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "uncensored_models",
                            "description": "List available Venice uncensored models live from the API.",
                            "inputSchema": { "type": "object", "properties": {} }
                        },
                        {
                            "name": "uncensored_chat",
                            "description": "Direct single-turn uncensored chat completion (no server tools). Supports attach_paths to pack code/directories/.zip files into structured .md context.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "prompt": { "type": "string", "description": "Prompt text" },
                                    "model": { "type": "string", "description": "Optional uncensored model ID" },
                                    "system_prompt": { "type": "string", "description": "Optional system prompt" },
                                    "attach_paths": { "type": "array", "items": { "type": "string" }, "description": "Optional local file, directory, or .zip paths to pack into .md and attach to prompt" }
                                },
                                "required": ["prompt"]
                            }
                        },
                        {
                            "name": "uncensored_agent",
                            "description": "Run an autonomous OpenHands-grade Venice Uncensored Agent with full Ubuntu server tools (file_editor w/ insert+undo_edit, task_tracker, glob_files, find_symbols, git_ops, 100-call execute_code Python RPC, bash/PTY, code_to_md, verify_project, inspect_image, search-v3, ai-memory, skillport, MCPs, auto-loaded repo microagents).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "task": { "type": "string", "description": "Autonomous task to execute" },
                                    "model": { "type": "string", "description": "Optional uncensored model ID" },
                                    "cwd": { "type": "string", "description": "Working directory (default /root/agy-workspace)" },
                                    "max_steps": { "type": "integer", "description": "Maximum tool steps (default 40, max 100)" },
                                    "session_key": { "type": "string", "description": "Optional persistent multi-turn session key" },
                                    "system_prompt": { "type": "string", "description": "Optional custom system prompt" },
                                    "attach_paths": { "type": "array", "items": { "type": "string" }, "description": "Optional local file, directory, or .zip paths to pack into .md and attach to task" },
                                    "three_stage": { "description": "3-stage background memory + SkillHub + chunked coding pipeline: 'auto' (default), 'always' (or true), 'off' (or false)" }
                                },
                                "required": ["task"]
                            }
                        },
                        {
                            "name": "uncensored_glob",
                            "description": "Fast recursive file discovery by glob pattern (e.g. '**/*.rs', 'src/*.{ts,tsx}') skipping .git/target/node_modules/.venv.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "pattern": { "type": "string", "description": "Glob pattern" },
                                    "path": { "type": "string", "description": "Directory to search (default workspace)" },
                                    "max_results": { "type": "integer", "description": "Max files (default 100, max 300)" }
                                },
                                "required": ["pattern"]
                            }
                        },
                        {
                            "name": "uncensored_find_symbols",
                            "description": "Fast multi-language code symbol indexer (Rust, Python, TS/JS, Go, PHP, Java, C/C++, Ruby, Shell) returning file:line declarations.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": { "type": "string", "description": "Directory or file to scan (default workspace)" },
                                    "query": { "type": "string", "description": "Optional substring filter" },
                                    "file_glob": { "type": "string", "description": "Optional file glob filter (e.g. '*.rs')" },
                                    "max_results": { "type": "integer", "description": "Max symbols (default 100, max 200)" }
                                }
                            }
                        },
                        {
                            "name": "uncensored_pack_md",
                            "description": "Convert a code file, directory, or .zip archive into a structured .md bundle (directory tree, folder-to-file map, symbol map, and code blocks) for Venice API.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": { "type": "string", "description": "Path to .zip archive, directory, or code file" },
                                    "output_path": { "type": "string", "description": "Optional .md file path to save the bundle" },
                                    "include_extensions": { "type": "array", "items": { "type": "string" }, "description": "Optional extension filter" },
                                    "exclude_patterns": { "type": "array", "items": { "type": "string" }, "description": "Optional path/name substrings to exclude" },
                                    "include_line_numbers": { "type": "boolean", "description": "Include line numbers (default true)" },
                                    "include_symbols": { "type": "boolean", "description": "Include symbol map (default true)" }
                                },
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "uncensored_apply_md",
                            "description": "Unpack ### `rel/path` fenced code blocks from a .md bundle back onto disk safely (only writes files present in the markdown, never touches unrelated files).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "target_dir": { "type": "string", "description": "Project root directory" },
                                    "markdown": { "type": "string", "description": "Markdown content with ### `path` code blocks" },
                                    "markdown_path": { "type": "string", "description": "Optional path to a .md file instead of inline markdown" },
                                    "dry_run": { "type": "boolean", "description": "Preview without writing (default false)" }
                                },
                                "required": ["target_dir"]
                            }
                        },
                        {
                            "name": "uncensored_verify",
                            "description": "Run auto-detected (Rust/Python/TS/Go/PHP/Bash) or custom health checks on a project and return PASS or a structured errors.md with source context.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "project_dir": { "type": "string", "description": "Project root directory" },
                                    "commands": { "type": "array", "items": { "type": "string" }, "description": "Optional custom check commands" },
                                    "run_tests": { "type": "boolean", "description": "Also run unit tests (default false)" },
                                    "timeout_secs": { "type": "integer", "description": "Timeout per command (default 45)" },
                                    "errors_md_path": { "type": "string", "description": "Optional path to write errors.md" }
                                },
                                "required": ["project_dir"]
                            }
                        },
                        {
                            "name": "uncensored_dev_loop",
                            "description": "Autonomous OpenHands/Markdown dev/fix loop: either fast .md round-trip (default) or full agentic=true autonomous multi-tool coding + verify_project loop until healthy.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "project_dir": { "type": "string", "description": "Project root directory" },
                                    "task": { "type": "string", "description": "Task or fix instruction" },
                                    "commands": { "type": "array", "items": { "type": "string" }, "description": "Optional custom verification commands" },
                                    "run_tests": { "type": "boolean", "description": "Run unit tests during verification (default false)" },
                                    "max_iters": { "type": "integer", "description": "Max fix iterations (default 4, max 10)" },
                                    "agentic": { "type": "boolean", "description": "Use full autonomous OpenHands agent with all tools per iteration instead of single-shot .md unpack (default false)" },
                                    "model": { "type": "string", "description": "Optional uncensored model ID" },
                                    "search_on_error": { "type": "boolean", "description": "Use search-v3 to look up unfamiliar errors (default true)" }
                                },
                                "required": ["project_dir", "task"]
                            }
                        }
                    ]
                }
            }),
            "tools/call" => {
                let tname = params.get("name").and_then(Value::as_str).unwrap_or("");
                let targs = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                let (_tx, rx) = watch::channel(false);

                match tname {
                    "uncensored_models" => {
                        let ms = ensure_uncensored_models(&state_dir, &api_base, &api_key).await;
                        let body = serde_json::to_string_pretty(&ms).unwrap_or_else(|_| "[]".to_string());
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": { "content": [{ "type": "text", "text": body }] }
                        })
                    }
                    "uncensored_chat" => {
                        let raw_prompt = targs.get("prompt").and_then(Value::as_str).unwrap_or("");
                        let prompt = prepend_packed_attachments(raw_prompt, &targs, &workspace).await;
                        let model = targs
                            .get("model")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .unwrap_or(DEFAULT_UNCENSORED_MODEL);
                        let sys = targs.get("system_prompt").and_then(Value::as_str);
                        match run_uncensored_agent(
                            &api_base,
                            &api_key,
                            model,
                            &prompt,
                            &workspace,
                            &workspace,
                            &mcp_config,
                            &skills_dir,
                            &state_dir,
                            None,
                            true,
                            true,
                            false,
                            Some(1),
                            sys,
                            None,
                            rx,
                        )
                        .await
                        {
                            Ok(res) if res.error.is_none() => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": { "content": [{ "type": "text", "text": res.text }] }
                            }),
                            Ok(res) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "isError": true,
                                    "content": [{ "type": "text", "text": res.error.map(|e| e.to_string()).unwrap_or_else(|| "empty response".to_string()) }]
                                }
                            }),
                            Err(e) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "isError": true,
                                    "content": [{ "type": "text", "text": redact_secrets_in_text(&e.to_string()) }]
                                }
                            }),
                        }
                    }
                    "uncensored_agent" => {
                        let raw_task = targs
                            .get("task")
                            .or_else(|| targs.get("prompt"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let cwd = targs
                            .get("cwd")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .map(PathBuf::from)
                            .unwrap_or_else(|| workspace.clone());
                        let task = prepend_packed_attachments(raw_task, &targs, &cwd).await;
                        let model = targs
                            .get("model")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .unwrap_or(DEFAULT_UNCENSORED_MODEL);
                        let max_steps = targs
                            .get("max_steps")
                            .and_then(Value::as_u64)
                            .map(|n| n as usize);
                        let session_key = targs
                            .get("session_key")
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string);
                        let sys = targs.get("system_prompt").and_then(Value::as_str);
                        let three_stage = match targs.get("three_stage") {
                            Some(Value::Bool(true)) => ThreeStageMode::Always,
                            Some(Value::Bool(false)) => ThreeStageMode::Off,
                            Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
                                "always" | "on" | "true" | "1" => ThreeStageMode::Always,
                                "off" | "false" | "0" => ThreeStageMode::Off,
                                _ => ThreeStageMode::Auto,
                            },
                            _ => ThreeStageMode::Auto,
                        };

                        info!(model = %model, ?three_stage, "mcp-uncensored executing autonomous agent task");
                        match run_uncensored_agent_with_stage(
                            &api_base,
                            &api_key,
                            model,
                            &task,
                            &cwd,
                            &workspace,
                            &mcp_config,
                            &skills_dir,
                            &state_dir,
                            session_key,
                            true,
                            true,
                            true,
                            max_steps,
                            sys,
                            three_stage,
                            None,
                            rx,
                        )
                        .await
                        {
                            Ok(res) if res.error.is_none() => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": { "content": [{ "type": "text", "text": res.text }] }
                            }),
                            Ok(res) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "isError": true,
                                    "content": [{ "type": "text", "text": res.error.map(|e| e.to_string()).unwrap_or_else(|| "agent returned empty output".to_string()) }]
                                }
                            }),
                            Err(e) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "isError": true,
                                    "content": [{ "type": "text", "text": redact_secrets_in_text(&e.to_string()) }]
                                }
                            }),
                        }
                    }
                    "uncensored_glob" => {
                        let pattern = targs.get("pattern").and_then(Value::as_str).unwrap_or("").to_string();
                        let raw_path = targs.get("path").and_then(Value::as_str).filter(|s| !s.trim().is_empty());
                        let root = match raw_path {
                            Some(p) if Path::new(p).is_absolute() => PathBuf::from(p),
                            Some(p) => workspace.join(p),
                            None => workspace.clone(),
                        };
                        let max_results = targs.get("max_results").and_then(Value::as_u64).unwrap_or(100) as usize;
                        let out = tokio::task::spawn_blocking(move || crate::openhands::glob_files(&root, &pattern, max_results))
                            .await
                            .unwrap_or_else(|e| format!("Error: {e}"));
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": { "content": [{ "type": "text", "text": out }] }
                        })
                    }
                    "uncensored_find_symbols" => {
                        let query = targs.get("query").and_then(Value::as_str).map(str::to_string);
                        let file_glob = targs.get("file_glob").and_then(Value::as_str).map(str::to_string);
                        let raw_path = targs.get("path").and_then(Value::as_str).filter(|s| !s.trim().is_empty());
                        let root = match raw_path {
                            Some(p) if Path::new(p).is_absolute() => PathBuf::from(p),
                            Some(p) => workspace.join(p),
                            None => workspace.clone(),
                        };
                        let max_results = targs.get("max_results").and_then(Value::as_u64).unwrap_or(100) as usize;
                        let out = tokio::task::spawn_blocking(move || {
                            crate::openhands::find_symbols(&root, query.as_deref(), file_glob.as_deref(), max_results)
                        })
                        .await
                        .unwrap_or_else(|e| format!("Error: {e}"));
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": { "content": [{ "type": "text", "text": out }] }
                        })
                    }
                    "uncensored_pack_md" => {
                        let raw_path = targs.get("path").and_then(Value::as_str).unwrap_or("");
                        let p = PathBuf::from(raw_path);
                        let target = if p.is_absolute() { p } else { workspace.join(p) };
                        let mut opts = crate::code_to_md::PackOptions::new(target);
                        if let Some(out_raw) = targs.get("output_path").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                            let op = PathBuf::from(out_raw);
                            opts.output_path = Some(if op.is_absolute() { op } else { workspace.join(op) });
                        }
                        if let Some(arr) = targs.get("include_extensions").and_then(Value::as_array) {
                            opts.include_extensions = arr.iter().filter_map(Value::as_str).map(str::to_string).collect();
                        }
                        if let Some(arr) = targs.get("exclude_patterns").and_then(Value::as_array) {
                            opts.exclude_patterns = arr.iter().filter_map(Value::as_str).map(str::to_string).collect();
                        }
                        if let Some(v) = targs.get("include_line_numbers").and_then(Value::as_bool) {
                            opts.include_line_numbers = v;
                        }
                        if let Some(v) = targs.get("include_symbols").and_then(Value::as_bool) {
                            opts.include_symbols = v;
                        }
                        match crate::code_to_md::pack_to_markdown(&opts).await {
                            Ok(res) => {
                                let text = if let Some(ref saved) = res.output_path {
                                    format!(
                                        "Saved structured .md to {}\nSource: {} | Folders: {} | Files: {} ({} included, {} skipped) | Lines: {}\n\n{}",
                                        saved.display(),
                                        res.source_kind,
                                        res.total_folders,
                                        res.total_files,
                                        res.included_files,
                                        res.skipped_files,
                                        res.total_lines,
                                        res.markdown
                                    )
                                } else {
                                    res.markdown
                                };
                                json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": { "content": [{ "type": "text", "text": text }] }
                                })
                            }
                            Err(e) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "isError": true,
                                    "content": [{ "type": "text", "text": e }]
                                }
                            }),
                        }
                    }
                    "uncensored_apply_md" => {
                        let raw_dir = targs.get("target_dir").and_then(Value::as_str).unwrap_or("");
                        let p = PathBuf::from(raw_dir);
                        let target_dir = if p.is_absolute() { p } else { workspace.join(p) };
                        let md_res: std::result::Result<String, String> = if let Some(md) = targs.get("markdown").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                            Ok(md.to_string())
                        } else if let Some(mdp) = targs.get("markdown_path").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                            let mp = PathBuf::from(mdp);
                            let full = if mp.is_absolute() { mp } else { workspace.join(mp) };
                            std::fs::read_to_string(&full).map_err(|e| format!("failed reading {}: {e}", full.display()))
                        } else {
                            Err("provide either 'markdown' or 'markdown_path'".to_string())
                        };
                        match md_res {
                            Ok(markdown) => {
                                let dry_run = targs.get("dry_run").and_then(Value::as_bool).unwrap_or(false);
                                match crate::code_to_md::unpack_from_markdown(&crate::code_to_md::UnpackOptions {
                                    target_dir,
                                    markdown,
                                    dry_run,
                                }).await {
                                    Ok(res) => json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "result": { "content": [{ "type": "text", "text": serde_json::to_string_pretty(&res).unwrap_or_default() }] }
                                    }),
                                    Err(e) => json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "result": { "isError": true, "content": [{ "type": "text", "text": e }] }
                                    }),
                                }
                            }
                            Err(e) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": { "isError": true, "content": [{ "type": "text", "text": e }] }
                            }),
                        }
                    }
                    "uncensored_verify" => {
                        let raw_dir = targs.get("project_dir").and_then(Value::as_str).unwrap_or("");
                        let p = PathBuf::from(raw_dir);
                        let project_dir = if p.is_absolute() { p } else { workspace.join(p) };
                        let mut opts = crate::code_to_md::VerifyOptions::new(project_dir);
                        if let Some(arr) = targs.get("commands").and_then(Value::as_array) {
                            opts.commands = arr.iter().filter_map(Value::as_str).map(str::to_string).collect();
                        }
                        if let Some(rt) = targs.get("run_tests").and_then(Value::as_bool) {
                            opts.run_tests = rt;
                        }
                        if let Some(ts) = targs.get("timeout_secs").and_then(Value::as_u64) {
                            opts.timeout_secs = ts;
                        }
                        if let Some(ep) = targs.get("errors_md_path").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                            let ep_p = PathBuf::from(ep);
                            opts.errors_md_path = Some(if ep_p.is_absolute() { ep_p } else { workspace.join(ep_p) });
                        }
                        match crate::code_to_md::verify_project(&opts).await {
                            Ok(res) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": { "content": [{ "type": "text", "text": res.errors_md }] }
                            }),
                            Err(e) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": { "isError": true, "content": [{ "type": "text", "text": e }] }
                            }),
                        }
                    }
                    "uncensored_dev_loop" => {
                        let raw_dir = targs.get("project_dir").and_then(Value::as_str).unwrap_or("");
                        let p = PathBuf::from(raw_dir);
                        let project_dir = if p.is_absolute() { p } else { workspace.join(p) };
                        let task = targs.get("task").and_then(Value::as_str).unwrap_or("");
                        let model = targs
                            .get("model")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .unwrap_or(DEFAULT_UNCENSORED_MODEL);
                        let max_iters = targs.get("max_iters").and_then(Value::as_u64).unwrap_or(4).clamp(1, 10) as usize;
                        let run_tests = targs.get("run_tests").and_then(Value::as_bool).unwrap_or(false);
                        let search_on_error = targs.get("search_on_error").and_then(Value::as_bool).unwrap_or(true);
                        let agentic = targs.get("agentic").and_then(Value::as_bool).unwrap_or(false);
                        let commands: Vec<String> = targs
                            .get("commands")
                            .and_then(Value::as_array)
                            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                            .unwrap_or_default();

                        let dev_res = if agentic {
                            let mut agent_prompt = format!(
                                "Project directory: {}\nTask: {task}\nUse file_editor/patch_file/glob_files/find_symbols/git_ops/execute_code to complete the task cleanly, then run verify_project(project_dir=\"{}\", run_tests={run_tests}) and fix any errors before finishing.",
                                project_dir.display(),
                                project_dir.display()
                            );
                            if !commands.is_empty() {
                                agent_prompt.push_str(&format!("\nCustom verification commands: {:?}", commands));
                            }
                            match run_uncensored_agent(
                                &api_base,
                                &api_key,
                                model,
                                &agent_prompt,
                                &project_dir,
                                &workspace,
                                &mcp_config,
                                &skills_dir,
                                &state_dir,
                                None,
                                true,
                                true,
                                true,
                                Some((max_iters * 12).min(100)),
                                None,
                                None,
                                rx,
                            )
                            .await
                            {
                                Ok(r) if r.error.is_none() => Ok(r.text),
                                Ok(r) => Err(r.error.map(|e| e.to_string()).unwrap_or_else(|| "agentic dev loop failed".to_string())),
                                Err(e) => Err(e.to_string()),
                            }
                        } else {
                            run_uncensored_dev_loop(
                                &api_base,
                                &api_key,
                                model,
                                &project_dir,
                                task,
                                commands,
                                run_tests,
                                max_iters,
                                search_on_error,
                                &workspace,
                                &mcp_config,
                                &skills_dir,
                                &state_dir,
                                rx,
                            )
                            .await
                        };

                        match dev_res {
                            Ok(report) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": { "content": [{ "type": "text", "text": report }] }
                            }),
                            Err(e) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": { "isError": true, "content": [{ "type": "text", "text": redact_secrets_in_text(&e) }] }
                            }),
                        }
                    }
                    other => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": format!("Unknown tool: {other}") }
                    }),
                }
            }
            other => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("Method not found: {other}") }
            }),
        };

        let mut encoded = serde_json::to_vec(&response)
            .map_err(|e| BridgeError::json("serializing mcp-uncensored response", e))?;
        encoded.push(b'\n');
        stdout
            .write_all(&encoded)
            .await
            .map_err(|e| BridgeError::io("writing mcp-uncensored stdout", e))?;
        let _ = stdout.flush().await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncensored_model_helpers() {
        assert!(is_uncensored_model("veniceai/deepseek-v4-1-flash-1017-uncensored"));
        assert!(is_uncensored_model("uncensored:foo"));
        assert!(!is_uncensored_model("grok-4.7"));
        assert_eq!(clean_model_id("uncensored:abc"), "abc");
        assert!(DEFAULT_VENICE_API_KEY.is_empty());
        assert!(!UNCENSORED_AGENT_SYSTEM_PROMPT.contains("searxng"));
        assert!(UNCENSORED_AGENT_SYSTEM_PROMPT.contains("search-v3"));

        let v1 = crate::code_to_md::VerifyResult {
            passed: false,
            checks: vec![crate::code_to_md::VerifyCheckOutput {
                command: "cargo check".to_string(),
                exit_code: 101,
                passed: false,
                duration_ms: 1200,
                output: "error[E0425]: cannot find value `foo` in this scope".to_string(),
            }],
            errors_md: "# ❌ Verification Errors\n| cargo check | FAIL | 101 | 1200 ms |".to_string(),
            errors_md_path: None,
        };
        let v2 = crate::code_to_md::VerifyResult {
            passed: false,
            checks: vec![crate::code_to_md::VerifyCheckOutput {
                command: "cargo check".to_string(),
                exit_code: 101,
                passed: false,
                duration_ms: 1550,
                output: "error[E0425]: cannot find value `foo` in this scope".to_string(),
            }],
            errors_md: "# ❌ Verification Errors\n| cargo check | FAIL | 101 | 1550 ms |".to_string(),
            errors_md_path: None,
        };
        assert_eq!(
            normalize_verify_error_fingerprint(&v1),
            normalize_verify_error_fingerprint(&v2)
        );
        let q = extract_primary_error_query(&v1).expect("must extract real compiler error");
        assert!(q.contains("E0425"));
        assert!(!q.contains("Verification Errors"));

        // Legacy Cloudflare-403 venice-web/, ven/, and unfunded hanz/ models auto-upgrade to healthy veniceai/
        assert_eq!(clean_model_id("venice-web/venice-uncensored"), "veniceai/venice-uncensored-1-2");
        assert_eq!(clean_model_id("ven/venice-uncensored-1.2"), "veniceai/venice-uncensored-1-2");
        assert_eq!(clean_model_id("hanz/cognitivecomputations/dolphin-mistral-24b-venice-edition"), "veniceai/venice-uncensored-1-2");
        assert_eq!(model_max_tokens("veniceai/venice-uncensored-role-play"), 4096);
        assert_eq!(model_max_tokens("veniceai/gemma-4-uncensored"), 8192);
        assert_eq!(model_max_tokens("veniceai/deepseek-v4-1-flash-1017-uncensored"), 16384);
        let chain = fallback_failover_chain("veniceai/deepseek-v4-1-flash-1017-uncensored");
        assert!(chain.len() >= 3);
        assert!(!chain.iter().any(|m| m == "veniceai/deepseek-v4-1-flash-1017-uncensored"));
        assert_eq!(chain[0], "veniceai/glm-5-3-flash-uncensored");
    }

    #[tokio::test]
    async fn custom_sysprompt_persistence_and_attachment_enrichment() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");

        // Full 32KB system prompt persists with zero truncation
        let big_prompt = format!("START\n{}\nEND_32K", "Rule sentence. ".repeat(2000));
        let saved = save_custom_sysprompt(&state_dir, 42, &big_prompt).unwrap();
        assert_eq!(saved, big_prompt.len());
        let loaded = load_custom_sysprompt(&state_dir, 42).unwrap();
        assert_eq!(loaded, big_prompt);
        assert!(clear_custom_sysprompt(&state_dir, 42));
        assert!(load_custom_sysprompt(&state_dir, 42).is_none());

        // Attachment enrichment inlines compact code completely for Agent mode and full 120K for Chat mode
        let py_file = dir.path().join("calc.py");
        std::fs::write(&py_file, "def add(a, b):\n    return a + b\n").unwrap();
        let enriched = enrich_prompt_with_attachments("Fix bugs", &[py_file], true).await;
        assert!(enriched.contains("VERIFIED ATTACHMENT MANIFEST"));
        assert!(enriched.contains("def add(a, b):"));

        // Large >12KB file in Agent mode emits lean manifest + preview instead of dumping 28KB into Step 1
        let big_py = dir.path().join("big.py");
        std::fs::write(&big_py, format!("# top\n{}", "def f(): return 1\n".repeat(1200))).unwrap();
        let big_enriched = enrich_prompt_with_attachments("Fix", &[big_py], true).await;
        assert!(big_enriched.contains("Large attachment"));
        assert!(big_enriched.len() < 4000);

        // Unfunded hanz/ and broken venice-web/ entries are filtered out when loading cached models
        save_cached_uncensored_models(
            &state_dir,
            &[
                UncensoredModel {
                    id: "hanz/cognitivecomputations/dolphin-mistral-24b-venice-edition".into(),
                    name: "Dolphin".into(),
                    context_length: Some(128000),
                    tool_calling: true,
                },
                UncensoredModel {
                    id: "venice-web/venice-uncensored".into(),
                    name: "VenWeb".into(),
                    context_length: Some(128000),
                    tool_calling: true,
                },
                UncensoredModel {
                    id: "veniceai/deepseek-v4-1-flash-1017-uncensored".into(),
                    name: "DeepSeek".into(),
                    context_length: Some(1000000),
                    tool_calling: true,
                },
            ],
        )
        .unwrap();
        let loaded_models = load_cached_uncensored_models(&state_dir);
        assert_eq!(loaded_models.len(), 1);
        assert_eq!(loaded_models[0].id, "veniceai/deepseek-v4-1-flash-1017-uncensored");
    }
}
