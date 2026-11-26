//! OpenHands V1 / CodeActAgent professional coding primitives for `agent_runtime`:
//! - Per-file edit snapshot history & `undo_edit` rollback stack ([`EditHistory`])
//! - Structured multi-step plan & milestone memory ([`TaskTracker`])
//! - Line-based insertion ([`insert_at_line`]) for `file_editor` (`str_replace_editor`)
//! - Repository microagents auto-discovery & YAML trigger matching ([`load_repo_microagents`])
//! - Fast recursive file discovery ([`glob_files`]) and multi-language symbol indexer ([`find_symbols`])
//! - First-class Git inspection, diff, checkpoint & restore ([`run_git_ops`])

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex as StdMutex, OnceLock};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::exec_backend::{run_exec_command, ExecOptions};
use crate::mcp_client::redact_secrets_in_text;

/// Maximum undo snapshots retained per file path during a turn.
const MAX_UNDO_SNAPSHOTS_PER_FILE: usize = 12;
/// Maximum bytes of combined repo microagents injected into system prompt.
const MAX_MICROAGENT_BYTES: usize = 8 * 1024;

/// Build the unified, action-first OpenHands V1 Pro Coding system prompt shared across
/// ALL agent engines (Venice Uncensored, xAI Grok, and delegated sub-agents).
pub fn build_openhands_agent_prompt(agent_identity: &str) -> String {
    format!(
        "You are {agent_identity}, operating as an action-first, OpenHands-grade autonomous AI software engineering agent on an Ubuntu server.\n\
Core Pro Coding & Speed Tools (31 live tools):\n\
- Programmatic Batching (5-10x FASTER): execute_code (Python 3 Unix-socket RPC with 24 agy_tools functions, up to 150 calls in ONE turn, 300s timeout — collapse multi-file reads/greps/edits/git/MCP/verify into 1 turn!)\n\
- Code Editing & Rollback: batch_read (read up to 20 files concurrently in 1 call), multi_edit (apply up to 25 surgical edits across files in 1 call w/ undo_edit snapshots), file_editor (OpenHands str_replace_editor: view, create, str_replace, insert at line, undo_edit rollback stack), read_file, write_file (append=true for large files), patch_file/edit_file (unique/fuzzy/unified diff + differential syntax check)\n\
- Codebase Discovery & Git: glob_files (**/*.rs, *.py), find_symbols (multi-language fn/struct/class/trait indexer), grep_files (regex + glob + context_lines), list_dir, git_ops (status, diff, log, branch, checkpoint, restore)\n\
- Planning & Project Packs: task_tracker (plan/update/view checklist preserved across compaction), think, finish, code_to_md (.zip/dir -> .md), md_to_code (.md -> disk), verify_project (auto-detect Rust/Python/TS/Go/PHP/Bash -> PASS or errors.md)\n\
- Shell & Persistent PTYs: run_command (bash, builds, tests, timeout 600s, background/pty tmux, optional bubblewrap sandbox), process_manage (list/poll/wait/log/write/kill persistent tmux sessions)\n\
- Vision, Memory, Skills & MCPs: inspect_image (multimodal vision), web_search & fetch_url (search-v3), memory_search & memory_store (ai-memory), search_skills/load_skill/skillhub_*, call_mcp_tool (up to 50/turn: context7, gortex, graphify, search-v3, openhands, ai-memory, skillport, skillhub)\n\
Execution & Speed Discipline:\n\
1. ACT IMMEDIATELY & BATCH PARALLEL: Never stall in planning mode or ask permission when the user already asked you to inspect/write/fix/test/send code. Emit independent read/search/git-inspect calls together in ONE turn (they execute in parallel waves of up to 12) or batch 10-150 ops inside ONE execute_code Python RPC script.\n\
2. TELEGRAM FILE DELIVERY: Whenever the user asks for code, a fixed file, a project, or a report, write it directly into the `outbox/.../` folder path given in the prompt so Telegram delivers it automatically.\n\
3. SURGICAL EDITS & VERIFICATION: Prefer file_editor (str_replace/insert/undo_edit) or patch_file over full rewrites; use task_tracker for multi-file tasks; always run verify_project or tests before calling finish.\n\
4. ZERO GUESSING & NO LOOPS: Ground every claim in fresh tool output. Never repeat a failing call twice; roll back bad edits with undo_edit if needed, and never reveal secrets/keys."
    )
}
/// Directories skipped by `glob_files` and `find_symbols`.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".cache",
    "dist",
    "build",
    ".next",
    ".pytest_cache",
    ".mypy_cache",
];

/// Per-file edit history stack enabling OpenHands `file_editor(command="undo_edit")`
/// and tracking all modified paths for Condenser summaries.
#[derive(Default)]
pub struct EditHistory {
    /// Stack of pre-edit raw byte snapshots (`None` = file did not exist prior to edit).
    stacks: StdMutex<HashMap<PathBuf, Vec<Option<Vec<u8>>>>>,
    /// Ordered set of modified paths touched in this turn.
    modified: StdMutex<BTreeSet<String>>,
}

impl EditHistory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the current file bytes (or `None` if absent) before a write/patch/insert.
    pub fn record_before_write(&self, path: &Path) {
        let prev = match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.is_file() || meta.file_type().is_symlink() => {
                match std::fs::read(path) {
                    Ok(bytes) => Some(bytes),
                    Err(_) => return, // refuse to record a false `None` snapshot that would delete the file on undo
                }
            }
            Ok(_) => return,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return,
        };
        if let Ok(mut map) = self.stacks.lock() {
            let stack = map.entry(path.to_path_buf()).or_default();
            stack.push(prev);
            if stack.len() > MAX_UNDO_SNAPSHOTS_PER_FILE {
                stack.remove(0);
            }
        }
        if let Ok(mut mods) = self.modified.lock() {
            mods.insert(path.display().to_string());
        }
    }

    /// Undo the most recent edit to `path`, restoring previous content or removing a newly created file.
    pub fn undo_last(&self, path: &Path) -> Result<String, String> {
        let prev = {
            let mut map = self
                .stacks
                .lock()
                .map_err(|_| "Error: edit history lock poisoned".to_string())?;
            let Some(stack) = map.get_mut(path) else {
                return Err(format!(
                    "Error: no edit history recorded for {} in this turn.",
                    path.display()
                ));
            };
            let Some(snap) = stack.pop() else {
                return Err(format!(
                    "Error: no remaining edits to undo for {}.",
                    path.display()
                ));
            };
            snap
        };

        match prev {
            Some(old_bytes) => {
                std::fs::write(path, &old_bytes).map_err(|e| {
                    if let Ok(mut map) = self.stacks.lock() {
                        map.entry(path.to_path_buf())
                            .or_default()
                            .push(Some(old_bytes.clone()));
                    }
                    format!("Error restoring {}: {e}", path.display())
                })?;
                let line_cnt = String::from_utf8_lossy(&old_bytes).lines().count();
                Ok(format!(
                    "Undid last edit to {} (restored {} bytes, {} lines).",
                    path.display(),
                    old_bytes.len(),
                    line_cnt
                ))
            }
            None => {
                if path.exists() {
                    std::fs::remove_file(path).map_err(|e| {
                        if let Ok(mut map) = self.stacks.lock() {
                            map.entry(path.to_path_buf()).or_default().push(None);
                        }
                        format!("Error removing newly created {}: {e}", path.display())
                    })?;
                }
                Ok(format!(
                    "Undid creation of {} (file removed).",
                    path.display()
                ))
            }
        }
    }

    /// Return sorted list of files modified during this turn.
    pub fn modified_files(&self) -> Vec<String> {
        self.modified
            .lock()
            .map(|m| m.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// One item in the OpenHands `task_tracker` checklist.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskItem {
    pub id: String,
    pub title: String,
    #[serde(default = "default_todo")]
    pub status: String,
    #[serde(default)]
    pub notes: Option<String>,
}

fn default_todo() -> String {
    "todo".to_string()
}

fn normalize_task_status(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "in_progress" | "in-progress" | "active" | "doing" => "in_progress",
        "done" | "completed" | "complete" => "done",
        "blocked" | "failed" => "blocked",
        _ => "todo",
    }
}

/// Structured OpenHands `task_tracker` state persisted across a multi-step turn
/// and preserved verbatim across Context Condenser compaction events.
#[derive(Default)]
pub struct TaskTracker {
    items: StdMutex<Vec<TaskItem>>,
}

impl TaskTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Execute a `task_tracker` tool call (`command`: `"view"` | `"plan"` | `"update"`).
    pub fn handle_command(&self, args: &Value) -> String {
        let cmd = args
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("view")
            .trim()
            .to_ascii_lowercase();

        match cmd.as_str() {
            "view" => self.render(),
            "plan" => {
                let Some(arr) = args.get("task_list").and_then(Value::as_array) else {
                    return "Error: 'task_list' array is required for task_tracker(command='plan')."
                        .to_string();
                };
                let mut next = Vec::with_capacity(arr.len().min(30));
                for (idx, item) in arr.iter().take(30).enumerate() {
                    let id = item
                        .get("id")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("T{}", idx + 1));
                    let title = item
                        .get("title")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .unwrap_or("")
                        .to_string();
                    if title.is_empty() {
                        continue;
                    }
                    let status = item
                        .get("status")
                        .and_then(Value::as_str)
                        .map(normalize_task_status)
                        .unwrap_or("todo")
                        .to_string();
                    let notes = item
                        .get("notes")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                    next.push(TaskItem {
                        id,
                        title,
                        status,
                        notes,
                    });
                }
                if let Ok(mut guard) = self.items.lock() {
                    *guard = next;
                }
                self.render()
            }
            "update" => {
                let id = args.get("id").and_then(Value::as_str).unwrap_or("").trim();
                if id.is_empty() {
                    return "Error: 'id' is required for task_tracker(command='update').".to_string();
                }
                let new_status = args
                    .get("status")
                    .and_then(Value::as_str)
                    .map(normalize_task_status);
                let new_notes = args
                    .get("notes")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .map(str::to_string);
                let mut found = false;
                if let Ok(mut guard) = self.items.lock() {
                    if let Some(it) = guard.iter_mut().find(|t| t.id == id) {
                        if let Some(st) = new_status {
                            it.status = st.to_string();
                        }
                        if let Some(n) = new_notes {
                            it.notes = if n.is_empty() { None } else { Some(n) };
                        }
                        found = true;
                    }
                }
                if !found {
                    return format!("Error: task id '{id}' not found. Call view to inspect IDs.");
                }
                self.render()
            }
            other => format!(
                "Error: unknown task_tracker command '{other}' (use 'view', 'plan', or 'update')."
            ),
        }
    }

    pub fn render(&self) -> String {
        let items = self.items.lock().map(|g| g.clone()).unwrap_or_default();
        if items.is_empty() {
            return "Task tracker is empty. Use command='plan' with task_list=[{id, title, status}] to create a plan.".to_string();
        }
        let done = items.iter().filter(|t| t.status == "done").count();
        let mut out = format!("Task Plan ({done}/{} done):\n", items.len());
        for it in &items {
            let icon = match it.status.as_str() {
                "done" => "[x]",
                "in_progress" => "[~]",
                "blocked" => "[!]",
                _ => "[ ]",
            };
            out.push_str(&format!("- {icon} `{}`: {}", it.id, it.title));
            if let Some(ref n) = it.notes {
                out.push_str(&format!(" — {n}"));
            }
            out.push('\n');
        }
        out
    }

    /// Compact representation for Condenser state preservation (returns `None` when empty).
    pub fn compact_summary(&self) -> Option<String> {
        let items = self.items.lock().map(|g| g.clone()).unwrap_or_default();
        if items.is_empty() {
            return None;
        }
        Some(self.render())
    }
}

/// Insert `new_str` after 1-based `insert_line` (`0` inserts at the very top of the file).
pub fn insert_at_line(existing: &str, insert_line: usize, new_str: &str) -> Result<String, String> {
    let had_trailing_nl = existing.ends_with('\n');
    let mut lines: Vec<&str> = if existing.is_empty() {
        Vec::new()
    } else {
        existing.lines().collect()
    };
    if insert_line > lines.len() {
        return Err(format!(
            "Error: insert_line {insert_line} out of range (file has {} lines).",
            lines.len()
        ));
    }
    let insert_lines: Vec<&str> = new_str.split('\n').collect();
    let tail = lines.split_off(insert_line);
    lines.extend(insert_lines);
    lines.extend(tail);
    let mut out = lines.join("\n");
    if (had_trailing_nl || existing.is_empty()) && !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// Parse optional YAML frontmatter (`--- ... ---`) from a microagent markdown file,
/// returning `(triggers, is_always_repo, body)`.
fn parse_microagent_frontmatter(raw: &str) -> (Vec<String>, bool, &str) {
    let trimmed = raw.trim_start();
    if !trimmed.starts_with("---") {
        return (Vec::new(), true, raw);
    }
    let after_first = &trimmed[3..];
    let Some(end_idx) = after_first.find("\n---") else {
        return (Vec::new(), true, raw);
    };
    let fm = &after_first[..end_idx];
    let body = after_first[end_idx + 4..].trim_start();

    let mut triggers = Vec::new();
    let mut is_repo = false;
    let mut in_triggers_list = false;

    for line in fm.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(rest) = l.strip_prefix("type:") {
            if rest.trim().eq_ignore_ascii_case("repo") {
                is_repo = true;
            }
            in_triggers_list = false;
        } else if let Some(rest) = l.strip_prefix("triggers:") {
            let r = rest.trim();
            if r.starts_with('[') && r.ends_with(']') {
                for tok in r[1..r.len() - 1].split(',') {
                    let t = tok.trim().trim_matches(|c| c == '"' || c == '\'');
                    if !t.is_empty() {
                        triggers.push(t.to_ascii_lowercase());
                    }
                }
                in_triggers_list = false;
            } else {
                in_triggers_list = true;
            }
        } else if in_triggers_list && l.starts_with('-') {
            let t = l
                .trim_start_matches('-')
                .trim()
                .trim_matches(|c| c == '"' || c == '\'');
            if !t.is_empty() {
                triggers.push(t.to_ascii_lowercase());
            }
        } else {
            in_triggers_list = false;
        }
    }

    if triggers.is_empty() {
        is_repo = true;
    }
    (triggers, is_repo, body)
}

/// Auto-discover OpenHands repository microagents (`.openhands/microagents/*.md`) and
/// project instruction files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`) in `cwd`.
pub fn load_repo_microagents(cwd: &Path, user_prompt: &str) -> Option<String> {
    let prompt_low = user_prompt.to_ascii_lowercase();
    let mut sections: Vec<String> = Vec::new();
    let mut used_bytes = 0usize;

    let mut push_doc = |label: &str, text: &str| {
        if used_bytes >= MAX_MICROAGENT_BYTES {
            return;
        }
        let clean = redact_secrets_in_text(text.trim());
        if clean.is_empty() {
            return;
        }
        let budget = MAX_MICROAGENT_BYTES.saturating_sub(used_bytes);
        let mut end = clean.len().min(budget);
        while end > 0 && !clean.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            return;
        }
        let slice = &clean[..end];
        used_bytes += slice.len();
        sections.push(format!("### Microagent: `{label}`\n{slice}"));
    };

    // 1. Always-active repository convention files
    for fname in ["AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules"] {
        let p = cwd.join(fname);
        if p.is_file() {
            if let Ok(raw) = std::fs::read_to_string(&p) {
                push_doc(fname, &raw);
            }
        }
    }

    // 2. OpenHands `.openhands/microagents/*.md` (always-active repo.md + keyword-triggered)
    let ma_dir = cwd.join(".openhands").join("microagents");
    if ma_dir.is_dir() {
        if let Ok(rd) = std::fs::read_dir(&ma_dir) {
            let mut paths: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.is_file()
                        && p.extension()
                            .and_then(|e| e.to_str())
                            .is_some_and(|e| e.eq_ignore_ascii_case("md"))
                })
                .collect();
            paths.sort();

            for p in paths {
                let Ok(raw) = std::fs::read_to_string(&p) else {
                    continue;
                };
                let (triggers, is_repo, body) = parse_microagent_frontmatter(&raw);
                let matched = is_repo || triggers.iter().any(|kw| prompt_low.contains(kw.as_str()));
                if matched {
                    let name = p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("microagent.md");
                    push_doc(&format!(".openhands/microagents/{name}"), body);
                }
            }
        }
    }

    if sections.is_empty() {
        None
    } else {
        Some(format!(
            "Repository Microagents & Project Rules (auto-loaded):\n{}",
            sections.join("\n\n")
        ))
    }
}

/// Convert a glob pattern (`**/*.rs`, `src/*.{ts,tsx}`, `test_?.py`) into a compiled `Regex`.
pub fn glob_to_regex(pattern: &str) -> Result<Regex, String> {
    let norm = pattern.trim().replace('\\', "/");
    let norm = norm.strip_prefix("./").unwrap_or(&norm);
    let chars: Vec<char> = norm.chars().collect();
    let mut re = String::from("^(?:.*/)?");
    if norm.contains('/') {
        re = String::from("^");
    }
    let mut i = 0usize;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    if i + 2 < chars.len() && chars[i + 2] == '/' {
                        re.push_str("(?:.*/)?");
                        i += 3;
                    } else {
                        re.push_str(".*");
                        i += 2;
                    }
                } else {
                    re.push_str("[^/]*");
                    i += 1;
                }
            }
            '?' => {
                re.push_str("[^/]");
                i += 1;
            }
            '{' => {
                if let Some(close) = chars[i + 1..].iter().position(|&c| c == '}') {
                    let inner: String = chars[i + 1..i + 1 + close].iter().collect();
                    let alts: Vec<String> = inner
                        .split(',')
                        .map(|s| regex::escape(s.trim()))
                        .collect();
                    re.push_str("(?:");
                    re.push_str(&alts.join("|"));
                    re.push(')');
                    i += close + 2;
                } else {
                    re.push_str(r"\{");
                    i += 1;
                }
            }
            c => {
                re.push_str(&regex::escape(&c.to_string()));
                i += 1;
            }
        }
    }
    re.push('$');
    Regex::new(&re).map_err(|e| format!("Invalid glob pattern '{pattern}': {e}"))
}

/// Recursively find files matching a glob pattern under `root` (skips `.git`, `target`, `node_modules`, etc.).
pub fn glob_files(root: &Path, pattern: &str, max_results: usize) -> String {
    let re = match glob_to_regex(pattern) {
        Ok(r) => r,
        Err(e) => return format!("Error: {e}"),
    };
    let cap = max_results.clamp(1, 300);
    let mut hits: Vec<(String, u64)> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut scanned = 0usize;

    while let Some(cur) = stack.pop() {
        if scanned >= 15_000 {
            break;
        }
        let Ok(meta) = std::fs::symlink_metadata(&cur) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let skip = cur
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| SKIP_DIRS.contains(&n));
            if skip && cur != root {
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(&cur) {
                for ent in rd.flatten() {
                    stack.push(ent.path());
                }
            }
        } else if meta.is_file() {
            scanned += 1;
            let rel = cur
                .strip_prefix(root)
                .unwrap_or(&cur)
                .to_string_lossy()
                .replace('\\', "/");
            if re.is_match(&rel) {
                hits.push((rel, meta.len()));
            }
        }
    }

    hits.sort_by(|a, b| a.0.cmp(&b.0));
    let total = hits.len();
    hits.truncate(cap);

    if hits.is_empty() {
        format!(
            "No files matched '{pattern}' in {} ({scanned} files scanned).",
            root.display()
        )
    } else {
        let lines: Vec<String> = hits
            .iter()
            .map(|(p, sz)| format!("{sz:>10}  {p}"))
            .collect();
        let trunc = if total > hits.len() {
            format!(" (showing first {} of {total})", hits.len())
        } else {
            String::new()
        };
        format!(
            "Matched {total} file(s) for '{pattern}' in {}{trunc}:\n{}",
            root.display(),
            lines.join("\n")
        )
    }
}

fn symbol_regexes() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        [
            // Rust
            r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?(?:fn|struct|enum|trait|type|mod)\s+([A-Za-z_][A-Za-z0-9_]*)",
            r"^\s*impl(?:<[^>]*>)?\s+([A-Za-z_][A-Za-z0-9_:<>\s]+?)\s*(?:for\s+([A-Za-z_][A-Za-z0-9_:<>]+))?\s*\{",
            // Python
            r"^\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)",
            // JS / TS
            r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function|class|interface|type|enum)\s+([A-Za-z_$][A-Za-z0-9_$]*)",
            r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(",
            // Go
            r"^\s*func\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)",
            r"^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\s+(?:struct|interface)\b",
            // PHP / Java / C# / Ruby / Shell
            r"^\s*(?:public|private|protected|static|final|abstract|\s)*(?:function|class|interface|trait)\s+([A-Za-z_][A-Za-z0-9_]*)",
        ]
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
    })
}

fn is_code_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| {
            matches!(
                e.to_ascii_lowercase().as_str(),
                "rs" | "py" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "go" | "php" | "java"
                    | "kt" | "c" | "cc" | "cpp" | "h" | "hpp" | "rb" | "sh" | "bash" | "cs" | "swift"
            )
        })
}

/// Fast multi-language symbol indexer: locates functions, structs, classes, traits, impls, interfaces.
pub fn find_symbols(
    root: &Path,
    query: Option<&str>,
    file_glob: Option<&str>,
    max_results: usize,
) -> String {
    let glob_re = match file_glob.map(str::trim).filter(|s| !s.is_empty()) {
        Some(g) => match glob_to_regex(g) {
            Ok(r) => Some(r),
            Err(e) => return format!("Error: {e}"),
        },
        None => None,
    };
    let q_low = query
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase);
    let cap = max_results.clamp(1, 200);
    let res = symbol_regexes();

    let mut hits: Vec<String> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut files_scanned = 0usize;

    while let Some(cur) = stack.pop() {
        if hits.len() >= cap || files_scanned >= 3000 {
            break;
        }
        let Ok(meta) = std::fs::symlink_metadata(&cur) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let skip = cur
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| SKIP_DIRS.contains(&n));
            if skip && cur != root {
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(&cur) {
                let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
                entries.sort();
                entries.reverse();
                stack.extend(entries);
            }
        } else if meta.is_file() && meta.len() <= 512 * 1024 {
            let rel = cur
                .strip_prefix(root)
                .unwrap_or(&cur)
                .to_string_lossy()
                .replace('\\', "/");
            if let Some(ref gre) = glob_re {
                if !gre.is_match(&rel) {
                    continue;
                }
            } else if !is_code_extension(&cur) && cur != root {
                continue;
            }
            files_scanned += 1;
            let Ok(text) = std::fs::read_to_string(&cur) else {
                continue;
            };
            for (idx, line) in text.lines().enumerate() {
                if hits.len() >= cap {
                    break;
                }
                let matched = res.iter().any(|r| r.is_match(line));
                if !matched {
                    continue;
                }
                if let Some(ref ql) = q_low {
                    if !line.to_ascii_lowercase().contains(ql.as_str()) {
                        continue;
                    }
                }
                let snippet: String = line.trim().chars().take(140).collect();
                hits.push(format!("{rel}:{}: {snippet}", idx + 1));
            }
        }
    }

    if hits.is_empty() {
        format!(
            "No symbols found (query={:?}, glob={:?}) in {} ({files_scanned} files scanned).",
            query,
            file_glob,
            root.display()
        )
    } else {
        format!(
            "Found {} symbol(s) ({files_scanned} files scanned):\n{}",
            hits.len(),
            hits.join("\n")
        )
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// First-class OpenHands `git_ops` tool (`status` | `diff` | `log` | `branch` | `checkpoint` | `restore`).
pub async fn run_git_ops(
    action: &str,
    args: &Value,
    cwd: &Path,
    workspace_root: &Path,
    allow_root: bool,
    can_exec: bool,
) -> String {
    let act = action.trim().to_ascii_lowercase();
    let is_write = matches!(act.as_str(), "checkpoint" | "restore");
    if is_write && !can_exec {
        return format!(
            "Permission denied: git_ops action '{act}' requires sandbox_exec or root_access."
        );
    }

    let git_cmd = match act.as_str() {
        "status" => "git status --short --branch".to_string(),
        "branch" => "git branch -a --verbose".to_string(),
        "log" => {
            let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(15).clamp(1, 50);
            format!("git log --oneline --decorate -n {limit}")
        }
        "diff" => {
            let staged = args.get("staged").and_then(Value::as_bool).unwrap_or(false);
            let stat = args.get("stat").and_then(Value::as_bool).unwrap_or(false);
            let mut cmd = String::from("git diff");
            if staged {
                cmd.push_str(" --staged");
            }
            if stat {
                cmd.push_str(" --stat");
            }
            if let Some(p) = args.get("path").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                cmd.push_str(" -- ");
                cmd.push_str(&shell_quote(p.trim()));
            }
            cmd
        }
        "checkpoint" => {
            let msg = args
                .get("message")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("openhands-checkpoint");
            format!("git stash push -u -m {}", shell_quote(msg))
        }
        "restore" => {
            let Some(p) = args.get("path").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) else {
                return "Error: 'path' is required for git_ops(action='restore').".to_string();
            };
            format!("git checkout -- {}", shell_quote(p))
        }
        other => {
            return format!(
                "Error: unknown git_ops action '{other}' (use status|diff|log|branch|checkpoint|restore)."
            );
        }
    };

    let mut opts = ExecOptions::for_shell(
        git_cmd,
        cwd.to_path_buf(),
        workspace_root.to_path_buf(),
        30,
        allow_root,
    );
    opts.allow_network = false;
    run_exec_command(&opts).await.format_for_agent()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn edit_history_records_and_undoes_modify_and_create() {
        let dir = TempDir::new().unwrap();
        let existing = dir.path().join("a.txt");
        std::fs::write(&existing, "v1\n").unwrap();

        let hist = EditHistory::new();
        hist.record_before_write(&existing);
        std::fs::write(&existing, "v2\n").unwrap();
        hist.record_before_write(&existing);
        std::fs::write(&existing, "v3\n").unwrap();

        let r1 = hist.undo_last(&existing).unwrap();
        assert!(r1.contains("Undid last edit"));
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "v2\n");

        let r2 = hist.undo_last(&existing).unwrap();
        assert!(r2.contains("Undid last edit"));
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "v1\n");
        assert!(hist.undo_last(&existing).is_err());

        // Undo newly created file deletes it
        let fresh = dir.path().join("created.txt");
        hist.record_before_write(&fresh);
        std::fs::write(&fresh, "hello").unwrap();
        let r3 = hist.undo_last(&fresh).unwrap();
        assert!(r3.contains("file removed"));
        assert!(!fresh.exists());
        assert_eq!(hist.modified_files().len(), 2);
    }

    #[test]
    fn task_tracker_plan_update_view() {
        let tracker = TaskTracker::new();
        assert!(tracker.compact_summary().is_none());

        let planned = tracker.handle_command(&json!({
            "command": "plan",
            "task_list": [
                {"id": "1", "title": "Inspect code", "status": "done"},
                {"id": "2", "title": "Implement feature", "status": "in_progress"}
            ]
        }));
        assert!(planned.contains("1/2 done"));
        assert!(planned.contains("[x] `1`"));
        assert!(planned.contains("[~] `2`"));

        let updated = tracker.handle_command(&json!({
            "command": "update",
            "id": "2",
            "status": "done",
            "notes": "all tests green"
        }));
        assert!(updated.contains("2/2 done"));
        assert!(updated.contains("all tests green"));
    }

    #[test]
    fn insert_at_line_top_middle_bottom_and_bounds() {
        let orig = "line1\nline2\nline3\n";
        assert_eq!(
            insert_at_line(orig, 0, "top").unwrap(),
            "top\nline1\nline2\nline3\n"
        );
        assert_eq!(
            insert_at_line(orig, 2, "midA\nmidB").unwrap(),
            "line1\nline2\nmidA\nmidB\nline3\n"
        );
        assert_eq!(
            insert_at_line(orig, 3, "end").unwrap(),
            "line1\nline2\nline3\nend\n"
        );
        assert!(insert_at_line(orig, 4, "bad").is_err());
    }

    #[test]
    fn microagents_load_repo_and_matching_triggers() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("AGENTS.md"), "Always run cargo test.").unwrap();
        let ma = dir.path().join(".openhands/microagents");
        std::fs::create_dir_all(&ma).unwrap();
        std::fs::write(
            ma.join("rust.md"),
            "---\ntriggers: [cargo, clippy]\n---\nUse clippy -D warnings.\n",
        )
        .unwrap();
        std::fs::write(
            ma.join("docker.md"),
            "---\ntriggers: [dockerfile, compose]\n---\nUse multi-stage builds.\n",
        )
        .unwrap();

        let loaded = load_repo_microagents(dir.path(), "Please fix cargo build error").unwrap();
        assert!(loaded.contains("Always run cargo test."));
        assert!(loaded.contains("Use clippy -D warnings."));
        assert!(!loaded.contains("multi-stage builds"));
    }

    #[test]
    fn glob_files_and_find_symbols_work_accurately() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("src/nested")).unwrap();
        std::fs::write(
            dir.path().join("src/nested/engine.rs"),
            "pub struct HyperEngine {\n    pub workers: usize,\n}\npub async fn launch_engine() {}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("src/helper.py"),
            "class DataLoader:\n    pass\n\ndef compute_score(x):\n    return x * 2\n",
        )
        .unwrap();

        let g = glob_files(dir.path(), "**/*.rs", 50);
        assert!(g.contains("src/nested/engine.rs"), "got: {g}");
        assert!(!g.contains("helper.py"));

        let s1 = find_symbols(dir.path(), Some("launch_engine"), None, 50);
        assert!(s1.contains("src/nested/engine.rs:4:"), "got: {s1}");

        let s2 = find_symbols(dir.path(), None, Some("*.py"), 50);
        assert!(s2.contains("class DataLoader"), "got: {s2}");
        assert!(s2.contains("def compute_score"), "got: {s2}");
    }
}
