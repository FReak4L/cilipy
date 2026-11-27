//! Parallel mode: bot-orchestrated "mother" agents.
//!
//! Plan (lead conversation) → fan-out (up to [`PARALLEL_MAX`] separate `agy` processes, each
//! its own conversation, spread over distinct pool accounts) → merge (lead conversation resumes).
//! Mothers may use agy's native subagents internally; the rule forbids `/swarm` inside them.
//! One edited Telegram status message per run; Stop all / Stop #k buttons.
//!
//! Declared as a child module of `jobs` so it can use `JobManager` internals.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agy_core::accounts::{
    classify_failure, Account, FailureAction, FailureClass, HealthStatus,
};
use agy_core::proxies::ResolvedProxy;
use agy_core::tg::{InlineKeyboardButton, InlineKeyboardMarkup};
use agy_core::store::UserState;
use agy_core::Result;
use agy_ext::engines::{EngineRequest, JobResult, JobStopHandle, Progress, ProgressCallback};
use agy_render::markdown::esc;
use futures_util::stream::{FuturesUnordered, StreamExt};
use serde_json::{json, Value};
use tracing::{info, warn};

use super::{error_parts, human_secs, ActiveJobEntry, JobManager, JobRequest, MAX_ENGINE_ATTEMPTS};
use crate::handoff;

/// Hard cap on concurrent mothers per run.
/// Callback: (account id, failure reason if the attempt failed).
pub(crate) type OnAccount = Arc<dyn Fn(&str, Option<String>) + Send + Sync>;
/// Accounts to avoid (held by sibling workers).
pub(crate) type AvoidFn = Arc<dyn Fn() -> HashSet<String> + Send + Sync>;

pub const PARALLEL_MAX: usize = 3;
/// `UserState.extra` key holding the user's Parallel setting (0 = off, 2, 3).
pub const PARALLEL_SETTING_KEY: &str = "parallel";
/// ACL permission flag that allows a user to use Parallel mode.
pub const PARALLEL_PERM: &str = "parallel";
/// Max concurrent runs of one account inside a parallel run.
pub const PER_ACCOUNT_CONCURRENCY: usize = 2;
/// Default free-memory floor before spawning another mother (override: `PARALLEL_MIN_MEM_MB`).
pub const DEFAULT_MIN_MEM_MB: u64 = 900;
const RESULT_CLIP: usize = 3000;

/// The user's Parallel setting (0 = Off).
pub fn user_parallel_setting(u: &UserState) -> usize {
    u.extra
        .get(PARALLEL_SETTING_KEY)
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .filter(|n| *n >= 2)
        .map(|n| n.min(PARALLEL_MAX))
        .unwrap_or(0)
}

/// `MemAvailable` from `/proc/meminfo`, in MiB.
pub fn mem_available_mb() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    s.lines()
        .find(|l| l.starts_with("MemAvailable:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| kb / 1024)
}

fn min_mem_mb() -> u64 {
    std::env::var("PARALLEL_MIN_MEM_MB")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_MIN_MEM_MB)
}

// ---------------------------------------------------------------------------------------------
// Plan parsing and scheduling
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Subtask {
    pub id: String,
    pub title: String,
    pub brief: String,
    pub owns: Vec<String>,
    pub readonly: bool,
    pub depends_on: Vec<String>,
    /// Planner asked for an isolated git worktree.
    pub needs_worktree: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub reason: String,
    pub subtasks: Vec<Subtask>,
    pub merge_instructions: String,
}

/// Every top-level JSON object embedded in `text` (fenced or bare), in order.
pub fn json_objects(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(off) = text[i..].find('{') {
        let at = i + off;
        let mut it = serde_json::Deserializer::from_str(&text[at..]).into_iter::<Value>();
        match it.next() {
            Some(Ok(v)) if v.is_object() => {
                let used = it.byte_offset();
                out.push(v);
                i = at + used.max(1);
            }
            _ => i = at + 1,
        }
        if i >= text.len() {
            break;
        }
    }
    out
}

fn str_field(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").trim().to_string()
}

fn str_list(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.trim().to_string()).or_else(|| x.as_i64().map(|n| n.to_string())))
                .filter(|s| !s.is_empty())
                .take(32)
                .collect()
        })
        .unwrap_or_default()
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut o: String = s.chars().take(n).collect();
        o.push_str(" …[truncated]");
        o
    }
}

/// Parse the planner reply. `None` = no fan-out (the planner answered directly or said no).
pub fn parse_plan(text: &str, max_subtasks: usize) -> Option<Plan> {
    let obj = json_objects(text)
        .into_iter()
        .rev()
        .find(|v| v.get("subtasks").is_some_and(Value::is_array))?;
    if obj.get("parallel").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let mut seen = HashSet::new();
    let mut subtasks = Vec::new();
    for (i, s) in obj["subtasks"].as_array()?.iter().enumerate() {
        let brief = str_field(s, "brief");
        if brief.is_empty() {
            continue;
        }
        let mut id = match s.get("id") {
            Some(Value::String(x)) if !x.trim().is_empty() => x.trim().to_string(),
            Some(Value::Number(n)) => n.to_string(),
            _ => (i + 1).to_string(),
        };
        if !seen.insert(id.clone()) {
            id = format!("{}-{}", id, i + 1);
            seen.insert(id.clone());
        }
        let mut title = str_field(s, "title");
        if title.is_empty() {
            title = format!("task {}", i + 1);
        }
        subtasks.push(Subtask {
            id,
            title: clip(&title, 60),
            brief: clip(&brief, 4000),
            owns: str_list(s, "owns"),
            readonly: s.get("readonly").and_then(Value::as_bool).unwrap_or(false),
            needs_worktree: s.get("needs_worktree").and_then(Value::as_bool).unwrap_or(false),
            depends_on: str_list(s, "depends_on"),
        });
        if subtasks.len() >= max_subtasks {
            break;
        }
    }
    if subtasks.len() < 2 {
        return None;
    }
    let ids: HashSet<String> = subtasks.iter().map(|s| s.id.clone()).collect();
    for s in &mut subtasks {
        let me = s.id.clone();
        s.depends_on.retain(|d| ids.contains(d) && *d != me);
    }
    Some(Plan {
        reason: clip(&str_field(&obj, "reason"), 300),
        subtasks,
        merge_instructions: clip(&str_field(&obj, "merge_instructions"), 2000),
    })
}

fn norm_path(p: &str) -> String {
    let p = p.trim().trim_start_matches("./");
    let p = match p.find(['*', '?', '[']) {
        Some(i) => &p[..i],
        None => p,
    };
    p.trim_end_matches('/').to_string()
}

/// True when two ownership lists may touch the same files.
pub fn owns_overlap(a: &[String], b: &[String]) -> bool {
    if a.is_empty() || b.is_empty() {
        return true; // a writer without declared ownership may touch anything
    }
    a.iter().any(|raw_x| {
        let x_glob = raw_x.contains(['*', '?', '[']);
        let x = norm_path(raw_x);
        b.iter().any(|raw_y| {
            let y_glob = raw_y.contains(['*', '?', '[']);
            let y = norm_path(raw_y);
            x.is_empty()
                || y.is_empty()
                || x == y
                || y.starts_with(&format!("{x}/"))
                || x.starts_with(&format!("{y}/"))
                || (x_glob && y.starts_with(&x))
                || (y_glob && x.starts_with(&y))
        })
    })
}

/// Which subtasks get their own git worktree: writers whose ownership overlaps another writer
/// (or that asked for one), when the workspace is a git repository.
pub fn isolation_plan(subtasks: &[Subtask], have_git: bool) -> Vec<bool> {
    let n = subtasks.len();
    let mut iso = vec![false; n];
    if !have_git {
        return iso;
    }
    for i in 0..n {
        if subtasks[i].readonly {
            continue;
        }
        if subtasks[i].needs_worktree {
            iso[i] = true;
        }
        for j in 0..n {
            if i != j && !subtasks[j].readonly && owns_overlap(&subtasks[i].owns, &subtasks[j].owns) {
                iso[i] = true;
            }
        }
    }
    iso
}

/// Execution order + prerequisites (indices into the returned order).
/// Explicit `depends_on` edges are honoured (cycles dropped); overlapping writers are serialized.
#[cfg_attr(not(test), allow(dead_code))]
pub fn schedule(subtasks: &[Subtask]) -> (Vec<usize>, Vec<Vec<usize>>) {
    schedule_with(subtasks, &vec![false; subtasks.len()])
}

/// [`schedule`], except that overlapping writers which both run in isolated worktrees
/// (`isolated[i]`) are not serialized: their branches are merged afterwards.
pub fn schedule_with(subtasks: &[Subtask], isolated: &[bool]) -> (Vec<usize>, Vec<Vec<usize>>) {
    let n = subtasks.len();
    let idx: HashMap<&str, usize> = subtasks.iter().enumerate().map(|(i, s)| (s.id.as_str(), i)).collect();
    let mut indeg = vec![0usize; n];
    let mut out_edges: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, s) in subtasks.iter().enumerate() {
        for d in &s.depends_on {
            if let Some(&j) = idx.get(d.as_str()) {
                out_edges[j].push(i);
                indeg[i] += 1;
            }
        }
    }
    let mut order = Vec::with_capacity(n);
    let mut ready: Vec<usize> = (0..n).filter(|&i| indeg[i] == 0).collect();
    while let Some(i) = (!ready.is_empty()).then(|| ready.remove(0)) {
        order.push(i);
        for &k in &out_edges[i] {
            indeg[k] -= 1;
            if indeg[k] == 0 {
                ready.push(k);
                ready.sort_unstable();
            }
        }
    }
    let cyclic: Vec<usize> = (0..n).filter(|i| !order.contains(i)).collect();
    order.extend(cyclic.iter().copied());
    let pos: HashMap<usize, usize> = order.iter().enumerate().map(|(p, &i)| (i, p)).collect();
    let mut deps: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (p, &i) in order.iter().enumerate() {
        let s = &subtasks[i];
        if !cyclic.contains(&i) {
            for d in &s.depends_on {
                if let Some(&j) = idx.get(d.as_str()) {
                    if pos[&j] < p {
                        deps[p].push(pos[&j]);
                    }
                }
            }
        }
        if !s.readonly {
            for q in 0..p {
                let o = &subtasks[order[q]];
                let both_isolated = isolated.get(i).copied().unwrap_or(false) && isolated.get(order[q]).copied().unwrap_or(false);
                if !o.readonly && !both_isolated && owns_overlap(&s.owns, &o.owns) && !deps[p].contains(&q) {
                    deps[p].push(q);
                }
            }
        }
        deps[p].sort_unstable();
    }
    (order, deps)
}

// ---------------------------------------------------------------------------------------------
// Run state
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum MotherStatus {
    Queued,
    Running,
    Done,
    Partial,
    Blocked,
    Failed(String),
    Stopped,
}

impl MotherStatus {
    fn finished(&self) -> bool {
        !matches!(self, MotherStatus::Queued | MotherStatus::Running)
    }
    fn icon(&self) -> &'static str {
        match self {
            MotherStatus::Queued => "⏳",
            MotherStatus::Running => "🟢",
            MotherStatus::Done => "✅",
            MotherStatus::Partial => "🟡",
            MotherStatus::Blocked => "🚧",
            MotherStatus::Failed(_) => "❌",
            MotherStatus::Stopped => "⏹",
        }
    }
    fn label(&self) -> String {
        match self {
            MotherStatus::Queued => "queued".into(),
            MotherStatus::Running => "working".into(),
            MotherStatus::Done => "done".into(),
            MotherStatus::Partial => "partial".into(),
            MotherStatus::Blocked => "blocked".into(),
            MotherStatus::Failed(r) => format!("failed ({r})"),
            MotherStatus::Stopped => "stopped".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MotherState {
    pub k: usize,
    pub title: String,
    pub status: MotherStatus,
    pub account: Option<String>,
    pub started: Option<Instant>,
    pub ended: Option<Instant>,
    pub steps: usize,
    pub last_step: String,
    pub note: Option<String>,
    pub summary: String,
    pub raw: String,
    pub conversation_id: Option<String>,
    /// Files this mother changed outside its ownership (shared-tree mothers).
    pub violations: Vec<String>,
    /// Isolated worktree: (path, branch).
    pub worktree: Option<(std::path::PathBuf, String)>,
}

/// Supervisor record of one parallel run (keyed by `run_id`).
pub struct ParallelRun {
    pub run_id: String,
    pub uid: i64,
    pub chat_id: i64,
    pub dir: std::path::PathBuf,
    pub started: Instant,
    pub phase: Mutex<String>,
    pub mothers: Mutex<Vec<MotherState>>,
    pub stop_all: AtomicBool,
    pub stop_one: Mutex<HashSet<usize>>,
    pub handles: Mutex<HashMap<usize, JobStopHandle>>,
    pub lead_handle: Mutex<Option<JobStopHandle>>,
}

impl ParallelRun {
    fn set_phase(&self, p: &str) {
        if let Ok(mut g) = self.phase.lock() {
            *g = p.to_string();
        }
    }
    fn update<F: FnOnce(&mut MotherState)>(&self, k: usize, f: F) {
        if let Ok(mut g) = self.mothers.lock() {
            if let Some(m) = g.iter_mut().find(|m| m.k == k) {
                f(m);
            }
        }
    }
    fn snapshot(&self) -> Vec<MotherState> {
        self.mothers.lock().map(|g| g.clone()).unwrap_or_default()
    }
    fn is_stopped(&self, k: Option<usize>) -> bool {
        self.stop_all.load(Ordering::SeqCst)
            || k.is_some_and(|k| self.stop_one.lock().map(|g| g.contains(&k)).unwrap_or(false))
    }
    fn append_board(&self, text: &str) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join("board.md")) {
            let _ = writeln!(f, "{text}");
        }
    }
}

fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}m{:02}s", s / 60, s % 60)
    }
}

/// HTML status card (one message per run).
pub fn render_status(run: &ParallelRun, n: usize) -> String {
    let phase = run.phase.lock().map(|g| g.clone()).unwrap_or_default();
    let mut lines = vec![format!(
        "⚡ <b>Parallel run</b> <code>{}</code> · {} agents · {}",
        esc(&run.run_id),
        n,
        fmt_dur(run.started.elapsed())
    )];
    lines.push(format!("🧭 <b>lead</b> · {}", esc(&phase)));
    let mut rows = Vec::new();
    for m in run.snapshot() {
        let dur = match (m.started, m.ended) {
            (Some(s), Some(e)) => fmt_dur(e.duration_since(s)),
            (Some(s), None) => fmt_dur(s.elapsed()),
            _ => String::new(),
        };
        let mut detail = m.status.label();
        if m.status == MotherStatus::Running {
            detail.push_str(&format!(" · {} steps", m.steps));
            if !m.last_step.is_empty() {
                detail.push_str(&format!(" · {}", clip(&m.last_step, 28)));
            }
        }
        if let Some(n) = &m.note {
            detail.push_str(&format!(" · {}", clip(n, 40)));
        }
        if !m.violations.is_empty() {
            detail.push_str(&format!(" · ⚠ {} outside ownership", m.violations.len()));
        }
        if m.worktree.is_some() {
            detail.push_str(" · worktree");
        }
        rows.push(format!(
            "{} {} {:<18} {:<34} {:>7} {}",
            m.status.icon(),
            m.k,
            clip(&m.title, 18),
            clip(&detail, 34),
            dur,
            m.account.as_deref().map(|a| format!("acc:{a}")).unwrap_or_default()
        ));
    }
    if !rows.is_empty() {
        lines.push(format!("<pre>{}</pre>", esc(&rows.join("\n"))));
    }
    lines.join("\n")
}

fn status_kb(run: &ParallelRun) -> InlineKeyboardMarkup {
    let mut row: Vec<InlineKeyboardButton> = vec![InlineKeyboardButton {
        text: "⏹ Stop all".into(),
        callback_data: Some(format!("par:stop:{}:all", run.run_id)),
        style: Some("danger".into()),
        ..Default::default()
    }];
    for m in run.snapshot() {
        if m.status == MotherStatus::Running || m.status == MotherStatus::Queued {
            row.push(InlineKeyboardButton {
                text: format!("⏹ #{}", m.k),
                callback_data: Some(format!("par:stop:{}:{}", run.run_id, m.k)),
                ..Default::default()
            });
        }
    }
    InlineKeyboardMarkup::new(vec![row])
}

// ---------------------------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------------------------

pub fn plan_prompt(base_prompt: &str, n: usize, run_id: &str, dir: &std::path::Path) -> String {
    format!(
        "[parallel-plan run={run_id} max={n}] The user enabled Parallel mode: up to {n} separate agents (\"mothers\", each its own agy process and conversation, possibly on different accounts) can work on this request at the same time.\n\
         Decide FIRST whether splitting is worth it (independent parts, real speed-up). Follow ~/.gemini/config/rules/parallel-agents.md.\n\
         - If NOT worth splitting (small, sequential, or a quick answer): just do the task normally and answer. Do not output a plan.\n\
         - If worth splitting: do NOT do the work yourself now. Reply with ONLY one JSON object:\n\
         {{\"parallel\": true, \"reason\": \"...\", \"subtasks\": [{{\"id\": \"1\", \"title\": \"short\", \"brief\": \"self-contained instructions\", \"owns\": [\"paths/globs this agent may modify\"], \"readonly\": false, \"depends_on\": [], \"needs_worktree\": false}}], \"merge_instructions\": \"how to combine and verify\"}}\n\
         Use 2..{n} subtasks (more only if some depend on others). Owned paths should not overlap; if two writers must touch the same files, set needs_worktree=true on them (each then works in its own git worktree/branch, merged afterwards). Research/review subtasks use readonly=true. Shared run dir: {}\n---\n{base_prompt}",
        dir.display()
    )
}

pub fn mother_prompt(
    base_prompt_head: &str,
    k: usize,
    n: usize,
    run_id: &str,
    dir: &std::path::Path,
    st: &Subtask,
    deps: &[(String, String)],
) -> String {
    let owns = if st.readonly {
        "READ-ONLY: do not modify any files outside your notes folder.".to_string()
    } else if st.owns.is_empty() {
        "No explicit ownership: change only what this subtask strictly needs.".to_string()
    } else {
        format!("You own ONLY: {}. Do not modify anything else.", st.owns.join(", "))
    };
    let mut dep_txt = String::new();
    for (t, s) in deps {
        dep_txt.push_str(&format!("\n- [{t}] {}", clip(s, 800)));
    }
    format!(
        "[parallel-worker {k}/{n} run={run_id}] You are mother agent #{k} in a parallel run. Follow ~/.gemini/config/rules/parallel-agents.md.\n\
         Shared run dir: {dir} (read REQUEST.md, PLAN.json and board.md first). Write your notes only in {dir}/agents/{k}/. {owns}\n\
         You may use native subagents / run_workflow if useful, but NEVER start /swarm. Post key findings to ai-memory with tags par-{run_id}, agent-{k}.\n\
         {head}\n\
         ## Your subtask: {title}\n{brief}{deps}\n\n\
         End your reply with ONE JSON object: {{\"status\": \"done|partial|blocked\", \"summary\": \"<=600 chars\", \"files_changed\": [], \"findings\": [], \"next_steps\": []}}",
        dir = dir.display(),
        head = base_prompt_head,
        title = st.title,
        brief = st.brief,
        deps = if dep_txt.is_empty() { String::new() } else { format!("\n\nResults of prerequisite subtasks:{dep_txt}") },
    )
}

pub fn merge_prompt(run_id: &str, dir: &std::path::Path, plan: &Plan, mothers: &[MotherState], user_text: &str) -> String {
    let mut body = String::new();
    for m in mothers {
        body.push_str(&format!(
            "\n### Agent {} — {} [{}]\n{}\n",
            m.k,
            m.title,
            m.status.label(),
            clip(if m.raw.trim().is_empty() { &m.summary } else { &m.raw }, RESULT_CLIP)
        ));
        if let Some((_, b)) = &m.worktree {
            body.push_str(&format!("Its work is committed on git branch `{b}` (isolated worktree). Merge it into the main tree with `git merge --no-ff {b}` and resolve conflicts.\n"));
        }
        if !m.violations.is_empty() {
            body.push_str(&format!(
                "⚠ Ownership conflict: these files changed outside this agent's owned paths while it ran (check them): {}\n",
                m.violations.iter().take(30).cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    format!(
        "[parallel-merge run={run_id}] The parallel agents finished. Full outputs: {}/agents/<k>/result.md, board: {}/board.md.\n\
         Merge their work into ONE final answer for the user: verify consistency, resolve conflicts, run checks if code changed, and do any subtask that is not done yourself if feasible. Mention briefly what each agent did.\n\
         Merge instructions from the plan: {}\n\
         Then refresh the handoff note and the ai-memory `handoff tg-<uid>` entry (mention par-{run_id}).\n\
         ## Agent results{body}\n---\nOriginal request:\n{}",
        dir.display(),
        dir.display(),
        if plan.merge_instructions.is_empty() { "(none)" } else { &plan.merge_instructions },
        clip(user_text, 4000)
    )
}

/// Lenient parse of the mother's trailing JSON object.
pub fn parse_worker(text: &str) -> (MotherStatus, String) {
    let obj = json_objects(text).into_iter().rev().find(|v| v.get("status").is_some() || v.get("summary").is_some());
    match obj {
        Some(v) => {
            let st = match v.get("status").and_then(Value::as_str).unwrap_or("done") {
                "partial" => MotherStatus::Partial,
                "blocked" => MotherStatus::Blocked,
                _ => MotherStatus::Done,
            };
            let mut summary = str_field(&v, "summary");
            if summary.is_empty() {
                summary = clip(text.trim(), 600);
            }
            (st, summary)
        }
        None => (MotherStatus::Done, clip(text.trim(), 600)),
    }
}

// ---------------------------------------------------------------------------------------------
// Engine attempt loop (shared by planner, mothers and merge)
// ---------------------------------------------------------------------------------------------

pub struct EngineOutcome {
    pub res: JobResult,
    pub progress: Progress,
    pub account: Option<String>,
    pub notes: Vec<String>,
}


// ---------------------------------------------------------------------------------------------
// Git: ownership check and worktrees
// ---------------------------------------------------------------------------------------------

async fn git(cwd: &std::path::Path, args: &[&str]) -> Option<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new("git")
            .arg("-C")
            .arg(cwd)
            .args(["-c", "user.name=agy-bridge", "-c", "user.email=agy-bridge@localhost"])
            .args(args)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Top level of the git repository containing `cwd`.
pub async fn repo_root(cwd: &std::path::Path) -> Option<std::path::PathBuf> {
    git(cwd, &["rev-parse", "--show-toplevel"]).await.map(|s| std::path::PathBuf::from(s.trim())).filter(|p| p.is_dir())
}

fn file_hash(p: &std::path::Path) -> u64 {
    use std::hash::{Hash, Hasher};
    match std::fs::read(p) {
        Ok(b) => {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            b.hash(&mut h);
            h.finish() | 2
        }
        Err(_) => 1, // deleted
    }
}

/// Dirty files (tracked changes + untracked) -> content hash. Bridge dirs are ignored.
pub async fn dirty_snapshot(root: &std::path::Path) -> HashMap<String, u64> {
    let mut m = HashMap::new();
    let Some(out) = git(root, &["status", "--porcelain=v1", "-uall", "-z"]).await else {
        return m;
    };
    let mut it = out.split('\0');
    while let Some(e) = it.next() {
        if e.len() < 4 {
            continue;
        }
        let st = &e[..2];
        let path = e[3..].to_string();
        if st.starts_with('R') || st.starts_with('C') {
            let _ = it.next();
        }
        if path.starts_with(".parallel/") || path.starts_with(".agents/teamwork/") {
            continue;
        }
        let h = file_hash(&root.join(&path));
        m.insert(path, h);
    }
    m
}

/// Project agent used for mothers (`.agents/agents/tg-mother/agent.md`).
pub const MOTHER_AGENT: &str = "tg-mother";

pub fn mother_agent_available(workspace: &std::path::Path) -> bool {
    workspace.join(".agents/agents").join(MOTHER_AGENT).join("agent.md").is_file()
}

/// Remove the run's worktrees. A branch is deleted when it has no commits beyond `base`
/// or is already merged into the main tree's HEAD; otherwise it is kept and reported.
pub async fn cleanup_worktrees(repo: &std::path::Path, mothers: &[MotherState]) -> Vec<String> {
    let mut kept = Vec::new();
    for m in mothers {
        let Some((path, branch)) = &m.worktree else { continue };
        let _ = git(repo, &["worktree", "remove", "--force", &path.to_string_lossy()]).await;
        let merged = git(repo, &["branch", "--merged", "HEAD", "--list", branch])
            .await
            .is_some_and(|s| !s.trim().is_empty());
        if merged {
            let _ = git(repo, &["branch", "-D", branch]).await;
        } else {
            kept.push(branch.clone());
        }
    }
    let _ = git(repo, &["worktree", "prune"]).await;
    kept
}

/// Keep bridge artefacts out of commits made by agents/merges: append `.parallel/` and the
/// copied mother agent to the repo-local `info/exclude` (never to a tracked .gitignore).
pub async fn ensure_local_excludes(repo: &std::path::Path) {
    let Some(p) = git(repo, &["rev-parse", "--git-common-dir"]).await else { return };
    let common = repo.join(p.trim());
    let f = common.join("info").join("exclude");
    let cur = std::fs::read_to_string(&f).unwrap_or_default();
    let mut add = String::new();
    for pat in ["/.parallel/", "/.agents/agents/tg-mother/"] {
        if !cur.lines().any(|l| l.trim() == pat) {
            add.push_str(pat);
            add.push('\n');
        }
    }
    if !add.is_empty() {
        let _ = std::fs::create_dir_all(common.join("info"));
        let sep = if cur.is_empty() || cur.ends_with('\n') { "" } else { "\n" };
        let _ = std::fs::write(&f, format!("{cur}{sep}# agy-telegram parallel mode\n{add}"));
    }
}

/// Paths whose content changed between two snapshots.
pub fn changed_between(a: &HashMap<String, u64>, b: &HashMap<String, u64>) -> Vec<String> {
    let mut v: Vec<String> = a
        .keys()
        .chain(b.keys())
        .filter(|k| a.get(*k) != b.get(*k))
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    v.sort();
    v
}

/// `path` lies inside one of the owned paths/globs.
pub fn path_owned(path: &str, owns: &[String]) -> bool {
    owns.iter().any(|raw| {
        let glob = raw.contains(['*', '?', '[']);
        let o = norm_path(raw);
        if o.is_empty() {
            return glob; // "*" owns everything
        }
        path == o || path.starts_with(&format!("{o}/")) || (glob && path.starts_with(&o))
    })
}

/// Files changed while a shared-tree mother ran that neither it (by ownership) nor another
/// writer owns. Read-only mothers own nothing.
pub fn ownership_violations(changed: &[String], me: &Subtask, others: &[&Subtask]) -> Vec<String> {
    changed
        .iter()
        .filter(|p| !(!me.readonly && path_owned(p, &me.owns)))
        .filter(|p| !others.iter().any(|o| !o.readonly && path_owned(p, &o.owns)))
        .cloned()
        .collect()
}

impl JobManager {
    /// Parallel width for this request, or `None` for a normal single run.
    pub(super) fn parallel_width(&self, req: &JobRequest, u: &UserState) -> Option<usize> {
        if req.overrides.isolated || self.accounts().is_none() {
            return None;
        }
        if !matches!(self.cfg.agy_engine, agy_core::config::EngineKind::Agy) {
            return None;
        }
        if !self.acl.has_perm(req.uid, PARALLEL_PERM) {
            return None;
        }
        let n = req.overrides.parallel.map(|n| n as usize).unwrap_or_else(|| user_parallel_setting(u));
        (n >= 2).then(|| n.min(PARALLEL_MAX))
    }

    /// Test hook: override the free-memory probe.
    pub fn set_mem_probe(&self, f: Arc<dyn Fn() -> Option<u64> + Send + Sync>) {
        if let Ok(mut g) = self.mem_probe.write() {
            *g = Some(f);
        }
    }

    fn mem_mb(&self) -> Option<u64> {
        match self.mem_probe.read().ok().and_then(|g| g.clone()) {
            Some(f) => f(),
            None => mem_available_mb(),
        }
    }

    /// Active parallel runs of `uid`.
    pub fn parallel_runs_of(&self, uid: i64) -> Vec<Arc<ParallelRun>> {
        self.parallel_runs.iter().filter(|r| r.uid == uid).map(|r| Arc::clone(r.value())).collect()
    }

    /// Stop a whole run (`which = None`) or one mother. `actor` must own the run or be the bot owner.
    pub async fn stop_parallel(&self, actor: i64, run_id: &str, which: Option<usize>) -> bool {
        let Some(run) = self.parallel_runs.get(run_id).map(|r| Arc::clone(r.value())) else {
            return false;
        };
        if run.uid != actor && !self.acl.is_owner(actor) {
            return false;
        }
        let handles: Vec<JobStopHandle> = match which {
            None => {
                run.stop_all.store(true, Ordering::SeqCst);
                let mut v: Vec<JobStopHandle> = run.handles.lock().map(|g| g.values().cloned().collect()).unwrap_or_default();
                if let Some(h) = run.lead_handle.lock().ok().and_then(|g| g.clone()) {
                    v.push(h);
                }
                v
            }
            Some(k) => {
                if let Ok(mut g) = run.stop_one.lock() {
                    g.insert(k);
                }
                run.handles.lock().ok().and_then(|g| g.get(&k).cloned()).into_iter().collect()
            }
        };
        for h in handles {
            h.stop().await;
        }
        true
    }

    /// Run one engine invocation with account failover (no Telegram UI side effects except
    /// the owner alert on a disabled account).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn engine_with_failover(
        &self,
        uid: i64,
        chat_id: i64,
        base: EngineRequest,
        sticky: bool,
        progress_sink: Arc<dyn Fn(Progress) + Send + Sync>,
        on_handle: Arc<dyn Fn(Option<JobStopHandle>) + Send + Sync>,
        stop_flag: Arc<dyn Fn() -> bool + Send + Sync>,
        on_account: OnAccount,
        avoid: Option<AvoidFn>,
    ) -> EngineOutcome {
        let Some(pool) = self.accounts() else {
            let job = self.runner.create_job(&base, None);
            let res = job.run().await.unwrap_or_default();
            return EngineOutcome { progress: job.progress_snapshot(), res, account: None, notes: vec![] };
        };
        let pick_uid = if sticky { uid } else { 0 };
        let mut tried: HashSet<String> = HashSet::new();
        let mut notes = Vec::new();
        let mut req = base.clone();
        let mut last: Option<(JobResult, Progress)> = None;
        let mut same_retry = false;
        let mut model_refresh: HashSet<String> = HashSet::new();
        let mut model_retried: HashSet<String> = HashSet::new();
        let mut pinned: Option<String> = None;
        let max_attempts = pool.policy().max_failover_attempts.clamp(1, MAX_ENGINE_ATTEMPTS);
        let mut attempt: usize = 0;
        let mut blocked_skips: usize = 0;
        while attempt < max_attempts {
            attempt += 1;
            if stop_flag() {
                break;
            }
            if let Some(brk) = pool.breaker_status() {
                notes.push(self.pool_breaker_note(&brk));
                break;
            }
            let try_pick = || {
                pinned
                    .as_deref()
                    .and_then(|id| {
                        pool.pick_pinned_begin_with_filter(id, &tried, |a| {
                            self.account_proxy_allowed(a)
                        })
                    })
                    .or_else(|| match avoid.as_ref() {
                        // parallel workers: prefer an account no other worker of this run holds
                        Some(f) => pool.acquire_distinct_with_filter(pick_uid, &tried, &f(), |a| {
                            self.account_proxy_allowed(a)
                        }),
                        None => pool.pick_begin_with_filter(pick_uid, &tried, |a| {
                            self.account_proxy_allowed(a)
                        }),
                    })
            };
            let mut picked = try_pick();
            if picked.is_none() && pool.breaker_status().is_none() {
                let deadline = Instant::now() + Duration::from_secs(45);
                while picked.is_none() && Instant::now() < deadline && !stop_flag() {
                    let now_i = super::now_secs() as i64;
                    let pol = pool.policy();
                    let any_busy_eligible = pool.list().iter().any(|a| {
                        !tried.contains(&a.id)
                            && a.available_at_with_policy(now_i, &pol)
                            && self.account_proxy_allowed(a)
                            && pool.in_flight(&a.id) > 0
                    });
                    if !any_busy_eligible {
                        break;
                    }
                    let notified = self.account_freed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if pool.breaker_status().is_some() {
                        break;
                    }
                    picked = try_pick();
                    if picked.is_some() {
                        break;
                    }
                    tokio::select! {
                        _ = &mut notified => {}
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                    }
                    if pool.breaker_status().is_some() {
                        break;
                    }
                    picked = try_pick();
                }
            }
            if picked.is_some() {
                pinned.take();
            }
            let _inflight = picked.as_ref().map(|a| {
                super::InFlightGuard(
                    Arc::clone(&pool),
                    a.id.clone(),
                    Arc::clone(&self.account_freed),
                )
            });
            let Some(a): Option<Account> = picked else {
                if !stop_flag() {
                    notes.push(self.pool_exhausted_note(&pool));
                }
                break;
            };
            // Publish chosen account immediately so sibling workers' `avoid` sees it before async model check.
            on_account(&a.id, None);
            {
                let sf = Arc::clone(&stop_flag);
                let stop = move || sf();
                let force = model_refresh.remove(&a.id);
                match self
                    .resolve_model_for_account(uid, chat_id, &a, base.model.as_deref(), &stop, force)
                    .await
                {
                    super::ModelDecision::Keep => {
                        req.model = base.model.clone().filter(|m| !m.is_empty()).or_else(|| self.account_default_model(&a));
                    }
                    super::ModelDecision::Use(m) => {
                        notes.push(format!("{}: model {} (your choice)", a.id, m));
                        req.model = Some(m);
                    }
                    super::ModelDecision::Cancelled(_) => break,
                }
            }
            if let Err(e) = pool.prepare_home(&a) {
                warn!(account = %a.id, error = %e, "shadow home refresh failed");
            }
            // Clear any prior attempt's sticky proxy env vars before resolving this account's route.
            super::clear_proxy_env(&mut req.env_overrides);
            req.env_overrides.insert("HOME".into(), a.home.to_string_lossy().into_owned());
            if let Some(reg) = self.proxies() {
                match reg.resolve(a.proxy_id.as_deref()) {
                    ResolvedProxy::Use { url, .. } => {
                        super::inject_proxy_env(&mut req.env_overrides, &url);
                    }
                    ResolvedProxy::Direct | ResolvedProxy::DirectFallback { .. } => {}
                    ResolvedProxy::Blocked { reason, .. } => {
                        warn!(account = %a.id, reason = %reason, "parallel account proxy blocked (fail-closed); skipping");
                        drop(_inflight);
                        tried.insert(a.id.clone());
                        blocked_skips += 1;
                        if blocked_skips <= agy_core::accounts::MAX_ACCOUNTS {
                            attempt = attempt.saturating_sub(1);
                        }
                        continue;
                    }
                }
            }
            let pace_s = pool.pacing_wait_secs(&a.id);
            if pace_s > 0 {
                let end = Instant::now()
                    + Duration::from_secs(pace_s)
                    + Duration::from_millis(super::polite_jitter_ms(attempt as u64, 1500));
                while Instant::now() < end {
                    if stop_flag() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                if stop_flag() {
                    break;
                }
            }
            on_account(&a.id, None);
            info!(uid, account = %a.id, attempt, "parallel engine attempt");
            let sink = Arc::clone(&progress_sink);
            let cb: ProgressCallback = Arc::new(move |p: Progress| {
                let sink = Arc::clone(&sink);
                Box::pin(async move { sink(p) })
            });
            let job = self.runner.create_job(&req, Some(cb));
            on_handle(Some(job.stop_handle()));
            if stop_flag() {
                job.stop_handle().stop().await;
            }
            let run = job.run().await;
            drop(_inflight);
            on_handle(None);
            pool.record_run_finished(&a.id);
            let prog = job.progress_snapshot();
            let res = match run {
                Ok(r) => r,
                Err(e) => JobResult { error: Some(json!({"message": e.to_string()})), ..Default::default() },
            };
            if let Some(ref usage_val) = res.usage {
                if pool.record_usage(&a.id, usage_val) {
                    self.alert_owner_weekly_reserved(&a, &pool).await;
                }
            }
            let failed = res.error.is_some()
                || (res.exit_code != Some(0)
                    && res.text.trim().is_empty()
                    && !res.timed_out
                    && res.guard_tripped.is_none());
            if res.stopped || stop_flag() || res.timed_out || res.guard_tripped.is_some() || !failed {
                if let Some(ref reason) = res.guard_tripped {
                    notes.push(format!("🛡 AI Safety Guard stopped worker: {reason}"));
                }
                if !failed && !res.stopped && !res.timed_out && res.guard_tripped.is_none() {
                    pool.record_success(&a.id, sticky.then_some(uid));
                }
                return EngineOutcome { res, progress: prog, account: Some(a.id.clone()), notes };
            }
            let (msg, code) = error_parts(res.error.as_ref());
            if crate::models_pool::is_model_unavailable_error(&msg) && model_retried.insert(a.id.clone()) {
                model_refresh.insert(a.id.clone());
                pinned = Some(a.id.clone());
                last = Some((res, prog));
                continue;
            }
            let cls = classify_failure(&msg, code.as_deref(), res.exit_code, !res.text.trim().is_empty());
            match cls.action {
                FailureAction::Deliver => {
                    return EngineOutcome { res, progress: prog, account: Some(a.id.clone()), notes };
                }
                FailureAction::RetrySame { delay_s } => {
                    pool.record_failure(&a.id, &cls, &msg);
                    if !same_retry {
                        same_retry = true;
                        last = Some((res, prog));
                        tokio::time::sleep(Duration::from_secs(delay_s)).await;
                        continue;
                    }
                    if cls.class == FailureClass::Network {
                        return EngineOutcome { res, progress: prog, account: Some(a.id.clone()), notes };
                    }
                    tried.insert(a.id.clone());
                }
                FailureAction::Cooldown { .. } | FailureAction::Disable => {
                    let was_tripped = pool.breaker_status().is_some();
                    let st = pool.record_failure(&a.id, &cls, &msg);
                    tried.insert(a.id.clone());
                    if st == HealthStatus::Disabled {
                        self.alert_owner_disabled(&a, cls.class, &msg).await;
                    }
                    if !was_tripped {
                        if let Some(brk) = pool.breaker_status() {
                            self.alert_owner_breaker(&brk).await;
                            notes.push(self.pool_breaker_note(&brk));
                            return EngineOutcome { res, progress: prog, account: Some(a.id.clone()), notes };
                        }
                    }
                }
            }
            // continue the same conversation on the next account when it exists
            if let Some(c) = res.conversation_id.clone().filter(|c| !c.is_empty() && pool.conversation_exists(c)) {
                if res.steps > 0 || req.conversation_id.is_some() {
                    req.conversation_id = Some(c);
                    if res.steps > 0 && !req.prompt.starts_with("[failover]") {
                        req.prompt = format!(
                            "[failover] The previous attempt of this same turn stopped after {} step(s) because its Antigravity account failed. Continue from there; do not redo completed steps.\n{}",
                            res.steps, base.prompt
                        );
                    }
                }
            }
            let reason = format!("{}{}", cls.class.label(), cls.reset_secs.map(|s| format!(", retry in {}", human_secs(s))).unwrap_or_default());
            on_account(&a.id, Some(reason.clone()));
            notes.push(format!("{} → next account ({})", a.id, reason));
            same_retry = false;
            last = Some((res, prog));
            let sw = pool.policy().switch_delay_secs;
            if sw > 0 && !stop_flag() {
                let end = Instant::now()
                    + Duration::from_secs(sw)
                    + Duration::from_millis(super::polite_jitter_ms(attempt as u64, 1200));
                while Instant::now() < end && !stop_flag() {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
        let (res, progress) = last.unwrap_or_else(|| {
            (
                JobResult { error: Some(json!({"message": "No Antigravity account is available"})), ..Default::default() },
                Progress::default(),
            )
        });
        EngineOutcome { res, progress, account: None, notes }
    }

    /// Full parallel run. Returns `Ok(true)` when it handled (delivered) the request.
    pub(super) async fn run_parallel(
        &self,
        req: &JobRequest,
        active_entry: &Arc<ActiveJobEntry>,
        n: usize,
        outdir: &std::path::Path,
        user_state: &UserState,
    ) -> Result<()> {
        let now = super::now_secs() as i64;
        let run_id = format!("p{now}-{}-{:04x}", req.uid, (req.req_id as u64) & 0xffff);
        let dir = self.cfg.agy_workspace.join(".parallel").join(&run_id);
        let _ = std::fs::create_dir_all(dir.join("agents"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let mut req_md = format!("# Request ({run_id})\n\n{}\n", req.text);
        if !req.attachments.is_empty() {
            req_md.push_str("\n## Attachments\n");
            for a in &req.attachments {
                req_md.push_str(&format!("- {}\n", a.display()));
            }
        }
        let _ = std::fs::write(dir.join("REQUEST.md"), req_md);

        let run = Arc::new(ParallelRun {
            run_id: run_id.clone(),
            uid: req.uid,
            chat_id: req.chat_id,
            dir: dir.clone(),
            started: Instant::now(),
            phase: Mutex::new("planning…".into()),
            mothers: Mutex::new(Vec::new()),
            stop_all: AtomicBool::new(false),
            stop_one: Mutex::new(HashSet::new()),
            handles: Mutex::new(HashMap::new()),
            lead_handle: Mutex::new(None),
        });
        self.parallel_runs.insert(run_id.clone(), Arc::clone(&run));
        struct Unreg<'a>(&'a dashmap::DashMap<String, Arc<ParallelRun>>, String);
        impl Drop for Unreg<'_> {
            fn drop(&mut self) {
                self.0.remove(&self.1);
            }
        }
        let _unreg = Unreg(&self.parallel_runs, run_id.clone());
        info!(uid = req.uid, run = %run_id, n, "parallel run start");

        // single status message + ticker
        let status_id = self
            .render
            .send_html(req.chat_id, &render_status(&run, n), Some(status_kb(&run)), None, Some(true), false)
            .await
            .ok()
            .flatten()
            .map(|m| m.message_id);
        let tick_secs = self.cfg.stream_interval.max(3.0);
        let ticker = {
            let run_t = Arc::clone(&run);
            let render = Arc::clone(&self.render);
            let chat = req.chat_id;
            tokio::spawn(async move {
                let Some(mid) = status_id else { return };
                let mut last = String::new();
                loop {
                    tokio::time::sleep(Duration::from_secs_f64(tick_secs)).await;
                    let html = render_status(&run_t, n);
                    if html != last {
                        let _ = render.edit_html(chat, mid, &html, Some(status_kb(&run_t))).await;
                        last = html;
                    }
                }
            })
        };
        struct AbortOnDrop(tokio::task::JoinHandle<()>);
        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let ticker_guard = AbortOnDrop(ticker);

        let entry = Arc::clone(active_entry);
        let run_s = Arc::clone(&run);
        let lead_stop: Arc<dyn Fn() -> bool + Send + Sync> =
            Arc::new(move || run_s.is_stopped(None) || entry.stop_requested.load(Ordering::SeqCst));

        // ---- 1. plan (lead conversation, sticky account) ----
        let base_req = self.build_engine_request(req, outdir);
        let mut plan_req = base_req.clone();
        let pool = self.accounts();
        let mut prefix = String::new();
        if let (Some(p), Some(c)) = (pool.as_ref(), plan_req.conversation_id.clone()) {
            if !p.conversation_exists(&c) {
                plan_req.conversation_id = None;
                prefix = handoff::context_pack(&self.cfg.state_dir, &self.cfg.agy_workspace, req.uid, Some(&c), handoff::DEFAULT_PACK_CHARS)
                    .unwrap_or_else(|| handoff::recall_directive(&self.cfg.agy_workspace, req.uid, Some(&c)));
                prefix.push('\n');
            }
        }
        plan_req.prompt = format!("{prefix}{}", plan_prompt(&base_req.prompt, n, &run_id, &dir));
        let entry_p = Arc::clone(active_entry);
        let run_h = Arc::clone(&run);
        let entry_h = Arc::clone(active_entry);
        let planned = self
            .engine_with_failover(
                req.uid,
                req.chat_id,
                plan_req,
                true,
                Arc::new(move |p: Progress| {
                    if let Ok(mut g) = entry_p.progress.lock() {
                        *g = p;
                    }
                }),
                Arc::new(move |h: Option<JobStopHandle>| {
                    if let Ok(mut g) = run_h.lead_handle.lock() {
                        *g = h.clone();
                    }
                    if let Ok(mut g) = entry_h.stop_handle.lock() {
                        *g = h;
                    }
                }),
                Arc::clone(&lead_stop),
                Arc::new(|_: &str, _: Option<String>| {}),
                None,
            )
            .await;
        let lead_cid = planned.res.conversation_id.clone().filter(|c| !c.is_empty());
        let plan = if planned.res.error.is_none() && !lead_stop() {
            parse_plan(&planned.res.text, n * 2)
        } else {
            None
        };
        let Some(plan) = plan else {
            // The planner answered directly (or failed/stopped): deliver like a normal turn.
            drop(ticker_guard);
            if let Some(mid) = status_id {
                let _ = self.client.delete_message(req.chat_id, mid).await;
            }
            let _ = std::fs::remove_dir_all(&dir);
            return self.finish_like_normal(req, user_state, &planned.progress, &planned.res, outdir, planned.account.as_deref(), &planned.notes).await;
        };
        let _ = std::fs::write(
            dir.join("PLAN.json"),
            serde_json::to_string_pretty(&json!({
                "run_id": run_id, "reason": plan.reason, "merge_instructions": plan.merge_instructions,
                "subtasks": plan.subtasks.iter().map(|s| json!({"id": s.id, "title": s.title, "brief": s.brief, "owns": s.owns, "readonly": s.readonly, "depends_on": s.depends_on, "needs_worktree": s.needs_worktree})).collect::<Vec<_>>()
            }))
            .unwrap_or_default(),
        );
        run.append_board(&format!("# Board {run_id}\nPlan: {} subtasks. {}\n", plan.subtasks.len(), plan.reason));

        // ---- 2. fan-out ----
        // git: isolated worktrees for overlapping writers, ownership check for the rest
        let work_cwd = base_req.cwd.clone().unwrap_or_else(|| self.cfg.agy_workspace.clone());
        let repo = repo_root(&work_cwd).await;
        let isolated = isolation_plan(&plan.subtasks, repo.is_some());
        let base_commit: Option<String> = if let (true, Some(r)) = (isolated.iter().any(|x| *x), repo.as_ref()) {
            match git(r, &["stash", "create"]).await.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
                Some(c) => Some(c),
                None => git(r, &["rev-parse", "HEAD"]).await.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            }
        } else {
            None
        };
        if let Some(r) = repo.as_ref() {
            ensure_local_excludes(r).await;
        }
        let mut snap_start: HashMap<usize, HashMap<String, u64>> = HashMap::new();
        let (order, deps) = schedule_with(&plan.subtasks, &isolated);
        let total = order.len();
        if let Ok(mut g) = run.mothers.lock() {
            for (p, &i) in order.iter().enumerate() {
                g.push(MotherState {
                    k: p + 1,
                    title: plan.subtasks[i].title.clone(),
                    status: MotherStatus::Queued,
                    account: None,
                    started: None,
                    ended: None,
                    steps: 0,
                    last_step: String::new(),
                    note: None,
                    summary: String::new(),
                    raw: String::new(),
                    conversation_id: None,
                    violations: Vec::new(),
                    worktree: None,
                });
            }
        }
        // capacity: available accounts × policy per-account concurrency, capped by n
        let cap = pool
            .as_ref()
            .map(|p| {
                let per_acct =
                    (p.policy().max_concurrency_per_account as usize).clamp(1, PER_ACCOUNT_CONCURRENCY);
                (p.available_count() * per_acct).max(1)
            })
            .unwrap_or(1);
        let width = n.min(cap).max(1);
        run.set_phase(&format!("plan ✓ ({} subtasks) · running up to {width} at once", total));
        let head = base_req.prompt.split("\n---\n").next().unwrap_or("").to_string();
        let min_mem = min_mem_mb();

        let mut started: HashSet<usize> = HashSet::new();
        let mut running = FuturesUnordered::new();
        let mut mem_note_sent = false;
        loop {
            if run.is_stopped(None) || active_entry.stop_requested.load(Ordering::SeqCst) {
                run.stop_all.store(true, Ordering::SeqCst);
            }
            // launch what is ready
            if !run.stop_all.load(Ordering::SeqCst) {
                let snap = run.snapshot();
                for p in 0..total {
                    if started.contains(&p) || running.len() >= width {
                        continue;
                    }
                    if run.is_stopped(Some(p + 1)) {
                        started.insert(p);
                        run.update(p + 1, |m| m.status = MotherStatus::Stopped);
                        continue;
                    }
                    if !deps[p].iter().all(|&q| snap[q].status.finished()) {
                        continue;
                    }
                    if !running.is_empty() {
                        if let Some(mem) = self.mem_mb() {
                            if mem < min_mem {
                                if !mem_note_sent {
                                    mem_note_sent = true;
                                    run.set_phase(&format!("low memory ({mem} MiB free < {min_mem}) · running fewer agents at once"));
                                    warn!(run = %run_id, mem, min_mem, "parallel: RAM guard, not spawning more");
                                }
                                break;
                            }
                        }
                    }
                    started.insert(p);
                    let st = plan.subtasks[order[p]].clone();
                    let dep_res: Vec<(String, String)> = deps[p]
                        .iter()
                        .map(|&q| (snap[q].title.clone(), format!("{}: {}", snap[q].status.label(), snap[q].summary)))
                        .collect();
                    let k = p + 1;
                    let mut mreq = base_req.clone();
                    mreq.conversation_id = None;
                    mreq.prompt = mother_prompt(&head, k, total, &run_id, &dir, &st, &dep_res);
                    // isolated worktree (overlapping writers) or ownership baseline (shared tree)
                    let mut wt: Option<(std::path::PathBuf, String)> = None;
                    if let (Some(r), true, Some(base)) = (repo.as_ref(), isolated[order[p]], base_commit.as_ref()) {
                        let path = dir.join("wt").join(k.to_string());
                        let branch = format!("par/{run_id}/{k}");
                        let ok = git(r, &["worktree", "add", "-b", &branch, &path.to_string_lossy(), base]).await.is_some();
                        if ok {
                            // project agents (untracked) must be visible inside the worktree
                            let src = self.cfg.agy_workspace.join(".agents/agents/tg-mother");
                            if src.is_dir() {
                                let dst = path.join(".agents/agents/tg-mother");
                                let _ = std::fs::create_dir_all(&dst);
                                let _ = std::fs::copy(src.join("agent.md"), dst.join("agent.md"));
                            }
                            mreq.prompt.push_str(&format!(
                                "\n\nYou work in an ISOLATED git worktree: {} (branch `{branch}`). Edit files only there. Before you finish, commit all your changes on that branch (git add -A && git commit). The lead merges the branch afterwards.",
                                path.display()
                            ));
                            mreq.cwd = Some(path.clone());
                            wt = Some((path, branch));
                        } else {
                            warn!(run = %run_id, k, "git worktree add failed; running in the shared tree");
                            run.update(k, |m| m.note = Some("worktree failed: shared tree".into()));
                        }
                    }
                    if wt.is_none() {
                        if let Some(r) = repo.as_ref() {
                            snap_start.insert(k, dirty_snapshot(r).await);
                        }
                    }
                    if mother_agent_available(&self.cfg.agy_workspace) && mreq.agent.as_deref().is_none_or(str::is_empty) {
                        mreq.agent = Some(MOTHER_AGENT.to_string());
                    }
                    let wt_c = wt.clone();
                    run.update(k, |m| m.worktree = wt_c);
                    let _ = std::fs::create_dir_all(dir.join("agents").join(k.to_string()));
                    run.update(k, |m| {
                        m.status = MotherStatus::Running;
                        m.started = Some(Instant::now());
                    });
                    let run_p = Arc::clone(&run);
                    let run_hh = Arc::clone(&run);
                    let run_st = Arc::clone(&run);
                    let run_acc = Arc::clone(&run);
                    let run_avoid = Arc::clone(&run);
                    let avoid: AvoidFn = Arc::new(move || {
                        run_avoid
                            .snapshot()
                            .into_iter()
                            .filter(|m| m.k != k && m.status == MotherStatus::Running)
                            .filter_map(|m| m.account)
                            .collect()
                    });
                    let owner_view = self.acl.is_owner(req.uid);
                    let fut = self.engine_with_failover(
                        req.uid,
                        req.chat_id,
                        mreq,
                        false,
                        Arc::new(move |pr: Progress| {
                            run_p.update(k, |m| {
                                m.steps = pr.steps;
                                m.last_step = pr.last_step.clone();
                            })
                        }),
                        Arc::new(move |h: Option<JobStopHandle>| {
                            if let Ok(mut g) = run_hh.handles.lock() {
                                match h {
                                    Some(h) => {
                                        g.insert(k, h);
                                    }
                                    None => {
                                        g.remove(&k);
                                    }
                                }
                            }
                        }),
                        Arc::new(move || run_st.is_stopped(Some(k))),
                        Arc::new(move |acc: &str, failed: Option<String>| {
                            let acc = acc.to_string();
                            run_acc.update(k, |m| match failed {
                                Some(r) => m.note = Some(format!("failover from {acc}: {r}")),
                                None => m.account = Some(if owner_view { acc } else { acc.clone() }),
                            })
                        }),
                        Some(avoid),
                    );
                    running.push(async move { (k, fut.await) });
                }
            }
            if running.is_empty() {
                let snap = run.snapshot();
                let pending: Vec<usize> = (0..total).filter(|p| !started.contains(p)).collect();
                if pending.is_empty() || run.stop_all.load(Ordering::SeqCst) {
                    for p in pending {
                        run.update(p + 1, |m| m.status = MotherStatus::Stopped);
                    }
                    break;
                }
                // a pending subtask whose prerequisites can never finish: mark failed
                if pending.iter().all(|&p| !deps[p].iter().all(|&q| snap[q].status.finished())) {
                    for p in pending {
                        started.insert(p);
                        run.update(p + 1, |m| m.status = MotherStatus::Failed("unmet dependency".into()));
                    }
                    break;
                }
                continue;
            }
            tokio::select! {
                done = running.next() => {
                    if let Some((k, out)) = done {
                        let o: EngineOutcome = out;
                        let stopped = o.res.stopped || run.is_stopped(Some(k));
                        let text = o.res.text.clone();
                        let (status, summary) = if stopped {
                            (MotherStatus::Stopped, clip(text.trim(), 600))
                        } else if o.res.error.is_some()
                            || (o.res.exit_code != Some(0) && !o.res.timed_out)
                        {
                            let (msg, _) = error_parts(o.res.error.as_ref());
                            let fallback_msg = if msg.is_empty() {
                                format!("exit {:?}", o.res.exit_code)
                            } else {
                                msg
                            };
                            (
                                MotherStatus::Failed(clip(&fallback_msg, 60)),
                                clip(text.trim(), 600),
                            )
                        } else if text.trim().is_empty() {
                            (MotherStatus::Failed("no output".to_string()), String::new())
                        } else if o.res.timed_out {
                            (MotherStatus::Partial, parse_worker(&text).1)
                        } else {
                            parse_worker(&text)
                        };
                        let _ = std::fs::write(dir.join("agents").join(k.to_string()).join("result.md"), &text);
                        // ownership check (shared tree) / keep isolated work on its branch
                        let mut violations = Vec::new();
                        let wt_now = run.snapshot().get(k - 1).and_then(|m| m.worktree.clone());
                        if let Some((wpath, _)) = wt_now.as_ref() {
                            if git(wpath, &["status", "--porcelain"]).await.is_some_and(|s| !s.trim().is_empty()) {
                                let _ = git(wpath, &["add", "-A"]).await;
                                let _ = git(wpath, &["commit", "-q", "-m", &format!("parallel {run_id} agent {k} (auto-commit by bridge)")]).await;
                            }
                        } else if let (Some(r), Some(start)) = (repo.as_ref(), snap_start.get(&k)) {
                            let now_snap = dirty_snapshot(r).await;
                            let changed = changed_between(start, &now_snap);
                            let me = &plan.subtasks[order[k - 1]];
                            let others: Vec<&Subtask> = order
                                .iter()
                                .enumerate()
                                .filter(|(q, _)| *q != k - 1)
                                .map(|(_, &i)| &plan.subtasks[i])
                                .collect();
                            violations = ownership_violations(&changed, me, &others);
                            if !violations.is_empty() {
                                warn!(run = %run_id, k, n = violations.len(), "parallel: changes outside ownership");
                                run.append_board(&format!("⚠ [{k}] changed outside its ownership: {}", violations.join(", ")));
                            }
                        }
                        run.append_board(&format!("## [{k}] {} — {}\n{}\n", run.snapshot().get(k - 1).map(|m| m.title.clone()).unwrap_or_default(), status.label(), summary));
                        run.update(k, |m| {
                            m.status = status;
                            m.summary = summary;
                            m.raw = text;
                            m.ended = Some(Instant::now());
                            m.conversation_id = o.res.conversation_id.clone();
                            if o.account.is_some() { m.account = o.account.clone(); }
                            m.violations = violations;
                        });
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        }

        let mothers = run.snapshot();
        if run.stop_all.load(Ordering::SeqCst) {
            drop(ticker_guard);
            if let Some(mid) = status_id {
                let _ = self.render.edit_html(req.chat_id, mid, &render_status(&run, n), None).await;
            }
            run.append_board("\n_run cancelled_\n");
            if let Some(r) = repo.as_ref() {
                let kept = cleanup_worktrees(r, &mothers).await;
                if !kept.is_empty() {
                    run.append_board(&format!("unmerged branches kept: {}", kept.join(", ")));
                }
            }
            let mut html = format!("⏹ <b>Parallel run stopped</b> · <code>{}</code>", esc(&run_id));
            for m in &mothers {
                html.push_str(&format!("\n{} #{} {} — {}", m.status.icon(), m.k, esc(&m.title), esc(&m.status.label())));
            }
            let _ = self.render.send_html_simple(req.chat_id, &html, Some(self.answer_kb())).await;
            return Ok(());
        }

        // ---- 3. merge (lead conversation resumes) ----
        run.set_phase("merging…");
        let mut merge_req = base_req.clone();
        merge_req.conversation_id = lead_cid.clone();
        merge_req.prompt = format!(
            "{}\n{}",
            head,
            merge_prompt(&run_id, &dir, &plan, &mothers, &req.text)
        );
        let entry_m = Arc::clone(active_entry);
        let run_mh = Arc::clone(&run);
        let entry_mh = Arc::clone(active_entry);
        let merged = self
            .engine_with_failover(
                req.uid,
                req.chat_id,
                merge_req,
                true,
                Arc::new(move |p: Progress| {
                    if let Ok(mut g) = entry_m.progress.lock() {
                        *g = p;
                    }
                }),
                Arc::new(move |h: Option<JobStopHandle>| {
                    if let Ok(mut g) = run_mh.lead_handle.lock() {
                        *g = h.clone();
                    }
                    if let Ok(mut g) = entry_mh.stop_handle.lock() {
                        *g = h;
                    }
                }),
                Arc::clone(&lead_stop),
                Arc::new(|_: &str, _: Option<String>| {}),
                None,
            )
            .await;
        drop(ticker_guard);
        if let Some(mid) = status_id {
            let _ = self.client.delete_message(req.chat_id, mid).await;
        }
        let mut notes = planned.notes.clone();
        if let Some(r) = repo.as_ref() {
            let kept = cleanup_worktrees(r, &mothers).await;
            if !kept.is_empty() {
                notes.push(format!("Unmerged worktree branches kept for review: {}", kept.join(", ")));
            }
        }
        for m in mothers.iter().filter(|m| !m.violations.is_empty()) {
            notes.push(format!(
                "Agent #{} changed files outside its ownership: {}",
                m.k,
                m.violations.iter().take(10).cloned().collect::<Vec<_>>().join(", ")
            ));
        }
        notes.extend(merged.notes.iter().cloned());
        let mut summary = format!("⚡ <b>Parallel</b> · {} agents · {}", mothers.len(), fmt_dur(run.started.elapsed()));
        let mut quote = String::new();
        for m in &mothers {
            quote.push_str(&format!(
                "{} <b>#{} {}</b> — {}{}\n{}\n",
                m.status.icon(),
                m.k,
                esc(&m.title),
                esc(&m.status.label()),
                m.account.as_deref().map(|a| format!(" · <code>{}</code>", esc(a))).unwrap_or_default(),
                esc(&clip(&m.summary, 300))
            ));
        }
        summary.push_str(&format!("\n<blockquote expandable>{}</blockquote>", quote.trim_end()));
        let mut all_notes = vec![summary];
        all_notes.extend(notes.into_iter().map(|n| format!("🔁 <i>{}</i>", esc(&n))));
        let mut res = merged.res;
        if res.conversation_id.is_none() {
            res.conversation_id = lead_cid;
        }
        self.finish_like_normal(req, user_state, &merged.progress, &res, outdir, merged.account.as_deref(), &all_notes).await
    }

    /// Session save + transcript + delivery, mirroring the end of `run_job_inner`.
    #[allow(clippy::too_many_arguments)]
    async fn finish_like_normal(
        &self,
        req: &JobRequest,
        user_state: &UserState,
        progress: &Progress,
        res: &JobResult,
        outdir: &std::path::Path,
        account: Option<&str>,
        notes: &[String],
    ) -> Result<()> {
        if let Some(cid) = res.conversation_id.as_deref().filter(|c| !c.is_empty()) {
            if user_state.conversation_id.as_deref() != Some(cid) {
                let title = if req.text.trim().is_empty() { "file" } else { req.text.trim() };
                let ts = super::now_secs() as i64;
                let cid = cid.to_string();
                if let Err(err) = self.store.update_user(req.uid, |u| u.push_session(cid, title, ts)) {
                    warn!(uid = req.uid, error = %err, "failed to save session");
                }
            }
        }
        if !res.text.trim().is_empty() {
            handoff::append_turn(&self.cfg.state_dir, req.uid, res.conversation_id.as_deref(), account, &req.text, &res.text);
        }
        self.deliver_result_with_notes(req, user_state, progress, res, outdir, notes, "Antigravity").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(id: &str, owns: &[&str], ro: bool, deps: &[&str]) -> Subtask {
        Subtask {
            id: id.into(),
            title: id.into(),
            brief: "b".into(),
            owns: owns.iter().map(|s| s.to_string()).collect(),
            readonly: ro,
            depends_on: deps.iter().map(|s| s.to_string()).collect(),
            needs_worktree: false,
        }
    }

    #[test]
    fn isolation_ownership_and_distinct_schedule() {
        let t = vec![st("1", &["src/"], false, &[]), st("2", &["src/a.rs"], false, &[]), st("3", &["docs/"], false, &[]), st("4", &[], true, &[])];
        assert_eq!(isolation_plan(&t, false), vec![false; 4]);
        let iso = isolation_plan(&t, true);
        assert_eq!(iso, vec![true, true, false, false]);
        // isolated overlapping writers run concurrently; without isolation they are serialized
        let (_, d0) = schedule(&t);
        assert!(d0.iter().any(|d| !d.is_empty()));
        let (_, d1) = schedule_with(&t, &iso);
        assert!(d1.iter().all(|d| d.is_empty()), "{d1:?}");
        assert!(path_owned("src/x/y.rs", &["src/".into()]));
        assert!(path_owned("src/a.rs", &["src/a.rs".into()]));
        assert!(!path_owned("srcx/a.rs", &["src".into()]));
        assert!(path_owned("docs/a.md", &["docs/*.md".into()]));
        let changed = vec!["docs/d.md".to_string(), "rogue.txt".to_string(), "src/a.rs".to_string()];
        let others: Vec<&Subtask> = vec![&t[0]];
        assert_eq!(ownership_violations(&changed, &t[2], &others), vec!["rogue.txt".to_string()]);
        // read-only agents own nothing
        assert_eq!(ownership_violations(&changed, &t[3], &[]), changed);
        let mut a = HashMap::new();
        a.insert("x".to_string(), 5u64);
        let mut b = a.clone();
        b.insert("y".into(), 3);
        assert_eq!(changed_between(&a, &b), vec!["y".to_string()]);
    }

    #[test]
    fn plan_parsing_is_lenient_and_bounded() {
        let txt = "Sure.\n```json\n{\"parallel\": true, \"reason\": \"r\", \"subtasks\": [{\"id\": 1, \"title\": \"api\", \"brief\": \"do api\", \"owns\": [\"src/api\"]}, {\"title\": \"tests\", \"brief\": \"do tests\", \"depends_on\": [\"1\", \"zz\"]}, {\"brief\": \"\"}], \"merge_instructions\": \"m\"}\n```";
        let p = parse_plan(txt, 6).unwrap();
        assert_eq!(p.subtasks.len(), 2);
        assert_eq!(p.subtasks[0].id, "1");
        assert_eq!(p.subtasks[1].depends_on, vec!["1".to_string()]);
        assert!(parse_plan("{\"parallel\": false, \"subtasks\": []}", 6).is_none());
        assert!(parse_plan("Here is the answer, no plan.", 6).is_none());
        assert!(parse_plan("{\"parallel\": true, \"subtasks\": [{\"brief\": \"only one\"}]}", 6).is_none());
        let many: Vec<String> = (0..9).map(|i| format!("{{\"brief\": \"t{i}\"}}")).collect();
        let p = parse_plan(&format!("{{\"parallel\": true, \"subtasks\": [{}]}}", many.join(",")), 4).unwrap();
        assert_eq!(p.subtasks.len(), 4);
    }

    #[test]
    fn overlapping_writers_are_serialized_readonly_are_not() {
        assert!(owns_overlap(&["src/".into()], &["src/a.rs".into()]));
        assert!(owns_overlap(&["src/**".into()], &["src/x/y".into()]));
        assert!(!owns_overlap(&["src/api".into()], &["docs".into()]));
        assert!(owns_overlap(&[], &["docs".into()]));
        let s = vec![st("a", &["src"], false, &[]), st("b", &["src/x"], false, &[]), st("c", &[], true, &[]), st("d", &["docs"], false, &[])];
        let (order, deps) = schedule(&s);
        assert_eq!(order, vec![0, 1, 2, 3]);
        assert_eq!(deps[1], vec![0]); // b waits for a (overlap)
        assert!(deps[2].is_empty()); // readonly
        assert!(deps[3].is_empty()); // disjoint
    }

    #[test]
    fn explicit_dependencies_and_cycles() {
        let s = vec![st("a", &["x"], false, &["b"]), st("b", &["y"], false, &[])];
        let (order, deps) = schedule(&s);
        assert_eq!(order, vec![1, 0]);
        assert_eq!(deps[1], vec![0]);
        let c = vec![st("a", &["x"], false, &["b"]), st("b", &["y"], false, &["a"])];
        let (order, deps) = schedule(&c);
        assert_eq!(order.len(), 2);
        assert!(deps.iter().all(|d| d.is_empty()));
    }

    #[test]
    fn worker_json_parsing() {
        let (s, sum) = parse_worker("work...\n{\"status\": \"partial\", \"summary\": \"half\"}");
        assert_eq!(s, MotherStatus::Partial);
        assert_eq!(sum, "half");
        let (s, sum) = parse_worker("plain text answer");
        assert_eq!(s, MotherStatus::Done);
        assert_eq!(sum, "plain text answer");

        let mut env = std::collections::BTreeMap::new();
        super::super::inject_proxy_env(&mut env, "socks5h://127.0.0.1:1080");
        assert!(env.contains_key("HTTPS_PROXY"));
        super::super::clear_proxy_env(&mut env);
        assert!(!env.contains_key("HTTPS_PROXY"));
        assert!(!env.contains_key("HTTP_PROXY"));
        assert!(!env.contains_key("ALL_PROXY"));
    }
}
