//! Session continuity across Antigravity accounts.
//!
//! Three methods, tried in this order (see docs/ACCOUNTS.md for the evaluation):
//!
//! 1. **Resume (primary)** — every account's shadow `HOME` shares the primary
//!    `antigravity-cli/conversations/` store, and `agy --conversation <id>` resolves the
//!    conversation from that LOCAL store, so the next account continues the very same
//!    conversation (full trajectory, artifacts in `brain/<id>/`). Used whenever the
//!    `<id>.db` file exists.
//! 2. **Replay (fallback 1)** — a fresh conversation whose prompt is prefixed with a
//!    bounded *context pack*: the agent-maintained handoff note
//!    (`<workspace>/.handoff/tg-<uid>.md`) plus the last exchanges from the bridge's own
//!    transcript log (`$STATE_DIR/transcripts/<uid>.jsonl`). Used when the conversation file
//!    is missing or resume was rejected.
//! 3. **Recall (fallback 2)** — a fresh conversation with a short directive telling the
//!    agent to rebuild context itself from ai-memory (`handoff tg-<uid>`), the handoff note
//!    and the graphify/gortex code graph. Used when replay is unavailable or rejected
//!    (e.g. request too large).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::warn;

/// Maximum transcript lines kept per user (older lines are trimmed).
const MAX_TRANSCRIPT_LINES: usize = 200;
/// Per-field truncation in the transcript log.
const MAX_PROMPT_CHARS: usize = 4000;
const MAX_ANSWER_CHARS: usize = 6000;
/// Default context pack budget (characters).
pub const DEFAULT_PACK_CHARS: usize = 12_000;

/// Continuity strategy for one engine attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Continuity {
    /// Continue an existing conversation by id (or start fresh when there is none).
    Resume,
    /// Fresh conversation with replayed context pack.
    Replay,
    /// Fresh conversation with a self-recall directive.
    Recall,
}

impl Continuity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Resume => "resumed",
            Self::Replay => "rebuilt (transcript replay)",
            Self::Recall => "rebuilt (memory recall)",
        }
    }
    pub fn next(self) -> Option<Self> {
        match self {
            Self::Resume => Some(Self::Replay),
            Self::Replay => Some(Self::Recall),
            Self::Recall => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnRecord {
    pub ts: i64,
    #[serde(default)]
    pub cid: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
    pub prompt: String,
    pub answer: String,
}

fn clip(s: &str, n: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= n {
        t.to_string()
    } else {
        let mut out: String = t.chars().take(n).collect();
        out.push_str(" …[truncated]");
        out
    }
}

pub fn transcript_path(state_dir: &Path, uid: i64) -> PathBuf {
    state_dir.join("transcripts").join(format!("{uid}.jsonl"))
}

pub fn handoff_note_path(workspace: &Path, uid: i64) -> PathBuf {
    workspace.join(".handoff").join(format!("tg-{uid}.md"))
}

/// Append one completed turn (0600, trimmed to [`MAX_TRANSCRIPT_LINES`]).
pub fn append_turn(
    state_dir: &Path,
    uid: i64,
    cid: Option<&str>,
    account: Option<&str>,
    prompt: &str,
    answer: &str,
) {
    let path = transcript_path(state_dir, uid);
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_ok() {
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let rec = TurnRecord {
        ts: chrono::Utc::now().timestamp(),
        cid: cid.map(str::to_string),
        account: account.map(str::to_string),
        // never persist (and later replay) pasted credentials
        prompt: clip(&agy_ext::mcp_client::redact_secrets_in_text(prompt), MAX_PROMPT_CHARS),
        answer: clip(&agy_ext::mcp_client::redact_secrets_in_text(answer), MAX_ANSWER_CHARS),
    };
    let Ok(line) = serde_json::to_string(&rec) else {
        return;
    };
    let res = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| writeln!(f, "{line}"));
    if let Err(e) = res {
        warn!(uid, error = %e, "transcript append failed");
        return;
    }
    // trim
    if let Ok(txt) = fs::read_to_string(&path) {
        let lines: Vec<&str> = txt.lines().collect();
        if lines.len() > MAX_TRANSCRIPT_LINES {
            let keep = lines[lines.len() - MAX_TRANSCRIPT_LINES..].join("\n") + "\n";
            let _ = agy_core::atomic_write_text(&path, &keep, 0o600);
        }
    }
}

/// Read the last `max` turns (newest last), preferring turns of `cid` when given.
pub fn recent_turns(state_dir: &Path, uid: i64, cid: Option<&str>, max: usize) -> Vec<TurnRecord> {
    let Ok(txt) = fs::read_to_string(transcript_path(state_dir, uid)) else {
        return Vec::new();
    };
    let all: Vec<TurnRecord> = txt
        .lines()
        .filter_map(|l| serde_json::from_str::<TurnRecord>(l).ok())
        .collect();
    let same: Vec<TurnRecord> = match cid {
        Some(c) if !c.is_empty() => all.iter().filter(|t| t.cid.as_deref() == Some(c)).cloned().collect(),
        _ => Vec::new(),
    };
    let src = if same.is_empty() { all } else { same };
    let start = src.len().saturating_sub(max);
    src[start..].to_vec()
}

fn read_handoff_note(workspace: &Path, uid: i64, max_chars: usize) -> Option<String> {
    let p = handoff_note_path(workspace, uid);
    let meta = fs::metadata(&p).ok()?;
    // ignore stale notes (> 14 days)
    if let Ok(m) = meta.modified() {
        if m.elapsed().map(|e| e.as_secs() > 14 * 86400).unwrap_or(false) {
            return None;
        }
    }
    let txt = fs::read_to_string(&p).ok()?;
    let t = txt.trim();
    if t.is_empty() {
        None
    } else {
        Some(clip(t, max_chars))
    }
}

/// Build the replay context pack (fallback 1). `None` when there is nothing to replay.
pub fn context_pack(
    state_dir: &Path,
    workspace: &Path,
    uid: i64,
    cid: Option<&str>,
    budget: usize,
) -> Option<String> {
    let note = read_handoff_note(workspace, uid, budget / 2);
    let turns = recent_turns(state_dir, uid, cid, 8);
    if note.is_none() && turns.is_empty() {
        return None;
    }
    let mut out = String::new();
    out.push_str("[session-handoff] This conversation was moved to another Antigravity account and the previous conversation could not be resumed directly. Reconstructed context follows; treat it as the conversation so far and continue seamlessly (do not re-introduce yourself, do not redo finished work).\n");
    if let Some(n) = note {
        out.push_str("\n## Handoff note (written by the previous session)\n");
        out.push_str(&n);
        out.push('\n');
    }
    if !turns.is_empty() {
        out.push_str("\n## Recent exchanges (oldest first)\n");
        // fill from newest backwards within budget
        let mut blocks: Vec<String> = Vec::new();
        let mut used = out.chars().count();
        for t in turns.iter().rev() {
            let b = format!(
                "\n### User\n{}\n### Assistant\n{}\n",
                clip(&t.prompt, 1500),
                clip(&t.answer, 2500)
            );
            let n = b.chars().count();
            if used + n > budget {
                break;
            }
            used += n;
            blocks.push(b);
        }
        blocks.reverse();
        for b in blocks {
            out.push_str(&b);
        }
    }
    out.push_str("\n## End of reconstructed context\n");
    Some(out)
}

/// Build the recall directive (fallback 2).
pub fn recall_directive(workspace: &Path, uid: i64, cid: Option<&str>) -> String {
    format!(
        "[session-handoff] This conversation was moved to another Antigravity account and its history is not available in this conversation. Before answering, rebuild context yourself: (1) read the handoff note {} if it exists; (2) use the ai-memory MCP to search for `handoff tg-{uid}`{} and load the most recent handoff/session-summary memories; (3) use graphify/gortex only if code context is needed. Then continue the user's request below. Keep the rebuild brief and do not mention it unless it fails.\n",
        handoff_note_path(workspace, uid).display(),
        cid.map(|c| format!(" and `conv {c}`")).unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn transcript_pack_and_recall() {
        let d = TempDir::new().unwrap();
        let st = d.path().join("state");
        let ws = d.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        assert!(context_pack(&st, &ws, 5, Some("c1"), DEFAULT_PACK_CHARS).is_none());
        for i in 0..210 {
            append_turn(&st, 5, Some(if i % 2 == 0 { "c1" } else { "c2" }), Some("primary"), &format!("q{i}"), &format!("a{i}"));
        }
        let txt = fs::read_to_string(transcript_path(&st, 5)).unwrap();
        assert_eq!(txt.lines().count(), MAX_TRANSCRIPT_LINES);
        let mode = fs::metadata(transcript_path(&st, 5)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let turns = recent_turns(&st, 5, Some("c1"), 3);
        assert_eq!(turns.len(), 3);
        assert!(turns.iter().all(|t| t.cid.as_deref() == Some("c1")));
        assert_eq!(turns.last().unwrap().prompt, "q208");

        fs::create_dir_all(ws.join(".handoff")).unwrap();
        fs::write(handoff_note_path(&ws, 5), "Goal: ship feature X. Next: run tests.").unwrap();
        let pack = context_pack(&st, &ws, 5, Some("c1"), 2000).unwrap();
        assert!(pack.contains("Goal: ship feature X"));
        assert!(pack.contains("q208"));
        assert!(pack.chars().count() <= 2600);
        let r = recall_directive(&ws, 5, Some("c1"));
        assert!(r.contains("handoff tg-5") && r.contains("conv c1"));
        assert_eq!(Continuity::Resume.next(), Some(Continuity::Replay));
        assert_eq!(Continuity::Recall.next(), None);
    }
}
