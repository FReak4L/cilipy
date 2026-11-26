//! Structured secret-redacted JSONL audit logger + in-memory ring buffer for `/mcpgw`.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use agy_ext::mcp_client::redact_secrets_in_text;
use chrono::Utc;
use serde::{Deserialize, Serialize};

const MAX_AUDIT_FILE_BYTES: u64 = 10 * 1024 * 1024;
const RING_CAP: usize = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub principal: String,
    pub ip: String,
    pub section: String,
    pub tool: String,
    pub status: String,
    pub duration_ms: u64,
    pub summary: String,
}

pub struct AuditLogger {
    path: PathBuf,
    ring: Mutex<VecDeque<AuditEntry>>,
    file_lock: Mutex<()>,
}

impl AuditLogger {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        Self {
            path,
            ring: Mutex::new(VecDeque::with_capacity(RING_CAP)),
            file_lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(
        &self,
        principal: impl Into<String>,
        ip: impl Into<String>,
        section: impl Into<String>,
        tool: impl Into<String>,
        status: impl Into<String>,
        duration_ms: u64,
        raw_summary: &str,
    ) {
        let safe_summary: String = redact_secrets_in_text(raw_summary)
            .chars()
            .take(240)
            .collect();
        let entry = AuditEntry {
            ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            principal: principal.into(),
            ip: ip.into(),
            section: section.into(),
            tool: tool.into(),
            status: status.into(),
            duration_ms,
            summary: safe_summary,
        };

        {
            let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
            if ring.len() >= RING_CAP {
                ring.pop_front();
            }
            ring.push_back(entry.clone());
        }

        if let Ok(line) = serde_json::to_string(&entry) {
            let _g = self.file_lock.lock().unwrap_or_else(|e| e.into_inner());
            if let Ok(meta) = fs::metadata(&self.path) {
                if meta.len() >= MAX_AUDIT_FILE_BYTES {
                    let rotated = self.path.with_extension("jsonl.1");
                    let _ = fs::rename(&self.path, rotated);
                }
            }
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
                let _ = writeln!(f, "{line}");
            }
        }
    }

    pub fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        ring.iter()
            .rev()
            .take(limit.clamp(1, RING_CAP))
            .cloned()
            .collect()
    }
}
