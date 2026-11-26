//! Section 7: Sessions, Transcripts & `.handoff` Continuity (`/mcp/s/sessions`).

use std::path::Path;

use serde_json::{json, Value};

use crate::config::SectionId;
use crate::host::GatewayHostBridge;
use crate::policy::ToolRisk;
use crate::registry::{make_annotations, ToolSpec};
use crate::sanitize::compact_head_tail;

pub fn sessions_tool_specs() -> Vec<ToolSpec> {
    let ro = make_annotations(true, false, true, false);
    let wr = make_annotations(false, false, true, false);
    vec![
        ToolSpec {
            name: "session_list".to_string(),
            section: SectionId::Sessions,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "List active and recent Telegram/Antigravity bot conversation sessions.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "limit": {"type": "integer", "default": 10, "minimum": 1, "maximum": 50} }
            }),
            annotations: ro.clone(),
            keywords: vec!["session".into(), "conversation".into(), "history".into()],
        },
        ToolSpec {
            name: "session_select".to_string(),
            section: SectionId::Sessions,
            risk: ToolRisk::Write,
            untrusted_output: false,
            description: "Switch active bot conversation to an existing conversation_id or start a fresh session (new_session=true).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "conversation_id": {"type": "string"},
                    "new_session": {"type": "boolean", "default": false}
                }
            }),
            annotations: wr.clone(),
            keywords: vec!["session".into(), "resume".into(), "switch".into(), "new".into()],
        },
        ToolSpec {
            name: "session_handoff_read".to_string(),
            section: SectionId::Sessions,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Read the active Telegram Owner `.handoff` continuity note for seamless cross-client context pickup.".to_string(),
            input_schema: json!({"type": "object", "properties": {}}),
            annotations: ro.clone(),
            keywords: vec!["handoff".into(), "continuity".into(), "context".into()],
        },
        ToolSpec {
            name: "session_handoff_write".to_string(),
            section: SectionId::Sessions,
            risk: ToolRisk::Write,
            untrusted_output: false,
            description: "Update the `.handoff` continuity note (secret-redacted, atomic write, max 60 lines).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "content": {"type": "string"} },
                "required": ["content"]
            }),
            annotations: wr,
            keywords: vec!["handoff".into(), "save".into(), "milestone".into()],
        },
        ToolSpec {
            name: "session_transcript_list".to_string(),
            section: SectionId::Sessions,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "List saved transcript files under `$STATE_DIR/transcripts/` with sizes and timestamps.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "limit": {"type": "integer", "default": 15, "minimum": 1, "maximum": 50} }
            }),
            annotations: ro.clone(),
            keywords: vec!["transcript".into(), "logs".into(), "history".into()],
        },
        ToolSpec {
            name: "session_transcript_read".to_string(),
            section: SectionId::Sessions,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Read a compacted, secret-redacted excerpt of a specific transcript filename.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "filename": {"type": "string"},
                    "max_bytes": {"type": "integer", "default": 8192, "minimum": 512, "maximum": 32768}
                },
                "required": ["filename"]
            }),
            annotations: ro,
            keywords: vec!["transcript".into(), "read".into(), "session".into()],
        },
    ]
}

pub fn call_sessions_tool(
    host: &dyn GatewayHostBridge,
    state_dir: &Path,
    workspace: &Path,
    tool: &str,
    args: &Value,
) -> std::result::Result<Value, String> {
    let owner_uid = host.owner_id();
    let handoff_path = workspace.join(".handoff").join(format!("tg-{owner_uid}.md"));

    match tool {
        "session_list" => {
            let lim = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(10)
                .clamp(1, 50) as usize;
            Ok(host.list_sessions(lim))
        }
        "session_select" => {
            let conv = args.get("conversation_id").and_then(Value::as_str);
            let new_sess = args
                .get("new_session")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            host.select_session(conv, new_sess)
        }
        "session_handoff_read" => {
            if !handoff_path.exists() {
                return Ok(json!({"exists": false, "path": handoff_path.display().to_string(), "content": ""}));
            }
            let raw = std::fs::read_to_string(&handoff_path).map_err(|e| e.to_string())?;
            Ok(json!({
                "exists": true,
                "path": handoff_path.display().to_string(),
                "content": agy_ext::mcp_client::redact_secrets_in_text(&raw)
            }))
        }
        "session_handoff_write" => {
            let raw = args
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| "content is required".to_string())?;
            let clean = agy_ext::mcp_client::redact_secrets_in_text(raw);
            let capped: String = clean.lines().take(65).collect::<Vec<_>>().join("\n");
            if let Some(parent) = handoff_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            agy_core::atomic::atomic_write_bytes(&handoff_path, capped.as_bytes(), 0o600)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "written": true,
                "path": handoff_path.display().to_string(),
                "bytes": capped.len()
            }))
        }
        "session_transcript_list" => {
            let dir = state_dir.join("transcripts");
            let lim = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(15)
                .clamp(1, 50) as usize;
            let mut items = Vec::new();
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for ent in rd.flatten() {
                    if let Ok(meta) = ent.metadata() {
                        if meta.is_file() {
                            let mtime = meta
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            items.push((
                                mtime,
                                json!({
                                    "filename": ent.file_name().to_string_lossy(),
                                    "bytes": meta.len(),
                                    "modified_unix": mtime
                                }),
                            ));
                        }
                    }
                }
            }
            items.sort_by(|a, b| b.0.cmp(&a.0));
            let out: Vec<Value> = items.into_iter().take(lim).map(|(_, v)| v).collect();
            Ok(json!({"count": out.len(), "transcripts": out}))
        }
        "session_transcript_read" => {
            let fname = args
                .get("filename")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.contains('/') && !s.contains('\\') && !s.contains(".."))
                .ok_or_else(|| "invalid transcript filename".to_string())?;
            let max_b = args
                .get("max_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(8192)
                .clamp(512, 32_768) as usize;
            let p = state_dir.join("transcripts").join(fname);
            let raw = std::fs::read_to_string(&p).map_err(|e| format!("reading transcript: {e}"))?;
            let safe = agy_ext::mcp_client::redact_secrets_in_text(&raw);
            Ok(json!({
                "filename": fname,
                "content": compact_head_tail(&safe, max_b)
            }))
        }
        other => Err(format!("unknown sessions tool: {other}")),
    }
}
