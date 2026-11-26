//! Async AI-Memory MCP client helpers (`memory_overview`, `memory_add`, `memory_remove`).

use std::collections::BTreeMap;

use agy_core::error::{BridgeError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::mcp_client::{call_stdio_mcp_tool, looks_like_secret, DEFAULT_MCP_TIMEOUT_SECS};

/// Default binary path for the AI-Memory stdio MCP server.
pub const DEFAULT_AI_MEMORY_BIN: &str = "/root/.local/bin/ai-memory-mcp";

/// Allowed memory types accepted by AI-Memory.
pub const VALID_MEMORY_TYPES: &[&str] = &[
    "fact",
    "conversation",
    "decision",
    "insight",
    "error",
    "context",
    "preference",
    "task",
];

/// Normalized AI-Memory record returned in [`MemoryOverview`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryItem {
    pub id: String,
    pub short_id: String,
    pub title: String,
    pub summary: String,
    #[serde(rename = "type")]
    pub mtype: String,
    pub tags: Vec<String>,
    pub confidence: f64,
    pub created_at: String,
}

/// Combined stats + recent/searched memories payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryOverview {
    pub ok: bool,
    pub total: u64,
    pub recent_24h: u64,
    pub types: BTreeMap<String, u64>,
    pub items: Vec<MemoryItem>,
    pub error: Option<String>,
}

fn parse_u64_lenient(val: Option<&Value>) -> u64 {
    match val {
        Some(Value::Number(n)) => n
            .as_u64()
            .or_else(|| n.as_i64().and_then(|i| u64::try_from(i).ok()))
            .or_else(|| n.as_f64().map(|f| if f > 0.0 { f as u64 } else { 0 }))
            .unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

fn parse_f64_lenient(val: Option<&Value>) -> f64 {
    match val {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.trim().parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn parse_memory_types(raw_dist: Option<&Value>) -> BTreeMap<String, u64> {
    let mut types = BTreeMap::new();
    match raw_dist {
        Some(Value::Object(map)) => {
            for (k, v) in map {
                if let Some(count) = try_parse_u64(v) {
                    types.insert(k.clone(), count);
                }
            }
        }
        Some(Value::Array(arr)) => {
            for entry in arr {
                let Some(obj) = entry.as_object() else {
                    continue;
                };
                let Some(mtype) = obj.get("type").and_then(Value::as_str).filter(|s| !s.is_empty())
                else {
                    continue;
                };
                let count_val = obj.get("count").unwrap_or(&Value::Null);
                if let Some(count) = try_parse_u64(count_val) {
                    types.insert(mtype.to_string(), count);
                } else if count_val.is_null() {
                    types.insert(mtype.to_string(), 0);
                }
            }
        }
        _ => {}
    }
    types
}

fn try_parse_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n
            .as_u64()
            .or_else(|| n.as_i64().and_then(|i| u64::try_from(i).ok())),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn non_empty_str_field(obj: &Map<String, Value>, keys: &[&str]) -> String {
    for key in keys {
        if let Some(val) = obj.get(*key) {
            match val {
                Value::String(s) if !s.is_empty() => return s.clone(),
                Value::Number(n) => return n.to_string(),
                Value::Bool(b) => return b.to_string(),
                _ => {}
            }
        }
    }
    String::new()
}

fn normalize_memory_item(raw: &Map<String, Value>) -> MemoryItem {
    let mid = raw
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let short_id: String = mid.chars().take(8).collect();

    let mut title = String::new();
    let mut summary = String::new();

    match raw.get("content") {
        Some(Value::Object(content)) => {
            title = non_empty_str_field(content, &["title", "name", "decision", "fact"]);
            summary = non_empty_str_field(
                content,
                &["summary", "description", "text", "message", "fact"],
            );
            if title.is_empty() {
                if let Some(first_val) = content
                    .values()
                    .find_map(|v| v.as_str().filter(|s| !s.trim().is_empty()))
                {
                    title = first_val.chars().take(80).collect();
                }
            }
            if summary.is_empty() && !title.is_empty() {
                summary = title.clone();
            }
        }
        Some(Value::String(s)) => {
            title = s.chars().take(80).collect();
            summary = s.clone();
        }
        _ => {}
    }

    let tags = raw
        .get("tags")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    Value::Bool(b) => Some(b.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    let confidence = parse_f64_lenient(raw.get("confidence"));

    MemoryItem {
        id: mid,
        short_id,
        title,
        summary,
        mtype: raw
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        tags,
        confidence,
        created_at: raw
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    }
}

/// Fetch AI-Memory stats and recent or searched memories concurrently via stdio MCP.
///
/// Preserves partial data (`total`, `types`, or `items`) when one of the two calls fails,
/// reporting errors in `ok: false` and `error: Some(...)`.
pub async fn memory_overview(
    bin: &str,
    query: &str,
    mtype: Option<&str>,
    limit: usize,
) -> MemoryOverview {
    let q = query.trim();
    let mut list_args = Map::new();
    list_args.insert("limit".to_string(), json!(limit.max(1)));
    if let Some(t) = mtype.map(str::trim).filter(|s| !s.is_empty()) {
        list_args.insert("type".to_string(), Value::String(t.to_string()));
    }
    let list_tool = if q.is_empty() {
        "memory_list"
    } else {
        list_args.insert("query".to_string(), Value::String(q.to_string()));
        "memory_search"
    };

    let stats_fut = call_stdio_mcp_tool(bin, "memory_stats", json!({}), None, DEFAULT_MCP_TIMEOUT_SECS);
    let items_fut = call_stdio_mcp_tool(
        bin,
        list_tool,
        Value::Object(list_args),
        None,
        DEFAULT_MCP_TIMEOUT_SECS,
    );

    let (stats_res, items_res) = tokio::join!(stats_fut, items_fut);

    let mut total = 0u64;
    let mut recent_24h = 0u64;
    let mut types = BTreeMap::new();
    let mut errors = Vec::new();

    match stats_res {
        Ok(Value::Object(stats)) => {
            total = parse_u64_lenient(stats.get("total_memories"));
            recent_24h = parse_u64_lenient(stats.get("recent_memories_24h"));
            types = parse_memory_types(stats.get("type_distribution"));
        }
        Ok(_) => errors.push("stats: unexpected response format".to_string()),
        Err(exc) => errors.push(format!("stats: {exc}")),
    }

    let mut items = Vec::new();
    match items_res {
        Ok(Value::Array(arr)) => {
            for item in arr {
                if let Some(obj) = item.as_object() {
                    items.push(normalize_memory_item(obj));
                }
            }
        }
        Ok(Value::Object(obj)) if obj.get("results").is_some_and(Value::is_array) => {
            if let Some(arr) = obj.get("results").and_then(Value::as_array) {
                for item in arr {
                    if let Some(mobj) = item.as_object() {
                        items.push(normalize_memory_item(mobj));
                    }
                }
            }
        }
        Ok(_) => errors.push(format!("{list_tool}: unexpected response format")),
        Err(exc) => errors.push(format!("{list_tool}: {exc}")),
    }

    MemoryOverview {
        ok: errors.is_empty(),
        total,
        recent_24h,
        types,
        items,
        error: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
    }
}

/// Validate and store a new memory via AI-Memory stdio MCP (`memory_store`).
pub async fn memory_add(
    bin: &str,
    title: &str,
    summary: &str,
    mtype: &str,
    tags: &[String],
) -> Result<Value> {
    memory_add_with_source(bin, title, summary, mtype, tags, "telegram").await
}

/// Validate and store a new memory via AI-Memory stdio MCP with an explicit `source` label.
pub async fn memory_add_with_source(
    bin: &str,
    title: &str,
    summary: &str,
    mtype: &str,
    tags: &[String],
    source: &str,
) -> Result<Value> {
    let clean_title = title.trim();
    let clean_summary = summary.trim();
    if clean_title.is_empty() || clean_summary.is_empty() {
        return Err(BridgeError::Validation(
            "Title and summary must be non-empty".to_string(),
        ));
    }
    if clean_title.chars().count() > 200 || clean_summary.chars().count() > 200 {
        return Err(BridgeError::Validation(
            "Title and summary must each be <= 200 characters".to_string(),
        ));
    }
    if !VALID_MEMORY_TYPES.contains(&mtype) {
        return Err(BridgeError::Validation(format!(
            "Invalid memory type: {mtype}"
        )));
    }

    let clean_tags: Vec<String> = tags
        .iter()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect();

    if looks_like_secret(clean_title)
        || looks_like_secret(clean_summary)
        || clean_tags.iter().any(|t| looks_like_secret(t))
    {
        return Err(BridgeError::Validation(
            "Refused: potential secret pattern detected in memory content".to_string(),
        ));
    }

    let src = if source.trim().is_empty() {
        "telegram"
    } else {
        source.trim()
    };

    let mut args = Map::new();
    args.insert(
        "content".to_string(),
        json!({
            "title": clean_title,
            "summary": clean_summary,
        }),
    );
    args.insert("type".to_string(), Value::String(mtype.to_string()));
    args.insert("source".to_string(), Value::String(src.to_string()));
    args.insert("confidence".to_string(), json!(0.9));
    if !clean_tags.is_empty() {
        args.insert("tags".to_string(), json!(clean_tags));
    }

    let res = call_stdio_mcp_tool(
        bin,
        "memory_store",
        Value::Object(args),
        None,
        DEFAULT_MCP_TIMEOUT_SECS,
    )
    .await?;

    if res.is_object() {
        Ok(res)
    } else {
        Ok(json!({ "result": res }))
    }
}

fn is_hyphenated_uuid(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && Uuid::parse_str(raw).is_ok()
}

/// Delete a memory by full UUID or unambiguous hex/hyphen prefix (`>= 6` characters).
pub async fn memory_remove(bin: &str, id: &str) -> Result<String> {
    let raw = id.trim();
    if raw.is_empty() {
        return Err(BridgeError::Validation(
            "Memory ID must not be empty".to_string(),
        ));
    }

    let target_id = if is_hyphenated_uuid(raw) {
        raw.to_string()
    } else {
        if raw.len() < 6 || !raw.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
            return Err(BridgeError::Validation(
                "Memory ID prefix must be at least 6 hex/hyphen characters".to_string(),
            ));
        }
        let list_val = call_stdio_mcp_tool(
            bin,
            "memory_list",
            json!({ "limit": 50 }),
            None,
            DEFAULT_MCP_TIMEOUT_SECS,
        )
        .await?;

        let items = match &list_val {
            Value::Array(arr) => arr,
            Value::Object(obj) if obj.get("results").is_some_and(Value::is_array) => obj
                .get("results")
                .and_then(Value::as_array)
                .ok_or_else(|| BridgeError::Mcp {
                    server: bin.to_string(),
                    tool: "memory_list".to_string(),
                    message: "Unexpected response from memory_list".to_string(),
                })?,
            _ => {
                return Err(BridgeError::Mcp {
                    server: bin.to_string(),
                    tool: "memory_list".to_string(),
                    message: "Unexpected response from memory_list".to_string(),
                });
            }
        };

        let prefix_l = raw.to_ascii_lowercase();
        let matches: Vec<String> = items
            .iter()
            .filter_map(|item| item.as_object()?.get("id")?.as_str())
            .filter(|mid| mid.to_ascii_lowercase().starts_with(&prefix_l))
            .map(str::to_string)
            .collect();

        if matches.is_empty() {
            return Err(BridgeError::NotFound(format!(
                "No memory found matching prefix '{raw}'"
            )));
        }
        if matches.len() > 1 {
            return Err(BridgeError::Validation(format!(
                "Ambiguous prefix '{raw}' matched {} memories",
                matches.len()
            )));
        }
        matches[0].clone()
    };

    let res = call_stdio_mcp_tool(
        bin,
        "memory_delete",
        json!({ "id": target_id }),
        None,
        DEFAULT_MCP_TIMEOUT_SECS,
    )
    .await?;

    let short: String = target_id.chars().take(8).collect();
    if let Some(obj) = res.as_object() {
        if obj.get("success").and_then(Value::as_bool) == Some(false) {
            let msg = obj
                .get("message")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("Memory not found: {target_id}"));
            return Err(BridgeError::NotFound(msg));
        }
        let msg = obj
            .get("message")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("Deleted memory {short}"));
        return Ok(msg);
    }

    Ok(format!("Deleted memory {short}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn write_mock_mem_mcp(dir: &TempDir, name: &str, body: &str) -> String {
        let path = dir.path().join(name);
        let script = format!("#!/usr/bin/env python3\nimport json, sys\n{body}\n");
        fs::write(&path, script).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn test_memory_overview_add_and_remove() {
        let dir = TempDir::new().unwrap();
        let db_file = dir.path().join("mem_calls.json");
        fs::write(&db_file, "[]").unwrap();
        let uuid_1 = "11111111-2222-3333-4444-555555555555";
        let uuid_2 = "11111199-aaaa-bbbb-cccc-dddddddddddd";

        let mem_bin = write_mock_mem_mcp(
            &dir,
            "fake_mem_mcp.py",
            &format!(
                r#"
DB = {db:?}
U1 = {u1:?}
U2 = {u2:?}
for raw in sys.stdin:
    msg = json.loads(raw)
    m = msg.get("method")
    if m == "initialize":
        print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": {{}}}}), flush=True)
    elif m == "tools/call":
        name = msg["params"]["name"]
        args = msg["params"]["arguments"]
        if name == "memory_stats":
            res = {{
                "total_memories": 2,
                "recent_memories_24h": 1,
                "type_distribution": [{{"type": "decision", "count": "2"}}, {{"type": "fact", "count": 1}}],
            }}
        elif name in ("memory_list", "memory_search"):
            res = [
                {{
                    "id": U1,
                    "content": {{"title": "Use atomic writes", "summary": "Always swap via tmp"}},
                    "type": "decision",
                    "tags": ["safety"],
                    "confidence": 0.95,
                    "created_at": "2026-11-18T00:00:00Z",
                }},
                {{
                    "id": U2,
                    "content": {{"title": "Prefer cargo test", "summary": "Run with clippy"}},
                    "type": "fact",
                    "tags": [],
                    "confidence": 0.9,
                    "created_at": "2026-11-18T00:01:00Z",
                }},
            ]
        elif name == "memory_store":
            calls = json.loads(open(DB).read())
            calls.append(["store", args])
            open(DB, "w").write(json.dumps(calls))
            res = {{"id": U1, "content": args["content"], "type": args["type"]}}
        elif name == "memory_delete":
            calls = json.loads(open(DB).read())
            calls.append(["delete", args["id"]])
            open(DB, "w").write(json.dumps(calls))
            if args["id"] == U1:
                res = {{"success": True, "message": "Soft deleted 1 memory"}}
            else:
                res = {{"success": False, "message": "No memory found to delete"}}
        print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": {{"content": [{{"type": "text", "text": json.dumps(res)}}]}}}}), flush=True)
        break
"#,
                db = db_file.to_string_lossy(),
                u1 = uuid_1,
                u2 = uuid_2
            ),
        );

        let ov = memory_overview(&mem_bin, "", None, 8).await;
        assert!(ov.ok);
        assert_eq!(ov.total, 2);
        assert_eq!(ov.recent_24h, 1);
        assert_eq!(ov.types.get("decision"), Some(&2));
        assert_eq!(ov.types.get("fact"), Some(&1));
        assert_eq!(ov.items[0].short_id, "11111111");
        assert_eq!(ov.items[0].title, "Use atomic writes");

        let ov_q = memory_overview(&mem_bin, "atomic", Some("decision"), 8).await;
        assert!(ov_q.ok);
        assert_eq!(ov_q.items.len(), 2);

        // Validation & secret blocking in memory_add
        assert!(memory_add(&mem_bin, "", "ok", "fact", &[]).await.is_err());
        assert!(memory_add(&mem_bin, &"t".repeat(201), "ok", "fact", &[]).await.is_err());
        assert!(memory_add(&mem_bin, "title", "ok", "invalid_type", &[]).await.is_err());
        for secret in [
            "sk-proj-1234567890abcdef",
            "ghp_abcdefghij1234567890",
            "BOT_TOKEN=123456:ABCDEF",
            "postgres://user:pass@localhost/db",
        ] {
            let err = memory_add(&mem_bin, "bad", secret, "fact", &[])
                .await
                .unwrap_err()
                .to_string();
            assert!(!err.contains(secret));
        }

        // Benign strings containing `sk-` inside words must pass
        let stored = memory_add(
            &mem_bin,
            "task-123 note",
            "Ask user before purge",
            "fact",
            &["ops".to_string()],
        )
        .await
        .unwrap();
        assert!(stored.is_object());

        // Prefix resolution & deletion
        assert!(memory_remove(&mem_bin, "11111").await.is_err()); // < 6 chars
        assert!(memory_remove(&mem_bin, "111111").await.is_err()); // ambiguous
        assert!(memory_remove(&mem_bin, "not-hex-!").await.is_err());
        memory_remove(&mem_bin, "11111111").await.unwrap();
        assert!(memory_remove(&mem_bin, "99999999-2222-3333-4444-555555555555").await.is_err());

        let recorded: Value = serde_json::from_str(&fs::read_to_string(&db_file).unwrap()).unwrap();
        let arr = recorded.as_array().unwrap();
        assert!(arr.contains(&json!(["delete", uuid_1])));
    }

    #[tokio::test]
    async fn test_memory_overview_partial_error_handling() {
        let dir = TempDir::new().unwrap();
        let failing_bin = write_mock_mem_mcp(
            &dir,
            "fail_mem.py",
            r#"
for raw in sys.stdin:
    msg = json.loads(raw)
    if msg.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {}}), flush=True)
    elif msg.get("method") == "tools/call":
        name = msg["params"]["name"]
        if name == "memory_stats":
            print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": json.dumps({"total_memories": 5, "recent_memories_24h": 1, "type_distribution": []})}]}}), flush=True)
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"isError": True, "content": [{"type": "text", "text": "db down"}]}}), flush=True)
        break
"#,
        );

        let ov = memory_overview(&failing_bin, "", None, 8).await;
        assert!(!ov.ok);
        assert_eq!(ov.total, 5);
        assert!(ov.items.is_empty());
        assert!(ov.error.as_deref().unwrap_or("").contains("db down"));
    }

    #[tokio::test]
    async fn test_memory_overview_dict_dist_and_string_content() {
        let dir = TempDir::new().unwrap();
        let bin = write_mock_mem_mcp(
            &dir,
            "dict_mem.py",
            r#"
for raw in sys.stdin:
    msg = json.loads(raw)
    if msg.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {}}), flush=True)
    elif msg.get("method") == "tools/call":
        name = msg["params"]["name"]
        if name == "memory_stats":
            res = {"total_memories": "3", "recent_memories_24h": 2, "type_distribution": {"fact": 3}}
        else:
            res = {"results": [{"id": "abcdef12-0000-0000-0000-000000000000", "content": "Plain memory note", "type": "fact"}]}
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": json.dumps(res)}]}}), flush=True)
        break
"#,
        );
        let ov = memory_overview(&bin, "note", None, 5).await;
        assert!(ov.ok);
        assert_eq!(ov.total, 3);
        assert_eq!(ov.types.get("fact"), Some(&3));
        assert_eq!(ov.items.len(), 1);
        assert_eq!(ov.items[0].title, "Plain memory note");
        assert_eq!(ov.items[0].short_id, "abcdef12");
    }
}
