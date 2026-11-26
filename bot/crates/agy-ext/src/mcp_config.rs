//! Secret-safe `mcp_config.json` CRUD with atomic `0600` writes and `.bak` retention.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

fn mcp_config_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Unmasked runtime specification for spawning a configured MCP server internally.
/// Never serialize or print `env`/`headers` into UI, logs, or responses.
#[derive(Clone)]
pub struct McpServerRaw {
    pub name: String,
    pub server_type: String,
    pub enabled: bool,
    pub command: String,
    pub args: Vec<String>,
    pub url: String,
    pub env: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
}

impl std::fmt::Debug for McpServerRaw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpServerRaw")
            .field("name", &self.name)
            .field("server_type", &self.server_type)
            .field("enabled", &self.enabled)
            .field("command", &self.command)
            .field("args", &self.args)
            .field("url", &self.url)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .finish()
    }
}

use agy_core::error::{BridgeError, Result};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tempfile::Builder;
use url::Url;

/// Default path to Antigravity MCP configuration.
pub const DEFAULT_MCP_CONFIG_PATH: &str = "/root/.gemini/config/mcp_config.json";

/// Placeholder emitted in place of sensitive env/header values when rendering config views.
pub const MASKED_SECRET: &str = "••••••••";

const SENSITIVE_KEY_PATTERN: &str =
    r"(TOKEN|KEY|SECRET|PASS|AUTH|BEARER|COOKIE|DSN|URI|CONNECTION|PRIVATE|CREDENTIAL)";

fn sensitive_key_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        RegexBuilder::new(SENSITIVE_KEY_PATTERN)
            .case_insensitive(true)
            .build()
            .ok()
    })
    .as_ref()
}

/// Redacted view of a configured MCP server entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpServerView {
    pub name: String,
    #[serde(rename = "type")]
    pub server_type: String,
    pub enabled: bool,
    pub command: String,
    pub args: Vec<String>,
    pub url: String,
    pub env: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub env_keys: Vec<String>,
    pub config_redacted: Value,
}

/// Partial update patch for [`update_mcp_server`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpServerUpdate {
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub url: Option<String>,
    pub env_set: Option<BTreeMap<String, String>>,
    pub env_unset: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

/// Return `true` if an env/header key name likely holds a secret.
pub fn is_sensitive_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    if upper == "SKILLPORT_SKILLS_DIR" || upper.ends_with("_DIR") || upper.ends_with("_PATH") {
        return false;
    }
    match sensitive_key_regex() {
        Some(re) => re.is_match(key),
        None => true,
    }
}

/// Return a copy of `mapping` with sensitive values replaced by [`MASKED_SECRET`].
pub fn mask_mapping(mapping: &BTreeMap<String, Value>) -> BTreeMap<String, String> {
    mapping
        .iter()
        .map(|(k, v)| {
            let masked_val = if is_sensitive_key(k) {
                MASKED_SECRET.to_string()
            } else {
                value_to_string(v)
            };
            (k.clone(), masked_val)
        })
        .collect()
}

fn mask_json_map(mapping: &Map<String, Value>) -> BTreeMap<String, String> {
    mapping
        .iter()
        .map(|(k, v)| {
            let masked_val = if is_sensitive_key(k) {
                MASKED_SECRET.to_string()
            } else {
                value_to_string(v)
            };
            (k.clone(), masked_val)
        })
        .collect()
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Atomically write UTF-8 text via a temporary sibling file, optional `chmod`, `fsync`, and `rename`.
pub(crate) fn atomic_write_text(target: &Path, content: &str, mode: Option<u32>) -> Result<()> {
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|e| BridgeError::io(format!("creating parent dir {}", parent.display()), e))?;

    let base_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let mut tmp = Builder::new()
        .prefix(&format!(".{base_name}."))
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|e| BridgeError::io(format!("creating temp file in {}", parent.display()), e))?;

    if let Some(m) = mode {
        tmp.as_file()
            .set_permissions(Permissions::from_mode(m))
            .map_err(|e| BridgeError::io("setting temp file permissions", e))?;
    }

    tmp.write_all(content.as_bytes())
        .map_err(|e| BridgeError::io(format!("writing temp file for {}", target.display()), e))?;
    tmp.flush()
        .map_err(|e| BridgeError::io(format!("flushing temp file for {}", target.display()), e))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| BridgeError::io(format!("fsyncing temp file for {}", target.display()), e))?;

    tmp.persist(target).map_err(|e| {
        BridgeError::io(format!("persisting atomic write to {}", target.display()), e.error)
    })?;
    Ok(())
}

fn load_mcp_config(config_path: &Path) -> Result<(PathBuf, Map<String, Value>)> {
    if !config_path.exists() {
        return Err(BridgeError::NotFound(format!(
            "MCP config not found: {}",
            config_path.display()
        )));
    }
    let raw = fs::read_to_string(config_path)
        .map_err(|e| BridgeError::io(format!("reading MCP config {}", config_path.display()), e))?;
    let parsed: Value = serde_json::from_str(&raw)
        .map_err(|e| BridgeError::json(format!("parsing MCP config {}", config_path.display()), e))?;

    let mut root = match parsed {
        Value::Object(map) => map,
        _ => {
            return Err(BridgeError::Validation(
                "MCP config root must be a JSON object".to_string(),
            ));
        }
    };

    match root.get("mcpServers") {
        None | Some(Value::Null) => {
            root.insert("mcpServers".to_string(), Value::Object(Map::new()));
        }
        Some(Value::Object(_)) => {}
        Some(_) => {
            return Err(BridgeError::Validation(
                "MCP config 'mcpServers' must be a JSON object".to_string(),
            ));
        }
    }

    Ok((config_path.to_path_buf(), root))
}

fn write_mcp_config(path: &Path, data: &Map<String, Value>) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .map_err(|e| BridgeError::io(format!("creating config dir {}", parent.display()), e))?;
    }

    if path.exists() {
        let orig = fs::read_to_string(path)
            .map_err(|e| BridgeError::io(format!("reading existing config {}", path.display()), e))?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("mcp_config.json");
        let bak_path = path.with_file_name(format!("{file_name}.bak"));
        atomic_write_text(&bak_path, &orig, Some(0o600))?;
    }

    let mut serialized = serde_json::to_string_pretty(data)
        .map_err(|e| BridgeError::json("serializing MCP config", e))?;
    serialized.push('\n');
    atomic_write_text(path, &serialized, Some(0o600))?;
    Ok(())
}

fn format_mcp_server(name: &str, entry: &Map<String, Value>) -> McpServerView {
    let url = entry
        .get("url")
        .or_else(|| entry.get("serverUrl"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let server_type = if url.is_empty() {
        "stdio".to_string()
    } else {
        "http".to_string()
    };

    let empty_map = Map::new();
    let raw_env = entry
        .get("env")
        .and_then(Value::as_object)
        .unwrap_or(&empty_map);
    let raw_headers = entry
        .get("headers")
        .and_then(Value::as_object)
        .unwrap_or(&empty_map);

    let masked_env = mask_json_map(raw_env);
    let masked_headers = mask_json_map(raw_headers);

    let mut redacted = entry.clone();
    if entry.get("env").and_then(Value::as_object).is_some() {
        let env_obj: Map<String, Value> = masked_env
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        redacted.insert("env".to_string(), Value::Object(env_obj));
    }
    if entry.get("headers").and_then(Value::as_object).is_some() {
        let hdr_obj: Map<String, Value> = masked_headers
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        redacted.insert("headers".to_string(), Value::Object(hdr_obj));
    }

    let args = entry
        .get("args")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(value_to_string).collect())
        .unwrap_or_default();

    let enabled = !entry
        .get("disabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let command = entry
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let env_keys = raw_env.keys().cloned().collect();

    McpServerView {
        name: name.to_string(),
        server_type,
        enabled,
        command,
        args,
        url,
        env: masked_env,
        headers: masked_headers,
        env_keys,
        config_redacted: Value::Object(redacted),
    }
}

fn is_valid_http_url(raw: &str) -> bool {
    match Url::parse(raw) {
        Ok(u) => matches!(u.scheme(), "http" | "https") && u.has_host(),
        Err(_) => false,
    }
}

fn restore_masked_dict(
    new_val: &Value,
    orig_val: Option<&Value>,
    field_name: &str,
) -> Result<Map<String, Value>> {
    let Some(new_map) = new_val.as_object() else {
        return Err(BridgeError::Validation(format!(
            "'{field_name}' must be a JSON object"
        )));
    };
    let empty = Map::new();
    let orig = orig_val.and_then(Value::as_object).unwrap_or(&empty);
    let mut restored = Map::new();

    for (k, v) in new_map {
        let vs = value_to_string(v);
        if vs == MASKED_SECRET {
            let Some(orig_v) = orig.get(k) else {
                return Err(BridgeError::Validation(format!(
                    "Cannot use masked placeholder for unknown {field_name} key '{k}'"
                )));
            };
            restored.insert(k.clone(), Value::String(value_to_string(orig_v)));
        } else {
            restored.insert(k.clone(), Value::String(vs));
        }
    }
    Ok(restored)
}

/// List configured MCP servers with all sensitive `env`/`headers` values masked.
/// Returns `Ok(vec![])` if `config_path` does not exist.
pub fn list_mcp_servers(config_path: &Path) -> Result<Vec<McpServerView>> {
    if !config_path.is_file() {
        return Ok(Vec::new());
    }
    let (_, data) = load_mcp_config(config_path)?;
    let Some(servers) = data.get("mcpServers").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (name, entry) in servers {
        if let Some(obj) = entry.as_object() {
            out.push(format_mcp_server(name, obj));
        }
    }
    Ok(out)
}

/// Return a single redacted MCP server view by `name`, or `Ok(None)` if not found.
pub fn get_mcp_server(config_path: &Path, name: &str) -> Result<Option<McpServerView>> {
    if name.is_empty() {
        return Ok(None);
    }
    let servers = list_mcp_servers(config_path)?;
    Ok(servers.into_iter().find(|s| s.name == name))
}

/// Internal-only unmasked list of configured MCP servers for spawning subprocesses
/// (e.g. `ai-memory` needs its real `DATABASE_URL`). Never expose to UI/logs.
pub fn list_mcp_servers_raw(config_path: &Path) -> Result<Vec<McpServerRaw>> {
    if !config_path.is_file() {
        return Ok(Vec::new());
    }
    let (_, data) = load_mcp_config(config_path)?;
    let Some(servers) = data.get("mcpServers").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (name, entry) in servers {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let url = obj
            .get("url")
            .or_else(|| obj.get("serverUrl"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let server_type = if url.is_empty() {
            "stdio".to_string()
        } else {
            "http".to_string()
        };
        let enabled = !obj
            .get("disabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let command = obj
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let args = obj
            .get("args")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().map(value_to_string).collect())
            .unwrap_or_default();
        let env = obj
            .get("env")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), value_to_string(v))).collect())
            .unwrap_or_default();
        let headers = obj
            .get("headers")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), value_to_string(v))).collect())
            .unwrap_or_default();
        out.push(McpServerRaw {
            name: name.clone(),
            server_type,
            enabled,
            command,
            args,
            url,
            env,
            headers,
        });
    }
    Ok(out)
}

/// Internal-only lookup of a single unmasked MCP server entry by `name`.
pub fn get_mcp_server_raw(config_path: &Path, name: &str) -> Result<Option<McpServerRaw>> {
    if name.is_empty() {
        return Ok(None);
    }
    Ok(list_mcp_servers_raw(config_path)?
        .into_iter()
        .find(|s| s.name == name))
}

/// Enable, disable, or toggle an MCP server in `mcp_config.json`.
pub fn toggle_mcp_server(
    config_path: &Path,
    name: &str,
    enabled: Option<bool>,
) -> Result<McpServerView> {
    let _guard = mcp_config_lock().lock().unwrap_or_else(|e| e.into_inner());
    let (path, mut data) = load_mcp_config(config_path)?;
    let servers = data
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| BridgeError::Validation("MCP config 'mcpServers' must be a JSON object".to_string()))?;

    let entry = servers
        .get_mut(name)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| BridgeError::NotFound(format!("MCP server not found: {name}")))?;

    let currently_enabled = !entry
        .get("disabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let new_enabled = enabled.unwrap_or(!currently_enabled);

    if new_enabled {
        entry.remove("disabled");
    } else {
        entry.insert("disabled".to_string(), Value::Bool(true));
    }

    let view = format_mcp_server(name, entry);
    write_mcp_config(&path, &data)?;
    Ok(view)
}

/// Update fields on an existing MCP server while preserving masked secrets and unknown top-level keys.
pub fn update_mcp_server(
    config_path: &Path,
    name: &str,
    patch: McpServerUpdate,
) -> Result<String> {
    let _guard = mcp_config_lock().lock().unwrap_or_else(|e| e.into_inner());
    let (path, mut data) = load_mcp_config(config_path)?;
    let servers = data
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| BridgeError::Validation("MCP config 'mcpServers' must be a JSON object".to_string()))?;

    let orig_entry = servers
        .get(name)
        .and_then(Value::as_object)
        .ok_or_else(|| BridgeError::NotFound(format!("MCP server not found: {name}")))?
        .clone();

    let mut updated = orig_entry.clone();

    if let Some(command) = patch.command {
        let trimmed = command.trim();
        if trimmed.is_empty() {
            return Err(BridgeError::Validation(
                "command must be a non-empty string".to_string(),
            ));
        }
        updated.insert("command".to_string(), Value::String(trimmed.to_string()));
        if patch.url.is_none() {
            updated.remove("url");
            updated.remove("serverUrl");
        }
    }

    if let Some(args) = patch.args {
        updated.insert(
            "args".to_string(),
            Value::Array(args.into_iter().map(Value::String).collect()),
        );
    }

    if let Some(url) = patch.url {
        let trimmed = url.trim();
        if !is_valid_http_url(trimmed) {
            return Err(BridgeError::Validation(
                "url must be a valid http(s) URL".to_string(),
            ));
        }
        updated.remove("command");
        updated.remove("args");
        if updated.contains_key("serverUrl") && !updated.contains_key("url") {
            updated.insert("serverUrl".to_string(), Value::String(trimmed.to_string()));
        } else {
            updated.insert("url".to_string(), Value::String(trimmed.to_string()));
        }
    }

    if patch.env_set.is_some() || patch.env_unset.is_some() {
        let orig_env = orig_entry
            .get("env")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let unset_set: HashSet<String> = patch
            .env_unset
            .unwrap_or_default()
            .into_iter()
            .collect();

        let mut new_env: Map<String, Value> = orig_env
            .iter()
            .filter(|(k, _)| !unset_set.contains(*k))
            .map(|(k, v)| (k.clone(), Value::String(value_to_string(v))))
            .collect();

        if let Some(env_set) = patch.env_set {
            for (k, v) in env_set {
                if v == MASKED_SECRET {
                    if !unset_set.contains(&k) {
                        if let Some(orig_v) = orig_env.get(&k) {
                            new_env.insert(k, Value::String(value_to_string(orig_v)));
                        }
                    }
                    continue;
                }
                new_env.insert(k, Value::String(v));
            }
        }

        if new_env.is_empty() {
            updated.remove("env");
        } else {
            updated.insert("env".to_string(), Value::Object(new_env));
        }
    }

    if let Some(enabled) = patch.enabled {
        if enabled {
            updated.remove("disabled");
        } else {
            updated.insert("disabled".to_string(), Value::Bool(true));
        }
    }

    servers.insert(name.to_string(), Value::Object(updated));
    write_mcp_config(&path, &data)?;
    Ok(format!("Updated MCP server '{name}'"))
}

/// Validate and replace (or add) an MCP server entry from raw JSON, restoring masked secrets.
pub fn replace_mcp_server_json(config_path: &Path, name: &str, raw_json: &str) -> Result<String> {
    let parsed: Value = serde_json::from_str(raw_json)
        .map_err(|e| BridgeError::Validation(format!("Invalid JSON: {e}")))?;
    replace_mcp_server_value(config_path, name, parsed)
}

/// Validate and replace (or add) an MCP server entry from a JSON [`Value`], restoring masked secrets.
pub fn replace_mcp_server_value(
    config_path: &Path,
    name: &str,
    entry: Value,
) -> Result<String> {
    let srv_name = name.trim();
    if srv_name.is_empty() || srv_name.chars().any(char::is_whitespace) {
        return Err(BridgeError::Validation(
            "Server name must be non-empty without whitespace".to_string(),
        ));
    }

    let mut parsed = match entry {
        Value::Object(map) => map,
        _ => {
            return Err(BridgeError::Validation(
                "Server configuration must be a JSON object".to_string(),
            ));
        }
    };

    let cmd = parsed.get("command");
    let url_val = if parsed.contains_key("url") {
        parsed.get("url")
    } else {
        parsed.get("serverUrl")
    };

    if cmd.is_none() && url_val.is_none() {
        return Err(BridgeError::Validation(
            "Server configuration must specify 'command' or 'url'/'serverUrl'".to_string(),
        ));
    }

    if let Some(cmd_v) = cmd {
        let Some(cmd_s) = cmd_v.as_str() else {
            return Err(BridgeError::Validation(
                "'command' must be a non-empty string".to_string(),
            ));
        };
        if cmd_s.trim().is_empty() {
            return Err(BridgeError::Validation(
                "'command' must be a non-empty string".to_string(),
            ));
        }
    }

    if let Some(url_v) = url_val {
        let Some(url_s) = url_v.as_str() else {
            return Err(BridgeError::Validation(
                "'url'/'serverUrl' must be a valid http(s) URL".to_string(),
            ));
        };
        if !is_valid_http_url(url_s.trim()) {
            return Err(BridgeError::Validation(
                "'url'/'serverUrl' must be a valid http(s) URL".to_string(),
            ));
        }
    }

    if let Some(args_v) = parsed.get("args") {
        let valid_args = args_v
            .as_array()
            .is_some_and(|arr| arr.iter().all(Value::is_string));
        if !valid_args {
            return Err(BridgeError::Validation(
                "'args' must be a list of strings".to_string(),
            ));
        }
    }

    if let Some(dis_v) = parsed.get("disabled") {
        if !dis_v.is_boolean() {
            return Err(BridgeError::Validation(
                "'disabled' must be a boolean".to_string(),
            ));
        }
    }

    let _guard = mcp_config_lock().lock().unwrap_or_else(|e| e.into_inner());
    let (path, mut data) = if config_path.exists() {
        load_mcp_config(config_path)?
    } else {
        let mut root = Map::new();
        root.insert("mcpServers".to_string(), Value::Object(Map::new()));
        (config_path.to_path_buf(), root)
    };

    let orig_entry = data
        .get("mcpServers")
        .and_then(Value::as_object)
        .and_then(|srvs| srvs.get(srv_name))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    for field_name in ["env", "headers"] {
        if let Some(field_val) = parsed.get(field_name) {
            let restored = restore_masked_dict(field_val, orig_entry.get(field_name), field_name)?;
            parsed.insert(field_name.to_string(), Value::Object(restored));
        }
    }

    let servers = data
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| BridgeError::Validation("MCP config 'mcpServers' must be a JSON object".to_string()))?;
    servers.insert(srv_name.to_string(), Value::Object(parsed));

    write_mcp_config(&path, &data)?;
    Ok(format!("Saved MCP server '{srv_name}'"))
}

/// Remove an MCP server from `mcp_config.json`.
pub fn remove_mcp_server(config_path: &Path, name: &str) -> Result<String> {
    let _guard = mcp_config_lock().lock().unwrap_or_else(|e| e.into_inner());
    let (path, mut data) = load_mcp_config(config_path)?;
    let servers = data
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| BridgeError::Validation("MCP config 'mcpServers' must be a JSON object".to_string()))?;

    if servers.remove(name).is_none() {
        return Err(BridgeError::NotFound(format!(
            "MCP server not found: {name}"
        )));
    }

    write_mcp_config(&path, &data)?;
    Ok(format!("Removed MCP server '{name}'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn test_sensitive_key_detection_and_masking() {
        for k in [
            "BOT_TOKEN",
            "openai_api_key",
            "MY_SECRET",
            "db_password",
            "Authorization",
            "bearer_val",
            "session_cookie",
            "pg_dsn",
            "DATABASE_URI",
            "conn_connection",
            "private_pem",
            "aws_credential",
        ] {
            assert!(is_sensitive_key(k), "expected {k} to be sensitive");
        }

        for k in [
            "SKILLPORT_SKILLS_DIR",
            "DATA_DIR",
            "SSL_KEY_PATH",
            "TOKEN_DIR",
            "PORT",
            "LOG_LEVEL",
        ] {
            assert!(!is_sensitive_key(k), "expected {k} NOT to be sensitive");
        }

        let mut input = BTreeMap::new();
        input.insert("API_KEY".to_string(), json!("super-secret-val"));
        input.insert(
            "SKILLPORT_SKILLS_DIR".to_string(),
            json!("/root/.skillport/skills"),
        );
        input.insert("DEBUG".to_string(), json!("1"));

        let masked = mask_mapping(&input);
        assert_eq!(masked.get("API_KEY").unwrap(), MASKED_SECRET);
        assert_eq!(
            masked.get("SKILLPORT_SKILLS_DIR").unwrap(),
            "/root/.skillport/skills"
        );
        assert_eq!(masked.get("DEBUG").unwrap(), "1");
    }

    #[test]
    fn test_mcp_config_crud_masks_preserves_secrets_unknown_keys_and_0600() {
        let dir = TempDir::new().unwrap();
        let cfg_path = dir.path().join("mcp_config.json");
        let initial = json!({
            "theme": "dark",
            "customMeta": {"version": 2, "flags": ["alpha"]},
            "mcpServers": {
                "local": {
                    "command": "/usr/bin/node",
                    "args": ["srv.js"],
                    "env": {
                        "API_KEY": "real-secret-123",
                        "SKILLPORT_SKILLS_DIR": "/root/.skillport/skills"
                    }
                },
                "remote": {
                    "url": "https://mcp.example.com/sse",
                    "headers": {
                        "Authorization": "Bearer real-header-secret",
                        "X-Env": "prod"
                    },
                    "disabled": true
                }
            }
        });
        fs::write(&cfg_path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();

        let srvs = list_mcp_servers(&cfg_path).unwrap();
        assert_eq!(srvs.len(), 2);
        let local = srvs.iter().find(|s| s.name == "local").unwrap();
        let remote = srvs.iter().find(|s| s.name == "remote").unwrap();

        assert_eq!(local.server_type, "stdio");
        assert!(local.enabled);
        assert_eq!(local.env.get("API_KEY").unwrap(), MASKED_SECRET);
        assert_eq!(
            local.env.get("SKILLPORT_SKILLS_DIR").unwrap(),
            "/root/.skillport/skills"
        );
        assert!(!serde_json::to_string(&srvs)
            .unwrap()
            .contains("real-secret-123"));

        assert_eq!(remote.server_type, "http");
        assert!(!remote.enabled);
        assert_eq!(remote.headers.get("Authorization").unwrap(), MASKED_SECRET);
        assert_eq!(remote.headers.get("X-Env").unwrap(), "prod");
        assert!(!serde_json::to_string(&srvs)
            .unwrap()
            .contains("real-header-secret"));

        // Toggle remote -> enabled (removes "disabled") + verify 0600 & .bak
        let toggled = toggle_mcp_server(&cfg_path, "remote", None).unwrap();
        assert!(toggled.enabled);
        let raw_after_toggle: Value =
            serde_json::from_str(&fs::read_to_string(&cfg_path).unwrap()).unwrap();
        assert!(raw_after_toggle["mcpServers"]["remote"]
            .get("disabled")
            .is_none());
        assert_eq!(raw_after_toggle["theme"], "dark");
        assert_eq!(raw_after_toggle["customMeta"]["version"], 2);
        assert_eq!(
            fs::metadata(&cfg_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let bak_path = dir.path().join("mcp_config.json.bak");
        assert!(bak_path.exists());
        assert_eq!(
            fs::metadata(&bak_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Update local passing MASKED_SECRET -> preserves real secret
        let mut env_set = BTreeMap::new();
        env_set.insert("API_KEY".to_string(), MASKED_SECRET.to_string());
        env_set.insert("MODE".to_string(), "prod".to_string());
        update_mcp_server(
            &cfg_path,
            "local",
            McpServerUpdate {
                args: Some(vec!["srv.js".to_string(), "--fast".to_string()]),
                env_set: Some(env_set),
                env_unset: Some(vec!["SKILLPORT_SKILLS_DIR".to_string()]),
                ..Default::default()
            },
        )
        .unwrap();

        let raw_after_update: Value =
            serde_json::from_str(&fs::read_to_string(&cfg_path).unwrap()).unwrap();
        assert_eq!(
            raw_after_update["mcpServers"]["local"]["args"],
            json!(["srv.js", "--fast"])
        );
        assert_eq!(
            raw_after_update["mcpServers"]["local"]["env"],
            json!({"API_KEY": "real-secret-123", "MODE": "prod"})
        );
        assert_eq!(raw_after_update["theme"], "dark");

        // Replace JSON using redacted copy of remote -> restores Authorization secret
        let mut redacted_remote = get_mcp_server(&cfg_path, "remote")
            .unwrap()
            .unwrap()
            .config_redacted;
        redacted_remote["url"] = json!("https://mcp.example.com/v2");
        replace_mcp_server_json(
            &cfg_path,
            "remote",
            &serde_json::to_string(&redacted_remote).unwrap(),
        )
        .unwrap();
        let raw_after_replace: Value =
            serde_json::from_str(&fs::read_to_string(&cfg_path).unwrap()).unwrap();
        assert_eq!(
            raw_after_replace["mcpServers"]["remote"]["url"],
            "https://mcp.example.com/v2"
        );
        assert_eq!(
            raw_after_replace["mcpServers"]["remote"]["headers"]["Authorization"],
            "Bearer real-header-secret"
        );
        assert_eq!(raw_after_replace["customMeta"]["flags"], json!(["alpha"]));

        // Validation rejections
        assert!(replace_mcp_server_json(&cfg_path, "bad", "{broken").is_err());
        assert!(replace_mcp_server_value(&cfg_path, "bad", json!({"url": "ftp://nope"})).is_err());
        assert!(replace_mcp_server_value(&cfg_path, "bad", json!({"command": "   "})).is_err());
        assert!(replace_mcp_server_value(
            &cfg_path,
            "new_srv",
            json!({"command": "node", "env": {"API_KEY": MASKED_SECRET}})
        )
        .is_err());
        assert!(update_mcp_server(
            &cfg_path,
            "local",
            McpServerUpdate {
                command: Some("   ".to_string()),
                ..Default::default()
            }
        )
        .is_err());
        assert!(update_mcp_server(
            &cfg_path,
            "remote",
            McpServerUpdate {
                url: Some("ftp://invalid".to_string()),
                ..Default::default()
            }
        )
        .is_err());

        // Remove server & verify unknown top-level keys remain
        remove_mcp_server(&cfg_path, "remote").unwrap();
        assert!(get_mcp_server(&cfg_path, "remote").unwrap().is_none());
        let raw_after_remove: Value =
            serde_json::from_str(&fs::read_to_string(&cfg_path).unwrap()).unwrap();
        assert_eq!(raw_after_remove["theme"], "dark");

        // Creating a brand-new config file from scratch enforces 0600 and preserves serverUrl
        let brand_new = dir.path().join("sub").join("new_mcp.json");
        replace_mcp_server_json(
            &brand_new,
            "srvA",
            r#"{"serverUrl":"https://api.example.com/mcp","headers":{"X-Auth":"tok"}}"#,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&brand_new).unwrap().permissions().mode() & 0o777,
            0o600
        );
        update_mcp_server(
            &brand_new,
            "srvA",
            McpServerUpdate {
                url: Some("https://api.example.com/v2".to_string()),
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
        let raw_new: Value =
            serde_json::from_str(&fs::read_to_string(&brand_new).unwrap()).unwrap();
        assert_eq!(
            raw_new["mcpServers"]["srvA"]["serverUrl"],
            "https://api.example.com/v2"
        );
        assert!(raw_new["mcpServers"]["srvA"].get("url").is_none());
        assert_eq!(raw_new["mcpServers"]["srvA"]["disabled"], true);
    }
}
