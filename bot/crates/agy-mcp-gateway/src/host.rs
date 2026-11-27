//! Host bridge trait decoupling `agy-mcp-gateway` from `agy-bot` runtime internals.

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Request to execute a guarded prompt on an upstream Antigravity / Grok / Venice model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostModelRunRequest {
    pub engine: String,
    pub model: Option<String>,
    pub prompt: String,
    pub effort: Option<String>,
    pub conversation_id: Option<String>,
    pub three_stage: Option<String>,
    pub agent_mode: bool,
    pub cwd: Option<String>,
}

/// Sanitized model run outcome returned to MCP clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostModelRunResult {
    pub ok: bool,
    pub engine: String,
    pub model: String,
    pub text: String,
    pub conversation_id: Option<String>,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// Bridge implemented by `agy-bot` to give `agy-mcp-gateway` direct in-process access to
/// Telegram Owner notifications, `AccountStore`, `StateStore`, `JobManager`, and `local_fast`.
pub trait GatewayHostBridge: Send + Sync {
    fn owner_id(&self) -> i64;

    /// All configured owner Telegram user IDs (defaults to primary `owner_id()`).
    fn owner_ids(&self) -> Vec<i64> {
        vec![self.owner_id()]
    }

    /// Send an inline OAuth 2.1 approval card to the Owner in Telegram.
    fn notify_owner_oauth<'a>(
        &'a self,
        req_id: &'a str,
        client_name: &'a str,
        scope: &'a str,
        client_ip: &'a str,
        resource: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

    /// Send an inline HITL approval card to the Owner in Telegram for a high-risk tool call.
    fn notify_owner_hitl<'a>(
        &'a self,
        req_id: &'a str,
        principal_label: &'a str,
        tool_name: &'a str,
        args_preview: &'a str,
        client_ip: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

    /// Send a security alert (e.g. manifest rug-pull drift) to the Owner in Telegram.
    fn notify_owner_security_alert<'a>(
        &'a self,
        title: &'a str,
        detail: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

    /// List available Antigravity models (cached / live).
    fn list_antigravity_models(&self) -> Value;

    /// Sanitized account pool health summary (opaque slot IDs & % remaining; NEVER emails/tokens).
    fn pool_health_summary(&self) -> Value;

    /// Get Owner's current active model/engine/effort/conversation state.
    fn current_bot_state(&self) -> Value;

    /// Switch active model/effort on Owner's bot state (or session).
    fn switch_bot_model(
        &self,
        engine: Option<&str>,
        model: Option<&str>,
        effort: Option<&str>,
        three_stage: Option<&str>,
    ) -> Result<Value, String>;

    /// List recent bot sessions from `StateStore`.
    fn list_sessions(&self, limit: usize) -> Value;

    /// Switch or create a bot session in `StateStore`.
    fn select_session(&self, conversation_id: Option<&str>, new_session: bool) -> Result<Value, String>;

    /// Classify prompt complexity locally (0 AI tokens) via `turn_profile`.
    fn classify_turn(&self, text: &str, has_attachments: bool) -> &'static str;

    /// Attempt zero-token local evaluation via `local_fast` (math/time/status).
    fn try_local_fast(&self, text: &str) -> Option<String>;

    /// Execute a guarded Antigravity model turn through `AccountStore` + sticky proxy + `JobManager`.
    fn run_antigravity_turn<'a>(
        &'a self,
        req: HostModelRunRequest,
    ) -> Pin<Box<dyn Future<Output = HostModelRunResult> + Send + 'a>>;
}

/// No-op mock bridge for unit/integration tests inside `agy-mcp-gateway`.
#[derive(Default)]
pub struct NullHostBridge;

impl GatewayHostBridge for NullHostBridge {
    fn owner_id(&self) -> i64 {
        0
    }

    fn notify_owner_oauth<'a>(
        &'a self,
        _req_id: &'a str,
        _client_name: &'a str,
        _scope: &'a str,
        _client_ip: &'a str,
        _resource: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    fn notify_owner_hitl<'a>(
        &'a self,
        _req_id: &'a str,
        _principal_label: &'a str,
        _tool_name: &'a str,
        _args_preview: &'a str,
        _client_ip: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    fn notify_owner_security_alert<'a>(
        &'a self,
        _title: &'a str,
        _detail: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    fn list_antigravity_models(&self) -> Value {
        serde_json::json!([])
    }

    fn pool_health_summary(&self) -> Value {
        serde_json::json!({"accounts": [], "mode": "test"})
    }

    fn current_bot_state(&self) -> Value {
        serde_json::json!({"engine": "agy", "model": "default"})
    }

    fn switch_bot_model(
        &self,
        engine: Option<&str>,
        model: Option<&str>,
        effort: Option<&str>,
        three_stage: Option<&str>,
    ) -> Result<Value, String> {
        Ok(serde_json::json!({
            "switched": true,
            "engine": engine,
            "model": model,
            "effort": effort,
            "three_stage": three_stage
        }))
    }

    fn list_sessions(&self, _limit: usize) -> Value {
        serde_json::json!({"active": null, "history": []})
    }

    fn select_session(&self, conversation_id: Option<&str>, new_session: bool) -> Result<Value, String> {
        Ok(serde_json::json!({"conversation_id": conversation_id, "new_session": new_session}))
    }

    fn classify_turn(&self, text: &str, has_attachments: bool) -> &'static str {
        if has_attachments || text.len() > 600 || text.contains("```") {
            "full"
        } else if text.len() > 220 {
            "standard"
        } else {
            "lite"
        }
    }

    fn try_local_fast(&self, _text: &str) -> Option<String> {
        None
    }

    fn run_antigravity_turn<'a>(
        &'a self,
        req: HostModelRunRequest,
    ) -> Pin<Box<dyn Future<Output = HostModelRunResult> + Send + 'a>> {
        Box::pin(async move {
            HostModelRunResult {
                ok: true,
                engine: req.engine,
                model: req.model.unwrap_or_else(|| "mock".to_string()),
                text: format!("mock-reply: {}", req.prompt),
                conversation_id: req.conversation_id,
                duration_ms: 1,
                error: None,
            }
        })
    }
}
