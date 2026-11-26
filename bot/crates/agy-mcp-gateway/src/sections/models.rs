//! Section 6: Multi-Model Catalog, Live Switching & Anti-Ban Guarded Execution (`/mcp/s/models`).

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};
use tokio::sync::watch;

use crate::config::SectionId;
use crate::host::{GatewayHostBridge, HostModelRunRequest};
use crate::policy::{PolicyEngine, ToolRisk};
use crate::registry::{make_annotations, ToolSpec};

pub fn models_tool_specs() -> Vec<ToolSpec> {
    let ro = make_annotations(true, false, true, false);
    let wr = make_annotations(false, false, true, false);
    let ai = make_annotations(false, false, false, true);
    vec![
        ToolSpec {
            name: "models_list".to_string(),
            section: SectionId::Models,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "List all available AI models across Antigravity (Gemini/Claude), Grok Subscription, and Venice Uncensored.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "engine": {"type": "string", "description": "Optional filter: all|agy|grok|uncensored", "default": "all"}
                }
            }),
            annotations: ro.clone(),
            keywords: vec!["models".into(), "gemini".into(), "claude".into(), "grok".into(), "venice".into()],
        },
        ToolSpec {
            name: "models_current".to_string(),
            section: SectionId::Models,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Get the active bot model, engine, effort level, and 3-Stage mode.".to_string(),
            input_schema: json!({"type": "object", "properties": {}}),
            annotations: ro.clone(),
            keywords: vec!["model".into(), "current".into(), "state".into()],
        },
        ToolSpec {
            name: "models_switch".to_string(),
            section: SectionId::Models,
            risk: ToolRisk::Write,
            untrusted_output: false,
            description: "Switch the active model, engine (agy/grok/uncensored), reasoning effort (low/medium/high), or Venice 3-Stage mode (auto/on/off).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "engine": {"type": "string", "description": "agy | grok | uncensored"},
                    "model": {"type": "string", "description": "Model ID (e.g. gemini-3-pro, grok-4, venice-uncensored)"},
                    "effort": {"type": "string", "description": "low | medium | high"},
                    "three_stage": {"type": "string", "description": "auto | on | off"}
                }
            }),
            annotations: wr,
            keywords: vec!["switch".into(), "model".into(), "effort".into(), "3stage".into()],
        },
        ToolSpec {
            name: "models_pool_health".to_string(),
            section: SectionId::Models,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Inspect sanitized upstream account pool health, remaining quota percentages, and active MCP AI concurrency slots (zero emails or tokens exposed).".to_string(),
            input_schema: json!({"type": "object", "properties": {}}),
            annotations: ro,
            keywords: vec!["quota".into(), "health".into(), "accounts".into(), "pool".into()],
        },
        ToolSpec {
            name: "models_run".to_string(),
            section: SectionId::Models,
            risk: ToolRisk::AiModelRun,
            untrusted_output: false,
            description: "Execute a prompt on Antigravity (Gemini/Claude), Grok, or Venice Uncensored with full anti-ban concurrency & quota protection.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "prompt": {"type": "string"},
                    "engine": {"type": "string", "default": "agy", "description": "agy | grok | uncensored"},
                    "model": {"type": "string", "description": "Optional model ID override"},
                    "effort": {"type": "string", "description": "low | medium | high"},
                    "conversation_id": {"type": "string", "description": "Optional conversation ID to resume"},
                    "agent_mode": {"type": "boolean", "default": false},
                    "three_stage": {"type": "string", "description": "For uncensored: auto | on | off"}
                },
                "required": ["prompt"]
            }),
            annotations: ai.clone(),
            keywords: vec!["run".into(), "chat".into(), "grok".into(), "uncensored".into(), "gemini".into(), "claude".into()],
        },
        ToolSpec {
            name: "models_compare".to_string(),
            section: SectionId::Models,
            risk: ToolRisk::AiModelRun,
            untrusted_output: false,
            description: "Run a prompt across two selected engines/models sequentially (respecting anti-ban concurrency caps) for a cross-model second opinion.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "prompt": {"type": "string"},
                    "engine_a": {"type": "string", "default": "uncensored"},
                    "model_a": {"type": "string"},
                    "engine_b": {"type": "string", "default": "grok"},
                    "model_b": {"type": "string"}
                },
                "required": ["prompt"]
            }),
            annotations: ai,
            keywords: vec!["compare".into(), "second_opinion".into(), "multi_model".into()],
        },
    ]
}

#[allow(clippy::too_many_arguments)]
pub async fn call_models_tool(
    host: &Arc<dyn GatewayHostBridge>,
    policy: &Arc<PolicyEngine>,
    state_dir: &Path,
    workspace: &Path,
    mcp_config: &Path,
    skills_dir: &Path,
    tool: &str,
    args: &Value,
    cancel: watch::Receiver<bool>,
) -> std::result::Result<Value, String> {
    match tool {
        "models_list" => {
            let filter = args
                .get("engine")
                .and_then(Value::as_str)
                .unwrap_or("all")
                .to_ascii_lowercase();
            let mut out = serde_json::Map::new();
            if filter == "all" || filter == "agy" {
                out.insert("antigravity".to_string(), host.list_antigravity_models());
            }
            if filter == "all" || filter == "grok" {
                let mut grok = agy_ext::grok_oauth::load_cached_grok_models(state_dir);
                if grok.is_empty() {
                    grok = agy_ext::grok_oauth::fallback_grok_models();
                }
                let list: Vec<Value> = grok
                    .into_iter()
                    .map(|m| json!({"id": m.id, "label": m.name}))
                    .collect();
                out.insert("grok".to_string(), Value::Array(list));
            }
            if filter == "all" || filter == "uncensored" || filter == "venice" {
                let mut unc = agy_ext::uncensored::load_cached_uncensored_models(state_dir);
                if unc.is_empty() {
                    unc = agy_ext::uncensored::fallback_uncensored_models();
                }
                let list: Vec<Value> = unc
                    .into_iter()
                    .map(|m| json!({"id": m.id, "name": m.name, "context_length": m.context_length}))
                    .collect();
                out.insert("venice_uncensored".to_string(), Value::Array(list));
            }
            Ok(Value::Object(out))
        }
        "models_current" => Ok(host.current_bot_state()),
        "models_switch" => {
            let engine = args.get("engine").and_then(Value::as_str);
            let model = args.get("model").and_then(Value::as_str);
            let effort = args.get("effort").and_then(Value::as_str);
            let three_stage = args.get("three_stage").and_then(Value::as_str);
            host.switch_bot_model(engine, model, effort, three_stage)
        }
        "models_pool_health" => {
            let mut summary = host.pool_health_summary();
            if let Some(obj) = summary.as_object_mut() {
                obj.insert(
                    "mcp_ai_slots_available".to_string(),
                    json!(policy.active_ai_slots_available()),
                );
            }
            Ok(summary)
        }
        "models_run" => {
            let _slot = policy.try_acquire_ai_slot().ok_or_else(|| {
                "MCP AI concurrency limit saturated (anti-ban protection). Try again shortly or use async_mode=true.".to_string()
            })?;
            let prompt = args
                .get("prompt")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "prompt must not be empty".to_string())?;
            let engine = args
                .get("engine")
                .and_then(Value::as_str)
                .unwrap_or("agy")
                .to_ascii_lowercase();
            let model = args.get("model").and_then(Value::as_str).map(str::to_string);
            let effort = args.get("effort").and_then(Value::as_str).map(str::to_string);
            let conv_id = args
                .get("conversation_id")
                .and_then(Value::as_str)
                .map(str::to_string);
            let agent_mode = args
                .get("agent_mode")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let three_stage = args
                .get("three_stage")
                .and_then(Value::as_str)
                .map(str::to_string);

            run_single_engine(
                host,
                state_dir,
                workspace,
                mcp_config,
                skills_dir,
                HostModelRunRequest {
                    engine,
                    model,
                    prompt: prompt.to_string(),
                    effort,
                    conversation_id: conv_id,
                    three_stage,
                    agent_mode,
                    cwd: None,
                },
                cancel,
            )
            .await
        }
        "models_compare" => {
            let _slot = policy.try_acquire_ai_slot().ok_or_else(|| {
                "MCP AI concurrency limit saturated (anti-ban protection).".to_string()
            })?;
            let prompt = args
                .get("prompt")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "prompt must not be empty".to_string())?;
            let eng_a = args
                .get("engine_a")
                .and_then(Value::as_str)
                .unwrap_or("uncensored")
                .to_string();
            let mod_a = args.get("model_a").and_then(Value::as_str).map(str::to_string);
            let eng_b = args
                .get("engine_b")
                .and_then(Value::as_str)
                .unwrap_or("grok")
                .to_string();
            let mod_b = args.get("model_b").and_then(Value::as_str).map(str::to_string);

            let res_a = run_single_engine(
                host,
                state_dir,
                workspace,
                mcp_config,
                skills_dir,
                HostModelRunRequest {
                    engine: eng_a,
                    model: mod_a,
                    prompt: prompt.to_string(),
                    effort: None,
                    conversation_id: None,
                    three_stage: Some("off".to_string()),
                    agent_mode: false,
                    cwd: None,
                },
                cancel.clone(),
            )
            .await;

            let res_b = run_single_engine(
                host,
                state_dir,
                workspace,
                mcp_config,
                skills_dir,
                HostModelRunRequest {
                    engine: eng_b,
                    model: mod_b,
                    prompt: prompt.to_string(),
                    effort: None,
                    conversation_id: None,
                    three_stage: Some("off".to_string()),
                    agent_mode: false,
                    cwd: None,
                },
                cancel,
            )
            .await;

            Ok(json!({
                "model_a": res_a.unwrap_or_else(|e| json!({"ok": false, "error": e})),
                "model_b": res_b.unwrap_or_else(|e| json!({"ok": false, "error": e}))
            }))
        }
        other => Err(format!("unknown models tool: {other}")),
    }
}

async fn run_single_engine(
    host: &Arc<dyn GatewayHostBridge>,
    state_dir: &Path,
    workspace: &Path,
    mcp_config: &Path,
    skills_dir: &Path,
    req: HostModelRunRequest,
    cancel: watch::Receiver<bool>,
) -> std::result::Result<Value, String> {
    let t0 = Instant::now();
    match req.engine.as_str() {
        "uncensored" | "venice" => {
            let (api_base, api_key) = agy_ext::agent_runtime::resolve_venice_credentials(mcp_config);
            if api_key.trim().is_empty() {
                return Err("Venice Uncensored API key is not configured on host".to_string());
            }
            let model_str = req
                .model
                .as_deref()
                .unwrap_or(agy_ext::uncensored::DEFAULT_UNCENSORED_MODEL);
            let ts_mode = match req.three_stage.as_deref().unwrap_or("auto") {
                "on" | "always" => agy_ext::agent_runtime::ThreeStageMode::Always,
                "off" => agy_ext::agent_runtime::ThreeStageMode::Off,
                _ => agy_ext::agent_runtime::ThreeStageMode::Auto,
            };
            let res = agy_ext::uncensored::run_uncensored_agent_with_stage(
                &api_base,
                &api_key,
                model_str,
                &req.prompt,
                workspace,
                workspace,
                mcp_config,
                skills_dir,
                state_dir,
                req.conversation_id.clone(),
                false,
                false,
                req.agent_mode,
                Some(20),
                None,
                ts_mode,
                None,
                cancel,
            )
            .await
            .map_err(|e| e.to_string())?;
            Ok(json!({
                "ok": res.error.is_none(),
                "engine": "uncensored",
                "model": model_str,
                "text": res.text,
                "duration_ms": t0.elapsed().as_millis() as u64
            }))
        }
        "grok" => {
            let model_str = req
                .model
                .as_deref()
                .unwrap_or(agy_ext::grok_oauth::DEFAULT_GROK_MODEL);
            let res = agy_ext::grok_oauth::run_grok_agent_with_options(
                state_dir,
                model_str,
                &req.prompt,
                workspace,
                workspace,
                mcp_config,
                skills_dir,
                req.conversation_id.clone(),
                false,
                false,
                req.agent_mode,
                Some(20),
                None,
                None,
                None,
                cancel,
            )
            .await
            .map_err(|e| e.to_string())?;
            Ok(json!({
                "ok": res.error.is_none(),
                "engine": "grok",
                "model": model_str,
                "text": res.text,
                "duration_ms": t0.elapsed().as_millis() as u64
            }))
        }
        _ => {
            let res = host.run_antigravity_turn(req).await;
            serde_json::to_value(&res).map_err(|e| e.to_string())
        }
    }
}
