//! Section 8: Zero-Token Token & Context Optimizers (`/mcp/s/optimizer`).
//!
//! Exposes `turn_profile` classification, `local_fast` evaluation, head+tail context compaction,
//! ECC `strategic-compact` & 6-phase `prompt-optimizer` analysis, token estimation,
//! `McpClientPool` RO cache telemetry, and `<agy_slot>` chunked file assembly — all in <1ms with
//! ZERO upstream AI token spend!

use serde_json::{json, Value};

use crate::config::SectionId;
use crate::host::GatewayHostBridge;
use crate::policy::ToolRisk;
use crate::registry::{make_annotations, ToolSpec};
use crate::sanitize::compact_head_tail;

pub fn optimizer_tool_specs() -> Vec<ToolSpec> {
    let ro = make_annotations(true, false, true, false);
    vec![
        ToolSpec {
            name: "opt_classify_turn".to_string(),
            section: SectionId::Optimizer,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Classify prompt complexity locally in <10us (0 AI tokens) into lite/standard/full with recommended model tier and reasoning effort.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "prompt": {"type": "string"},
                    "has_attachments": {"type": "boolean", "default": false}
                },
                "required": ["prompt"]
            }),
            annotations: ro.clone(),
            keywords: vec!["turn_profile".into(), "effort".into(), "token".into(), "optimize".into()],
        },
        ToolSpec {
            name: "opt_local_eval".to_string(),
            section: SectionId::Optimizer,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Attempt zero-token local evaluation (arithmetic, ping, status, time) via the bot's local_fast Rust engine.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "text": {"type": "string"} },
                "required": ["text"]
            }),
            annotations: ro.clone(),
            keywords: vec!["local_fast".into(), "zero_token".into(), "math".into()],
        },
        ToolSpec {
            name: "opt_compact_text".to_string(),
            section: SectionId::Optimizer,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Compact large logs, code, or tool outputs using UTF-8-safe head+tail preservation to save context tokens.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "max_tokens": {"type": "integer", "minimum": 64, "maximum": 32000, "default": 1500}
                },
                "required": ["text"]
            }),
            annotations: ro.clone(),
            keywords: vec!["compact".into(), "truncate".into(), "context".into(), "tokens".into()],
        },
        ToolSpec {
            name: "opt_strategic_compact_check".to_string(),
            section: SectionId::Optimizer,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Evaluate current context pressure and tool-call count using ECC strategic-compact heuristics and recommend whether/how to compact now.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "context_tokens": {"type": "integer", "minimum": 0},
                    "window_tokens": {"type": "integer", "default": 200000},
                    "tool_calls": {"type": "integer", "default": 0},
                    "phase": {"type": "string", "description": "research|planning|mid_implementation|debugging|testing|milestone"}
                },
                "required": ["context_tokens"]
            }),
            annotations: ro.clone(),
            keywords: vec!["strategic-compact".into(), "context".into(), "window".into()],
        },
        ToolSpec {
            name: "opt_prompt_analyze".to_string(),
            section: SectionId::Optimizer,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Analyze a draft prompt (0 AI tokens) to detect intent, scope, missing context, and recommended SkillHub workflows/sections.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "draft_prompt": {"type": "string"}
                },
                "required": ["draft_prompt"]
            }),
            annotations: ro.clone(),
            keywords: vec!["prompt-optimizer".into(), "prompt".into(), "skills".into(), "intent".into()],
        },
        ToolSpec {
            name: "opt_token_estimate".to_string(),
            section: SectionId::Optimizer,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Fast deterministic token estimator for English, Persian/Unicode, and code payloads with context window percentage.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "window_tokens": {"type": "integer", "default": 200000}
                },
                "required": ["text"]
            }),
            annotations: ro.clone(),
            keywords: vec!["token".into(), "count".into(), "budget".into(), "estimate".into()],
        },
        ToolSpec {
            name: "opt_cache_stats".to_string(),
            section: SectionId::Optimizer,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Inspect live McpClientPool read-only response cache hits, misses, and savings ratio.".to_string(),
            input_schema: json!({"type": "object", "properties": {}}),
            annotations: ro.clone(),
            keywords: vec!["cache".into(), "mcp".into(), "telemetry".into()],
        },
        ToolSpec {
            name: "opt_slot_assemble".to_string(),
            section: SectionId::Optimizer,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Assemble chunked `<agy_slot id=...>` markers deterministically into a clean merged source artifact without re-emitting untouched code.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "base_template": {"type": "string", "description": "Template containing `<!-- AGY_SLOT:id -->` or `// AGY_SLOT:id` markers"},
                    "slots": {"type": "object", "description": "Map of slot_id -> replacement code string"}
                },
                "required": ["base_template", "slots"]
            }),
            annotations: ro,
            keywords: vec!["agy_slot".into(), "chunked".into(), "assemble".into(), "codegen".into()],
        },
    ]
}

pub fn estimate_tokens_fast(text: &str) -> usize {
    let mut ascii_chars = 0usize;
    let mut non_ascii_chars = 0usize;
    for c in text.chars() {
        if c.is_ascii() {
            ascii_chars += 1;
        } else {
            non_ascii_chars += 1;
        }
    }
    // English/code ~3.8 chars/token; Persian/CJK ~1.7 chars/token
    ascii_chars.div_ceil(4) + (non_ascii_chars * 10).div_ceil(17)
}

pub fn call_optimizer_tool(
    host: &dyn GatewayHostBridge,
    tool: &str,
    args: &Value,
) -> std::result::Result<Value, String> {
    match tool {
        "opt_classify_turn" => {
            let prompt = args.get("prompt").and_then(Value::as_str).unwrap_or("");
            let has_att = args
                .get("has_attachments")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let tier = host.classify_turn(prompt, has_att);
            let (effort, model_hint) = match tier {
                "lite" => ("low", "fast/flash/haiku"),
                "standard" => ("medium", "sonnet/pro-standard"),
                _ => ("high", "opus/gemini-pro/3-stage"),
            };
            Ok(json!({
                "profile": tier,
                "recommended_effort": effort,
                "recommended_model_tier": model_hint,
                "estimated_tokens": estimate_tokens_fast(prompt),
                "ai_tokens_spent": 0
            }))
        }
        "opt_local_eval" => {
            let text = args.get("text").and_then(Value::as_str).unwrap_or("");
            let reply = host.try_local_fast(text);
            Ok(json!({
                "handled_locally": reply.is_some(),
                "reply": reply,
                "ai_tokens_spent": 0
            }))
        }
        "opt_compact_text" => {
            let text = args.get("text").and_then(Value::as_str).unwrap_or("");
            let max_tok = args
                .get("max_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(1500)
                .clamp(64, 32_000) as usize;
            let max_bytes = max_tok * 4;
            let before_tok = estimate_tokens_fast(text);
            let compacted = compact_head_tail(text, max_bytes);
            let after_tok = estimate_tokens_fast(&compacted);
            Ok(json!({
                "before_tokens": before_tok,
                "after_tokens": after_tok,
                "saved_tokens": before_tok.saturating_sub(after_tok),
                "compacted_text": compacted
            }))
        }
        "opt_strategic_compact_check" => {
            let ctx_tok = args.get("context_tokens").and_then(Value::as_u64).unwrap_or(0);
            let win_tok = args
                .get("window_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(200_000)
                .max(8_192);
            let tool_calls = args.get("tool_calls").and_then(Value::as_u64).unwrap_or(0);
            let phase = args
                .get("phase")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_ascii_lowercase();
            let pct = (ctx_tok as f64 / win_tok as f64) * 100.0;
            let threshold = if win_tok >= 900_000 { 250_000 } else { (win_tok * 80) / 100 };
            let do_not_compact = matches!(phase.as_str(), "mid_implementation" | "debugging");
            let should_compact = !do_not_compact && (ctx_tok >= threshold || tool_calls >= 50 || pct >= 75.0);
            let advice = if do_not_compact && pct < 90.0 {
                "Hold compaction until current implementation/debug unit finishes; write plan/state to disk first."
            } else if should_compact {
                "Compact now: persist plan & decisions to .handoff or ai-memory, then run /compact with a focus summary."
            } else {
                "Context budget healthy; continue without compacting."
            };
            Ok(json!({
                "should_compact": should_compact,
                "context_pct": (pct * 10.0).round() / 10.0,
                "threshold_tokens": threshold,
                "tool_calls": tool_calls,
                "phase": phase,
                "advice": advice
            }))
        }
        "opt_prompt_analyze" => {
            let draft = args.get("draft_prompt").and_then(Value::as_str).unwrap_or("");
            let low = draft.to_ascii_lowercase();
            let mut intents = Vec::new();
            let mut skills = Vec::new();
            let mut sections = Vec::new();
            if low.contains("bug") || low.contains("fix") || low.contains("error") || low.contains("باگ") {
                intents.push("bug_fix");
                skills.push("systematic-debugging");
                sections.push("codeintel");
            }
            if low.contains("security") || low.contains("auth") || low.contains("امنیت") || low.contains("oauth") {
                intents.push("security");
                skills.push("security-review");
            }
            if low.contains("build") || low.contains("create") || low.contains("بساز") || low.contains("پیاده") {
                intents.push("new_feature");
                skills.push("writing-plans");
                skills.push("test-driven-development");
                sections.push("openhands");
            }
            if low.contains("search") || low.contains("research") || low.contains("تحقیق") || low.contains("سرچ") {
                intents.push("research");
                sections.push("search");
                sections.push("skillhub");
            }
            if intents.is_empty() {
                intents.push("general");
            }
            let mut missing = Vec::new();
            if draft.chars().count() < 60 {
                missing.push("target_scope_and_files");
            }
            if !low.contains("test") && !low.contains("verify") && !low.contains("تست") {
                missing.push("acceptance_and_verification_criteria");
            }
            Ok(json!({
                "intents": intents,
                "turn_profile": host.classify_turn(draft, false),
                "estimated_tokens": estimate_tokens_fast(draft),
                "recommended_skills": skills,
                "recommended_sections": sections,
                "missing_context_hints": missing
            }))
        }
        "opt_token_estimate" => {
            let text = args.get("text").and_then(Value::as_str).unwrap_or("");
            let win = args
                .get("window_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(200_000)
                .max(1);
            let tokens = estimate_tokens_fast(text);
            Ok(json!({
                "chars": text.chars().count(),
                "bytes": text.len(),
                "estimated_tokens": tokens,
                "window_pct": ((tokens as f64 / win as f64) * 10_000.0).round() / 100.0
            }))
        }
        "opt_cache_stats" => {
            let (hits, misses) = agy_ext::mcp_client::global_mcp_pool().ro_cache_stats();
            let total = hits + misses;
            let hit_rate = if total == 0 {
                0.0
            } else {
                (hits as f64 / total as f64) * 100.0
            };
            Ok(json!({
                "ro_cache_hits": hits,
                "ro_cache_misses": misses,
                "hit_rate_pct": (hit_rate * 10.0).round() / 10.0
            }))
        }
        "opt_slot_assemble" => {
            let mut out = args
                .get("base_template")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let slots = args
                .get("slots")
                .and_then(Value::as_object)
                .ok_or_else(|| "slots must be a JSON object".to_string())?;
            let mut replaced = 0usize;
            for (k, v) in slots {
                let rep = v.as_str().unwrap_or("");
                for marker in [
                    format!("<!-- AGY_SLOT:{k} -->"),
                    format!("// AGY_SLOT:{k}"),
                    format!("# AGY_SLOT:{k}"),
                    format!("<agy_slot id=\"{k}\"/>"),
                ] {
                    if out.contains(&marker) {
                        out = out.replace(&marker, rep);
                        replaced += 1;
                    }
                }
            }
            Ok(json!({
                "slots_replaced": replaced,
                "assembled": out
            }))
        }
        other => Err(format!("unknown optimizer tool: {other}")),
    }
}
