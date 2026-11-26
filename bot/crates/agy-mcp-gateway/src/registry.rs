//! Tool catalog, section schemas, and lightweight BM25-style Progressive Discovery index
//! (`hub_discover_tools`) preventing the 40k-token MCP Context Tax while exposing 120+ tools.

use serde_json::{json, Value};

use crate::auth::AuthenticatedPrincipal;
use crate::config::{GatewayConfig, SectionId};
use crate::policy::ToolRisk;

/// Metadata for a single registered MCP tool.
#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: String,
    pub section: SectionId,
    pub risk: ToolRisk,
    pub untrusted_output: bool,
    pub description: String,
    pub input_schema: Value,
    pub annotations: Value,
    pub keywords: Vec<String>,
}

impl ToolSpec {
    pub fn to_mcp_json(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": self.annotations
        })
    }
}

pub fn make_annotations(read_only: bool, destructive: bool, idempotent: bool, open_world: bool) -> Value {
    json!({
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        "openWorldHint": open_world
    })
}

/// Core Smart Hub meta-tools (~12 tools, ~2.5k tokens total) exposed on `/mcp`.
pub fn smart_hub_meta_tools() -> Vec<Value> {
    vec![
        json!({
            "name": "hub_discover_tools",
            "description": "Search across all 120+ AGY bot tools (OpenHands, Search-v3, SkillHub, AI-Memory, Gortex/Graphify/Context7, Models, Sessions, Token Optimizers, Federation) using keywords or intent. Returns ranked tool names, sections, and compact descriptions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query or task intent (e.g. 'edit file', 'web search dork', 'switch grok model', 'compact tokens')"},
                    "section": {"type": "string", "description": "Optional section filter: openhands|search|skillhub|memory|codeintel|models|sessions|optimizer|federation"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 30, "default": 10}
                },
                "required": ["query"]
            },
            "annotations": make_annotations(true, false, true, false)
        }),
        json!({
            "name": "hub_tool_schema",
            "description": "Fetch the exact full JSON inputSchema and risk policy for one or more discovered tools before calling them via hub_call_tool.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "names": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tool names to inspect (max 10)"
                    }
                },
                "required": ["names"]
            },
            "annotations": make_annotations(true, false, true, false)
        }),
        json!({
            "name": "hub_call_tool",
            "description": "Execute any discovered tool from any allowed section with full RBAC, secret redaction, manifest pinning, and optional async task mode (recommended for >45s jobs behind Cloudflare).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "description": "Exact tool name (e.g. 'skillhub_search', 'search_web_v3', 'oh_glob_files', 'models_switch')"},
                    "arguments": {"type": "object", "description": "Tool arguments matching its inputSchema", "default": {}},
                    "async_mode": {"type": "boolean", "description": "If true, runs in background and returns task_id immediately for polling via hub_task_status", "default": false}
                },
                "required": ["tool"]
            },
            "annotations": make_annotations(false, true, false, true)
        }),
        json!({
            "name": "hub_list_sections",
            "description": "List all 9 modular AGY MCP sections, their dedicated direct URLs (/mcp/s/<section>), tool counts, and whether your token has access.",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": make_annotations(true, false, true, false)
        }),
        json!({
            "name": "hub_status",
            "description": "Return live AGY MCP Gateway health, active mode, rate-limit posture, RO cache stats, and sanitized account pool status.",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": make_annotations(true, false, true, false)
        }),
        json!({
            "name": "hub_task_status",
            "description": "Poll the status and result of a background async MCP task launched with async_mode=true.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"}
                },
                "required": ["task_id"]
            },
            "annotations": make_annotations(true, false, true, false)
        }),
        json!({
            "name": "hub_task_cancel",
            "description": "Cancel a running background async MCP task immediately.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"}
                },
                "required": ["task_id"]
            },
            "annotations": make_annotations(false, false, true, false)
        }),
    ]
}

/// Rank tools matching `query` using lightweight BM25-style term scoring across name, section,
/// description, and keywords. Only returns tools allowed by `cfg` & `principal` (Discovery != AuthZ,
/// and unauthorized sections are hidden by default to prevent capability leakage).
pub fn discover_tools(
    catalog: &[ToolSpec],
    cfg: &GatewayConfig,
    principal: &AuthenticatedPrincipal,
    query: &str,
    section_filter: Option<SectionId>,
    limit: usize,
) -> Vec<Value> {
    let terms: Vec<String> = query
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .filter(|s| s.len() >= 2)
        .map(str::to_string)
        .collect();

    let mut scored: Vec<(f64, &ToolSpec)> = catalog
        .iter()
        .filter(|t| {
            if !cfg.is_section_enabled(t.section) {
                return false;
            }
            if !principal.is_owner && !principal.has_section(t.section) {
                return false;
            }
            if let Some(sf) = section_filter {
                if t.section != sf {
                    return false;
                }
            }
            true
        })
        .filter_map(|t| {
            if terms.is_empty() {
                return Some((1.0, t));
            }
            let name_l = t.name.to_ascii_lowercase();
            let desc_l = t.description.to_ascii_lowercase();
            let sec_l = t.section.slug();
            let mut score = 0.0f64;
            let mut matched_terms = 0usize;
            for term in &terms {
                let mut hit = false;
                if name_l == *term {
                    score += 12.0;
                    hit = true;
                } else if name_l.contains(term.as_str()) {
                    score += 6.0;
                    hit = true;
                }
                if sec_l.contains(term.as_str()) {
                    score += 4.0;
                    hit = true;
                }
                if t.keywords.iter().any(|k| k.contains(term.as_str())) {
                    score += 3.5;
                    hit = true;
                }
                if desc_l.contains(term.as_str()) {
                    score += 2.0;
                    hit = true;
                }
                if hit {
                    matched_terms += 1;
                }
            }
            if score > 0.0 {
                // Coordination boost when multiple query terms match
                let coord = 1.0 + (matched_terms as f64 / terms.len().max(1) as f64);
                Some((score * coord, t))
            } else {
                None
            }
        })
        .collect();

    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.name.cmp(&b.1.name))
    });

    scored
        .into_iter()
        .take(limit.clamp(1, 30))
        .map(|(sc, t)| {
            json!({
                "name": t.name,
                "section": t.section.slug(),
                "risk": format!("{:?}", t.risk),
                "score": (sc * 10.0).round() / 10.0,
                "description": t.description
            })
        })
        .collect()
}
