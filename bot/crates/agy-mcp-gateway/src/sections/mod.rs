//! Unified Section Dispatcher bridging all 9 modular sections:
//! 1. OpenHands (in-process `agy_ext::openhands_mcp` — 19 tools)
//! 2. Search-v3 (pooled `search-v3` MCP — 8 tools)
//! 3. SkillHub + SkillPort + Skills-Catalog (in-process Rust SkillHub + pooled MCPs — 13 tools)
//! 4. AI-Memory (pooled `ai-memory` with tenant tag isolation — 17 tools)
//! 5. Code Intelligence (pooled `gortex` + `graphify` + `context7` — 31 tools)
//! 6. Multi-Model & Switcher (`models.rs`)
//! 7. Sessions & Handoff (`sessions.rs`)
//! 8. Token & Context Optimizers (`optimizer.rs`)
//! 9. Dynamic MCP Federation (`mcp_config.json` + SHA-256 `ManifestPinStore`)

pub mod browser;
pub mod models;
pub mod optimizer;
pub mod sessions;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agy_ext::mcp_client::{global_mcp_pool, is_readonly_mcp_tool, list_stdio_mcp_tools};
use agy_ext::mcp_config::{get_mcp_server_raw, list_mcp_servers_raw, McpServerRaw};
use agy_ext::openhands_mcp::{
    handle_mcp_request as handle_openhands_rpc, openhands_mcp_tools_schema, OpenHandsMcpContext,
};
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::auth::AuthenticatedPrincipal;
use crate::config::{GatewayConfigStore, SectionId};
use crate::host::GatewayHostBridge;
use crate::manifest_pin::{ManifestPinStore, PinVerdict};
use crate::policy::{PolicyEngine, ToolRisk};
use crate::registry::{make_annotations, ToolSpec};

/// Build the complete static + in-process tool catalog across all 9 sections (120+ tools).
pub fn build_full_catalog() -> Vec<ToolSpec> {
    let mut specs = Vec::with_capacity(140);

    // Section 1: OpenHands (19 real schemas pulled directly from agy_ext::openhands_mcp!)
    if let Some(arr) = openhands_mcp_tools_schema().as_array() {
        for item in arr {
            let Some(name) = item.get("name").and_then(Value::as_str) else {
                continue;
            };
            let desc = item
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let schema = item
                .get("inputSchema")
                .cloned()
                .unwrap_or_else(|| json!({"type": "object", "properties": {}}));
            let risk = classify_openhands_risk(name);
            specs.push(ToolSpec {
                name: name.to_string(),
                section: SectionId::Openhands,
                risk,
                untrusted_output: false,
                description: desc,
                input_schema: schema,
                annotations: make_annotations(
                    risk == ToolRisk::ReadOnly,
                    matches!(risk, ToolRisk::HighRiskExec | ToolRisk::Write),
                    risk == ToolRisk::ReadOnly,
                    matches!(risk, ToolRisk::HighRiskExec | ToolRisk::AiModelRun),
                ),
                keywords: vec!["openhands".into(), "coding".into(), "file".into(), "repo".into()],
            });
        }
    }

    // Section 2: Search-v3 (8 tools)
    for (name, desc, schema) in search_v3_defs() {
        specs.push(ToolSpec {
            name: name.to_string(),
            section: SectionId::Search,
            risk: ToolRisk::ReadOnly,
            untrusted_output: true,
            description: desc.to_string(),
            input_schema: schema,
            annotations: make_annotations(true, false, true, true),
            keywords: vec!["search".into(), "web".into(), "dork".into(), "crawl".into(), "fetch".into()],
        });
    }

    // Section 3: SkillHub + SkillPort + Skills-Catalog
    for (name, risk, desc, schema) in skillhub_defs() {
        specs.push(ToolSpec {
            name: name.to_string(),
            section: SectionId::Skillhub,
            risk,
            untrusted_output: true,
            description: desc.to_string(),
            input_schema: schema,
            annotations: make_annotations(risk == ToolRisk::ReadOnly, false, true, false),
            keywords: vec!["skillhub".into(), "skill".into(), "superpowers".into(), "ecc".into(), "workflow".into()],
        });
    }

    // Section 4: AI-Memory (17 tools)
    for (name, risk, desc, schema) in memory_defs() {
        specs.push(ToolSpec {
            name: name.to_string(),
            section: SectionId::Memory,
            risk,
            untrusted_output: false,
            description: desc.to_string(),
            input_schema: schema,
            annotations: make_annotations(risk == ToolRisk::ReadOnly, name.contains("delete"), false, false),
            keywords: vec!["memory".into(), "graph".into(), "recall".into(), "knowledge".into()],
        });
    }

    // Section 5: Code Intel (Gortex + Graphify + Context7)
    for (name, risk, desc, schema) in codeintel_defs() {
        specs.push(ToolSpec {
            name: name.to_string(),
            section: SectionId::Codeintel,
            risk,
            untrusted_output: name.starts_with("context7_"),
            description: desc.to_string(),
            input_schema: schema,
            annotations: make_annotations(risk == ToolRisk::ReadOnly, risk == ToolRisk::Write, risk == ToolRisk::ReadOnly, name.starts_with("context7_")),
            keywords: vec!["gortex".into(), "graphify".into(), "context7".into(), "code".into(), "docs".into()],
        });
    }

    // Section 6: Models
    specs.extend(models::models_tool_specs());
    // Section 7: Sessions
    specs.extend(sessions::sessions_tool_specs());
    // Section 8: Optimizers
    specs.extend(optimizer::optimizer_tool_specs());
    // Section 9: Dynamic Federation
    specs.extend(federation_tool_specs());
    // Section 10: Hybrid Browser Automation (Moli + agent-browser)
    specs.extend(browser::browser_tool_specs());

    specs
}

fn classify_openhands_risk(name: &str) -> ToolRisk {
    match name {
        "oh_glob_files" | "oh_find_symbols" | "oh_grep_files" | "oh_batch_read"
        | "oh_inspect_image" | "oh_microagents" | "oh_pack_md" => ToolRisk::ReadOnly,
        "oh_file_editor" | "oh_patch_file" | "oh_multi_edit" | "oh_task_tracker"
        | "oh_apply_md" => ToolRisk::Write,
        "oh_delegate_agent" | "oh_dev_loop" => ToolRisk::AiModelRun,
        _ => ToolRisk::HighRiskExec, // oh_execute_code, oh_pty_start, oh_process_manage, oh_git_ops, oh_verify
    }
}

fn search_v3_defs() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        ("search_web_v3", "Federated web & Boolean dork search (SearXNG, Yahoo, DDG, Google) with strict AST verification and SQLite cache.", json!({"type":"object","properties":{"query":{"type":"string"},"profile":{"type":"string","default":"hybrid"},"max_results":{"type":"integer","default":10},"strict_ast":{"type":"boolean","default":true}},"required":["query"]})),
        ("search_all_engines", "Run a query across all healthy Search-v3 engines concurrently and aggregate deduplicated results.", json!({"type":"object","properties":{"query":{"type":"string"},"max_results":{"type":"integer","default":15}},"required":["query"]})),
        ("batch_search", "Execute multiple Search-v3 queries/dorks in a batch.", json!({"type":"object","properties":{"queries":{"type":"array","items":{"type":"string"}},"profile":{"type":"string","default":"hybrid"}},"required":["queries"]})),
        ("fetch_url", "Fetch and extract clean text/Markdown from a public HTTP(S) URL via Search-v3.", json!({"type":"object","properties":{"url":{"type":"string"},"max_chars":{"type":"integer","default":16000}},"required":["url"]})),
        ("parse_dork_ast", "Parse and validate a Boolean search dork AST before running a query.", json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]})),
        ("crawl_urls", "Bounded multi-page crawl restricted to explicit allowed_domains.", json!({"type":"object","properties":{"urls":{"type":"array","items":{"type":"string"}},"allowed_domains":{"type":"array","items":{"type":"string"}},"max_pages":{"type":"integer","default":5}},"required":["urls","allowed_domains"]})),
        ("search_status", "Return live health, engine Thompson-Sampling scores, and cache telemetry of Search-v3.", json!({"type":"object","properties":{}})),
        ("export_links_txt", "Export deduplicated URLs from a search query into a clean text list.", json!({"type":"object","properties":{"query":{"type":"string"},"max_results":{"type":"integer","default":20}},"required":["query"]})),
    ]
}

fn skillhub_defs() -> Vec<(&'static str, ToolRisk, &'static str, Value)> {
    vec![
        ("skillhub_catalog", ToolRisk::ReadOnly, "Browse the local 4,700+ SkillHub catalog (Superpowers, Anthropic Official Skills, ECC, VoltAgent, wshobson, Composio).", json!({"type":"object","properties":{"source":{"type":"string"},"kind":{"type":"string"},"offset":{"type":"integer","default":0},"limit":{"type":"integer","default":50}}})),
        ("skillhub_search", ToolRisk::ReadOnly, "Sub-millisecond Rust BM25F/phrase/regex/field-scoped search across 4,700+ skills, agents, commands, rules & prompts.", json!({"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","default":10,"maximum":50}},"required":["query"]})),
        ("skillhub_get", ToolRisk::ReadOnly, "Read a SkillHub document by exact id or name with optional section or line-range slicing.", json!({"type":"object","properties":{"id":{"type":"string"},"max_chars":{"type":"integer","default":16000},"section":{"type":"string"},"start_line":{"type":"integer"},"end_line":{"type":"integer"}},"required":["id"]})),
        ("skillhub_sources", ToolRisk::ReadOnly, "List synced SkillHub GitHub repositories, commits, and timestamps.", json!({"type":"object","properties":{}})),
        ("skillhub_stats", ToolRisk::ReadOnly, "Return SkillHub index counts (docs, terms, trigrams, memory, build latency).", json!({"type":"object","properties":{}})),
        ("skillhub_sync", ToolRisk::OwnerAdmin, "Owner-only: pull latest SkillHub repos and rebuild Rust BM25F index.", json!({"type":"object","properties":{"source":{"type":"string"}}})),
        ("skillport_search", ToolRisk::ReadOnly, "Search installed local SkillPort skills.", json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]})),
        ("skillport_load", ToolRisk::ReadOnly, "Load an installed SkillPort skill by id.", json!({"type":"object","properties":{"skill_id":{"type":"string"}},"required":["skill_id"]})),
        ("catalog_search", ToolRisk::ReadOnly, "Search the extended skills-catalog repository index.", json!({"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","default":10}},"required":["query"]})),
        ("catalog_get", ToolRisk::ReadOnly, "Read a skill from skills-catalog by id.", json!({"type":"object","properties":{"id":{"type":"string"}},"required":["id"]})),
        ("catalog_domains", ToolRisk::ReadOnly, "List available domains in skills-catalog.", json!({"type":"object","properties":{}})),
        ("catalog_recommend", ToolRisk::ReadOnly, "Recommend skills from skills-catalog for a task description.", json!({"type":"object","properties":{"task":{"type":"string"}},"required":["task"]})),
        ("catalog_stats", ToolRisk::ReadOnly, "Return skills-catalog statistics.", json!({"type":"object","properties":{}})),
    ]
}

fn memory_defs() -> Vec<(&'static str, ToolRisk, &'static str, Value)> {
    vec![
        ("memory_search", ToolRisk::ReadOnly, "Semantic pgvector search across durable AI-Memory records.", json!({"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","default":5},"tags":{"type":"array","items":{"type":"string"}}},"required":["query"]})),
        ("memory_store", ToolRisk::Write, "Store a durable decision, root cause, preference, or fact into PostgreSQL pgvector AI-Memory (auto-tagged per client for safety).", json!({"type":"object","properties":{"content":{"type":"object"},"type":{"type":"string","default":"context"},"source":{"type":"string","default":"agy-mcp-gateway"},"confidence":{"type":"number","default":0.85},"tags":{"type":"array","items":{"type":"string"}}},"required":["content"]})),
        ("memory_list", ToolRisk::ReadOnly, "List recent memories with optional tag/type filtering.", json!({"type":"object","properties":{"limit":{"type":"integer","default":10},"type":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}}}})),
        ("memory_update", ToolRisk::Write, "Update metadata/tags/confidence of an existing memory.", json!({"type":"object","properties":{"id":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}},"confidence":{"type":"number"}},"required":["id"]})),
        ("memory_delete", ToolRisk::Write, "Soft-delete a memory record by id.", json!({"type":"object","properties":{"id":{"type":"string"}},"required":["id"]})),
        ("memory_graph_search", ToolRisk::ReadOnly, "Hybrid vector + knowledge-graph search in AI-Memory.", json!({"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","default":5}},"required":["query"]})),
        ("memory_relate", ToolRisk::Write, "Create a typed relation edge between two memories.", json!({"type":"object","properties":{"source_id":{"type":"string"},"target_id":{"type":"string"},"relation_type":{"type":"string"}},"required":["source_id","target_id","relation_type"]})),
        ("memory_get_relations", ToolRisk::ReadOnly, "Get outgoing/incoming graph relations for a memory id.", json!({"type":"object","properties":{"id":{"type":"string"}},"required":["id"]})),
        ("memory_traverse", ToolRisk::ReadOnly, "Traverse the AI-Memory knowledge graph from a starting memory id.", json!({"type":"object","properties":{"start_id":{"type":"string"},"max_depth":{"type":"integer","default":2}},"required":["start_id"]})),
        ("memory_stats", ToolRisk::ReadOnly, "Return AI-Memory database & graph statistics.", json!({"type":"object","properties":{}})),
        ("memory_graph_analysis", ToolRisk::ReadOnly, "Run graph cluster/centrality analysis over AI-Memory.", json!({"type":"object","properties":{}})),
    ]
}

fn codeintel_defs() -> Vec<(&'static str, ToolRisk, &'static str, Value)> {
    vec![
        ("gortex_search", ToolRisk::ReadOnly, "Search symbols, files, or text across indexed repositories via Gortex live index.", json!({"type":"object","properties":{"query":{"type":"string"},"kind":{"type":"string"},"limit":{"type":"integer","default":10}},"required":["query"]})),
        ("gortex_relations", ToolRisk::ReadOnly, "Find callers, callees, references, usages, and dependents of a symbol in Gortex.", json!({"type":"object","properties":{"symbol":{"type":"string"},"kind":{"type":"string","default":"references"}},"required":["symbol"]})),
        ("gortex_change", ToolRisk::ReadOnly, "Compute blast-radius impact, detect changes, or recommend tests in Gortex.", json!({"type":"object","properties":{"operation":{"type":"string","default":"impact"},"symbol":{"type":"string"}},"required":["operation"]})),
        ("gortex_trace", ToolRisk::ReadOnly, "Trace execution/data flow between symbols in Gortex.", json!({"type":"object","properties":{"from":{"type":"string"},"to":{"type":"string"}},"required":["from"]})),
        ("gortex_analyze", ToolRisk::ReadOnly, "Analyze code communities, architecture, or dead code in Gortex.", json!({"type":"object","properties":{"operation":{"type":"string","default":"communities"},"id":{"type":"string"}}})),
        ("gortex_read", ToolRisk::ReadOnly, "Read exact symbol body or line range through Gortex.", json!({"type":"object","properties":{"path":{"type":"string"},"start_line":{"type":"integer"},"end_line":{"type":"integer"}},"required":["path"]})),
        ("graphify_query_graph", ToolRisk::ReadOnly, "Query the whole-repo Graphify knowledge graph (depth 2-3).", json!({"type":"object","properties":{"query":{"type":"string"},"depth":{"type":"integer","default":2}},"required":["query"]})),
        ("graphify_god_nodes", ToolRisk::ReadOnly, "Identify highest-centrality architectural hub nodes in Graphify.", json!({"type":"object","properties":{"limit":{"type":"integer","default":10}}})),
        ("graphify_shortest_path", ToolRisk::ReadOnly, "Find shortest architectural path between two Graphify nodes.", json!({"type":"object","properties":{"source":{"type":"string"},"target":{"type":"string"}},"required":["source","target"]})),
        ("graphify_graph_stats", ToolRisk::ReadOnly, "Return node/edge/community statistics from Graphify.", json!({"type":"object","properties":{}})),
        ("context7_resolve_library_id", ToolRisk::ReadOnly, "Resolve a third-party library/framework name to a Context7 library ID.", json!({"type":"object","properties":{"libraryName":{"type":"string"},"query":{"type":"string"}},"required":["libraryName"]})),
        ("context7_query_docs", ToolRisk::ReadOnly, "Query up-to-date official library documentation via Context7.", json!({"type":"object","properties":{"libraryId":{"type":"string"},"query":{"type":"string"}},"required":["libraryId","query"]})),
    ]
}

fn federation_tool_specs() -> Vec<ToolSpec> {
    let ro = make_annotations(true, false, true, false);
    vec![
        ToolSpec {
            name: "fed_list_servers".to_string(),
            section: SectionId::Federation,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "List all enabled upstream MCP servers from mcp_config.json (secrets masked).".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            annotations: ro.clone(),
            keywords: vec!["federation".into(), "mcp".into(), "servers".into()],
        },
        ToolSpec {
            name: "fed_list_tools".to_string(),
            section: SectionId::Federation,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Query live tools/list from a configured upstream MCP server and verify SHA-256 manifest pins against rug-pull mutations.".to_string(),
            input_schema: json!({"type":"object","properties":{"server":{"type":"string"}},"required":["server"]}),
            annotations: ro.clone(),
            keywords: vec!["federation".into(), "tools".into(), "pin".into()],
        },
        ToolSpec {
            name: "fed_call_tool".to_string(),
            section: SectionId::Federation,
            risk: ToolRisk::Write,
            untrusted_output: true,
            description: "Invoke any tool on any enabled upstream MCP server via pooled stdio transport (checked against manifest pins & secret redaction).".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "server":{"type":"string"},
                    "tool":{"type":"string"},
                    "arguments":{"type":"object","default":{}}
                },
                "required":["server","tool"]
            }),
            annotations: make_annotations(false, true, false, true),
            keywords: vec!["federation".into(), "proxy".into(), "call".into()],
        },
        ToolSpec {
            name: "fed_manifest_status".to_string(),
            section: SectionId::Federation,
            risk: ToolRisk::ReadOnly,
            untrusted_output: false,
            description: "Inspect SHA-256 manifest lockfile status and any quarantined drifted upstream tools.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            annotations: ro,
            keywords: vec!["manifest".into(), "security".into(), "rug_pull".into()],
        },
    ]
}

/// Shared execution environment passed to section handlers.
pub struct SectionEnv {
    pub workspace: PathBuf,
    pub state_dir: PathBuf,
    pub mcp_config: PathBuf,
    pub skills_dir: PathBuf,
    pub cfg_store: Arc<GatewayConfigStore>,
    pub policy: Arc<PolicyEngine>,
    pub pins: Arc<ManifestPinStore>,
    pub host: Arc<dyn GatewayHostBridge>,
    pub openhands_ctx: Arc<OpenHandsMcpContext>,
}

impl SectionEnv {
    pub fn new(
        workspace: PathBuf,
        state_dir: PathBuf,
        mcp_config: PathBuf,
        skills_dir: PathBuf,
        cfg_store: Arc<GatewayConfigStore>,
        policy: Arc<PolicyEngine>,
        pins: Arc<ManifestPinStore>,
        host: Arc<dyn GatewayHostBridge>,
    ) -> Self {
        let oh = Arc::new(OpenHandsMcpContext {
            workspace: workspace.clone(),
            state_dir: state_dir.clone(),
            mcp_config: mcp_config.clone(),
            skills_dir: skills_dir.clone(),
            turn_state: Arc::new(agy_ext::agent_runtime::TurnRuntimeState::new()),
        });
        Self {
            workspace,
            state_dir,
            mcp_config,
            skills_dir,
            cfg_store,
            policy,
            pins,
            host,
            openhands_ctx: oh,
        }
    }
}

/// Dispatch a validated tool call to its owning section.
pub async fn dispatch_section_tool(
    env: &Arc<SectionEnv>,
    principal: &AuthenticatedPrincipal,
    spec: &ToolSpec,
    args: Value,
    cancel: watch::Receiver<bool>,
) -> std::result::Result<Value, String> {
    match spec.section {
        SectionId::Openhands => call_openhands_inproc(env, &spec.name, args).await,
        SectionId::Search => call_upstream_mcp(env, "search-v3", &spec.name, args, 45.0).await,
        SectionId::Skillhub => call_skillhub_section(env, &spec.name, args).await,
        SectionId::Memory => call_memory_section(env, principal, &spec.name, args).await,
        SectionId::Codeintel => call_codeintel_section(env, &spec.name, args).await,
        SectionId::Models => {
            models::call_models_tool(
                &env.host,
                &env.policy,
                &env.state_dir,
                &env.workspace,
                &env.mcp_config,
                &env.skills_dir,
                &spec.name,
                &args,
                cancel,
            )
            .await
        }
        SectionId::Sessions => {
            sessions::call_sessions_tool(&*env.host, &env.state_dir, &env.workspace, &spec.name, &args)
        }
        SectionId::Optimizer => optimizer::call_optimizer_tool(&*env.host, &spec.name, &args),
        SectionId::Federation => call_federation_section(env, principal, &spec.name, args).await,
        SectionId::Browser => {
            browser::call_browser_tool(principal, &env.state_dir, &env.workspace, &spec.name, &args)
                .await
        }
    }
}

async fn call_openhands_inproc(
    env: &Arc<SectionEnv>,
    tool: &str,
    args: Value,
) -> std::result::Result<Value, String> {
    let rpc = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": args
        }
    });
    let resp = handle_openhands_rpc(&rpc, &env.openhands_ctx)
        .await
        .ok_or_else(|| "OpenHands returned empty response".to_string())?;
    if let Some(err) = resp.get("error") {
        return Err(err.to_string());
    }
    Ok(resp.get("result").cloned().unwrap_or(resp))
}

async fn call_skillhub_section(
    env: &Arc<SectionEnv>,
    tool: &str,
    args: Value,
) -> std::result::Result<Value, String> {
    match tool {
        "skillhub_catalog" | "skillhub_search" | "skillhub_get" | "skillhub_sources"
        | "skillhub_stats" => {
            let txt = agy_ext::skill_hub::call_hub_tool(&env.state_dir, tool, &args).await?;
            Ok(json!({"text": txt}))
        }
        "skillhub_sync" => {
            let only = args.get("source").and_then(Value::as_str);
            let reps = agy_ext::skill_hub::sync_sources(&env.state_dir, only)
                .await
                .map_err(|e| e.to_string())?;
            serde_json::to_value(&reps).map_err(|e| e.to_string())
        }
        "skillport_search" => call_upstream_mcp(env, "skillport", "search_skills", args, 20.0).await,
        "skillport_load" => call_upstream_mcp(env, "skillport", "load_skill", args, 20.0).await,
        "catalog_search" => call_upstream_mcp(env, "skills-catalog", "search_skills", args, 20.0).await,
        "catalog_get" => call_upstream_mcp(env, "skills-catalog", "get_skill", args, 20.0).await,
        "catalog_domains" => call_upstream_mcp(env, "skills-catalog", "list_domains", args, 20.0).await,
        "catalog_recommend" => call_upstream_mcp(env, "skills-catalog", "recommend_skills", args, 20.0).await,
        "catalog_stats" => call_upstream_mcp(env, "skills-catalog", "catalog_stats", args, 20.0).await,
        other => Err(format!("unknown skillhub tool: {other}")),
    }
}

async fn call_memory_section(
    env: &Arc<SectionEnv>,
    principal: &AuthenticatedPrincipal,
    tool: &str,
    mut args: Value,
) -> std::result::Result<Value, String> {
    // Tenant tag isolation on writes for non-owner keys (prevents memory poisoning!)
    if tool == "memory_store" && !principal.is_owner {
        if let Some(obj) = args.as_object_mut() {
            let tenant_tag = format!("mcp-{}", principal.principal_id.replace(':', "-"));
            let tags = obj
                .entry("tags")
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Some(arr) = tags.as_array_mut() {
                if !arr.iter().any(|v| v.as_str() == Some(tenant_tag.as_str())) {
                    arr.push(Value::String(tenant_tag));
                }
            }
        }
    }
    call_upstream_mcp(env, "ai-memory", tool, args, 25.0).await
}

async fn call_codeintel_section(
    env: &Arc<SectionEnv>,
    tool: &str,
    args: Value,
) -> std::result::Result<Value, String> {
    if let Some(sub) = tool.strip_prefix("gortex_") {
        return call_upstream_mcp(env, "gortex", sub, args, 30.0).await;
    }
    if let Some(sub) = tool.strip_prefix("graphify_") {
        return call_upstream_mcp(env, "graphify", sub, args, 25.0).await;
    }
    if tool == "context7_resolve_library_id" {
        return call_upstream_mcp(env, "context7", "resolve-library-id", args, 25.0).await;
    }
    if tool == "context7_query_docs" {
        return call_upstream_mcp(env, "context7", "query-docs", args, 30.0).await;
    }
    Err(format!("unknown codeintel tool: {tool}"))
}

async fn call_federation_section(
    env: &Arc<SectionEnv>,
    principal: &AuthenticatedPrincipal,
    tool: &str,
    args: Value,
) -> std::result::Result<Value, String> {
    match tool {
        "fed_list_servers" => {
            let srvs = agy_ext::mcp_config::list_mcp_servers(&env.mcp_config)
                .map_err(|e| e.to_string())?;
            let out: Vec<Value> = srvs
                .into_iter()
                .map(|s| {
                    json!({
                        "name": s.name,
                        "type": if s.server_type.is_empty() { "stdio" } else { &s.server_type },
                        "enabled": s.enabled
                    })
                })
                .collect();
            Ok(json!({"servers": out}))
        }
        "fed_list_tools" => {
            let srv_name = args
                .get("server")
                .and_then(Value::as_str)
                .ok_or_else(|| "server is required".to_string())?;
            let raw = resolve_enabled_server(&env.mcp_config, srv_name)?;
            let (cmd, env_map) = server_cmd_and_env(&raw)?;
            let tools = list_stdio_mcp_tools(&cmd, Some(&env_map), 20.0)
                .await
                .map_err(|e| e.to_string())?;
            let pin_enabled = env.cfg_store.snapshot().manifest_pinning_enabled;
            let mut safe_tools = Vec::new();
            let mut drifted = Vec::new();
            for t in tools {
                let tname = t.get("name").and_then(Value::as_str).unwrap_or("unknown");
                if pin_enabled {
                    match env.pins.verify_or_pin(srv_name, tname, &t) {
                        PinVerdict::Drifted { .. } => {
                            drifted.push(tname.to_string());
                            continue;
                        }
                        PinVerdict::Quarantined => {
                            drifted.push(tname.to_string());
                            continue;
                        }
                        _ => {}
                    }
                }
                safe_tools.push(t);
            }
            if !drifted.is_empty() {
                let host = Arc::clone(&env.host);
                let title = format!("MCP Manifest Drift Detected: {srv_name}");
                let detail = format!(
                    "Quarantined {} drifted tools: {}. Inspect & re-approve in /mcpgw.",
                    drifted.len(),
                    drifted.join(", ")
                );
                tokio::spawn(async move {
                    host.notify_owner_security_alert(&title, &detail).await;
                });
            }
            Ok(json!({
                "server": srv_name,
                "tools": safe_tools,
                "quarantined_drifted": drifted
            }))
        }
        "fed_call_tool" => {
            let srv_name = args
                .get("server")
                .and_then(Value::as_str)
                .ok_or_else(|| "server is required".to_string())?;
            let target_tool = args
                .get("tool")
                .and_then(Value::as_str)
                .ok_or_else(|| "tool is required".to_string())?;
            let target_args = args
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));

            if !principal.allow_write && !is_readonly_mcp_tool(target_tool) {
                return Err(format!(
                    "Tool '{srv_name}.{target_tool}' is not read-only and requires write scope"
                ));
            }
            // Check quarantine status in ManifestPinStore
            if env.cfg_store.snapshot().manifest_pinning_enabled {
                let is_q = env
                    .pins
                    .list_quarantined()
                    .iter()
                    .any(|(s, p)| s == srv_name && p.tool_name == target_tool);
                if is_q {
                    return Err(format!(
                        "Tool '{srv_name}.{target_tool}' is QUARANTINED due to schema drift (possible rug-pull). Owner must re-approve in /mcpgw."
                    ));
                }
            }
            call_upstream_mcp(env, srv_name, target_tool, target_args, 35.0).await
        }
        "fed_manifest_status" => Ok(env.pins.summary()),
        other => Err(format!("unknown federation tool: {other}")),
    }
}

fn resolve_enabled_server(mcp_config: &Path, name: &str) -> std::result::Result<McpServerRaw, String> {
    let raw = get_mcp_server_raw(mcp_config, name)
        .map_err(|e| e.to_string())?
        .or_else(|| {
            list_mcp_servers_raw(mcp_config)
                .ok()
                .and_then(|all| all.into_iter().find(|s| s.name.eq_ignore_ascii_case(name)))
        })
        .ok_or_else(|| format!("MCP server '{name}' not found in mcp_config.json"))?;
    if !raw.enabled {
        return Err(format!("MCP server '{name}' is disabled in mcp_config.json"));
    }
    Ok(raw)
}

fn server_cmd_and_env(
    raw: &McpServerRaw,
) -> std::result::Result<(Vec<String>, HashMap<String, String>), String> {
    if raw.command.trim().is_empty() {
        return Err(format!(
            "MCP server '{}' has no stdio command configured",
            raw.name
        ));
    }
    let mut cmd = Vec::with_capacity(1 + raw.args.len());
    cmd.push(raw.command.clone());
    cmd.extend(raw.args.iter().cloned());
    let env_map: HashMap<String, String> = raw
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Ok((cmd, env_map))
}

async fn call_upstream_mcp(
    env: &Arc<SectionEnv>,
    server_name: &str,
    tool_name: &str,
    arguments: Value,
    timeout_secs: f64,
) -> std::result::Result<Value, String> {
    let raw = resolve_enabled_server(&env.mcp_config, server_name)?;
    let (cmd, env_map) = server_cmd_and_env(&raw)?;
    global_mcp_pool()
        .call_pooled_stdio_mcp_cmd(&cmd, tool_name, arguments, Some(&env_map), timeout_secs)
        .await
        .map_err(|e| e.to_string())
}
