//! Extensions, async stdio JSON-RPC MCP client, SkillPort/catalog management,
//! secret-safe `mcp_config.json` CRUD, AI-Memory helpers, and multi-engine process runners.

pub mod agent_runtime;
pub mod code_exec;
pub mod code_to_md;
pub mod command_guard;
pub mod engines;
pub mod exec_backend;
pub mod fleet_updater;
pub mod gemini_web;
pub mod grok_bot;
pub mod grok_oauth;
pub mod login;
pub mod mcp_client;
pub mod mcp_config;
pub mod memory;
pub mod openhands;
pub mod openhands_mcp;
pub mod pty_manager;
pub mod quota_probe;
pub mod skill_hub;
pub mod skill_index;
pub mod skills;
pub mod uncensored;
pub mod update_guard;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
