#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! `agy-mcp-gateway`: Production Remote MCP Gateway for `agy-telegram` (Rust v4).
//!
//! Features:
//! - Universal MCP Transports: Streamable HTTP (2025 stateful + 2026 stateless) & Legacy `/sse`
//! - Dual Authentication: OAuth 2.1 (PKCE S256, RFC 9728/8414/7591/8707 + Telegram 2FA) & Scoped Bearer API Keys
//! - Modular 9-Section Routing (`/mcp/s/<section>`) + Progressive Discovery Smart Hub (`/mcp`)
//! - Defense-in-Depth: Anti-DDoS `McpGuard`, Cloudflare CIDR-verified real IP, Auto-Ban, Anti-Ban Account Quota & Loop Breaker, SHA-256 Manifest Pinning, HITL Telegram Approval, Secret Redaction & Audit Log.

pub mod audit;
pub mod auth;
pub mod config;
pub mod guard;
pub mod hitl;
pub mod host;
pub mod manifest_pin;
pub mod oauth;
pub mod policy;
pub mod protocol;
pub mod registry;
pub mod sanitize;
pub mod sections;
pub mod tasks;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use agy_core::error::Result;
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info};

use crate::audit::AuditLogger;
use crate::auth::KeyStore;
use crate::config::GatewayConfigStore;
use crate::guard::{apply_mcp_guard, McpGuardState};
use crate::hitl::HitlBroker;
use crate::host::GatewayHostBridge;
use crate::manifest_pin::ManifestPinStore;
use crate::oauth::{build_oauth_router, OAuthStore};
use crate::policy::PolicyEngine;
use crate::protocol::{build_mcp_protocol_router, McpRuntime};
use crate::sections::{build_full_catalog, SectionEnv};
use crate::tasks::TaskManager;

/// Live handle held by `BotCtx` so Telegram `/mcpgw` Owner panel controls the gateway in-process.
pub struct McpGatewayHandle {
    pub cfg_store: Arc<GatewayConfigStore>,
    pub keys: Arc<KeyStore>,
    pub oauth: Arc<OAuthStore>,
    pub guard: Arc<McpGuardState>,
    pub policy: Arc<PolicyEngine>,
    pub pins: Arc<ManifestPinStore>,
    pub hitl: Arc<HitlBroker>,
    pub audit: Arc<AuditLogger>,
    pub tasks: Arc<TaskManager>,
    pub runtime: Arc<McpRuntime>,
}

impl McpGatewayHandle {
    pub fn open(
        state_dir: PathBuf,
        workspace: PathBuf,
        mcp_config: PathBuf,
        skills_dir: PathBuf,
        host: Arc<dyn GatewayHostBridge>,
    ) -> Result<Arc<Self>> {
        let cfg_store = Arc::new(GatewayConfigStore::open(
            state_dir.join("mcp_gateway.json"),
        )?);
        let keys = Arc::new(KeyStore::open(state_dir.join("mcp_gateway_keys.json"))?);
        let oauth = Arc::new(OAuthStore::open(
            state_dir.join("mcp_gateway_oauth.json"),
            Arc::clone(&cfg_store),
            Arc::clone(&host),
        )?);
        let guard = Arc::new(McpGuardState::new(Arc::clone(&cfg_store)));
        let policy = Arc::new(PolicyEngine::new(Arc::clone(&cfg_store)));
        let pins = Arc::new(ManifestPinStore::open(
            state_dir.join("mcp_manifest_lock.json"),
        )?);
        let hitl = Arc::new(HitlBroker::new());
        let audit = Arc::new(AuditLogger::open(
            state_dir.join("mcp_gateway_audit.jsonl"),
        ));
        let tasks = Arc::new(TaskManager::new());

        let section_env = Arc::new(SectionEnv::new(
            workspace,
            state_dir,
            mcp_config,
            skills_dir,
            Arc::clone(&cfg_store),
            Arc::clone(&policy),
            Arc::clone(&pins),
            Arc::clone(&host),
        ));
        let catalog = build_full_catalog();
        let runtime = Arc::new(McpRuntime::new(
            Arc::clone(&cfg_store),
            Arc::clone(&keys),
            Arc::clone(&oauth),
            Arc::clone(&guard),
            Arc::clone(&policy),
            Arc::clone(&hitl),
            Arc::clone(&audit),
            Arc::clone(&tasks),
            section_env,
            catalog,
        ));

        Ok(Arc::new(Self {
            cfg_store,
            keys,
            oauth,
            guard,
            policy,
            pins,
            hitl,
            audit,
            tasks,
            runtime,
        }))
    }

    /// Build the full Axum [`Router`] (MCP Streamable HTTP + Legacy SSE + OAuth 2.1 + McpGuard).
    pub fn build_router(&self) -> Router {
        let base = build_mcp_protocol_router(Arc::clone(&self.runtime))
            .merge(build_oauth_router(Arc::clone(&self.oauth)));
        apply_mcp_guard(base, Arc::clone(&self.guard))
    }

    /// Spawn the isolated loopback HTTP listener (`127.0.0.1:<bind_port>`).
    pub async fn spawn_listener(
        self: &Arc<Self>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<tokio::task::JoinHandle<()>> {
        let port = std::env::var("MCP_GW_PORT")
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
            .filter(|&p| p >= 1024)
            .unwrap_or_else(|| self.cfg_store.snapshot().bind_port);
        let bind_addr = format!("127.0.0.1:{port}");
        let listener = TcpListener::bind(&bind_addr).await?;
        let router = self.build_router();
        info!(
            addr = %bind_addr,
            tools = self.runtime.catalog.len(),
            "AGY Remote MCP Gateway listening (/mcp, /mcp/all, /mcp/s/*, /sse, /oauth/*, /.well-known/*)"
        );
        let handle = tokio::spawn(async move {
            if let Err(err) = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                while !*shutdown_rx.borrow() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
            {
                error!(error = %err, "AGY MCP Gateway server exited with error");
            }
        });
        Ok(handle)
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::auth::KeyPreset;
    use crate::host::NullHostBridge;
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use tempfile::TempDir;
    use tower::ServiceExt;

    async fn json_body(resp: axum::response::Response) -> Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn full_gateway_e2e_auth_streamable_2025_2026_sections_hub_and_security() {
        let dir = TempDir::new().unwrap();
        let gw = McpGatewayHandle::open(
            dir.path().join("state"),
            dir.path().join("ws"),
            dir.path().join("mcp_config.json"),
            dir.path().join("skills"),
            Arc::new(NullHostBridge),
        )
        .unwrap();
        let app = gw.build_router();

        // 1. Unauthenticated POST /mcp returns 401 + RFC 9728 WWW-Authenticate
        let unauth = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "mcp.example.com")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
        let www = unauth
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www.contains("https://mcp.example.com/.well-known/oauth-protected-resource"));

        // 2. Provision an Owner key & test 2025 Stateful Initialize + Smart Hub tools/list
        let (_rec, raw_key) = gw
            .keys
            .create_key("owner-vscode", KeyPreset::Owner, None)
            .unwrap();
        let bearer = format!("Bearer {raw_key}");

        let init_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "mcp.example.com")
                    .header(header::AUTHORIZATION, &bearer)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(init_resp.status(), StatusCode::OK);
        let sid = init_resp
            .headers()
            .get("mcp-session-id")
            .expect("2025 stateful initialize returns Mcp-Session-Id")
            .to_str()
            .unwrap()
            .to_string();
        assert!(!sid.is_empty());

        // Smart Hub keeps context tiny (<= 15 tools instead of 100+)
        let list_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "mcp.example.com")
                    .header(header::AUTHORIZATION, &bearer)
                    .header("mcp-session-id", &sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let list_json = json_body(list_resp).await;
        let hub_tools = list_json["result"]["tools"].as_array().unwrap();
        assert!(hub_tools.len() <= 15, "hub should stay compact, got {}", hub_tools.len());

        // 3. 2026 Stateless Streamable HTTP call directly to /mcp/s/optimizer without prior initialize!
        let opt_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp/s/optimizer")
                    .header(header::HOST, "gateway.example.com")
                    .header(header::AUTHORIZATION, &bearer)
                    .header("mcp-protocol-version", "2026-07-28")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": {
                                "name": "opt_classify_turn",
                                "arguments": {"prompt": "سلام خوبی؟"}
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(opt_resp.status(), StatusCode::OK);
        let opt_json = json_body(opt_resp).await;
        assert_eq!(opt_json["result"]["isError"], false);
        assert!(opt_json["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("\"lite\""));

        // 4. Progressive discovery via hub_discover_tools finds OpenHands + Optimizer tools
        let disc_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "mcp.example.com")
                    .header(header::AUTHORIZATION, &bearer)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": 4,
                            "method": "tools/call",
                            "params": {
                                "name": "hub_discover_tools",
                                "arguments": {"query": "find symbols openhands", "limit": 5}
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let disc_json = json_body(disc_resp).await;
        assert!(disc_json["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("oh_find_symbols"));

        // 5. Security check: forbidden credential path blocked even for Owner remote key
        let sec_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp/s/openhands")
                    .header(header::HOST, "mcp.example.com")
                    .header(header::AUTHORIZATION, &bearer)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": 5,
                            "method": "tools/call",
                            "params": {
                                "name": "oh_file_editor",
                                "arguments": {"command": "view", "path": "/etc/agy-telegram/bot.env"}
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let sec_json = json_body(sec_resp).await;
        assert_eq!(sec_json["result"]["isError"], true);
        assert!(sec_json["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("forbidden"));

        // 6. Resources & Prompts work cleanly
        let res_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "mcp.example.com")
                    .header(header::AUTHORIZATION, &bearer)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"agy://gateway/status"}}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let res_json = json_body(res_resp).await;
        assert!(res_json["result"]["contents"][0]["text"]
            .as_str()
            .unwrap()
            .contains("mcp.example.com"));
    }

    #[tokio::test]
    #[ignore]
    async fn live_dual_domain_e2e_harness() {
        let gw = McpGatewayHandle::open(
            PathBuf::from("/var/lib/agy-telegram"),
            PathBuf::from("/root/agy-workspace"),
            PathBuf::from("/root/.gemini/config/mcp_config.json"),
            PathBuf::from("/root/.gemini/config/skills"),
            Arc::new(NullHostBridge),
        )
        .unwrap();
        let (rec, raw_key) = gw
            .keys
            .create_key("e2e-ephemeral-probe", KeyPreset::Owner, Some(1))
            .unwrap();
        let (tx, rx) = watch::channel(false);
        let srv = gw.spawn_listener(rx).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        let out = tokio::process::Command::new("python3")
            .arg("/root/agy-stack/data/workspace/scripts/verify_mcp_gateway_e2e.py")
            .arg(&raw_key)
            .output()
            .await
            .unwrap();

        let _ = tx.send(true);
        let _ = srv.await;
        let _ = gw.keys.revoke(&rec.id);

        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        println!("{stdout}");
        if !stderr.is_empty() {
            eprintln!("{stderr}");
        }
        assert!(out.status.success(), "Live E2E suite failed:\n{stdout}\n{stderr}");
    }
}
