#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! `agy-telegram`: High-performance Rust Telegram Bridge (Bot API 10.4) for Antigravity (`agy`).

mod auth;
mod automations;
mod handlers_skillhub;
mod handlers_updates;
mod cron;
mod ctx;
mod handlers_accounts;
mod handlers_business;
mod handlers_gemini;
mod handlers_grok;
mod handlers_grok_bot;
mod handlers_mcp;
mod handlers_mcpgw;
mod handlers_parallel;
mod handlers_proxies;
mod handlers_skills;
mod handlers_system;
mod handlers_uncensored;
mod handlers_users;
mod handlers_widgets;
mod handoff;
mod http_guard;
mod i18n;
mod jobs;
mod local_fast;
mod models_pool;
mod render_bridge;
mod turn_profile;
mod updater;
mod webapp_bridge;
mod webhook;

use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agy_core::acl::{AclStore, BulkTarget, RolePreset, UserStatus};
use agy_core::config::Config;
use agy_core::health::HealthTracker;
use agy_core::outbox::OutQueue;
use agy_core::store::StateStore;
use agy_core::tg::{
    BotCommandScope, CallbackQuery, Message, MessageGenerationStopped, Update, User,
};
use agy_core::{BridgeError, Result};
use agy_net::{
    sd_notify_ready, sd_notify_stopping, BotApiClient, MAX_DOWNLOAD_BYTES,
};
use agy_render::premium::PremiumState;
use agy_render::{esc, md_to_html, split_html};
use agy_widgets::{
    build_webapp_router, builtin_widget, count_widget_size, validate_widget_spec, WebAppState,
    WidgetBridge, WidgetStore, BUILTIN_WIDGET_KINDS, WIDGET_HTML_ZLIB_LIMIT,
};
use anyhow::Context;
use axum::Router;
use chrono::Local;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::auth::{owner_start_notice_card, AuthDecision, AuthGate};
use crate::cron::CronScheduler;
use crate::ctx::BotCtx;
use crate::jobs::{JobManager, JobRequest, JobWidgetSink};
use crate::render_bridge::RenderBridge;
use crate::updater::{
    atomic_self_update, build_proxy_pool_from_config, parse_cli_from_env, rollback_binary,
    run_check, run_health, CliMode,
};
use crate::webapp_bridge::BotWebAppBridge;
use crate::webhook::{webhook_router, FnDispatcher, TransportSupervisor, UpdateDispatcher};

const DEFAULT_TELEGRAM_API_BASE: &str = "https://api.telegram.org";

struct CtxWidgetSink {
    ctx: Weak<BotCtx>,
}

impl JobWidgetSink for CtxWidgetSink {
    fn extract_markdown_widgets<'a>(
        &'a self,
        chat_id: i64,
        md: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
        Box::pin(async move {
            let Some(ctx) = self.ctx.upgrade() else {
                return Ok(md.to_string());
            };
            handlers_widgets::extract_and_send_markdown_widgets(&ctx, chat_id, md).await
        })
    }

    fn deliver_outbox_widgets<'a>(
        &'a self,
        chat_id: i64,
        outdir: &'a Path,
    ) -> Pin<Box<dyn Future<Output = HashSet<PathBuf>> + Send + 'a>> {
        Box::pin(async move {
            let Some(ctx) = self.ctx.upgrade() else {
                return HashSet::new();
            };
            handlers_widgets::deliver_outbox_widgets_in_dir(&ctx, chat_id, outdir).await
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mode = match parse_cli_from_env() {
        Ok(m) => m,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    match mode {
        CliMode::Version => {
            println!("agy-telegram {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CliMode::Check => {
            let cfg = Config::from_env().context("loading configuration")?;
            run_check(&cfg, check_builtin_widgets).context("--check failed")?;
            Ok(())
        }
        CliMode::Health => {
            let cfg = Config::from_env().context("loading configuration")?;
            let report = run_health(&cfg).context("--health probe failed")?;
            let pretty = serde_json::to_string_pretty(&report)
                .context("serializing health output")?;
            println!("{pretty}");
            Ok(())
        }
        CliMode::SelfUpdate(staged) => {
            let _cfg = Config::from_env().context("loading configuration")?;
            let exe = std::env::current_exe().context("locating current binary")?;
            let backup_dir = std::env::var("AGY_BACKUP_DIR")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/opt/agy-telegram/backups/bin"));
            let report = atomic_self_update(&staged, &exe, &backup_dir)
                .context("--self-update failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        CliMode::Rollback => {
            let exe = std::env::current_exe().context("locating current binary")?;
            let backup_dir = std::env::var("AGY_BACKUP_DIR")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/opt/agy-telegram/backups/bin"));
            let report = rollback_binary(&exe, &backup_dir).context("--rollback failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        CliMode::BenchAb => {
            let report = run_ab_benchmark().context("--bench-ab failed")?;
            println!("{}", serde_json::to_string(&report)?);
            Ok(())
        }
        CliMode::McpUncensored => {
            agy_ext::uncensored::run_mcp_uncensored_server().await?;
            Ok(())
        }
        CliMode::McpSkillhub => {
            agy_ext::skill_hub::run_mcp_skillhub_server().await?;
            Ok(())
        }
        CliMode::McpOpenhands => {
            agy_ext::openhands_mcp::run_mcp_openhands_server().await?;
            Ok(())
        }
        CliMode::UpdatesCheck => {
            let cfg = Config::from_env().context("loading configuration")?;
            let rep = agy_ext::fleet_updater::check_all(
                &cfg.state_dir,
                agy_ext::fleet_updater::UpdateScope::All,
            )
            .await
            .context("--updates-check failed")?;
            println!("{}", serde_json::to_string_pretty(&rep)?);
            Ok(())
        }
        CliMode::UpdatesApply(scope_raw) => {
            let cfg = Config::from_env().context("loading configuration")?;
            let scope = agy_ext::fleet_updater::UpdateScope::parse(&scope_raw)
                .context("--updates-apply invalid scope")?;
            let force_mcps = matches!(scope, agy_ext::fleet_updater::UpdateScope::Mcps);
            let rep = agy_ext::fleet_updater::apply_updates(&cfg.state_dir, scope, force_mcps)
                .await
                .context("--updates-apply failed")?;
            println!("{}", serde_json::to_string_pretty(&rep)?);
            Ok(())
        }
        CliMode::Run => {
            init_tracing();
            run_bridge().await
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

fn check_builtin_widgets() -> Result<Value> {
    let mut details = serde_json::Map::new();
    for kind in BUILTIN_WIDGET_KINDS {
        let sp = builtin_widget(kind, Some(&json!({"tab": "inst"})))?;
        let (norm, warnings) = validate_widget_spec(&sp)?;
        let sz = count_widget_size(norm.html.as_deref().unwrap_or(""));
        if !sz.zlib_ok {
            return Err(BridgeError::PayloadTooLarge {
                actual: sz.zlib_bytes,
                limit: WIDGET_HTML_ZLIB_LIMIT,
            });
        }
        details.insert(
            kind.to_string(),
            json!({
                "raw_bytes": sz.raw_bytes,
                "zlib_bytes": sz.zlib_bytes,
                "warnings": warnings,
            }),
        );
    }
    Ok(json!({
        "builtins": BUILTIN_WIDGET_KINDS.len(),
        "items": details,
    }))
}

fn read_peak_rss_kb() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    let mut vm_rss = 0u64;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            if let Some(val) = rest.split_whitespace().next().and_then(|s| s.parse::<u64>().ok()) {
                return val;
            }
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            if let Some(val) = rest.split_whitespace().next().and_then(|s| s.parse::<u64>().ok()) {
                vm_rss = val;
            }
        }
    }
    vm_rss
}

fn round2(ms: f64) -> f64 {
    (ms * 100.0).round() / 100.0
}

fn run_ab_benchmark() -> Result<Value> {
    let td = tempfile::TempDir::new()
        .map_err(|e| BridgeError::io("creating ab benchmark tempdir", e))?;
    let state_dir = td.path().join("state");
    std::fs::create_dir_all(&state_dir)
        .map_err(|e| BridgeError::io("creating ab state_dir", e))?;

    // 1. Cold store/config/widget/premium initialization
    let t0 = Instant::now();
    let cfg = Config {
        bot_token: "123456:AB_BENCH_DUMMY".to_string(),
        state_dir: state_dir.clone(),
        owner_id: 1_000_000_001,
        allowed_user_ids: vec![1_000_000_001],
        ..Default::default()
    };
    let _store = StateStore::open(cfg.state_path())?;
    let _wstore = WidgetStore::from_state_dir(&state_dir)?;
    let _prem = PremiumState::load_from_state_dir(&state_dir, true);
    let _outq = OutQueue::open(cfg.outbox_path())?;
    let t_cold = t0.elapsed().as_secs_f64() * 1000.0;

    // 2. Render + split HTML 1000 iterations (parity with benches/ab_compare.py)
    let sample_md = std::hint::black_box(
        "# Report\n\n| Col A | Col B | Col C |\n|---|---|---|\n| alpha | 123 | ok |\n| beta | 456 | warn |\n\n```rust\nfn main() { println!(\"hi\"); }\n```\n\n> Quote with **bold** and `code`\n",
    );
    let t1 = Instant::now();
    let mut render_acc = 0usize;
    for _ in 0..1000 {
        let html = md_to_html(sample_md, 4);
        let parts = split_html(&html, 4096);
        render_acc = render_acc.wrapping_add(parts.iter().map(String::len).sum::<usize>());
    }
    std::hint::black_box(render_acc);
    let t_render = t1.elapsed().as_secs_f64() * 1000.0;

    // 3. ACL 200 user ops + bulk perm mutation
    let acl = AclStore::open(
        cfg.acl_path(),
        1_000_000_001,
        &[1_000_000_001],
        300,
    )?;
    let t2 = Instant::now();
    for i in 0..200_i64 {
        let u = User {
            id: 100_000 + i,
            is_bot: false,
            first_name: "Test".to_string(),
            last_name: None,
            username: Some(format!("u{i}")),
            language_code: None,
            is_premium: Some(false),
        };
        let _ = acl.record_start_attempt(&u)?;
        if i % 2 == 0 {
            acl.set_status(
                100_000 + i,
                UserStatus::Approved,
                Some(1_000_000_001),
                Some(RolePreset::Dev),
            )?;
        } else {
            acl.toggle_select(100_000 + i)?;
        }
    }
    let _ = acl.bulk_set_perm(BulkTarget::Selected, "skills_manage", true)?;
    let t_acl = t2.elapsed().as_secs_f64() * 1000.0;

    // 4. Built-in widget generation & validation (4 kinds x 100 = 400 ops)
    let init = json!({"tab": "inst"});
    let t3 = Instant::now();
    let mut widget_acc = 0usize;
    for kind in BUILTIN_WIDGET_KINDS {
        for _ in 0..100 {
            let sp = builtin_widget(kind, Some(&init))?;
            let (norm, _) = validate_widget_spec(&sp)?;
            widget_acc = widget_acc.wrapping_add(norm.html.as_deref().map_or(0, str::len));
        }
    }
    std::hint::black_box(widget_acc);
    let t_wid = t3.elapsed().as_secs_f64() * 1000.0;

    Ok(json!({
        "cold_startup_ms": round2(t_cold),
        "render_1000_ms": round2(t_render),
        "acl_200_ops_ms": round2(t_acl),
        "widget_400_ops_ms": round2(t_wid),
        "peak_rss_kb": read_peak_rss_kb(),
    }))
}

async fn run_bridge() -> anyhow::Result<()> {
    let cfg = Arc::new(Config::from_env().context("loading bridge config")?);
    cfg.validate().context("validating bridge config")?;

    std::fs::create_dir_all(&cfg.state_dir).context("creating state_dir")?;
    std::fs::create_dir_all(cfg.inbox_dir()).context("creating inbox_dir")?;
    std::fs::create_dir_all(cfg.outbox_dir()).context("creating outbox_dir")?;

    agy_ext::mcp_client::global_mcp_pool()
        .set_ro_cache_ttl(Duration::from_secs(cfg.mcp_ro_cache_ttl_secs));
    agy_ext::agent_runtime::set_agent_tool_output_cap(cfg.agent_tool_output_max_bytes);
    let store = Arc::new(StateStore::open(cfg.state_path()).context("opening StateStore")?);
    let acl = Arc::new(
        AclStore::open(cfg.acl_path(), cfg.owner_id, &cfg.allowed_user_ids, 300)
            .map(|acl| acl.with_extra_owners(&cfg.owner_ids))
            .context("opening AclStore")?,
    );
    let outbox = Arc::new(OutQueue::open(cfg.outbox_path()).context("opening OutQueue")?);
    // bounded Telegram flood-control waits (longer waits: queue to outbox / drop edits)
    for (var, slot) in [
        ("TG_MAX_RETRY_AFTER_SECS", &agy_net::client::MAX_RETRY_AFTER_SECS),
        ("TG_MAX_RETRY_AFTER_TOTAL_SECS", &agy_net::client::MAX_RETRY_AFTER_TOTAL_SECS),
    ] {
        if let Some(v) = std::env::var(var).ok().and_then(|v| v.parse::<u64>().ok()) {
            slot.store(v, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let widgets =
        Arc::new(WidgetStore::from_state_dir(&cfg.state_dir).context("opening WidgetStore")?);
    if let Ok(purged) = widgets.purge_legacy_widgets() {
        if purged > 0 {
            info!(purged, "purged legacy widget record(s)");
        }
    }

    let health = Arc::new(HealthTracker::new(cfg.health_path()));
    let premium = Arc::new(PremiumState::load_from_state_dir(
        &cfg.state_dir,
        cfg.premium_ui,
    ));
    let pool = Arc::new(build_proxy_pool_from_config(&cfg).context("building proxy pool")?);
    let api_base = std::env::var("TELEGRAM_API_BASE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_TELEGRAM_API_BASE.to_string());
    let req_timeout = Duration::from_secs(cfg.poll_timeout + 15);
    let client = Arc::new(
        BotApiClient::with_pool(cfg.bot_token.clone(), api_base, Arc::clone(&pool), req_timeout)
            .context("initializing BotApiClient")?,
    );

    let render = Arc::new(
        RenderBridge::new(
            Arc::clone(&client),
            Arc::clone(&premium),
            Arc::clone(&outbox),
        )
        .with_state_store(Arc::clone(&store)),
    );
    let cron = Arc::new(
        CronScheduler::new(Arc::clone(&cfg), Arc::clone(&health))
            .context("initializing CronScheduler")?,
    );
    let jobs = Arc::new(
        JobManager::new(
            Arc::clone(&cfg),
            Arc::clone(&acl),
            Arc::clone(&store),
            Arc::clone(&render),
            Arc::clone(&client),
        )
        .context("initializing JobManager")?,
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Multi-account Antigravity pool (accounts.json + per-account shadow HOMEs).
    let mut models_task: Option<tokio::task::JoinHandle<()>> = None;
    {
        let primary_home = std::env::var("AGY_HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOME").ok().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| "/root".to_string());
        match agy_core::accounts::AccountStore::open(
            cfg.state_dir.join("accounts.json"),
            cfg.state_dir.join("accounts"),
            primary_home,
        ) {
            Ok(acc_store) => {
                let desired_pol = cfg.account_policy();
                if let Err(e) = acc_store.init_policy_if_unset(desired_pol) {
                    warn!(error = %e, "failed initializing default account safety policy");
                }
                let active_pol = acc_store.policy();
                info!(
                    accounts = acc_store.len(),
                    available = acc_store.available_count(),
                    preset = active_pol.preset.label(),
                    weekly_reserve_pct = active_pol.weekly_reserve_pct,
                    max_conc = active_pol.max_concurrency_per_account,
                    min_gap_secs = active_pol.min_gap_secs,
                    "account pool loaded"
                );
                let pool = Arc::new(acc_store);
                jobs.set_accounts(Arc::clone(&pool));
                // per-account model catalogs (list-only `agy models`, no quota): fill missing/stale
                // politely with staggered 4s gaps through each account's sticky proxy every 6 h.
                let cfg_m = Arc::clone(&cfg);
                let jobs_m = Arc::clone(&jobs);
                let store_m = Arc::clone(&store);
                let render_m = Arc::clone(&render);
                let mut models_rx = shutdown_rx.clone();
                models_task = Some(tokio::spawn(async move {
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(20)) => {}
                        res = models_rx.changed() => {
                            if res.is_err() || *models_rx.borrow() {
                                return;
                            }
                        }
                    }
                    loop {
                        if *models_rx.borrow() {
                            break;
                        }
                        for a in pool.list() {
                            if *models_rx.borrow() {
                                return;
                            }
                            if a.is_primary() || !a.enabled || a.health.status == agy_core::accounts::HealthStatus::Disabled {
                                continue;
                            }
                            if models_pool::is_stale(&cfg_m.state_dir, &a.id) {
                                let px_opt = match jobs_m.proxies().map(|r| r.resolve(a.proxy_id.as_deref())) {
                                    Some(agy_core::proxies::ResolvedProxy::Blocked { .. }) => continue,
                                    Some(agy_core::proxies::ResolvedProxy::Use { url, .. }) => Some(url),
                                    _ => None,
                                };
                                let _ = models_pool::refresh_with_proxy(&cfg_m, &a, px_opt.as_deref()).await;
                                tokio::select! {
                                    _ = tokio::time::sleep(std::time::Duration::from_secs(4)) => {}
                                    res = models_rx.changed() => {
                                        if res.is_err() || *models_rx.borrow() {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        mark_stale_user_models(&jobs_m, &store_m);
                        alert_duplicate_accounts(&pool, &store_m, &render_m, cfg_m.owner_id).await;
                        tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)) => {}
                            res = models_rx.changed() => {
                                if res.is_err() || *models_rx.borrow() {
                                    break;
                                }
                            }
                        }
                    }
                }));
            }
            Err(err) => warn!(error = %err, "account pool unavailable; running single-account"),
        }
    }
    let auth = Arc::new(AuthGate::from_config(Arc::clone(&acl), &cfg));

    let ctx = BotCtx::new(
        Arc::clone(&cfg),
        Arc::clone(&store),
        Arc::clone(&acl),
        Arc::clone(&outbox),
        Arc::clone(&health),
        Arc::clone(&premium),
        Arc::clone(&pool),
        Arc::clone(&client),
        Arc::clone(&widgets),
        Arc::clone(&render),
        Arc::clone(&cron),
        Arc::clone(&jobs),
        Arc::clone(&auth),
    );

    let sink = Arc::new(CtxWidgetSink {
        ctx: Arc::downgrade(&ctx),
    });
    ctx.jobs.set_widget_sink(sink);

    let bridge: Arc<dyn WidgetBridge> = BotWebAppBridge::new(Arc::clone(&ctx));
    let token_prov = Arc::new({
        let c = Arc::clone(&cfg);
        move || c.bot_token.clone()
    });
    let uids_prov = Arc::new({
        let a = Arc::clone(&acl);
        move || a.approved_ids().into_iter().collect::<HashSet<i64>>()
    });
    let webapp_state = WebAppState::with_providers(
        token_prov,
        uids_prov,
        Arc::clone(&widgets),
        bridge,
    )
    .with_api_uid_rate_limit(cfg.http_rl_per_min);

    let disp_ctx = Arc::clone(&ctx);
    let dispatcher: Arc<dyn UpdateDispatcher> = Arc::new(FnDispatcher(move |upd: Update| {
        let c = Arc::clone(&disp_ctx);
        async move {
            dispatch_update(&c, upd).await;
        }
    }));

    let mut http_router: Router = build_webapp_router(webapp_state);
    if let Some(secret) = cfg.webhook_secret.as_deref().filter(|s| !s.is_empty()) {
        http_router = http_router.merge(webhook_router(
            secret.to_string(),
            Arc::clone(&dispatcher),
            Arc::clone(&health),
        ));
    }
    let http_router = http_guard::apply_http_guard(
        http_router,
        http_guard::HttpGuardConfig {
            rl_per_min: cfg.http_rl_per_min,
            max_concurrency: cfg.http_max_concurrency,
            req_timeout_secs: cfg.http_req_timeout_secs,
        },
    );

    let bind_addr = format!("127.0.0.1:{}", cfg.widget_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding HTTP/WebApp/Webhook listener on {bind_addr}"))?;
    info!(
        addr = %bind_addr,
        http_rl = cfg.http_rl_per_min,
        http_conc = cfg.http_max_concurrency,
        http_timeout_s = cfg.http_req_timeout_secs,
        "HTTP server listening (/w/*, /api/w/*, /tg/webhook, /healthz)"
    );

    // Embedded Remote MCP Gateway (127.0.0.1:8788, isolated from :8787 WebApp/Webhook).
    let mcp_gw_task = match agy_mcp_gateway::McpGatewayHandle::open(
        cfg.state_dir.clone(),
        cfg.agy_workspace.clone(),
        cfg.mcp_config_path.clone(),
        cfg.agy_skills_dir.clone(),
        handlers_mcpgw::BotGatewayHostBridge::new(&ctx),
    ) {
        Ok(gw) => {
            ctx.set_mcp_gw(Arc::clone(&gw));
            match gw.spawn_listener(shutdown_rx.clone()).await {
                Ok(h) => Some(h),
                Err(err) => {
                    error!(error = %err, "failed to bind Remote MCP Gateway listener; continuing without gateway");
                    None
                }
            }
        }
        Err(err) => {
            error!(error = %err, "failed to initialize Remote MCP Gateway; continuing without gateway");
            None
        }
    };

    let mut http_rx = shutdown_rx.clone();
    let http_task = tokio::spawn(async move {
        if let Err(err) = axum::serve(
            listener,
            http_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
            .with_graceful_shutdown(async move {
                while !*http_rx.borrow() {
                    if http_rx.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
        {
            error!(error = %err, "Axum HTTP server terminated with error");
        }
    });

    // Signal readiness BEFORE best-effort network startup work: with Telegram unreachable,
    // getMe/setMyCommands/notices can exceed TimeoutStartSec and systemd would kill and
    // restart the service in a loop (observed 2026-11-18 ~21:2x-22:10 UTC, 37 restarts).
    sd_notify_ready();
    {
        let st_ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            on_startup(&st_ctx).await;
        });
    }

    let outbox_ctx = Arc::clone(&ctx);
    let mut outbox_rx = shutdown_rx.clone();
    let outbox_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let _ = outbox_ctx.render.flush_outbox().await;
                }
                res = outbox_rx.changed() => {
                    if res.is_err() || *outbox_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });

    let auto_task = {
        let a_ctx = Arc::clone(&ctx);
        let a_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            automations::run_loop(a_ctx, a_rx).await;
        })
    };

    // Background sticky proxy health prober: gently probes registered AI egress proxies every 15 min.
    let px_task = {
        let px_ctx = Arc::clone(&ctx);
        let mut px_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(45)) => {}
                res = px_rx.changed() => {
                    if res.is_err() || *px_rx.borrow() {
                        return;
                    }
                }
            }
            loop {
                if !px_ctx.proxies.list().is_empty() {
                    let (ok_n, tot) = handlers_proxies::probe_all_proxies(&px_ctx).await;
                    info!(ok = ok_n, total = tot, "background sticky proxy health probe finished");
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(15 * 60)) => {}
                    res = px_rx.changed() => {
                        if res.is_err() || *px_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        })
    };

    // Skill Hub + Fleet Auto-Updater: refresh GitHub sources every 24 h, safely update
    // AutoSafe upstream-tracked skills (preserving protected files & seal), and check third-party MCPs.
    let hub_task = {
        let sd = ctx.cfg.state_dir.clone();
        let mut hub_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(24 * 3600)) => {}
                    res = hub_rx.changed() => {
                        if res.is_err() || *hub_rx.borrow() {
                            break;
                        }
                    }
                }
                if agy_ext::skill_hub::load_lock(&sd).is_empty() {
                    continue;
                }
                if let Err(e) = agy_ext::skill_hub::sync_sources(&sd, None).await {
                    warn!(error = %e, "skillhub daily sync failed");
                    continue;
                }
                match agy_ext::fleet_updater::apply_updates(
                    &sd,
                    agy_ext::fleet_updater::UpdateScope::Skills,
                    false,
                )
                .await
                {
                    Ok(rep) => {
                        let upd = rep
                            .skills
                            .iter()
                            .filter(|s| s.status == agy_ext::fleet_updater::SkillItemStatus::Updated)
                            .count();
                        let blk = rep
                            .skills
                            .iter()
                            .filter(|s| s.status == agy_ext::fleet_updater::SkillItemStatus::Blocked)
                            .count();
                        info!(
                            updated = upd,
                            blocked = blk,
                            seal_ok = rep.seal_after.as_ref().is_none_or(|s| s.ok),
                            "daily fleet skill update finished"
                        );
                    }
                    Err(e) => warn!(error = %e, "daily fleet skill update failed"),
                }
                if let Ok(mcp_rep) = agy_ext::fleet_updater::check_all(
                    &sd,
                    agy_ext::fleet_updater::UpdateScope::Mcps,
                )
                .await
                {
                    let avail = mcp_rep
                        .mcps
                        .iter()
                        .filter(|m| m.status == agy_ext::fleet_updater::McpItemStatus::UpdateAvailable)
                        .count();
                    if avail > 0 {
                        info!(available = avail, "third-party MCP updates available (/updates check)");
                    }
                }
            }
        })
    };

    let cron_task = if cfg.cron_enabled {
        let cron_ref = Arc::clone(&ctx.cron);
        let cron_rx = shutdown_rx.clone();
        Some(tokio::spawn(async move {
            cron_ref.run(cron_rx).await;
        }))
    } else {
        None
    };

    let sig_tx = shutdown_tx.clone();
    let signal_task = tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        let _ = sig_tx.send(true);
    });

    let busy_fn: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new({
        let j = Arc::clone(&ctx.jobs);
        move || j.is_busy()
    });
    let mut allowed: Vec<String> = webhook::DEFAULT_ALLOWED_UPDATES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    if cfg.allow_inline_widgets && !allowed.iter().any(|u| u == "inline_query") {
        allowed.push("inline_query".to_string());
    }
    let supervisor = TransportSupervisor::new(
        Arc::clone(&cfg),
        Arc::clone(&client),
        Arc::clone(&health),
        Arc::clone(&dispatcher),
        busy_fn,
    )
    .with_allowed_updates(allowed);

    let mut stop_rx = shutdown_rx.clone();
    let stop_ctx = Arc::clone(&ctx);
    let stop_jobs_task = tokio::spawn(async move {
        let _ = stop_rx.wait_for(|&v| v).await;
        stop_ctx.jobs.stop_all().await;
    });

    let sup_res = supervisor.run(shutdown_rx).await;
    let _ = shutdown_tx.send(true);
    sd_notify_stopping();
    ctx.jobs.stop_all().await;

    signal_task.abort();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = stop_jobs_task.await;
        let _ = outbox_task.await;
        let _ = auto_task.await;
        let _ = px_task.await;
        let _ = hub_task.await;
        if let Some(mt) = models_task {
            let _ = mt.await;
        }
        if let Some(ct) = cron_task {
            let _ = ct.await;
        }
        let _ = http_task.await;
        if let Some(gwt) = mcp_gw_task {
            let _ = gwt.await;
        }
    })
    .await;

    sup_res.context("transport supervisor exited with error")?;
    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).ok();
        let mut sigint = signal(SignalKind::interrupt()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = async {
                if let Some(ref mut s) = sigterm {
                    let _ = s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {},
            _ = async {
                if let Some(ref mut s) = sigint {
                    let _ = s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Startup initialization: `getMe`, slash commands, model/MCP metadata, `notice_once.html`, `widget_once.json`.
pub async fn on_startup(ctx: &Arc<BotCtx>) {
    match ctx.client.get_me().await {
        Ok(me) => {
            let uname = me.username.clone().unwrap_or_default();
            info!(id = me.id, username = %uname, "getMe ok");
            {
                let mut g = ctx.bot_info.write().await;
                *g = Some((me.id, uname.clone()));
            }
            let _ = ctx.store.set_meta(
                "bot",
                json!({
                    "id": me.id,
                    "username": uname,
                }),
            );
        }
        Err(err) => {
            warn!(error = %err, "startup getMe failed (continuing)");
        }
    }

    let _ = ctx
        .client
        .set_my_commands(&[], Some(BotCommandScope::Default))
        .await;

    let mut approved_uids: Vec<i64> = ctx.acl.approved_ids().into_iter().collect();
    approved_uids.sort_unstable();
    for &uid in &approved_uids {
        ctx.sync_user_commands(uid).await;
    }

    if ctx.get_models_cache().is_empty() {
        let _ = ctx.refresh_models().await;
    }

    let mcp_rows = ctx.mcp_rows_live(None).await;
    let (enabled_cnt, total_cnt) = if !mcp_rows.is_empty() {
        let en = mcp_rows.iter().filter(|(_, s)| s == "enabled").count();
        (en, mcp_rows.len())
    } else {
        let cfgs = ctx.list_mcp_config();
        let en = cfgs.iter().filter(|c| c.enabled).count();
        (en, cfgs.len())
    };

    let notice_path = ctx.cfg.state_dir.join("notice_once.html");
    let custom_notice = if notice_path.is_file() {
        std::fs::read_to_string(&notice_path)
            .ok()
            .filter(|s| !s.trim().is_empty())
    } else {
        None
    };
    let had_custom_notice = custom_notice.is_some();

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let last_notice_ts = ctx
        .store
        .meta("last_startup_notice")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let suppressed = !had_custom_notice && (now_ts - last_notice_ts) < 120.0;
    if suppressed {
        info!("startup notice suppressed (restarted < 2 min ago)");
    } else {
        let owner_uid = ctx.cfg.owner_id;
        let text = custom_notice
            .unwrap_or_else(|| startup_text(ctx, enabled_cnt, total_cnt));
        let eff = ctx.premium.effect("party");
        let mut results = serde_json::Map::new();
        let mk = ctx.main_kb(owner_uid, false);
        let res = ctx
            .render
            .send_html(owner_uid, &text, Some(mk), eff, None, false)
            .await;
        let mut any_delivered = false;
        let entry = match res {
            Ok(Some(m)) => {
                any_delivered = true;
                json!({"ok": true, "message_id": m.message_id})
            }
            Ok(None) => json!({"ok": false, "error": "skipped or unavailable"}),
            Err(err) => json!({"ok": false, "error": err.to_string()}),
        };
        results.insert(owner_uid.to_string(), entry);
        if had_custom_notice && any_delivered {
            let _ = std::fs::remove_file(&notice_path);
        }
        if any_delivered {
            let _ = ctx.store.set_meta("last_startup_notice", json!(now_ts));
        }
        let _ = ctx
            .store
            .set_meta("last_startup_results", Value::Object(results));
    }

    let owner_only_slice = [ctx.cfg.owner_id];
    if let Err(err) = handlers_widgets::consume_startup_widget_once(ctx, &owner_only_slice).await {
        warn!(error = %err, "consume_startup_widget_once failed");
    }
}

fn startup_text(ctx: &BotCtx, enabled: usize, total: usize) -> String {
    let lang = i18n::owner_lang(ctx);
    let now = Local::now();
    let skills_count = ctx.list_installed_skills().len();
    format!(
        "{} <b>{}</b>\n\
        <i>agy-telegram-rs v{} ({:?})</i>\n\
        <blockquote><b>Host</b>  <code>{}</code>\n\
        <b>Time</b>  <tg-time unix=\"{}\" format=\"wDT\">{}</tg-time>\n\
        <b>MCP</b>  {enabled}/{total} · <b>Skills</b>  {skills_count}</blockquote>\n\
        {} <i>{}</i>",
        ctx.e("brand"),
        i18n::t(lang, i18n::Tx::StartupConnectedTitle),
        env!("CARGO_PKG_VERSION"),
        ctx.cfg.tg_transport,
        esc(&ctx.host),
        now.timestamp(),
        now.format("%Y-%m-%d %H:%M %Z"),
        ctx.e("ok"),
        i18n::t(lang, i18n::Tx::StartupTip),
    )
}

/// Returns `true` for emergency cancellation updates that must always bypass per-user rate limits.
fn is_rate_limit_exempt(update: &Update) -> bool {
    if update.stopped_message_generation.is_some() {
        return true;
    }
    if let Some(ref cq) = update.callback_query {
        if matches!(cq.data.as_deref(), Some("stop") | Some("par:stop")) {
            return true;
        }
    }
    if let Some(ref m) = update.message {
        if let Some(first) = m.text.as_deref().and_then(|t| t.split_whitespace().next()) {
            let cmd = first.split('@').next().unwrap_or("");
            if cmd.eq_ignore_ascii_case("/stop") || cmd.eq_ignore_ascii_case("/cancel") {
                return true;
            }
        }
    }
    false
}

/// Returns `true` for benign UI panel navigation callbacks that deserve generous anti-flood headroom
/// so interactive browsing across menus, limits, accounts, Grok, Secretary, and skills never feels sluggish.
fn is_ui_nav_callback(update: &Update) -> bool {
    let Some(ref cq) = update.callback_query else {
        return false;
    };
    let Some(d) = cq.data.as_deref() else {
        return false;
    };
    d.starts_with("home")
        || d.starts_with("acct:")
        || d.starts_with("px:")
        || d.starts_with("lim:")
        || d == "limits"
        || d == "status"
        || d == "settings"
        || d == "adv"
        || d == "net"
        || d.starts_with("net:")
        || d == "help"
        || d == "mcp"
        || d.starts_with("mcp:")
        || d.starts_with("skills:")
        || d.starts_with("sk:")
        || d.starts_with("models:")
        || d.starts_with("uadm:")
        || d.starts_with("grok:")
        || d.starts_with("umodel:")
        || d.starts_with("umodels:")
        || d.starts_with("biz:")
        || d.starts_with("auto:")
        || d.starts_with("wmenu:")
        || d.starts_with("set:")
        || d.starts_with("cwd:")
        || d.starts_with("agent:")
        || d == "cron"
        || d.starts_with("cron:")
        || d == "sessions"
        || d.starts_with("lang:")
        || d == "changelog"
        || d == "inp:cancel"
        || d.starts_with("upd:")
        || d.starts_with("hub:")
        || d.starts_with("par:")
}

/// Top-level Telegram update router applying `AuthGate` first and dispatching to domain handlers.
pub async fn dispatch_update(ctx: &Arc<BotCtx>, mut update: Update) {
    // Secretary Mode (Telegram Business) updates carry the *contact* as sender, so they bypass
    // the ACL gate; handlers_business only acts for connections owned by the bot owner.
    if update.business.is_some() {
        let bu = std::mem::take(&mut update.business);
        Box::pin(handlers_business::handle_business_update(ctx, bu)).await;
        if update.message.is_none() && update.callback_query.is_none() {
            return;
        }
    }
    let actor_uid = match ctx.auth.evaluate(&update) {
        AuthDecision::Drop => return,
        AuthDecision::NotifyOwnerStart(rec) => {
            let (txt, mk) = owner_start_notice_card(&rec, &ctx.premium);
            let _ = ctx
                .render
                .send_html_simple(ctx.cfg.owner_id, &txt, Some(mk))
                .await;
            return;
        }
        AuthDecision::Allowed(rec) => {
            if !ctx.commands_set.contains_key(&rec.uid) {
                ctx.sync_user_commands(rec.uid).await;
            }
            rec.uid
        }
    };

    // Phase 3 per-UID Telegram anti-flood guard (exempts /stop and cancel controls).
    if ctx.tg_rl.is_enabled() && !is_rate_limit_exempt(&update) {
        let cost = if update.message.as_ref().is_some_and(has_media_attachment) {
            2
        } else {
            1
        };
        let base_scale = if ctx.is_owner(actor_uid) { 3.0 } else { 1.0 };
        let scale = if is_ui_nav_callback(&update) {
            base_scale * 3.0
        } else {
            base_scale
        };
        let rl = ctx.tg_rl.check_scaled(actor_uid, cost, scale);
        if !rl.allowed {
            warn!(
                uid = actor_uid,
                cost,
                retry_after = rl.retry_after_secs,
                "Telegram per-UID anti-flood triggered; dropping update"
            );
            if let Some(ref cq) = update.callback_query {
                ctx.ack(
                    &cq.id,
                    Some(&format!("⏳ Slow down ({}s)", rl.retry_after_secs)),
                    false,
                )
                .await;
            } else if let Some(ref msg) = update.message {
                let now_s = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);
                let should_warn = ctx
                    .tg_rl_notice_ts
                    .get(&actor_uid)
                    .is_none_or(|prev| (now_s - *prev) >= 30.0);
                if should_warn {
                    ctx.tg_rl_notice_ts.insert(actor_uid, now_s);
                    let _ = ctx
                        .render
                        .send_html_simple(
                            msg.chat.id,
                            &format!(
                                "⏳ <i>Rate limit reached — please wait {}s before sending more requests.</i>",
                                rl.retry_after_secs
                            ),
                            None,
                        )
                        .await;
                }
            }
            return;
        }
    }

    if let Some(cq) = update.callback_query {
        Box::pin(handle_callback(ctx, &cq)).await;
        return;
    }

    if let Some(wq) = update.widget_query {
        Box::pin(handlers_widgets::handle_widget_query(ctx, &wq)).await;
        return;
    }

    if let Some(swq) = update.shared_widget_query {
        Box::pin(handlers_widgets::handle_shared_widget_query(ctx, &swq)).await;
        return;
    }

    if let Some(iq) = update.inline_query {
        Box::pin(handlers_widgets::handle_inline_query(ctx, &iq)).await;
        return;
    }

    if let Some(ev) = update.stopped_message_generation {
        handle_draft_stop(ctx, &ev).await;
        return;
    }

    if let Some(msg) = update.message {
        Box::pin(handle_message(ctx, &msg)).await;
    }
}

async fn handle_draft_stop(ctx: &Arc<BotCtx>, ev: &MessageGenerationStopped) {
    if ctx.jobs.stop_user_draft(ev.chat.id, ev.draft_id).await {
        info!(chat_id = ev.chat.id, draft_id = ev.draft_id, "user stopped draft generation");
    }
}

async fn clear_reply_markup_quiet(ctx: &Arc<BotCtx>, cq: &CallbackQuery) {
    if let Some(ref msg) = cq.message {
        let _ = ctx
            .client
            .call_json::<Value>(
                "editMessageReplyMarkup",
                &json!({
                    "chat_id": msg.chat.id,
                    "message_id": msg.message_id,
                    "reply_markup": { "inline_keyboard": [] }
                }),
                None,
            )
            .await;
    }
}

async fn handle_callback(ctx: &Arc<BotCtx>, cq: &CallbackQuery) {
    let uid = cq.from_user.id;
    let chat_id = cq.message.as_ref().map(|m| m.chat.id).unwrap_or(uid);
    let data = cq.data.as_deref().unwrap_or("");
    if data.is_empty() {
        ctx.ack(&cq.id, None, false).await;
        return;
    }

    if data.starts_with("ask:") || data.starts_with("askr:") {
        ctx.ack(&cq.id, None, false).await;
        let choice_owned = if data.starts_with("ask:") {
            data.strip_prefix("ask:").unwrap_or("").trim().to_string()
        } else {
            ctx.render
                .resolve_ask_route(data)
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        if !choice_owned.is_empty() {
            clear_reply_markup_quiet(ctx, cq).await;
            let label = cq.from_user.display_label();
            let req = JobRequest::new(uid, chat_id, label, format!("[button] {choice_owned}"), Vec::new());
            if let Err(err) = ctx.jobs.enqueue(req).await {
                warn!(uid, error = %err, "ask: enqueue failed");
            }
        }
        return;
    }

    if data == "files:run" {
        ctx.ack(&cq.id, None, false).await;
        let files = handlers_widgets::take_pending_widget_files(ctx, uid);
        clear_reply_markup_quiet(ctx, cq).await;
        if !files.is_empty() {
            let label = cq.from_user.display_label();
            let req = JobRequest::new(uid, chat_id, label, "", files);
            if let Err(err) = ctx.jobs.enqueue(req).await {
                warn!(uid, error = %err, "files:run enqueue failed");
            }
        }
        return;
    }

    if data == "files:drop" {
        handlers_widgets::take_pending_widget_files(ctx, uid);
        ctx.ack(&cq.id, Some("Discarded"), false).await;
        if let Some(ref msg) = cq.message {
            let _ = ctx
                .render
                .edit_html(
                    chat_id,
                    msg.message_id,
                    "🗑 <i>Attachments discarded.</i>",
                    None,
                )
                .await;
        }
        return;
    }

    if let Some(rest) = data.strip_prefix("mpk:") {
        let (nonce, choice) = rest.split_once(':').unwrap_or((rest, ""));
        let toast = ctx.jobs.resolve_model_pick(uid, nonce, choice).unwrap_or("This choice has expired");
        ctx.ack(&cq.id, Some(toast), false).await;
        return;
    }
    if Box::pin(handlers_parallel::handle_par_cb(ctx, cq, uid, data)).await {
        return;
    }
    if Box::pin(handlers_accounts::handle_acct_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_proxies::handle_px_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_users::handle_uadm_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_skills::handle_sk_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_business::handle_biz_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(automations::handle_auto_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_mcp::handle_mcp_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_mcpgw::handle_mcpgw_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_widgets::handle_widget_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_uncensored::handle_uncensored_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_gemini::handle_gemini_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_grok::handle_grok_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_grok_bot::handle_grok_bot_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_updates::handle_updates_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_skillhub::handle_skillhub_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }
    if Box::pin(handlers_system::handle_system_cb(ctx, cq, uid, chat_id, data)).await {
        return;
    }

    ctx.ack(&cq.id, None, false).await;
}

async fn handle_message(ctx: &Arc<BotCtx>, msg: &Message) {
    if msg.widget.is_some() && handlers_widgets::handle_widget_message(ctx, msg).await {
        return;
    }

    if has_media_attachment(msg) {
        handle_file_message(ctx, msg).await;
        return;
    }

    let Some(raw_text) = msg.text.as_deref() else {
        if msg.from_user.is_some() && msg.chat.kind == "private" {
            let _ = ctx
                .render
                .send_html_simple(
                    msg.chat.id,
                    "<i>This message type isn't supported — send text or a file.</i>",
                    None,
                )
                .await;
        }
        return;
    };

    if msg.chat.kind == "private"
        && raw_text.trim_start().starts_with('/')
        && Box::pin(dispatch_slash_command(ctx, msg, raw_text)).await
    {
        return;
    }

    let Some(ref user) = msg.from_user else {
        return;
    };
    let uid = user.id;
    let chat_id = msg.chat.id;
    let user_label = user.display_label();

    if let Some(inp) = ctx.jobs.take_awaiting(uid) {
        if handlers_business::handle_biz_awaiting_text(ctx, uid, chat_id, &inp, raw_text).await {
            return;
        }
        if handlers_accounts::handle_accounts_awaiting_text(ctx, msg, uid, chat_id, &inp, raw_text)
            .await
        {
            return;
        }
        if handlers_proxies::handle_proxies_awaiting_text(ctx, msg, uid, chat_id, &inp, raw_text)
            .await
        {
            return;
        }
        if handlers_skills::handle_skills_awaiting_text(
            ctx,
            msg,
            uid,
            chat_id,
            &user_label,
            &inp,
            raw_text,
        )
        .await
        {
            return;
        }
        if handlers_mcp::handle_mcp_awaiting_text(
            ctx,
            msg,
            uid,
            chat_id,
            &user_label,
            &inp,
            raw_text,
        )
        .await
        {
            return;
        }
        if handlers_uncensored::handle_uncensored_awaiting_text(ctx, uid, chat_id, &inp, raw_text)
            .await
        {
            return;
        }
        if Box::pin(handlers_gemini::handle_gemini_awaiting_text(
            ctx, msg, uid, chat_id, &inp, raw_text,
        ))
        .await
        {
            return;
        }
        if handlers_mcpgw::handle_mcpgw_awaiting_text(ctx, uid, chat_id, &inp, raw_text).await {
            return;
        }
    }

    let attachments = handlers_widgets::take_pending_widget_files(ctx, uid);
    if attachments.is_empty() {
        if let Some(fast) = local_fast::try_local_fast_reply(ctx, uid, raw_text) {
            info!(uid, kind = fast.kind, "answered locally via Phase 4 fast-path (0 AI tokens)");
            let _ = ctx
                .render
                .send_html_simple(chat_id, &fast.html, fast.markup)
                .await;
            return;
        }
    }
    let req = JobRequest::new(uid, chat_id, user_label, raw_text, attachments);
    if let Err(err) = ctx.jobs.enqueue(req).await {
        warn!(uid, error = %err, "prompt enqueue failed");
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!("{} <b>Failed to queue request:</b> <code>{}</code>", ctx.e("err"), esc(&err.to_string())),
                None,
            )
            .await;
    }
}

/// Flag users whose saved AGY model no account offers any more; their next turn shows the
/// account's model picker (nothing is substituted automatically).
/// Non-AGY engines (`uncensored`, `grok`) are never flagged as invalid AGY models.
fn mark_stale_user_models(jobs: &Arc<JobManager>, store: &Arc<StateStore>) {
    for (k, u) in store.snapshot().users {
        let Ok(uid) = k.parse::<i64>() else { continue };
        let Some(m) = u.model.clone().filter(|m| !m.is_empty()) else { continue };
        let eng = u.extra.get("engine").and_then(|v| v.as_str());
        let is_external = matches!(
            eng,
            Some("uncensored") | Some("gemini_web") | Some("grok") | Some("grok_bot")
        )
            || agy_ext::uncensored::is_uncensored_model(&m)
            || agy_ext::grok_oauth::is_grok_model(&m);
        let stale = !is_external && !jobs.model_known_anywhere(&m);
        let flagged = u.extra.contains_key(jobs::model_pick::MODEL_INVALID_KEY);
        if stale != flagged {
            let _ = store.update_user(uid, |u| {
                if stale {
                    u.extra.insert(jobs::model_pick::MODEL_INVALID_KEY.to_string(), serde_json::json!(true));
                } else {
                    u.extra.remove(jobs::model_pick::MODEL_INVALID_KEY);
                }
            });
            if stale {
                warn!(uid, model = %m, "saved model is not offered by any account; user will be asked on next use");
            }
        }
    }
}

/// Tell the owner (once per set) when two pool accounts share one Google e-mail.
async fn alert_duplicate_accounts(
    pool: &Arc<agy_core::accounts::AccountStore>,
    store: &Arc<StateStore>,
    render: &Arc<RenderBridge>,
    owner: i64,
) {
    let groups = pool.duplicate_groups();
    let key: Vec<String> = groups.iter().map(|g| g.join("+")).collect();
    let key = key.join(",");
    let prev = store.meta("dup_accounts_alerted").and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
    if key == prev {
        return;
    }
    let _ = store.set_meta("dup_accounts_alerted", serde_json::json!(key));
    if groups.is_empty() {
        return;
    }
    let list: Vec<String> = groups.iter().map(|g| format!("<code>{}</code>", g.join("</code> = <code>"))).collect();
    let _ = render
        .send_html_simple(
            owner,
            &format!(
                "⚠️ <b>Duplicate accounts in the pool</b>\n{}\nThese are signed in with the same Google e-mail, so they share one quota. Nothing was removed — remove the extra one from /accounts if you want.",
                list.join("\n")
            ),
            None,
        )
        .await;
}

fn parse_slash_command(raw_text: &str) -> Option<(String, String)> {
    let trimmed = raw_text.trim();
    if !trimmed.starts_with('/') {
        return None;
    }
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let head = parts.next()?.strip_prefix('/')?;
    let cmd_only = head.split('@').next().unwrap_or("").to_ascii_lowercase();
    if cmd_only.is_empty() {
        return None;
    }
    let arg = parts.next().map(str::trim).unwrap_or("").to_string();
    Some((cmd_only, arg))
}

async fn dispatch_slash_command(ctx: &Arc<BotCtx>, msg: &Message, raw_text: &str) -> bool {
    let Some((cmd, arg)) = parse_slash_command(raw_text) else {
        return false;
    };
    let is_known = matches!(
        cmd.as_str(),
        "start"
            | "secretary"
            | "business"
            | "auto"
            | "automations"
            | "menu"
            | "help"
            | "new"
            | "lang"
            | "language"
            | "stop"
            | "cancel"
            | "model"
            | "uncensored"
            | "umodel"
            | "umodels"
            | "uagent"
            | "grok"
            | "gmodel"
            | "gmodels"
            | "gagent"
            | "status"
            | "settings"
            | "effort"
            | "mode"
            | "resume"
            | "cwd"
            | "agent"
            | "trace"
            | "changelog"
            | "net"
            | "limits"
            | "guards"
            | "safety"
            | "proxies"
            | "proxy"
            | "cron"
            | "users"
            | "accounts"
            | "parallel"
            | "skills"
            | "skillhub"
            | "hub"
            | "updates"
            | "fleet"
            | "sysupdate"
            | "mcp"
            | "widget"
    );
    if !is_known {
        return false;
    }
    if cmd != "cancel" {
        if let Some(uid) = msg.from_user.as_ref().map(|u| u.id) {
            ctx.jobs.clear_awaiting(uid);
        }
    }
    match cmd.as_str() {
        "start" if arg.starts_with("bizChat") => match arg.trim_start_matches("bizChat").parse::<i64>() {
            Ok(chat) => handlers_business::open_chat_panel(ctx, msg, chat).await,
            Err(_) => handlers_system::cmd_start(ctx, msg, "").await,
        },
        "start" => handlers_system::cmd_start(ctx, msg, &arg).await,
        "secretary" | "business" => handlers_business::cmd_secretary(ctx, msg, &arg).await,
        "auto" | "automations" => automations::cmd_auto(ctx, msg, &arg).await,
        "menu" => handlers_system::cmd_menu(ctx, msg, &arg).await,
        "help" => handlers_system::cmd_help(ctx, msg, &arg).await,
        "new" => handlers_system::cmd_new(ctx, msg, &arg).await,
        "lang" | "language" => handlers_system::cmd_lang(ctx, msg, &arg).await,
        "stop" => handlers_system::cmd_stop(ctx, msg, &arg).await,
        "cancel" => handlers_system::cmd_cancel(ctx, msg, &arg).await,
        "model" => handlers_system::cmd_model(ctx, msg, &arg).await,
        "uncensored" | "umodel" | "umodels" | "venice" => {
            handlers_uncensored::cmd_uncensored(ctx, msg, &arg).await
        }
        "webmodel" => Box::pin(handlers_gemini::cmd_web_model(ctx, msg, &arg)).await,
        "gemini" => Box::pin(handlers_gemini::cmd_web_model(ctx, msg, "gemini")).await,
        "gems" => Box::pin(handlers_gemini::cmd_web_model(ctx, msg, "gems")).await,
        "uagent" => handlers_uncensored::cmd_uagent(ctx, msg, &arg).await,
        "grok" | "gmodel" | "gmodels" => handlers_grok::cmd_grok(ctx, msg, &arg).await,
        "gagent" => handlers_grok::cmd_gagent(ctx, msg, &arg).await,
        "gbot" | "grokbot" => handlers_grok_bot::cmd_gbot(ctx, msg, &arg).await,
        "status" => handlers_system::cmd_status(ctx, msg, &arg).await,
        "settings" => handlers_system::cmd_settings(ctx, msg, &arg).await,
        "effort" => handlers_system::cmd_effort(ctx, msg, &arg).await,
        "mode" => handlers_system::cmd_mode(ctx, msg, &arg).await,
        "resume" => handlers_system::cmd_resume(ctx, msg, &arg).await,
        "cwd" => handlers_system::cmd_cwd(ctx, msg, &arg).await,
        "agent" => handlers_system::cmd_agent(ctx, msg, &arg).await,
        "trace" => handlers_system::cmd_trace(ctx, msg, &arg).await,
        "changelog" => handlers_system::cmd_changelog(ctx, msg, &arg).await,
        "net" => handlers_system::cmd_net(ctx, msg, &arg).await,
        "limits" | "guards" | "safety" => handlers_system::cmd_limits(ctx, msg, &arg).await,
        "proxies" | "proxy" => handlers_proxies::cmd_proxies(ctx, msg, &arg).await,
        "cron" => handlers_system::cmd_cron(ctx, msg, &arg).await,
        "users" => handlers_users::cmd_users(ctx, msg).await,
        "accounts" => handlers_accounts::cmd_accounts(ctx, msg).await,
        "parallel" => handlers_parallel::cmd_parallel(ctx, msg, &arg).await,
        "skills" => handlers_skills::cmd_skills(ctx, msg).await,
        "skillhub" | "hub" => handlers_skillhub::cmd_skillhub(ctx, msg, &arg).await,
        "updates" | "fleet" | "sysupdate" => handlers_updates::cmd_updates(ctx, msg, &arg).await,
        "mcp" => handlers_mcp::cmd_mcp(ctx, msg).await,
        "mcpgw" | "mcpgateway" => handlers_mcpgw::cmd_mcpgw(ctx, msg, &arg).await,
        "widget" => handlers_widgets::cmd_widget(ctx, msg, &arg).await,
        _ => return false,
    }
    true
}

fn has_media_attachment(msg: &Message) -> bool {
    msg.photo.as_ref().is_some_and(|p| !p.is_empty())
        || msg.document.is_some()
        || msg.video.is_some()
        || msg.audio.is_some()
        || msg.voice.is_some()
        || msg.animation.is_some()
        || msg.video_note.is_some()
        || msg.sticker.is_some()
}

fn safe_upload_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches(|c| c == '.' || c == '_');
    let base = if trimmed.is_empty() { "file" } else { trimmed };
    let chars: Vec<char> = base.chars().collect();
    if chars.len() > 120 {
        chars[chars.len() - 120..].iter().collect()
    } else {
        base.to_string()
    }
}

fn pick_media_meta(msg: &Message) -> Option<(String, String, u64)> {
    let mid = msg.message_id;
    if let Some(ref photos) = msg.photo {
        if let Some(p) = photos.last() {
            return Some((
                p.file_id.clone(),
                format!("photo_{mid}.jpg"),
                p.file_size.unwrap_or(0),
            ));
        }
    }
    if let Some(ref d) = msg.document {
        return Some((
            d.file_id.clone(),
            d.file_name
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("document_{mid}")),
            d.file_size.unwrap_or(0),
        ));
    }
    if let Some(ref v) = msg.video {
        return Some((
            v.file_id.clone(),
            v.file_name
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("video_{mid}.mp4")),
            v.file_size.unwrap_or(0),
        ));
    }
    if let Some(ref a) = msg.audio {
        return Some((
            a.file_id.clone(),
            a.file_name
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("audio_{mid}.mp3")),
            a.file_size.unwrap_or(0),
        ));
    }
    if let Some(ref v) = msg.voice {
        return Some((
            v.file_id.clone(),
            format!("voice_{mid}.ogg"),
            v.file_size.unwrap_or(0),
        ));
    }
    if let Some(ref a) = msg.animation {
        return Some((
            a.file_id.clone(),
            a.file_name
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("animation_{mid}.mp4")),
            a.file_size.unwrap_or(0),
        ));
    }
    if let Some(ref vn) = msg.video_note {
        return Some((
            vn.file_id.clone(),
            format!("videonote_{mid}.mp4"),
            vn.file_size.unwrap_or(0),
        ));
    }
    if let Some(ref st) = msg.sticker {
        let ext = if st.is_video {
            "webm"
        } else if st.is_animated {
            "tgs"
        } else {
            "webp"
        };
        return Some((
            st.file_id.clone(),
            format!("sticker_{mid}.{ext}"),
            st.file_size.unwrap_or(0),
        ));
    }
    None
}

async fn handle_file_message(ctx: &Arc<BotCtx>, msg: &Message) {
    let Some(ref user) = msg.from_user else {
        return;
    };
    let uid = user.id;
    let chat_id = msg.chat.id;
    let _ = ctx.client.send_chat_action(chat_id, "upload_document").await;

    let Some((file_id, raw_name, file_size)) = pick_media_meta(msg) else {
        let _ = ctx
            .render
            .send_html_simple(chat_id, "<i>Unsupported file.</i>", None)
            .await;
        return;
    };

    if file_size > MAX_DOWNLOAD_BYTES as u64 {
        let mb = (file_size as f64) / 1_048_576.0;
        let lang = ctx.lang(uid);
        let warn_msg = format!(
            "{} <b>{}</b> ({mb:.1} MB)",
            ctx.e("warn"),
            i18n::t(lang, i18n::Tx::FileRejectedSize),
        );
        let _ = ctx.render.send_html_simple(chat_id, &warn_msg, None).await;
        return;
    }

    let user_inbox = ctx.cfg.inbox_dir().join(uid.to_string());
    if let Err(err) = std::fs::create_dir_all(&user_inbox) {
        warn!(uid, error = %err, "creating inbox directory failed");
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!("{} <b>Inbox unavailable</b>.", ctx.e("err")),
                None,
            )
            .await;
        return;
    }

    let tg_file = match ctx.client.get_file(&file_id).await {
        Ok(f) => f,
        Err(err) => {
            warn!(uid, error = %err, "getFile failed");
            let lang = ctx.lang(uid);
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!("{} <b>{}</b>", ctx.e("err"), i18n::t(lang, i18n::Tx::FileDownloadFailed)),
                    None,
                )
                .await;
            return;
        }
    };
    let Some(file_path) = tg_file.file_path.as_deref() else {
        let lang = ctx.lang(uid);
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!("{} <b>{}</b>", ctx.e("err"), i18n::t(lang, i18n::Tx::FileDownloadFailed)),
                None,
            )
            .await;
        return;
    };

    let stamp = Local::now().format("%Y%m%d-%H%M%S");
    let dest_name = format!("{stamp}_{}_{}", msg.message_id, safe_upload_name(&raw_name));
    let dest = user_inbox.join(&dest_name);

    if let Err(err) = ctx
        .client
        .download_file(file_path, &dest, MAX_DOWNLOAD_BYTES)
        .await
    {
        warn!(uid, error = %err, "download_file failed");
        let lang = ctx.lang(uid);
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!("{} <b>{}</b>", ctx.e("err"), i18n::t(lang, i18n::Tx::FileDownloadFailed)),
                None,
            )
            .await;
        return;
    }

    if handlers_uncensored::handle_uncensored_awaiting_file(ctx, uid, chat_id, &dest).await {
        return;
    }

    if let Some(cap) = msg.caption.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let mut files = handlers_widgets::take_pending_widget_files(ctx, uid);
        files.push(dest);
        let req = JobRequest::new(uid, chat_id, user.display_label(), cap, files);
        let _ = ctx.jobs.enqueue(req).await;
        return;
    }

    handlers_widgets::push_pending_file(ctx, uid, dest);
    let n = handlers_widgets::pending_widget_files(ctx, uid).len();
    let count_suffix = if n > 1 {
        format!(" · <b>{n}</b>")
    } else {
        String::new()
    };
    let lang = ctx.lang(uid);
    let text = format!(
        "{} {}: <code>{}</code>{count_suffix}",
        ctx.e("file"),
        i18n::t(lang, i18n::Tx::FileSavedHeading),
        esc(&dest_name)
    );
    let mk = BotCtx::kb(vec![vec![
        ctx.btn("rocket", "Analyze", Some("files:run"), Some("primary"), None),
        ctx.btn("", "🗑 Discard", Some("files:drop"), None, None),
    ]]);
    let _ = ctx.render.send_html_simple(chat_id, &text, Some(mk)).await;
}

/// Strip `<tg-emoji>` when preparing clean log/fallback copies (keeps test helper self-contained).
#[cfg(test)]
fn _strip_helper_check(s: &str) -> String {
    agy_render::premium::strip_custom_emoji(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agy_core::tg::{Chat, PhotoSize};
    use agy_net::{NetConfig, ProxyPool};
    use agy_widgets::WidgetStore;
    use axum::body::Body;
    use axum::extract::{Path as AxumPath, Request, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::Json;
    use tempfile::TempDir;
    use tokio::sync::Mutex as TokioMutex;
    use tower::ServiceExt;

    const OWNER: i64 = 1_000_000_001;
    const STRANGER: i64 = 8_888_111;

    #[derive(Clone, Default)]
    struct MockServerState {
        calls: Arc<TokioMutex<Vec<(String, Value)>>>,
        files_served: Arc<TokioMutex<Vec<String>>>,
    }

    async fn mock_tg_api(
        State(st): State<MockServerState>,
        AxumPath((_tok, method)): AxumPath<(String, String)>,
        req: Request,
    ) -> Response {
        let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        let val: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|_| json!({}));
        st.calls.lock().await.push((method.clone(), val.clone()));

        match method.as_str() {
            "getMe" => (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "result": {
                        "id": 999,
                        "is_bot": true,
                        "first_name": "AgyBot",
                        "username": "your_agy_bot"
                    }
                })),
            )
                .into_response(),
            "getFile" => (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "result": {
                        "file_id": val.get("file_id").and_then(Value::as_str).unwrap_or("f1"),
                        "file_unique_id": "u1",
                        "file_size": 11,
                        "file_path": "photos/test.jpg"
                    }
                })),
            )
                .into_response(),
            "sendMessage" | "editMessageText" | "sendRichMessage" => (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "result": {
                        "message_id": 77,
                        "from": { "id": 999, "is_bot": true, "first_name": "AgyBot" },
                        "chat": { "id": OWNER, "type": "private" },
                        "text": "ok"
                    }
                })),
            )
                .into_response(),
            _ => (StatusCode::OK, Json(json!({"ok": true, "result": true}))).into_response(),
        }
    }

    async fn mock_tg_file(
        State(st): State<MockServerState>,
        AxumPath((_tok, fpath)): AxumPath<(String, String)>,
    ) -> Response {
        st.files_served.lock().await.push(fpath);
        (StatusCode::OK, b"hello-bytes".to_vec()).into_response()
    }

    fn mk_user(id: i64, uname: &str) -> User {
        User {
            id,
            is_bot: false,
            first_name: uname.into(),
            last_name: None,
            username: Some(uname.into()),
            language_code: None,
            is_premium: Some(true),
        }
    }

    fn mk_text_update(update_id: i64, uid: i64, text: &str) -> Update {
        Update {
            update_id,
            message: Some(Message {
                message_id: update_id,
                from_user: Some(mk_user(uid, "user")),
                chat: Chat {
                    id: uid,
                    kind: "private".into(),
                    username: Some("user".into()),
                    first_name: Some("User".into()),
                },
                message_thread_id: None,
                text: Some(text.into()),
                caption: None,
                entities: None,
                effect_id: None,
                reply_to_message: None,
                photo: None,
                document: None,
                video: None,
                audio: None,
                voice: None,
                animation: None,
                video_note: None,
                sticker: None,
                widget: None,
                business_connection_id: None,
                sender_business_bot: None,
            }),
            callback_query: None,
            inline_query: None,
            widget_query: None,
            shared_widget_query: None,
            business: Default::default(),
            stopped_message_generation: None,
        }
    }

    async fn setup_test_ctx(dir: &TempDir) -> (MockServerState, Arc<BotCtx>) {
        setup_test_ctx_with(dir, None).await
    }

    async fn setup_test_ctx_with(dir: &TempDir, agy_bin: Option<PathBuf>) -> (MockServerState, Arc<BotCtx>) {
        let st = MockServerState::default();
        let app = Router::new()
            .route("/bot{token}/{method}", post(mock_tg_api))
            .route("/file/bot{token}/{*fpath}", get(mock_tg_file))
            .with_state(st.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let state_dir = dir.path().join("state");
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(
            state_dir.join("models.json"),
            r#"[{"id":"m1","name":"Model 1"}]"#,
        )
        .unwrap();

        let cfg = Arc::new(Config {
            bot_token: "123:TOK".into(),
            state_dir: state_dir.clone(),
            agy_workspace: ws,
            owner_id: OWNER,
            allowed_user_ids: vec![OWNER],
            webhook_secret: Some("sec-main-test".into()),
            agy_bin: agy_bin.unwrap_or_else(|| PathBuf::from("/nonexistent/agy-test-guard")),
            ..Default::default()
        });
        let store = Arc::new(StateStore::open(cfg.state_path()).unwrap());
        let acl = Arc::new(AclStore::open(cfg.acl_path(), OWNER, &[OWNER], 300).unwrap());
        let outbox = Arc::new(OutQueue::open(cfg.outbox_path()).unwrap());
        let widgets = Arc::new(WidgetStore::from_state_dir(&state_dir).unwrap());
        let health = Arc::new(HealthTracker::new(cfg.health_path()));
        let premium = Arc::new(PremiumState::new(true));
        let pool = Arc::new(ProxyPool::new(NetConfig::default().with_api_base(format!("http://{addr}"))).unwrap());
        let client = Arc::new(
            BotApiClient::with_pool(
                "123:TOK",
                format!("http://{addr}"),
                Arc::clone(&pool),
                Duration::from_secs(5),
            )
            .unwrap(),
        );
        let render = Arc::new(
            RenderBridge::new(Arc::clone(&client), Arc::clone(&premium), Arc::clone(&outbox))
                .with_state_store(Arc::clone(&store))
                .with_retry_config(1, 0.01),
        );
        let cron = Arc::new(CronScheduler::new(Arc::clone(&cfg), Arc::clone(&health)).unwrap());
        let jobs = Arc::new(
            JobManager::new(
                Arc::clone(&cfg),
                Arc::clone(&acl),
                Arc::clone(&store),
                Arc::clone(&render),
                Arc::clone(&client),
            )
            .unwrap(),
        );
        let auth = Arc::new(AuthGate::from_config(Arc::clone(&acl), &cfg));
        let ctx = BotCtx::new(
            cfg, store, acl, outbox, health, premium, pool, client, widgets, render, cron, jobs,
            auth,
        );
        let sink = Arc::new(CtxWidgetSink {
            ctx: Arc::downgrade(&ctx),
        });
        ctx.jobs.set_widget_sink(sink);
        (st, ctx)
    }

    #[test]
    fn check_and_bench_ab_succeed_with_valid_outputs() {
        let chk = check_builtin_widgets().unwrap();
        assert_eq!(chk["builtins"], json!(4));

        let ab = run_ab_benchmark().unwrap();
        assert!(ab["cold_startup_ms"].as_f64().unwrap() >= 0.0);
        assert!(ab["render_1000_ms"].as_f64().unwrap() >= 0.0);
        assert!(ab["acl_200_ops_ms"].as_f64().unwrap() >= 0.0);
        assert!(ab["widget_400_ops_ms"].as_f64().unwrap() >= 0.0);
        assert!(ab["peak_rss_kb"].is_u64());
        assert_eq!(_strip_helper_check("<tg-emoji emoji-id=\"1\">✅</tg-emoji>"), "✅");
    }

    #[tokio::test]
    async fn full_update_dispatcher_auth_commands_files_and_combined_router() {
        let dir = TempDir::new().unwrap();
        let (st, ctx) = setup_test_ctx(&dir).await;

        // 1. Startup initializes bot_info, syncs owner commands, consumes notice_once.html -> sent ONLY to OWNER!
        let admin_uid: i64 = 8_111_222_333;
        let user_uid: i64 = 8_111_222_444;
        ctx.acl.set_status(admin_uid, UserStatus::Approved, Some(OWNER), None).unwrap();
        ctx.acl.set_tier(admin_uid, agy_core::acl::RoleTier::Admin, true).unwrap();
        ctx.acl.set_status(user_uid, UserStatus::Approved, Some(OWNER), Some(RolePreset::Std)).unwrap();

        std::fs::write(
            ctx.cfg.state_dir.join("notice_once.html"),
            "<b>Upgraded to Rust v4</b>",
        )
        .unwrap();
        on_startup(&ctx).await;
        assert!(!ctx.cfg.state_dir.join("notice_once.html").exists());
        assert!(ctx.commands_set.contains_key(&OWNER));
        let calls = st.calls.lock().await.clone();
        assert!(calls.iter().any(|(m, _)| m == "getMe"));
        assert!(calls.iter().any(|(m, _)| m == "setMyCommands"));
        assert!(calls.iter().any(|(m, v)| {
            m == "sendMessage"
                && v["chat_id"].as_i64() == Some(OWNER)
                && v["text"].as_str().unwrap_or("").contains("Rust v4")
        }));
        assert!(!calls.iter().any(|(m, v)| {
            m == "sendMessage" && matches!(v["chat_id"].as_i64(), Some(id) if id == admin_uid || id == user_uid)
        }));

        // 2. Unauthorized stranger message is dropped; stranger /start notifies owner
        st.calls.lock().await.clear();
        dispatch_update(&ctx, mk_text_update(1, STRANGER, "secret prompt")).await;
        assert!(st.calls.lock().await.is_empty());

        dispatch_update(&ctx, mk_text_update(2, STRANGER, "/start")).await;
        let start_calls = st.calls.lock().await.clone();
        assert!(start_calls.iter().any(|(m, v)| {
            m == "sendMessage" && v["chat_id"].as_i64() == Some(OWNER)
        }));

        // 3. Approved owner /status and /cron commands dispatch cleanly
        st.calls.lock().await.clear();
        dispatch_update(&ctx, mk_text_update(3, OWNER, "/status")).await;
        dispatch_update(&ctx, mk_text_update(4, OWNER, "/cron")).await;
        let owner_calls = st.calls.lock().await.clone();
        assert!(owner_calls.iter().filter(|(m, _)| m == "sendMessage").count() >= 2);

        // 4. Media upload downloads into inbox & registers pending attachment, then files:drop cleans it
        let mut photo_upd = mk_text_update(5, OWNER, "");
        if let Some(ref mut m) = photo_upd.message {
            m.text = None;
            m.photo = Some(vec![PhotoSize {
                file_id: "photo_f1".into(),
                file_unique_id: "u_f1".into(),
                file_size: Some(11),
            }]);
        }
        dispatch_update(&ctx, photo_upd).await;
        let pending = handlers_widgets::pending_widget_files(&ctx, OWNER);
        assert_eq!(pending.len(), 1);
        assert_eq!(std::fs::read(&pending[0]).unwrap(), b"hello-bytes");

        dispatch_update(
            &ctx,
            Update {
                update_id: 6,
                message: None,
                callback_query: Some(CallbackQuery {
                    id: "cq_drop".into(),
                    from_user: mk_user(OWNER, "owner"),
                    inline_message_id: None,
                    message: Some(Message {
                        message_id: 88,
                        from_user: None,
                        chat: Chat {
                            id: OWNER,
                            kind: "private".into(),
                            username: None,
                            first_name: None,
                        },
                        message_thread_id: None,
                        text: None,
                        caption: None,
                        entities: None,
                        effect_id: None,
                        reply_to_message: None,
                        photo: None,
                        document: None,
                        video: None,
                        audio: None,
                        voice: None,
                        animation: None,
                        video_note: None,
                        sticker: None,
                        widget: None,
                        business_connection_id: None,
                        sender_business_bot: None,
                    }),
                    data: Some("files:drop".into()),
                }),
                inline_query: None,
                widget_query: None,
                shared_widget_query: None,
                business: Default::default(),
                stopped_message_generation: None,
            },
        )
        .await;
        assert!(handlers_widgets::pending_widget_files(&ctx, OWNER).is_empty());

        // 5. Combined WebApp + Webhook router serves /healthz and protects /tg/webhook
        let bridge: Arc<dyn WidgetBridge> = BotWebAppBridge::new(Arc::clone(&ctx));
        let web_state = WebAppState::new(
            ctx.cfg.bot_token.clone(),
            [OWNER].into_iter().collect(),
            Arc::clone(&ctx.widgets),
            bridge,
        );
        let disp_ctx = Arc::clone(&ctx);
        let disp: Arc<dyn UpdateDispatcher> = Arc::new(FnDispatcher(move |u: Update| {
            let c = Arc::clone(&disp_ctx);
            async move {
                dispatch_update(&c, u).await;
            }
        }));
        let combined = build_webapp_router(web_state).merge(webhook_router(
            "sec-main-test".into(),
            disp,
            Arc::clone(&ctx.health),
        ));

        let hz = combined
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(hz.status(), StatusCode::OK);

        let wh_unauth = combined
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/tg/webhook")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&mk_text_update(10, OWNER, "/help")).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wh_unauth.status(), StatusCode::UNAUTHORIZED);
    }
    fn biz_msg(update_id: i64, from: i64, text: &str) -> Update {
        serde_json::from_value(json!({
            "update_id": update_id,
            "business_message": {"message_id": update_id, "business_connection_id": "bc1",
                "from": {"id": from, "is_bot": false, "first_name": if from == OWNER { "Mahdi" } else { "Eve" }, "username": "eve"},
                "chat": {"id": 7, "type": "private", "first_name": "Eve"}, "date": 1, "text": text}
        }))
        .unwrap()
    }

    async fn wait_call(st: &MockServerState, pred: impl Fn(&str, &Value) -> bool, ms: u64) -> Option<Value> {
        let t = std::time::Instant::now();
        while t.elapsed() < Duration::from_millis(ms) {
            if let Some((_, v)) = st.calls.lock().await.iter().find(|(m, v)| pred(m, v)).cloned() {
                return Some(v);
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        None
    }

    #[tokio::test]
    async fn secretary_mode_business_updates_draft_send_auto_and_automations_with_fake_agy() {
        // The four business update kinds must be requested explicitly in allowed_updates.
        for k in ["business_connection", "business_message", "edited_business_message", "deleted_business_messages"] {
            assert!(webhook::DEFAULT_ALLOWED_UPDATES.contains(&k), "{k}");
        }
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("agy.log");
        let bin = dir.path().join("fake-agy.sh");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\nprintf 'cwd=%s\\n' \"$(pwd)\" >> {log}\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> {log}; done\nprintf '%s\\n' '---' >> {log}\nprintf '{{\"type\":\"init\",\"conversation_id\":\"c-sec\"}}\\n'\nprintf '{{\"type\":\"result\",\"conversation_id\":\"c-sec\",\"result\":\"Hi Eve, Mahdi will get back to you soon.\"}}\\n'\n",
                log = log.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let (st, ctx) = setup_test_ctx_with(&dir, Some(bin)).await;

        // 1. connection from the owner is stored and announced
        let conn: Update = serde_json::from_value(json!({"update_id": 100, "business_connection": {
            "id": "bc1", "user": {"id": OWNER, "is_bot": false, "first_name": "Mahdi"}, "user_chat_id": OWNER,
            "date": 1, "is_enabled": true, "rights": {"can_reply": true, "can_read_messages": true}}}))
        .unwrap();
        dispatch_update(&ctx, conn).await;
        assert!(wait_call(&st, |m, v| m == "sendMessage" && v.to_string().contains("Secretary connected"), 2000).await.is_some());
        let saved: Value = serde_json::from_slice(&std::fs::read(ctx.cfg.state_dir.join("business.json")).unwrap()).unwrap();
        assert_eq!(saved["connections"]["bc1"]["rights"]["can_reply"], json!(true));
        assert_eq!(saved["settings"]["enabled"], json!(false), "secretary must default to OFF");
        assert_eq!(saved["settings"]["mode"], json!("draft"), "default mode must be draft");

        // 2. secretary OFF: no agy run
        dispatch_update(&ctx, biz_msg(101, 7, "hello?")).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!log.exists(), "agy must not run while the secretary is off");

        // 3. ON + draft mode -> draft card to the owner, locked-down agy flags
        handlers_business::state(&ctx).mutate(|d| d.settings.enabled = true);
        dispatch_update(&ctx, biz_msg(102, 7, "Can we talk tomorrow?")).await;
        let card = wait_call(&st, |m, v| m == "sendMessage" && v.to_string().contains("Draft reply"), 5000).await.expect("draft card");
        assert_eq!(card["chat_id"], json!(OWNER));
        assert!(card.get("business_connection_id").is_none(), "draft goes to the owner, not the contact");
        let args = std::fs::read_to_string(&log).unwrap();
        assert!(args.contains("--sandbox") && args.contains("--disable-slash-commands") && args.contains("--settings"));
        assert!(args.contains("command(*)") && args.contains("mcp(*)"));
        assert!(!args.contains("--dangerously-skip-permissions"));
        assert!(!args.contains("--conversation"));
        assert!(args.contains("[telegram-secretary]") && args.contains("Can we talk tomorrow?"));
        assert!(!args.contains("[telegram-bridge]"));
        assert!(args.contains("secretary-ws"), "runs in the empty secretary workspace");
        // no business send happened yet
        assert!(!st.calls.lock().await.iter().any(|(m, v)| m == "sendMessage" && v.get("business_connection_id").is_some()));

        // 4. owner taps Send -> sendMessage with business_connection_id to the contact
        let id = card.to_string().split("biz:send:").nth(1).unwrap()[..8].to_string();
        let cb: Update = serde_json::from_value(json!({"update_id": 103, "callback_query": {
            "id": "cq1", "from": {"id": OWNER, "is_bot": false, "first_name": "Mahdi"},
            "message": {"message_id": 77, "chat": {"id": OWNER, "type": "private"}, "date": 1, "text": "x"},
            "data": format!("biz:send:{id}")}}))
        .unwrap();
        dispatch_update(&ctx, cb).await;
        let sent = wait_call(&st, |m, v| m == "sendMessage" && v["business_connection_id"] == json!("bc1"), 2000).await.expect("business send");
        assert_eq!(sent["chat_id"], json!(7));
        assert_eq!(sent["text"], json!("Hi Eve, Mahdi will get back to you soon."));
        assert_eq!(sent["reply_parameters"]["message_id"], json!(102));

        // 5. owner's own message never triggers a run; auto mode sends directly
        let runs_before = std::fs::read_to_string(&log).unwrap().matches("---").count();
        dispatch_update(&ctx, biz_msg(104, OWNER, "I'm here")).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(std::fs::read_to_string(&log).unwrap().matches("---").count(), runs_before);
        handlers_business::state(&ctx).mutate(|d| d.settings.mode = handlers_business::ReplyMode::Auto);
        st.calls.lock().await.clear();
        dispatch_update(&ctx, biz_msg(105, 7, "Price?")).await;
        let auto = wait_call(&st, |m, v| m == "sendMessage" && v["business_connection_id"] == json!("bc1"), 5000).await.expect("auto send");
        assert_eq!(auto["reply_parameters"]["message_id"], json!(105));
        assert!(wait_call(&st, |m, v| m == "sendMessage" && v.to_string().contains("Auto-replied"), 2000).await.is_some());
        assert!(st.calls.lock().await.iter().any(|(m, v)| m == "sendChatAction" && v["business_connection_id"] == json!("bc1")));
        // mark_read is off by default -> no readBusinessMessage
        assert!(!st.calls.lock().await.iter().any(|(m, _)| m == "readBusinessMessage"));

        // 6. excluded chat -> ignored
        handlers_business::state(&ctx).mutate(|d| d.settings.exclude.push(7));
        let runs_before = std::fs::read_to_string(&log).unwrap().matches("---").count();
        dispatch_update(&ctx, biz_msg(106, 7, "hello again")).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(std::fs::read_to_string(&log).unwrap().matches("---").count(), runs_before);

        // 7. a non-owner connection is ignored (owner told once)
        st.calls.lock().await.clear();
        let foreign: Update = serde_json::from_value(json!({"update_id": 107, "business_connection": {
            "id": "bcX", "user": {"id": 555, "is_bot": false, "first_name": "Stranger"}, "user_chat_id": 555,
            "date": 1, "is_enabled": true, "rights": {"can_reply": true}}}))
        .unwrap();
        dispatch_update(&ctx, foreign.clone()).await;
        dispatch_update(&ctx, foreign).await;
        let n = st.calls.lock().await.iter().filter(|(m, v)| m == "sendMessage" && v.to_string().contains("only works for the owner")).count();
        assert_eq!(n, 1);
        assert!(!handlers_business::state(&ctx).snapshot().connections.contains_key("bcX"));

        // 8. disconnect clears the connection
        let off: Update = serde_json::from_value(json!({"update_id": 108, "business_connection": {
            "id": "bc1", "user": {"id": OWNER, "is_bot": false, "first_name": "Mahdi"}, "user_chat_id": OWNER,
            "date": 1, "is_enabled": false}}))
        .unwrap();
        dispatch_update(&ctx, off).await;
        assert!(handlers_business::state(&ctx).snapshot().connections.is_empty());

        // 9. automations: /auto add + manual run -> isolated agy turn with the automation marker
        dispatch_update(&ctx, mk_text_update(200, OWNER, "/auto add every 1h | report disk usage")).await;
        let items = automations::store(&ctx).of_user(OWNER);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].spec, "every:3600");
        dispatch_update(&ctx, mk_text_update(201, OWNER, "/auto add every 1m | too often")).await;
        assert_eq!(automations::store(&ctx).of_user(OWNER).len(), 1, "below the 5-minute minimum");
        let aid = items[0].id.clone();
        dispatch_update(&ctx, mk_text_update(202, OWNER, &format!("/auto run {aid}"))).await;
        let t = std::time::Instant::now();
        while t.elapsed() < Duration::from_secs(5) && !std::fs::read_to_string(&log).unwrap_or_default().contains("[automation #") {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let args = std::fs::read_to_string(&log).unwrap();
        assert!(args.contains(&format!("[automation #{aid}")) && args.contains("report disk usage"));
        // a non-owner without the permission is refused
        dispatch_update(&ctx, mk_text_update(203, OWNER, "/users")).await;
        assert!(!ctx.has_perm(123, automations::PERM));
    }

    #[tokio::test]
    async fn three_tier_rbac_modular_perms_and_five_language_e2e() {
        let dir = TempDir::new().unwrap();
        let (st, ctx) = setup_test_ctx(&dir).await;

        let locked_uid: i64 = 9_100_000_001;
        let custom_uid: i64 = 9_100_000_002;
        let admin_uid: i64 = 9_100_000_003;

        ctx.acl.set_status(locked_uid, UserStatus::Approved, Some(OWNER), Some(RolePreset::Std)).unwrap();
        ctx.acl.set_status(custom_uid, UserStatus::Approved, Some(OWNER), Some(RolePreset::Std)).unwrap();
        ctx.acl.set_perm(custom_uid, "dashboard_access", Some(true)).unwrap();
        ctx.acl.set_perm(custom_uid, "uncensored", Some(true)).unwrap();
        ctx.acl.set_status(admin_uid, UserStatus::Approved, Some(OWNER), None).unwrap();
        ctx.acl.set_tier(admin_uid, agy_core::acl::RoleTier::Admin, true).unwrap();

        // 1. Locked user sees minimal chat-only card and NO dashboard modules
        st.calls.lock().await.clear();
        dispatch_update(&ctx, mk_text_update(301, locked_uid, "/menu")).await;
        {
            let calls = st.calls.lock().await;
            let sent = calls.iter().find(|(m, _)| m == "sendMessage").expect("locked /menu sendMessage");
            let txt = sent.1["text"].as_str().unwrap_or("");
            assert!(txt.contains("Antigravity Chat"));
            let dumped_mk = sent.1["reply_markup"].to_string();
            assert!(!dumped_mk.contains("\"models:0\""));
            assert!(!dumped_mk.contains("\"webmodel:home\""));
            assert!(!dumped_mk.contains("\"grok:open\""));
            assert!(!dumped_mk.contains("uadm:"));
        }

        // Locked user is blocked from all disabled modules & owner controls
        for cmd in ["/uncensored", "/uagent x", "/grok", "/gagent x", "/mcp", "/skills", "/widget", "/parallel 2", "/auto", "/status", "/settings", "/users", "/accounts", "/secretary"] {
            st.calls.lock().await.clear();
            dispatch_update(&ctx, mk_text_update(302, locked_uid, cmd)).await;
            let calls = st.calls.lock().await;
            assert!(
                calls.iter().any(|(m, _)| m == "sendMessage"),
                "expected refusal notice for locked user on {cmd}"
            );
            assert!(!calls.iter().any(|(m, p)| m == "sendMessage" && p["reply_markup"].to_string().contains("uadm:")));
        }

        // 2. Custom user gets ONLY Dashboard + Uncensored (no Model/Grok/MCP/Skills/Settings/Users)
        st.calls.lock().await.clear();
        dispatch_update(&ctx, mk_text_update(303, custom_uid, "/menu")).await;
        {
            let calls = st.calls.lock().await;
            let sent = calls.iter().find(|(m, _)| m == "sendMessage").expect("custom /menu sendMessage");
            let dumped_mk = sent.1["reply_markup"].to_string();
            assert!(dumped_mk.contains("\"webmodel:home\""));
            assert!(dumped_mk.contains("\"sessions\""));
            assert!(!dumped_mk.contains("\"models:0\""));
            assert!(!dumped_mk.contains("\"grok:open\""));
            assert!(!dumped_mk.contains("\"mcp\""));
            assert!(!dumped_mk.contains("uadm:"));
        }

        // 3. Admin sees AI & Chat on Page 0 and Tools/Proxies/Settings on Page 1, NEVER Owner controls on Page 2
        assert!(ctx.has_perm(admin_uid, "root_access"));
        st.calls.lock().await.clear();
        dispatch_update(&ctx, mk_text_update(304, admin_uid, "/menu")).await;
        {
            let calls = st.calls.lock().await;
            let sent = calls.iter().find(|(m, _)| m == "sendMessage").expect("admin /menu sendMessage");
            let dumped_mk = sent.1["reply_markup"].to_string();
            assert!(dumped_mk.contains("models:0"));
            assert!(dumped_mk.contains("webmodel:home"));
            assert!(dumped_mk.contains("grok:open"));
            assert!(dumped_mk.contains("px:list"));
            assert!(dumped_mk.contains("home:1"));
            assert!(!dumped_mk.contains("home:2"));
            assert!(!dumped_mk.contains("uadm:"));
            assert!(!dumped_mk.contains("acct:list"));
            assert!(!dumped_mk.contains("biz:p"));
        }
        // Admin Page 1 has MCP/Skills/Settings/Proxies, and requesting Page 2 clamps safely without leaking Owner tools
        let admin_p1 = serde_json::to_string(&ctx.main_kb_page(admin_uid, false, 1)).unwrap();
        assert!(admin_p1.contains("\"mcp\""));
        assert!(admin_p1.contains("skills:0"));
        assert!(admin_p1.contains("settings"));
        assert!(admin_p1.contains("px:list"));
        let admin_p2_clamped = serde_json::to_string(&ctx.main_kb_page(admin_uid, false, 2)).unwrap();
        assert!(!admin_p2_clamped.contains("uadm:"));
        assert!(!admin_p2_clamped.contains("acct:list"));
        assert!(!admin_p2_clamped.contains("acct:pol"));
        assert!(!admin_p2_clamped.contains("biz:p"));

        // Owner modularly revokes uncensored & dashboard_access from Admin -> stays Admin, loses those modules
        ctx.acl.set_perm(admin_uid, "uncensored", Some(false)).unwrap();
        ctx.acl.set_perm(admin_uid, "dashboard_access", Some(false)).unwrap();
        assert!(ctx.acl.is_admin(admin_uid));
        assert!(!ctx.has_perm(admin_uid, "uncensored"));
        let admin_mk_revoked = ctx.main_kb(admin_uid, false).inline_keyboard;
        assert_eq!(admin_mk_revoked.len(), 2, "revoking dashboard_access on Admin hides dashboard cleanly");

        // 4. Startup widget_once.json without uid sends strictly to OWNER, never Admin or User
        std::fs::write(
            ctx.cfg.state_dir.join("widget_once.json"),
            serde_json::json!({ "builtins": ["models"] }).to_string(),
        )
        .unwrap();
        let w_res = handlers_widgets::consume_startup_widget_once(&ctx, &[OWNER, admin_uid, locked_uid])
            .await
            .unwrap()
            .unwrap();
        assert!(w_res.get(OWNER.to_string()).is_some());
        assert!(w_res.get(admin_uid.to_string()).is_none());
        assert!(w_res.get(locked_uid.to_string()).is_none());

        // 5. All 5 languages (fa, en, la, zh, ru) update stored lang, UI text, and Telegram commands
        let expected_markers = [
            ("fa", "انتخاب زبان"),
            ("en", "Bot Language"),
            ("la", "Lingua Instrumenti"),
            ("zh", "选择机器人语言"),
            ("ru", "Язык интерфейса"),
        ];
        for (code, title_marker) in expected_markers {
            st.calls.lock().await.clear();
            dispatch_update(&ctx, mk_text_update(310, locked_uid, &format!("/lang {code}"))).await;
            let calls = st.calls.lock().await;
            assert!(
                calls.iter().any(|(m, v)| m == "sendMessage" && v["text"].as_str().unwrap_or("").contains(title_marker)),
                "missing localized /lang card for {code}"
            );
            let cmd_call = calls.iter().find(|(m, _)| m == "setMyCommands").expect("setMyCommands called");
            let cmds = cmd_call.1["commands"].as_array().unwrap();
            assert!(!cmds.is_empty());
            for c in cmds {
                let dlen = c["description"].as_str().unwrap().chars().count();
                assert!((3..=256).contains(&dlen), "bad description len for {code}: {c}");
            }
        }
    }

    #[tokio::test]
    async fn phase3_telegram_antiflood_throttles_burst_and_exempts_stop() {
        let dir = TempDir::new().unwrap();
        let (st, ctx) = setup_test_ctx(&dir).await;
        let user_uid = 88_001i64;
        ctx.acl
            .set_status(user_uid, UserStatus::Approved, Some(OWNER), None)
            .unwrap();

        // Exhaust burst (default tg_user_rl_per_min=30 -> burst=30) via /help calls
        for i in 1..=36i64 {
            dispatch_update(&ctx, mk_text_update(400 + i, user_uid, "/help")).await;
        }
        let calls_after_flood = st.calls.lock().await.clone();
        let rl_notices = calls_after_flood
            .iter()
            .filter(|(m, v)| {
                m == "sendMessage"
                    && v["text"]
                        .as_str()
                        .unwrap_or("")
                        .contains("Rate limit reached")
            })
            .count();
        assert_eq!(
            rl_notices, 1,
            "flood must trigger exactly 1 debounced rate-limit notice (not spam Telegram API)"
        );

        // /stop MUST remain exempt even while the user's bucket is completely drained!
        assert!(is_rate_limit_exempt(&mk_text_update(500, user_uid, "/stop")));
        assert!(!is_rate_limit_exempt(&mk_text_update(501, user_uid, "/help")));
        st.calls.lock().await.clear();
        dispatch_update(&ctx, mk_text_update(502, user_uid, "/stop")).await;
        let stop_calls = st.calls.lock().await.clone();
        assert!(
            stop_calls.iter().any(|(m, _)| m == "sendMessage"),
            "/stop must bypass Telegram anti-flood and still execute"
        );
    }

    #[tokio::test]
    async fn phase4_local_fast_path_answers_zero_token_and_enforces_rbac() {
        let dir = TempDir::new().unwrap();
        let (st, ctx) = setup_test_ctx(&dir).await;
        let std_uid = 88_002i64;
        ctx.acl
            .set_status(std_uid, UserStatus::Approved, Some(OWNER), Some(RolePreset::Std))
            .unwrap();

        // 1. Arithmetic answered locally in Rust (0 AI jobs spawned!)
        st.calls.lock().await.clear();
        dispatch_update(&ctx, mk_text_update(601, OWNER, "(120 + 30) * 4")).await;
        assert!(!ctx.jobs.is_busy(), "fast-path math must not spawn an AI job");
        assert!(
            st.calls
                .lock()
                .await
                .iter()
                .any(|(m, v)| m == "sendMessage" && v["text"].as_str().unwrap_or("").contains("600")),
            "expected local arithmetic answer 600"
        );

        // 2. Owner status query returns pool/proxy telemetry locally
        st.calls.lock().await.clear();
        dispatch_update(&ctx, mk_text_update(602, OWNER, "وضعیت اکانت‌ها")).await;
        assert!(!ctx.jobs.is_busy());
        assert!(
            st.calls
                .lock()
                .await
                .iter()
                .any(|(m, v)| m == "sendMessage" && v["text"].as_str().unwrap_or("").contains("Proxies:")),
            "owner fast-path status should include proxy/account summary"
        );

        // 3. Chat-only user asking "وضعیت اکانت‌ها" must NEVER see host/account/proxy internals
        st.calls.lock().await.clear();
        dispatch_update(&ctx, mk_text_update(603, std_uid, "وضعیت اکانت‌ها")).await;
        let std_txt: String = st
            .calls
            .lock()
            .await
            .iter()
            .filter(|(m, _)| m == "sendMessage")
            .map(|(_, v)| v["text"].as_str().unwrap_or("").to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(std_txt.contains("آنلاین"), "std user should get minimal alive notice: {std_txt}");
        assert!(!std_txt.contains("Proxies:") && !std_txt.contains("Accounts:"), "RBAC violation on fast-path status");
    }

}
