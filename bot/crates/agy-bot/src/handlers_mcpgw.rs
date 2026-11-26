//! Owner-only `/mcpgw` Remote MCP Gateway management panel & `BotGatewayHostBridge`.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Instant;

use agy_core::tg::{CallbackQuery, InlineKeyboardButton, Message};
use agy_ext::engines::{AgyEngine, EngineRequest, EngineRunner};
use agy_mcp_gateway::auth::{render_client_configs, KeyPreset};
use agy_mcp_gateway::config::{GatewayMode, RiskAction, SectionId};
use agy_mcp_gateway::hitl::HitlDecision;
use agy_mcp_gateway::host::{GatewayHostBridge, HostModelRunRequest, HostModelRunResult};
use agy_render::md_cell;
use chrono::Utc;
use serde_json::{json, Value};

use crate::ctx::BotCtx;
use crate::jobs::AwaitingInput;
use crate::local_fast::try_local_fast_reply;
use crate::turn_profile::classify_turn_profile;

/// Bridges `agy-mcp-gateway` into live `BotCtx` without circular `Arc` leaks.
pub struct BotGatewayHostBridge {
    ctx: Weak<BotCtx>,
    owner_id: i64,
}

impl BotGatewayHostBridge {
    pub fn new(ctx: &Arc<BotCtx>) -> Arc<Self> {
        Arc::new(Self {
            ctx: Arc::downgrade(ctx),
            owner_id: ctx.cfg.owner_id,
        })
    }
}

impl GatewayHostBridge for BotGatewayHostBridge {
    fn owner_id(&self) -> i64 {
        self.owner_id
    }

    fn notify_owner_oauth<'a>(
        &'a self,
        req_id: &'a str,
        client_name: &'a str,
        scope: &'a str,
        client_ip: &'a str,
        resource: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let Some(ctx) = self.ctx.upgrade() else {
                return;
            };
            let md = format!(
                "### 🔐 درخواست اتصال OAuth 2.1 به MCP Gateway\n\n\
                | فیلد | مقدار |\n|---|---|\n\
                | کلاینت | `{}` |\n\
                | اسکوپ | `{}` |\n\
                | IP | `{}` |\n\
                | Resource | `{}` |\n\
                | شناسه | `{}` |\n\n\
                سطح دسترسی مورد نظر را انتخاب کنید:",
                md_cell(client_name),
                md_cell(scope),
                md_cell(client_ip),
                md_cell(resource),
                md_cell(req_id),
            );
            let rows = vec![
                vec![
                    ctx.btn("ok", "✅ تأیید (Developer)", Some(&format!("mcpgw:oa:dev:{req_id}")), Some("primary"), None),
                    ctx.btn("ok", "✅ تأیید (Owner)", Some(&format!("mcpgw:oa:own:{req_id}")), None, None),
                ],
                vec![
                    ctx.btn("info", "👁 فقط خواندنی", Some(&format!("mcpgw:oa:ro:{req_id}")), None, None),
                    ctx.btn("stop", "❌ رد اتصال", Some(&format!("mcpgw:oa:no:{req_id}")), Some("danger"), None),
                ],
            ];
            let _ = ctx
                .render
                .edit_or_send_rich(self.owner_id, None, &md, Some(BotCtx::kb(rows)))
                .await;
        })
    }

    fn notify_owner_hitl<'a>(
        &'a self,
        req_id: &'a str,
        principal_label: &'a str,
        tool_name: &'a str,
        args_preview: &'a str,
        client_ip: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let Some(ctx) = self.ctx.upgrade() else {
                return;
            };
            let md = format!(
                "### ⚠️ تأیید اجرای ابزار پرریسک MCP (HITL)\n\n\
                | فیلد | مقدار |\n|---|---|\n\
                | کلاینت | `{}` |\n\
                | ابزار | `{}` |\n\
                | IP | `{}` |\n\n\
                ```json\n{}\n```",
                md_cell(principal_label),
                md_cell(tool_name),
                md_cell(client_ip),
                args_preview.replace("```", "'''"),
            );
            let rows = vec![vec![
                ctx.btn("ok", "✅ یک‌بار", Some(&format!("mcpgw:hl:1:{req_id}")), Some("primary"), None),
                ctx.btn("ok", "✅ این سشن", Some(&format!("mcpgw:hl:s:{req_id}")), None, None),
                ctx.btn("stop", "❌ رد", Some(&format!("mcpgw:hl:n:{req_id}")), Some("danger"), None),
            ]];
            let _ = ctx
                .render
                .edit_or_send_rich(self.owner_id, None, &md, Some(BotCtx::kb(rows)))
                .await;
        })
    }

    fn notify_owner_security_alert<'a>(
        &'a self,
        title: &'a str,
        detail: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let Some(ctx) = self.ctx.upgrade() else {
                return;
            };
            let md = format!("### 🚨 {}\n\n{}", md_cell(title), detail);
            let rows = vec![vec![ctx.btn("mcp", "🌐 پنل MCP Gateway", Some("mcpgw"), Some("primary"), None)]];
            let _ = ctx
                .render
                .edit_or_send_rich(self.owner_id, None, &md, Some(BotCtx::kb(rows)))
                .await;
        })
    }

    fn list_antigravity_models(&self) -> Value {
        let Some(ctx) = self.ctx.upgrade() else {
            return json!([]);
        };
        let models = ctx.get_models_cache();
        Value::Array(
            models
                .into_iter()
                .map(|m| json!({"id": m.id, "name": m.name}))
                .collect(),
        )
    }

    fn pool_health_summary(&self) -> Value {
        let Some(ctx) = self.ctx.upgrade() else {
            return json!({"accounts": []});
        };
        let now = Utc::now().timestamp();
        let mut slots = Vec::new();
        let mut healthy = 0usize;
        if let Some(store) = ctx.jobs.accounts() {
            for (idx, acc) in store.list().into_iter().enumerate() {
                let avail = acc.available_at(now);
                if avail {
                    healthy += 1;
                }
                // Strictly opaque slot IDs: NEVER expose email, home path, or OAuth tokens!
                slots.push(json!({
                    "slot": format!("slot-{}", idx + 1),
                    "enabled": acc.enabled,
                    "available": avail,
                    "has_sticky_proxy": acc.proxy_id.is_some(),
                    "status": format!("{:?}", acc.health.status)
                }));
            }
        }
        json!({
            "total_slots": slots.len(),
            "healthy_slots": healthy,
            "active_global_jobs": ctx.jobs.active_global_jobs(),
            "max_global_jobs": ctx.jobs.max_global_jobs(),
            "slots": slots
        })
    }

    fn current_bot_state(&self) -> Value {
        let Some(ctx) = self.ctx.upgrade() else {
            return json!({});
        };
        let u = ctx.store.get_user(self.owner_id);
        let unc = crate::handlers_uncensored::uncensored_agent_mode(&u);
        let grok = crate::handlers_grok::is_grok_active(&u);
        let ts = crate::handlers_uncensored::uncensored_three_stage_mode(&u);
        json!({
            "model": u.model,
            "effort": u.effort,
            "mode": u.mode,
            "conversation_id": u.conversation_id,
            "grok_active": grok,
            "uncensored_agent_mode": unc,
            "three_stage_mode": format!("{ts:?}"),
            "cwd": u.cwd
        })
    }

    fn switch_bot_model(
        &self,
        engine: Option<&str>,
        model: Option<&str>,
        effort: Option<&str>,
        three_stage: Option<&str>,
    ) -> Result<Value, String> {
        let Some(ctx) = self.ctx.upgrade() else {
            return Err("Bot runtime shutting down".to_string());
        };
        ctx.store
            .update_user(self.owner_id, |u| {
                if let Some(m) = model.map(str::trim).filter(|s| !s.is_empty()) {
                    u.model = Some(m.to_string());
                }
                if let Some(ef) = effort.map(str::trim).filter(|s| !s.is_empty()) {
                    u.effort = Some(ef.to_ascii_lowercase());
                }
                if let Some(eng) = engine.map(str::trim).filter(|s| !s.is_empty()) {
                    match eng.to_ascii_lowercase().as_str() {
                        "grok" => {
                            if u.model
                                .as_deref()
                                .is_none_or(|m| !agy_ext::grok_oauth::is_grok_model(m))
                            {
                                u.model = Some(format!(
                                    "grok:{}",
                                    agy_ext::grok_oauth::DEFAULT_GROK_MODEL
                                ));
                            }
                        }
                        "uncensored" | "venice" => {
                            if u.model
                                .as_deref()
                                .is_none_or(|m| !agy_ext::uncensored::is_uncensored_model(m))
                            {
                                u.model = Some(format!(
                                    "uncensored:{}",
                                    agy_ext::uncensored::DEFAULT_UNCENSORED_MODEL
                                ));
                            }
                        }
                        "agy" | "antigravity" => {
                            if u.model.as_deref().is_some_and(|m| {
                                agy_ext::grok_oauth::is_grok_model(m)
                                    || agy_ext::uncensored::is_uncensored_model(m)
                            }) {
                                u.model = None;
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(ts) = three_stage.map(str::trim).filter(|s| !s.is_empty()) {
                    let norm = match ts.to_ascii_lowercase().as_str() {
                        "on" | "always" => "always",
                        "off" => "off",
                        _ => "auto",
                    };
                    u.extra
                        .insert("uncensored_3stage".to_string(), json!(norm));
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(self.current_bot_state())
    }

    fn list_sessions(&self, limit: usize) -> Value {
        let Some(ctx) = self.ctx.upgrade() else {
            return json!({"active": null, "history": []});
        };
        let u = ctx.store.get_user(self.owner_id);
        let hist: Vec<Value> = u
            .history
            .into_iter()
            .take(limit)
            .map(|h| json!({"id": h.id, "title": h.title, "ts": h.ts}))
            .collect();
        json!({
            "active_conversation_id": u.conversation_id,
            "history": hist
        })
    }

    fn select_session(
        &self,
        conversation_id: Option<&str>,
        new_session: bool,
    ) -> Result<Value, String> {
        let Some(ctx) = self.ctx.upgrade() else {
            return Err("Bot runtime shutting down".to_string());
        };
        ctx.store
            .update_user(self.owner_id, |u| {
                if new_session {
                    u.conversation_id = None;
                } else if let Some(cid) = conversation_id.map(str::trim).filter(|s| !s.is_empty()) {
                    u.push_session(cid, "MCP resumed session", Utc::now().timestamp());
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(self.list_sessions(10))
    }

    fn classify_turn(&self, text: &str, has_attachments: bool) -> &'static str {
        classify_turn_profile(text, has_attachments, false).as_str()
    }

    fn try_local_fast(&self, text: &str) -> Option<String> {
        let ctx = self.ctx.upgrade()?;
        try_local_fast_reply(&ctx, self.owner_id, text).map(|r| r.html)
    }

    fn run_antigravity_turn<'a>(
        &'a self,
        req: HostModelRunRequest,
    ) -> Pin<Box<dyn Future<Output = HostModelRunResult> + Send + 'a>> {
        Box::pin(async move {
            let t0 = Instant::now();
            let Some(ctx) = self.ctx.upgrade() else {
                return HostModelRunResult {
                    ok: false,
                    engine: "agy".to_string(),
                    model: req.model.unwrap_or_default(),
                    text: String::new(),
                    conversation_id: req.conversation_id,
                    duration_ms: 0,
                    error: Some("Bot runtime unavailable".to_string()),
                };
            };
            let mut env_over = std::collections::BTreeMap::new();
            let mut proxy_url = None;
            let now = Utc::now().timestamp();
            if let Some(acct_store) = ctx.jobs.accounts() {
                if let Some(acc) = acct_store.pick(self.owner_id, &HashSet::new()) {
                    env_over.insert("HOME".to_string(), acc.home.to_string_lossy().into_owned());
                    let resolved = ctx.proxies.resolve_at(acc.proxy_id.as_deref(), now);
                    if resolved.is_blocked() {
                        return HostModelRunResult {
                            ok: false,
                            engine: "agy".to_string(),
                            model: req.model.unwrap_or_default(),
                            text: String::new(),
                            conversation_id: req.conversation_id,
                            duration_ms: t0.elapsed().as_millis() as u64,
                            error: Some("Account sticky proxy is unavailable (fail-closed anti-ban protection)".to_string()),
                        };
                    }
                    proxy_url = resolved.url().map(str::to_string);
                }
            }
            if let Some(p) = proxy_url {
                env_over.insert("HTTP_PROXY".to_string(), p.clone());
                env_over.insert("HTTPS_PROXY".to_string(), p);
            }
            let agy_bin_str = ctx.cfg.agy_bin.to_string_lossy().into_owned();
            let engine = AgyEngine::new(
                Some(agy_bin_str.clone()),
                Some(ctx.cfg.agy_workspace.clone()),
            );
            let eng_req = EngineRequest {
                prompt: req.prompt,
                bin: Some(agy_bin_str),
                cwd: Some(ctx.cfg.agy_workspace.clone()),
                model: req.model.clone(),
                effort: req.effort.clone(),
                mode: None,
                conversation_id: req.conversation_id.clone(),
                skip_permissions: false,
                timeout_secs: 240,
                agent: None,
                add_dirs: Vec::new(),
                env_overrides: env_over,
                hard_grace_secs: None,
                extra_flags: Vec::new(),
                guard: agy_ext::engines::AgyGuardConfig::default(),
            };

            match engine.run(eng_req, None).await {
                Ok(res) => HostModelRunResult {
                    ok: res.error.is_none(),
                    engine: "agy".to_string(),
                    model: req.model.unwrap_or_else(|| "default".to_string()),
                    text: res.text,
                    conversation_id: res.conversation_id,
                    duration_ms: t0.elapsed().as_millis() as u64,
                    error: res.error.map(|e| e.to_string()),
                },
                Err(e) => HostModelRunResult {
                    ok: false,
                    engine: "agy".to_string(),
                    model: req.model.unwrap_or_default(),
                    text: String::new(),
                    conversation_id: req.conversation_id,
                    duration_ms: t0.elapsed().as_millis() as u64,
                    error: Some(e.to_string()),
                },
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Owner-Only Telegram `/mcpgw` Management Panel
// ---------------------------------------------------------------------------

async fn send_card(
    ctx: &BotCtx,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    md: &str,
    rows: Vec<Vec<InlineKeyboardButton>>,
) {
    let msg_id = cq.and_then(|c| c.message.as_ref()).map(|m| m.message_id);
    let mk = (!rows.is_empty()).then(|| BotCtx::kb(rows));
    let _ = ctx.render.edit_or_send_rich(chat_id, msg_id, md, mk).await;
}

/// Handle `/mcpgw` command (strictly Owner-only).
pub async fn cmd_mcpgw(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg.from_user.as_ref().map(|u| u.id) else {
        return;
    };
    if !ctx.is_owner(uid) {
        let _ = ctx
            .render
            .send_html_simple(msg.chat.id, "⛔ این پنل فقط مخصوص <b>Owner</b> است.", None)
            .await;
        return;
    }
    let trimmed = arg.trim();
    if trimmed.eq_ignore_ascii_case("kill") {
        if let Some(gw) = ctx.mcp_gw() {
            let _ = gw.cfg_store.update(|c| c.mode = GatewayMode::Disabled);
            let killed = gw.tasks.cancel_all();
            let _ = ctx
                .render
                .send_html_simple(
                    msg.chat.id,
                    &format!("🔴 <b>Kill Switch فعال شد</b> ({killed} تسک در حال اجرا متوقف شد)."),
                    None,
                )
                .await;
        }
        return;
    }
    show_mcpgw_home(ctx, None, msg.chat.id).await;
}

pub async fn show_mcpgw_home(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64) {
    let Some(gw) = ctx.mcp_gw() else {
        send_card(ctx, cq, chat_id, "⚠️ MCP Gateway هنوز راه‌اندازی نشده است.", vec![]).await;
        return;
    };
    let cfg = gw.cfg_store.snapshot();
    let keys = gw.keys.list();
    let active_keys = keys.iter().filter(|k| k.enabled).count();
    let oauth_tokens = gw.oauth.list_active_tokens().len();
    let quarantined = gw.pins.list_quarantined().len();
    let temp_bans = gw.guard.active_temp_bans().len();
    let enabled_secs = SectionId::ALL
        .iter()
        .filter(|&&s| cfg.is_section_enabled(s))
        .count();
    let total_req = gw
        .guard
        .total_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    let rl_blk = gw
        .guard
        .blocked_rate_limit
        .load(std::sync::atomic::Ordering::Relaxed);
    let auth_blk = gw
        .guard
        .blocked_auth
        .load(std::sync::atomic::Ordering::Relaxed);

    let md = format!(
        "### 🌐 پنل مدیریت AGY Remote MCP Gateway\n\n\
        | شاخص | مقدار |\n|---|---|\n\
        | وضعیت | **{}** (پورت `127.0.0.1:{}`) |\n\
        | دامنه مستقیم | `https://{}/mcp` |\n\
        | دامنه کلادفلر | `https://{}/mcp` |\n\
        | بخش‌های فعال | `{enabled_secs}/10` ({} ابزار) |\n\
        | کلیدها / OAuth | `{active_keys}/{}` کلید · `{oauth_tokens}` توکن OAuth |\n\
        | سشن / تسک زنده | `{}` سشن · `{}` تسک · `{}` اسلات AI آزاد |\n\
        | امنیت و DDoS | `{total_req}` req · `{rl_blk}` 429 · `{auth_blk}` 401 · `{temp_bans}` بن موقت · `{quarantined}` قرنطینه |\n\
        | سقف‌ها | IP `{}`/m · Key `{}`/m · AI همزمان `{}` |",
        cfg.mode.fa_label(),
        cfg.bind_port,
        md_cell(&cfg.primary_domain),
        md_cell(&cfg.cdn_domain),
        gw.runtime.catalog.len(),
        keys.len(),
        gw.runtime.active_session_count(),
        gw.tasks.running_count(),
        gw.policy.active_ai_slots_available(),
        cfg.limits.ip_rpm,
        cfg.limits.key_rpm,
        cfg.limits.max_mcp_ai_concurrency,
    );

    let rows = vec![
        vec![
            ctx.btn("ok", "🟢 فعال", Some("mcpgw:mode:active"), (cfg.mode == GatewayMode::Active).then_some("primary"), None),
            ctx.btn("info", "🟡 فقط خواندنی", Some("mcpgw:mode:ro"), (cfg.mode == GatewayMode::ReadOnly).then_some("primary"), None),
            ctx.btn("stop", "🔴 Kill", Some("mcpgw:mode:off"), Some("danger"), None),
        ],
        vec![
            ctx.btn("key", "🔑 کلیدها و کانفیگ‌ها", Some("mcpgw:keys"), Some("primary"), None),
            ctx.btn("mcp", "🧩 ۱۰ بخش ابزار", Some("mcpgw:secs"), None, None),
        ],
        vec![
            ctx.btn("shield", "🛡 امنیت، OAuth و سقف‌ها", Some("mcpgw:sec"), None, None),
            ctx.btn("doc", "📜 لاگ ممیزی (Audit)", Some("mcpgw:audit"), None, None),
        ],
        vec![
            ctx.btn("refresh", "بروزرسانی", Some("mcpgw"), None, None),
            ctx.btn("menu", "منوی MCP", Some("mcp"), None, None),
        ],
    ];
    send_card(ctx, cq, chat_id, &md, rows).await;
}

async fn show_keys_panel(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64) {
    let Some(gw) = ctx.mcp_gw() else {
        return;
    };
    let keys = gw.keys.list();
    let mut lines = vec![
        "### 🔑 مدیریت API Keyها و کانفیگ کلاینت‌ها".to_string(),
        String::new(),
    ];
    if keys.is_empty() {
        lines.push("> هنوز کلیدی ساخته نشده است. از دکمه‌های زیر یک کلید بسازید:".to_string());
    } else {
        lines.push("| نام | سطح | تماس | وضعیت |".to_string());
        lines.push("|---|---|---|---|".to_string());
        for k in keys.iter().take(15) {
            let st = if k.enabled { "✓" } else { "○" };
            lines.push(format!(
                "| `{}` | `{}` | `{}` | {st} |",
                md_cell(&k.label),
                k.preset.as_str(),
                k.total_calls
            ));
        }
    }
    let mut rows = vec![
        vec![
            ctx.btn("plus", "➕ Owner Key", Some("mcpgw:knew:owner"), Some("primary"), None),
            ctx.btn("plus", "➕ Dev Key", Some("mcpgw:knew:developer"), None, None),
        ],
        vec![
            ctx.btn("plus", "➕ Research Key", Some("mcpgw:knew:research"), None, None),
            ctx.btn("plus", "➕ Read-Only", Some("mcpgw:knew:read_only"), None, None),
        ],
    ];
    let kbtns: Vec<InlineKeyboardButton> = keys
        .iter()
        .take(10)
        .map(|k| {
            let mark = if k.enabled { "✓" } else { "○" };
            ctx.btn(
                "",
                &format!("{mark} {}", k.label.chars().take(16).collect::<String>()),
                Some(&format!("mcpgw:kv:{}", k.id)),
                None,
                None,
            )
        })
        .collect();
    for pair in kbtns.chunks(2) {
        rows.push(pair.to_vec());
    }
    rows.push(vec![
        ctx.btn("doc", "📋 نمونه کانفیگ کلاینت‌ها", Some("mcpgw:snip"), None, None),
        ctx.btn("back", "بازگشت", Some("mcpgw"), None, None),
    ]);
    send_card(ctx, cq, chat_id, &lines.join("\n"), rows).await;
}

async fn show_sections_panel(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64) {
    let Some(gw) = ctx.mcp_gw() else {
        return;
    };
    let cfg = gw.cfg_store.snapshot();
    let mut lines = vec![
        "### 🧩 مدیریت ۱۰ بخش ماژولار MCP".to_string(),
        format!("> هر بخش هم از `/mcp` (Smart Hub) و هم از مسیر `/mcp/s/<section>` در دسترس است."),
        String::new(),
        "| بخش | مسیر | وضعیت |".to_string(),
        "|---|---|---|".to_string(),
    ];
    let mut btns = Vec::new();
    for s in SectionId::ALL {
        let on = cfg.is_section_enabled(s);
        let mark = if on { "✓ فعال" } else { "○ خاموش" };
        lines.push(format!("| {} | `/mcp/s/{}` | {mark} |", s.title(), s.slug()));
        btns.push(ctx.btn(
            "",
            &format!("{} {}", if on { "✓" } else { "○" }, s.slug()),
            Some(&format!("mcpgw:stog:{}", s.slug())),
            None,
            None,
        ));
    }
    let mut rows: Vec<Vec<InlineKeyboardButton>> = btns.chunks(3).map(|c| c.to_vec()).collect();
    rows.push(vec![ctx.btn("back", "بازگشت", Some("mcpgw"), None, None)]);
    send_card(ctx, cq, chat_id, &lines.join("\n"), rows).await;
}

async fn show_security_panel(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64) {
    let Some(gw) = ctx.mcp_gw() else {
        return;
    };
    let cfg = gw.cfg_store.snapshot();
    let bans = gw.guard.active_temp_bans();
    let quar = gw.pins.list_quarantined();
    let oauth_cnt = gw.oauth.list_active_tokens().len();

    let md = format!(
        "### 🛡 امنیت، OAuth 2.1 و Anti-Ban\n\n\
        | تنظیم | وضعیت |\n|---|---|\n\
        | Legacy `/sse` | `{}` |\n\
        | OAuth 2.1 + DCR | `{}` (`{oauth_cnt}` توکن فعال) |\n\
        | Manifest Pinning | `{}` (`{}` قرنطینه) |\n\
        | HITL (غیر-Owner) | `{}` |\n\
        | HITL (Owner) | `{}` |\n\
        | سقف AI همزمان MCP | `{}` |\n\
        | سقف IP / Key RPM | `{}` / `{}` |\n\
        | IPهای بن موقت | `{}` |",
        cfg.legacy_sse_enabled,
        cfg.oauth_enabled,
        cfg.manifest_pinning_enabled,
        quar.len(),
        cfg.non_owner_high_risk_action.as_str(),
        cfg.owner_high_risk_action.as_str(),
        cfg.limits.max_mcp_ai_concurrency,
        cfg.limits.ip_rpm,
        cfg.limits.key_rpm,
        bans.len(),
    );

    let rows = vec![
        vec![
            ctx.btn("", &format!("SSE: {}", if cfg.legacy_sse_enabled { "ON" } else { "OFF" }), Some("mcpgw:t:sse"), None, None),
            ctx.btn("", &format!("OAuth: {}", if cfg.oauth_enabled { "ON" } else { "OFF" }), Some("mcpgw:t:oauth"), None, None),
            ctx.btn("", &format!("Pins: {}", if cfg.manifest_pinning_enabled { "ON" } else { "OFF" }), Some("mcpgw:t:pin"), None, None),
        ],
        vec![
            ctx.btn("", &format!("HITL کلاینت: {}", cfg.non_owner_high_risk_action.as_str()), Some("mcpgw:t:hitl"), None, None),
            ctx.btn("", &format!("AI همزمان: {}", cfg.limits.max_mcp_ai_concurrency), Some("mcpgw:t:aicap"), None, None),
        ],
        vec![
            ctx.btn("ok", "تأیید Pinهای قرنطینه", Some("mcpgw:pin:ok"), None, None),
            ctx.btn("stop", "ابطال همه OAuthها", Some("mcpgw:oa:revall"), Some("danger"), None),
        ],
        vec![
            ctx.btn("edit", "⚙️ تغییر سقف IP/Key RPM", Some("mcpgw:setrl"), None, None),
            ctx.btn("back", "بازگشت", Some("mcpgw"), None, None),
        ],
    ];
    send_card(ctx, cq, chat_id, &md, rows).await;
}

async fn show_audit_panel(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64) {
    let Some(gw) = ctx.mcp_gw() else {
        return;
    };
    let entries = gw.audit.recent(15);
    let mut lines = vec!["### 📜 ۱۵ فراخوانی اخیر MCP Gateway".to_string(), String::new()];
    if entries.is_empty() {
        lines.push("> هنوز فراخوانی‌ای ثبت نشده است.".to_string());
    } else {
        lines.push("| کلاینت | ابزار | وضعیت | ms |".to_string());
        lines.push("|---|---|---|---|".to_string());
        for e in entries {
            lines.push(format!(
                "| `{}` | `{}` | `{}` | `{}` |",
                md_cell(&e.principal),
                md_cell(&e.tool),
                md_cell(&e.status),
                e.duration_ms
            ));
        }
    }
    let rows = vec![vec![
        ctx.btn("refresh", "بروزرسانی", Some("mcpgw:audit"), None, None),
        ctx.btn("back", "بازگشت", Some("mcpgw"), None, None),
    ]];
    send_card(ctx, cq, chat_id, &lines.join("\n"), rows).await;
}

/// Handle all `mcpgw` / `mcpgw:*` Telegram callback buttons (strictly Owner-only).
pub async fn handle_mcpgw_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    if data != "mcpgw" && !data.starts_with("mcpgw:") {
        return false;
    }
    if !ctx.is_owner(uid) {
        ctx.ack(&cq.id, Some("⛔ فقط Owner"), true).await;
        return true;
    }
    let Some(gw) = ctx.mcp_gw() else {
        ctx.ack(&cq.id, Some("Gateway unavailable"), true).await;
        return true;
    };

    if data == "mcpgw" {
        ctx.ack(&cq.id, None, false).await;
        show_mcpgw_home(ctx, Some(cq), chat_id).await;
        return true;
    }

    let rest = data.strip_prefix("mcpgw:").unwrap_or("");
    let parts: Vec<&str> = rest.split(':').collect();
    match parts.as_slice() {
        ["mode", m] => {
            let new_mode = match *m {
                "active" => GatewayMode::Active,
                "ro" => GatewayMode::ReadOnly,
                _ => GatewayMode::Disabled,
            };
            let _ = gw.cfg_store.update(|c| c.mode = new_mode);
            if new_mode == GatewayMode::Disabled {
                let _ = gw.tasks.cancel_all();
            }
            ctx.ack(&cq.id, Some(new_mode.fa_label()), false).await;
            show_mcpgw_home(ctx, Some(cq), chat_id).await;
        }
        ["keys"] => {
            ctx.ack(&cq.id, None, false).await;
            show_keys_panel(ctx, Some(cq), chat_id).await;
        }
        ["secs"] => {
            ctx.ack(&cq.id, None, false).await;
            show_sections_panel(ctx, Some(cq), chat_id).await;
        }
        ["sec"] => {
            ctx.ack(&cq.id, None, false).await;
            show_security_panel(ctx, Some(cq), chat_id).await;
        }
        ["audit"] => {
            ctx.ack(&cq.id, None, false).await;
            show_audit_panel(ctx, Some(cq), chat_id).await;
        }
        ["knew", preset_s] => {
            let preset = KeyPreset::parse(preset_s).unwrap_or(KeyPreset::Developer);
            let label = format!("{}-{}", preset.as_str(), Utc::now().format("%m%d-%H%M"));
            match gw.keys.create_key(label, preset, None) {
                Ok((rec, raw)) => {
                    let cfg = gw.cfg_store.snapshot();
                    let snips = render_client_configs(&cfg.primary_domain, &cfg.cdn_domain, "/mcp", &raw);
                    ctx.ack(&cq.id, Some("کلید ساخته شد!"), false).await;
                    let md = format!(
                        "### 🔑 کلید جدید ساخته شد (فقط همین یک‌بار نمایش داده می‌شود!)\n\n\
                        - نام: `{}` | سطح: `{}`\n\
                        - کلید: `{raw}`\n\n\
                        **VS Code (`mcp.json`):**\n```json\n{}\n```\n\n\
                        **Claude Code CLI:**\n```bash\n{}\n```\n\n\
                        **Grok API (`tools[]`):**\n```json\n{}\n```\n\n\
                        **Gemini CLI (`settings.json`):**\n```json\n{}\n```",
                        md_cell(&rec.label),
                        rec.preset.as_str(),
                        snips.vscode_mcp_json,
                        snips.claude_code_cmd,
                        snips.grok_api_json,
                        snips.gemini_cli_json,
                    );
                    let rows = vec![vec![ctx.btn("back", "بازگشت به کلیدها", Some("mcpgw:keys"), None, None)]];
                    let _ = ctx
                        .render
                        .edit_or_send_rich(chat_id, None, &md, Some(BotCtx::kb(rows)))
                        .await;
                }
                Err(e) => {
                    ctx.ack(&cq.id, Some(&format!("خطا: {e}")), true).await;
                }
            }
        }
        ["kv", kid] => {
            ctx.ack(&cq.id, None, false).await;
            if let Some(rec) = gw.keys.get(kid) {
                let secs: Vec<&str> = rec.sections.iter().map(|s| s.slug()).collect();
                let md = format!(
                    "### 🔑 جزئیات کلید `{}`\n\n\
                    | فیلد | مقدار |\n|---|---|\n\
                    | شناسه | `{}` |\n\
                    | سطح | `{}` |\n\
                    | وضعیت | {} |\n\
                    | تماس‌ها | `{}` |\n\
                    | بخش‌ها | `{}` |",
                    md_cell(&rec.label),
                    md_cell(&rec.key_hint),
                    rec.preset.as_str(),
                    if rec.enabled { "✓ فعال" } else { "○ غیرفعال" },
                    rec.total_calls,
                    secs.join(", ")
                );
                let rows = vec![
                    vec![
                        ctx.btn(
                            "",
                            if rec.enabled { "⏸ تعلیق" } else { "▶ فعال‌سازی" },
                            Some(&format!("mcpgw:ktog:{kid}")),
                            None,
                            None,
                        ),
                        ctx.btn("refresh", "🔄 چرخش سکرت", Some(&format!("mcpgw:krot:{kid}")), None, None),
                    ],
                    vec![
                        ctx.btn("stop", "🗑 ابطال دائمی", Some(&format!("mcpgw:kdel:{kid}")), Some("danger"), None),
                        ctx.btn("back", "بازگشت", Some("mcpgw:keys"), None, None),
                    ],
                ];
                send_card(ctx, Some(cq), chat_id, &md, rows).await;
            }
        }
        ["ktog", kid] => {
            if let Some(rec) = gw.keys.get(kid) {
                let _ = gw.keys.set_enabled(kid, !rec.enabled);
            }
            ctx.ack(&cq.id, Some("تغییر وضعیت انجام شد"), false).await;
            show_keys_panel(ctx, Some(cq), chat_id).await;
        }
        ["krot", kid] => {
            match gw.keys.rotate(kid) {
                Ok(Some((rec, new_raw))) => {
                    ctx.ack(&cq.id, Some("کلید چرخانده شد"), false).await;
                    let md = format!(
                        "### 🔄 کلید `{}` چرخانده شد\n\nکلید جدید (قبلی باطل شد):\n`{new_raw}`",
                        md_cell(&rec.label)
                    );
                    let _ = ctx.render.edit_or_send_rich(chat_id, None, &md, None).await;
                }
                _ => ctx.ack(&cq.id, Some("کلید پیدا نشد"), true).await,
            }
        }
        ["kdel", kid] => {
            let _ = gw.keys.revoke(kid);
            ctx.ack(&cq.id, Some("کلید باطل و حذف شد"), false).await;
            show_keys_panel(ctx, Some(cq), chat_id).await;
        }
        ["snip"] => {
            ctx.ack(&cq.id, None, false).await;
            let cfg = gw.cfg_store.snapshot();
            let snips = render_client_configs(&cfg.primary_domain, &cfg.cdn_domain, "/mcp", "<YOUR_AGYMCP_KEY>");
            let md = format!(
                "### 📋 راهنمای اتصال جهانی (VS Code · Claude · Gemini · Grok · Cursor)\n\n\
                - **Claude.ai Custom Connector (OAuth 2.1):** `{}`\n\
                - **اندپوینت‌های بخش‌به‌بخش:** `https://{}/mcp/s/<section>` (`openhands`, `search`, `skillhub`, `memory`, `codeintel`, `models`, `sessions`, `optimizer`, `federation`, `browser`)\n\n\
                **VS Code (`mcp.json`):**\n```json\n{}\n```\n\n\
                **Grok CLI (`~/.grok/config.toml`):**\n```toml\n{}\n```\n\n\
                **Gemini CLI:**\n```json\n{}\n```",
                snips.claude_web_url,
                cfg.primary_domain,
                snips.vscode_mcp_json,
                snips.grok_cli_toml,
                snips.gemini_cli_json,
            );
            let rows = vec![vec![ctx.btn("back", "بازگشت", Some("mcpgw:keys"), None, None)]];
            send_card(ctx, Some(cq), chat_id, &md, rows).await;
        }
        ["stog", slug] => {
            if let Some(sec) = SectionId::parse_slug(slug) {
                let _ = gw.cfg_store.update(|c| {
                    let cur = c.is_section_enabled(sec);
                    c.sections_enabled.insert(sec, !cur);
                });
            }
            ctx.ack(&cq.id, Some("بخش تغییر کرد"), false).await;
            show_sections_panel(ctx, Some(cq), chat_id).await;
        }
        ["t", flag] => {
            let _ = gw.cfg_store.update(|c| match *flag {
                "sse" => c.legacy_sse_enabled = !c.legacy_sse_enabled,
                "oauth" => c.oauth_enabled = !c.oauth_enabled,
                "pin" => c.manifest_pinning_enabled = !c.manifest_pinning_enabled,
                "hitl" => {
                    c.non_owner_high_risk_action = match c.non_owner_high_risk_action {
                        RiskAction::AskTelegram => RiskAction::Deny,
                        RiskAction::Deny => RiskAction::Allow,
                        RiskAction::Allow => RiskAction::AskTelegram,
                    };
                }
                "aicap" => {
                    c.limits.max_mcp_ai_concurrency = match c.limits.max_mcp_ai_concurrency {
                        0 => 1,
                        1 => 2,
                        2 => 4,
                        _ => 0,
                    };
                }
                _ => {}
            });
            ctx.ack(&cq.id, Some("ذخیره شد"), false).await;
            show_security_panel(ctx, Some(cq), chat_id).await;
        }
        ["pin", "ok"] => {
            let n = gw.pins.approve_drifted(None).unwrap_or(0);
            ctx.ack(&cq.id, Some(&format!("{n} مورد تأیید شد")), false).await;
            show_security_panel(ctx, Some(cq), chat_id).await;
        }
        ["oa", "revall"] => {
            let n = gw.oauth.revoke_all_tokens();
            ctx.ack(&cq.id, Some(&format!("{n} توکن OAuth باطل شد")), false).await;
            show_security_panel(ctx, Some(cq), chat_id).await;
        }
        ["oa", level, req_id] => {
            let (approve, preset, label) = match *level {
                "own" => (true, KeyPreset::Owner, "✅ تأیید شد (Owner)"),
                "dev" => (true, KeyPreset::Developer, "✅ تأیید شد (Developer)"),
                "ro" => (true, KeyPreset::ReadOnly, "✅ تأیید شد (Read-Only)"),
                _ => (false, KeyPreset::ReadOnly, "❌ رد شد"),
            };
            let ok = gw.oauth.resolve_consent(req_id, approve, preset);
            ctx.ack(&cq.id, Some(if ok { label } else { "منقضی شده" }), false).await;
            let md = format!("### 🔐 OAuth 2.1 (`{}`)\n\nوضعیت: **{}**", md_cell(req_id), if ok { label } else { "منقضی شده" });
            send_card(ctx, Some(cq), chat_id, &md, vec![]).await;
        }
        ["hl", dec, req_id] => {
            let (d, lbl) = match *dec {
                "1" => (HitlDecision::AllowOnce, "✅ یک‌بار تأیید شد"),
                "s" => (HitlDecision::AllowSession, "✅ برای این سشن تأیید شد"),
                _ => (HitlDecision::Deny, "❌ رد شد"),
            };
            let ok = gw.hitl.resolve(req_id, d);
            ctx.ack(&cq.id, Some(if ok { lbl } else { "منقضی شده" }), false).await;
            let md = format!("### ⚠️ HITL (`{}`)\n\nنتیجه: **{}**", md_cell(req_id), if ok { lbl } else { "منقضی شده" });
            send_card(ctx, Some(cq), chat_id, &md, vec![]).await;
        }
        ["setrl"] => {
            ctx.jobs.set_awaiting(uid, AwaitingInput::new("mcpgw_setrl", json!({})));
            ctx.ack(&cq.id, None, false).await;
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    "⚙️ دو عدد با فاصله بفرستید: <code>IP_RPM KEY_RPM</code> (مثلاً <code>120 90</code>؛ برای لغو /cancel).",
                    None,
                )
                .await;
        }
        _ => {
            ctx.ack(&cq.id, None, false).await;
        }
    }
    true
}

/// Handle text input when Owner is setting rate limits in `/mcpgw`.
pub async fn handle_mcpgw_awaiting_text(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    inp: &AwaitingInput,
    raw_text: &str,
) -> bool {
    if inp.kind != "mcpgw_setrl" {
        return false;
    }
    if !ctx.is_owner(uid) {
        return true;
    }
    let nums: Vec<u32> = raw_text
        .split_whitespace()
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();
    if nums.len() < 2 {
        let _ = ctx
            .render
            .send_html_simple(chat_id, "❌ فرمت نامعتبر. مثال: <code>120 90</code>", None)
            .await;
        return true;
    }
    if let Some(gw) = ctx.mcp_gw() {
        let _ = gw.cfg_store.update(|c| {
            c.limits.ip_rpm = nums[0];
            c.limits.key_rpm = nums[1];
        });
        gw.guard.sync_rates_from_config();
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!("✅ سقف‌ها ذخیره شد: IP={} req/min · Key={} req/min", nums[0], nums[1]),
                None,
            )
            .await;
    }
    true
}
