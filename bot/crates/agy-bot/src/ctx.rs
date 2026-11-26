//! Shared runtime context (`BotCtx`) and UI/system helpers injected across all bot handlers,
//! WebApp bridge callbacks, and the startup/shutdown lifecycle.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use agy_core::acl::{AclStore, RoleTier, PERM_KEYS};
use agy_core::atomic::atomic_write_json;
use agy_core::config::Config;
use agy_core::health::HealthTracker;
use agy_core::outbox::OutQueue;
use agy_core::proxies::{ProxyRegistry, ResolvedProxy};
use agy_core::security::{KeyedTokenBucket, DEFAULT_MAX_BUCKET_KEYS};
use agy_core::store::StateStore;
use agy_core::tg::{
    BotCommand, BotCommandScope, CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup,
    MenuButton,
};
use agy_ext::engines::{parse_mcp_list, parse_models, run_cmd, ModelInfo};
use agy_ext::mcp_config::{list_mcp_servers, McpServerView};
use agy_ext::skills::{list_installed_skills, InstalledSkill};
use agy_net::client::AnswerCallbackQueryParams;
use agy_net::{BotApiClient, ProxyPool};
use agy_render::esc;
use agy_render::premium::PremiumState;
use agy_widgets::WidgetStore;
use dashmap::DashMap;
use serde_json::{json, Value};
use tracing::warn;

use crate::auth::AuthGate;
use crate::cron::CronScheduler;
use crate::i18n::{cmd_description, perm_label, t, tier_badge_name, user_lang, Lang, Tx};
use crate::jobs::JobManager;
use crate::render_bridge::RenderBridge;

type McpRowsEntry = (Instant, Vec<(String, String)>);

/// Per-user browser view state for `/skills`.
#[derive(Debug, Clone)]
pub struct SkillViewState {
    pub tab: String,
    pub sp_ns: Option<String>,
    pub cat_dom: Option<String>,
    pub q: String,
}

impl Default for SkillViewState {
    fn default() -> Self {
        Self {
            tab: "inst".to_string(),
            sp_ns: None,
            cat_dom: None,
            q: String::new(),
        }
    }
}

/// Shared runtime state passed via `Arc<BotCtx>` to all Telegram handlers and WebApp bridge routes.
pub struct BotCtx {
    pub cfg: Arc<Config>,
    pub store: Arc<StateStore>,
    pub acl: Arc<AclStore>,
    pub outbox: Arc<OutQueue>,
    pub health: Arc<HealthTracker>,
    pub premium: Arc<PremiumState>,
    pub pool: Arc<ProxyPool>,
    pub proxies: Arc<ProxyRegistry>,
    pub client: Arc<BotApiClient>,
    pub widgets: Arc<WidgetStore>,
    pub render: Arc<RenderBridge>,
    pub cron: Arc<CronScheduler>,
    pub jobs: Arc<JobManager>,
    pub auth: Arc<AuthGate>,
    pub started_at: Instant,
    pub started_unix: f64,
    pub host: String,
    pub bot_info: tokio::sync::RwLock<Option<(i64, String)>>,
    pub models_cache: RwLock<Vec<ModelInfo>>,
    models_mtime: std::sync::Mutex<Option<SystemTime>>,
    pub sk_view: DashMap<i64, SkillViewState>,
    pub commands_set: DashMap<i64, bool>,
    /// Phase 3 per-UID Telegram anti-flood limiter (commands, callbacks, messages, uploads).
    pub tg_rl: Arc<KeyedTokenBucket<i64>>,
    /// Last timestamp a rate-limit notice was sent to `uid` (throttled to <= 1 per 30s).
    pub tg_rl_notice_ts: DashMap<i64, f64>,
    /// Phase 4 short-TTL (30s) cache for `agy mcp list` rows keyed by optional uid (avoids repeated CLI spawns).
    mcp_rows_cache: DashMap<Option<i64>, McpRowsEntry>,
    /// Live handle to the embedded Remote MCP Gateway (`127.0.0.1:8788`).
    mcp_gw: std::sync::OnceLock<Arc<agy_mcp_gateway::McpGatewayHandle>>,
}

impl BotCtx {
    /// Construct a new [`BotCtx`] loading any cached `$STATE_DIR/models.json`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: Arc<Config>,
        store: Arc<StateStore>,
        acl: Arc<AclStore>,
        outbox: Arc<OutQueue>,
        health: Arc<HealthTracker>,
        premium: Arc<PremiumState>,
        pool: Arc<ProxyPool>,
        client: Arc<BotApiClient>,
        widgets: Arc<WidgetStore>,
        render: Arc<RenderBridge>,
        cron: Arc<CronScheduler>,
        jobs: Arc<JobManager>,
        auth: Arc<AuthGate>,
    ) -> Arc<Self> {
        let models_path = cfg.state_dir.join("models.json");
        let initial_models = load_models_file(&models_path);
        let initial_mtime = std::fs::metadata(&models_path)
            .and_then(|m| m.modified())
            .ok();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let host = read_hostname();
        let proxies = Arc::new(
            ProxyRegistry::open(cfg.proxies_path(), cfg.acct_proxy_fallback).unwrap_or_else(|e| {
                warn!(error = %e, "ProxyRegistry open failed; using empty fallback registry");
                ProxyRegistry::empty(cfg.proxies_path(), cfg.acct_proxy_fallback)
            }),
        );
        jobs.set_proxies(Arc::clone(&proxies));
        acl.set_max_pending(cfg.acl_max_pending);
        let rl_per_min = jobs.runtime_limits().tg_user_rl_per_min;
        let tg_burst = if rl_per_min == 0 {
            0
        } else {
            rl_per_min.clamp(20, 60)
        };
        let tg_rl = Arc::new(KeyedTokenBucket::new(
            rl_per_min,
            tg_burst,
            DEFAULT_MAX_BUCKET_KEYS,
        ));

        Arc::new(Self {
            cfg,
            store,
            acl,
            outbox,
            health,
            premium,
            pool,
            proxies,
            client,
            widgets,
            render,
            cron,
            jobs,
            auth,
            started_at: Instant::now(),
            started_unix: now_unix,
            host,
            bot_info: tokio::sync::RwLock::new(None),
            models_cache: RwLock::new(initial_models),
            models_mtime: std::sync::Mutex::new(initial_mtime),
            sk_view: DashMap::new(),
            commands_set: DashMap::new(),
            tg_rl,
            tg_rl_notice_ts: DashMap::new(),
            mcp_rows_cache: DashMap::new(),
            mcp_gw: std::sync::OnceLock::new(),
        })
    }

    pub fn set_mcp_gw(&self, gw: Arc<agy_mcp_gateway::McpGatewayHandle>) {
        let _ = self.mcp_gw.set(gw);
    }

    pub fn mcp_gw(&self) -> Option<Arc<agy_mcp_gateway::McpGatewayHandle>> {
        self.mcp_gw.get().cloned()
    }

    pub fn is_owner(&self, uid: i64) -> bool {
        self.acl.is_owner(uid)
    }

    pub fn is_admin(&self, uid: i64) -> bool {
        self.acl.is_admin(uid)
    }

    pub fn tier_of(&self, uid: i64) -> RoleTier {
        self.acl.tier_of(uid)
    }

    pub fn lang(&self, uid: i64) -> Lang {
        user_lang(self, uid)
    }

    pub fn has_perm(&self, uid: i64, perm: &str) -> bool {
        self.acl.has_perm(uid, perm)
    }

    pub fn is_approved(&self, uid: i64) -> bool {
        self.acl.is_approved(uid)
    }

    pub fn skills_dir(&self) -> PathBuf {
        self.cfg.agy_skills_dir.clone()
    }

    pub fn e(&self, key: &str) -> String {
        self.premium.e(key)
    }

    /// Build a callback or URL button with optional Premium icon (`icon_custom_emoji_id`) and style.
    pub fn btn(
        &self,
        key: &str,
        label: &str,
        data: Option<&str>,
        style: Option<&str>,
        url: Option<&str>,
    ) -> InlineKeyboardButton {
        let key_opt = (!key.is_empty()).then_some(key);
        let mut b = if let Some(u) = url {
            let mut btn = self.premium.button(key_opt, label);
            btn.url = Some(u.to_string());
            btn
        } else if let Some(cb) = data {
            self.premium.callback_button(key_opt, label, cb)
        } else {
            self.premium.button(key_opt, label)
        };
        if let Some(st) = style {
            if !st.is_empty() {
                b = b.with_style(st);
            }
        }
        b
    }

    /// Wrap rows into an [`InlineKeyboardMarkup`], dropping empty rows.
    pub fn kb(rows: Vec<Vec<InlineKeyboardButton>>) -> InlineKeyboardMarkup {
        InlineKeyboardMarkup::new(rows)
    }

    pub fn back_row(&self) -> Vec<InlineKeyboardButton> {
        vec![self.btn("menu", "Menu", Some("home"), None, None)]
    }

    pub fn back_row_for(&self, uid: i64) -> Vec<InlineKeyboardButton> {
        let lang = self.lang(uid);
        vec![self.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None)]
    }

    /// Language selector keyboard across all 5 supported languages (`fa`, `en`, `la`, `zh`, `ru`).
    pub fn lang_kb(&self, uid: i64) -> InlineKeyboardMarkup {
        let cur = self.lang(uid);
        let mk_btn = |l: Lang| {
            let label = if l == cur {
                format!("✓ {}", l.native_label())
            } else {
                l.native_label().to_string()
            };
            self.btn("", &label, Some(&format!("lang:{}", l.code())), None, None)
        };
        let mut rows = vec![
            vec![mk_btn(Lang::Fa), mk_btn(Lang::En)],
            vec![mk_btn(Lang::La), mk_btn(Lang::Zh), mk_btn(Lang::Ru)],
        ];
        if self.is_owner(uid) || self.has_perm(uid, "dashboard_access") {
            rows.push(self.back_row_for(uid));
        } else {
            rows.push(vec![
                self.btn("new", t(cur, Tx::BtnNewChat), Some("new"), Some("success"), None),
                self.btn("help", t(cur, Tx::BtnHelp), Some("help"), None, None),
            ]);
        }
        Self::kb(rows)
    }

    fn has_tools_page(&self, uid: i64) -> bool {
        self.is_owner(uid)
            || self.has_perm(uid, "mcp_manage")
            || self.has_perm(uid, "skills_manage")
            || self.has_perm(uid, "widgets")
            || self.has_perm(uid, "automations")
            || self.has_perm(uid, "settings_access")
            || self.has_perm(uid, "status_net")
            || self.has_perm(uid, "parallel")
    }

    /// Clamp a requested menu tab index strictly to the pages permitted for `uid`.
    pub fn clamp_menu_page(&self, uid: i64, page: usize) -> usize {
        let is_owner = self.is_owner(uid);
        let has_tools = self.has_tools_page(uid);
        match page {
            2 if is_owner => 2,
            2 if has_tools => 1,
            1 if has_tools => 1,
            _ => 0,
        }
    }

    fn menu_page_count(&self, uid: i64) -> usize {
        if self.is_owner(uid) {
            3
        } else if self.has_tools_page(uid) {
            2
        } else {
            1
        }
    }

    fn menu_tab_row(&self, uid: i64, active_page: usize) -> Vec<InlineKeyboardButton> {
        let lang = self.lang(uid);
        let is_owner = self.is_owner(uid);
        let has_tools = self.has_tools_page(uid);
        let mut tabs = Vec::new();
        let tab = |idx: usize, emoji: &str, label: &str| {
            let txt = if active_page == idx {
                format!("● {emoji} {label}")
            } else {
                format!("{emoji} {label}")
            };
            let style = (active_page == idx).then_some("primary");
            self.btn("", &txt, Some(&format!("home:{idx}")), style, None)
        };
        tabs.push(tab(0, "🤖", t(lang, Tx::MenuTabAi)));
        if has_tools {
            tabs.push(tab(1, "🧰", t(lang, Tx::MenuTabTools)));
        }
        if is_owner {
            tabs.push(tab(2, "🛡", t(lang, Tx::MenuTabAdmin)));
        }
        tabs
    }

    /// Tiered & modular main keyboard (Page 0 by default).
    pub fn main_kb(&self, uid: i64, running: bool) -> InlineKeyboardMarkup {
        self.main_kb_page(uid, running, 0)
    }

    /// Sleek 2-column symmetric tabbed dashboard keyboard:
    /// - Locked `User`: minimal 2-row chat-only card (no dashboard modules).
    /// - Page 0 (`home:0`): AI & Chat (New Chat / Model or Stop, Uncensored / Grok, Sessions / Proxies).
    /// - Page 1 (`home:1`): Tools, Network & Settings (MCPs / Skills, Widgets / Automations, Proxies / Network, Settings / Status, Language / Help).
    /// - Page 2 (`home:2`, Owner only): Accounting & Control Tower (Accounts / Proxies, Safety Policy / Network, Users / Cron, Secretary / Status).
    pub fn main_kb_page(&self, uid: i64, running: bool, page: usize) -> InlineKeyboardMarkup {
        let lang = self.lang(uid);
        let is_owner = self.is_owner(uid);

        if !is_owner && !self.has_perm(uid, "dashboard_access") {
            let mut row1 = vec![self.btn(
                "new",
                t(lang, Tx::BtnNewChat),
                Some("new"),
                Some("success"),
                None,
            )];
            if running {
                row1.push(self.btn("stop", t(lang, Tx::BtnStop), Some("stop"), Some("danger"), None));
            }
            let row2 = vec![
                self.btn("", t(lang, Tx::BtnLanguage), Some("lang:menu"), None, None),
                self.btn("help", t(lang, Tx::BtnHelp), Some("help"), None, None),
            ];
            return Self::kb(vec![row1, row2]);
        }

        let cur_page = self.clamp_menu_page(uid, page);
        let total_pages = self.menu_page_count(uid);
        let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();

        match cur_page {
            0 => {
                // Row 1: Primary Chat Action + Model/Stop
                let mut row1 = vec![self.btn(
                    "new",
                    t(lang, Tx::BtnNewChat),
                    Some("new"),
                    Some("success"),
                    None,
                )];
                if running {
                    row1.push(self.btn(
                        "stop",
                        t(lang, Tx::BtnStop),
                        Some("stop"),
                        Some("danger"),
                        None,
                    ));
                } else if self.has_perm(uid, "models_switch") {
                    row1.push(self.btn(
                        "model",
                        t(lang, Tx::BtnModel),
                        Some("models:0"),
                        None,
                        None,
                    ));
                }
                rows.push(row1);

                // Row 2: Alternative AI Engines (2-col)
                let mut engines = Vec::new();
                if self.has_perm(uid, "uncensored") {
                    engines.push(self.btn(
                        "fire",
                        t(lang, Tx::BtnUncensored),
                        Some("umodels:0"),
                        None,
                        None,
                    ));
                }
                if self.has_perm(uid, "grok") {
                    engines.push(self.btn(
                        "grok",
                        t(lang, Tx::BtnGrok),
                        Some("grok:open"),
                        None,
                        None,
                    ));
                }
                if !engines.is_empty() {
                    rows.push(engines);
                }

                // Row 3: Quick access (Sessions + Proxies/Settings)
                let mut quick = Vec::new();
                if !running {
                    quick.push(self.btn(
                        "sessions",
                        t(lang, Tx::BtnSessions),
                        Some("sessions"),
                        None,
                        None,
                    ));
                }
                if is_owner || self.has_perm(uid, "status_net") {
                    quick.push(self.btn(
                        "web",
                        t(lang, Tx::BtnProxies),
                        Some("px:list"),
                        None,
                        None,
                    ));
                } else if self.has_perm(uid, "settings_access") {
                    quick.push(self.btn(
                        "settings",
                        t(lang, Tx::BtnSettings),
                        Some("settings"),
                        None,
                        None,
                    ));
                }
                if !quick.is_empty() {
                    rows.push(quick);
                }

                if total_pages == 1 {
                    rows.push(vec![
                        self.btn("", t(lang, Tx::BtnLanguage), Some("lang:menu"), None, None),
                        self.btn("help", t(lang, Tx::BtnHelp), Some("help"), None, None),
                    ]);
                }
            }
            1 => {
                // Symmetric 2-column grid of Tools, Network & Settings
                let mut items: Vec<InlineKeyboardButton> = Vec::new();
                if self.has_perm(uid, "mcp_manage") {
                    items.push(self.btn("mcp", t(lang, Tx::BtnMcp), Some("mcp"), None, None));
                }
                if self.has_perm(uid, "skills_manage") {
                    items.push(self.btn(
                        "skills",
                        t(lang, Tx::BtnSkills),
                        Some("skills:0"),
                        None,
                        None,
                    ));
                }
                if self.has_perm(uid, "widgets") {
                    items.push(self.btn(
                        "party",
                        t(lang, Tx::BtnWidgets),
                        Some("wmenu:open"),
                        None,
                        None,
                    ));
                }
                if self.has_perm(uid, "automations") {
                    items.push(self.btn(
                        "bolt",
                        t(lang, Tx::BtnAutomations),
                        Some("auto:list"),
                        None,
                        None,
                    ));
                }
                if is_owner || self.has_perm(uid, "status_net") {
                    items.push(self.btn(
                        "web",
                        t(lang, Tx::BtnProxies),
                        Some("px:list"),
                        None,
                        None,
                    ));
                }
                if self.has_perm(uid, "status_net") {
                    items.push(self.btn(
                        "",
                        &format!("📡 {}", t(lang, Tx::BtnNetwork)),
                        Some("net"),
                        None,
                        None,
                    ));
                }
                if self.has_perm(uid, "settings_access") {
                    items.push(self.btn(
                        "settings",
                        t(lang, Tx::BtnSettings),
                        Some("settings"),
                        None,
                        None,
                    ));
                }
                if self.has_perm(uid, "status_net") {
                    items.push(self.btn(
                        "status",
                        t(lang, Tx::BtnStatus),
                        Some("status"),
                        None,
                        None,
                    ));
                }
                for pair in items.chunks(2) {
                    rows.push(pair.to_vec());
                }
                rows.push(vec![
                    self.btn("", t(lang, Tx::BtnLanguage), Some("lang:menu"), None, None),
                    self.btn("help", t(lang, Tx::BtnHelp), Some("help"), None, None),
                ]);
            }
            _ => {
                // Page 2 (Owner only): Accounting, Sticky Proxies, Safety Policy, Limits & Server Ops
                rows.push(vec![
                    self.btn(
                        "bolt",
                        t(lang, Tx::BtnAccounts),
                        Some("acct:list"),
                        None,
                        None,
                    ),
                    self.btn(
                        "web",
                        t(lang, Tx::BtnProxies),
                        Some("px:list"),
                        None,
                        None,
                    ),
                ]);
                rows.push(vec![
                    self.btn(
                        "admin",
                        t(lang, Tx::BtnPolicy),
                        Some("acct:pol"),
                        None,
                        None,
                    ),
                    self.btn(
                        "status",
                        "Limits & Guards",
                        Some("limits"),
                        None,
                        None,
                    ),
                ]);
                rows.push(vec![
                    self.btn(
                        "account",
                        t(lang, Tx::BtnUsers),
                        Some("uadm:list:all:0"),
                        None,
                        None,
                    ),
                    self.btn("cfg", t(lang, Tx::BtnCron), Some("cron"), None, None),
                ]);
                rows.push(vec![
                    self.btn("support", t(lang, Tx::BtnSecretary), Some("biz:p"), None, None),
                    self.btn(
                        "web",
                        t(lang, Tx::BtnNetwork),
                        Some("net"),
                        None,
                        None,
                    ),
                ]);
                rows.push(vec![
                    self.btn("status", t(lang, Tx::BtnStatus), Some("status"), None, None),
                    self.btn("", "🛡 Updates", Some("upd:status"), None, None),
                ]);
            }
        }

        if total_pages > 1 {
            rows.push(self.menu_tab_row(uid, cur_page));
        }

        Self::kb(rows)
    }

    pub fn stop_kb(&self) -> InlineKeyboardMarkup {
        Self::kb(vec![vec![self.btn(
            "stop",
            "Stop",
            Some("stop"),
            Some("danger"),
            None,
        )]])
    }

    pub fn stop_kb_for(&self, uid: i64) -> InlineKeyboardMarkup {
        let lang = self.lang(uid);
        Self::kb(vec![vec![self.btn(
            "stop",
            t(lang, Tx::BtnStop),
            Some("stop"),
            Some("danger"),
            None,
        )]])
    }

    pub fn answer_kb(&self) -> InlineKeyboardMarkup {
        Self::kb(vec![vec![
            self.btn("new", "New chat", Some("new"), None, None),
            self.btn("menu", "Menu", Some("home"), None, None),
        ]])
    }

    pub fn answer_kb_for(&self, uid: i64) -> InlineKeyboardMarkup {
        let lang = self.lang(uid);
        let right = if self.is_owner(uid) || self.has_perm(uid, "dashboard_access") {
            self.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None)
        } else {
            self.btn("", t(lang, Tx::BtnLanguage), Some("lang:menu"), None, None)
        };
        Self::kb(vec![vec![
            self.btn("new", t(lang, Tx::BtnNewChat), Some("new"), None, None),
            right,
        ]])
    }

    pub fn short(s: Option<&str>, max_chars: usize) -> String {
        let Some(val) = s else {
            return "—".to_string();
        };
        if val.is_empty() {
            return "—".to_string();
        }
        let count = val.chars().count();
        if count <= max_chars {
            val.to_string()
        } else {
            let truncated: String = val.chars().take(max_chars).collect();
            format!("{truncated}…")
        }
    }

    pub fn get_models_cache(&self) -> Vec<ModelInfo> {
        // Reload when models.json changed on disk (cron sync, per-account refresh of primary).
        let path = self.cfg.state_dir.join("models.json");
        let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        let changed = {
            let g = self.models_mtime.lock().unwrap_or_else(|e| e.into_inner());
            mtime.is_some() && *g != mtime
        };
        {
            let guard = match self.models_cache.read() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if !guard.is_empty() && !changed {
                return guard.clone();
            }
        }
        let disk = load_models_file(&path);
        if !disk.is_empty() {
            self.set_models_cache(disk.clone());
            return disk;
        }
        let guard = match self.models_cache.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.clone()
    }

    pub fn set_models_cache(&self, models: Vec<ModelInfo>) {
        let mtime = std::fs::metadata(self.cfg.state_dir.join("models.json"))
            .and_then(|m| m.modified())
            .ok();
        if mtime.is_some() {
            let mut mg = self.models_mtime.lock().unwrap_or_else(|e| e.into_inner());
            *mg = mtime;
        }
        let mut guard = match self.models_cache.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *guard = models;
    }

    /// Refresh model catalog from `agy models`, saving `$STATE_DIR/models.json` atomically.
    pub async fn refresh_models(&self) -> Vec<ModelInfo> {
        let args = vec![
            self.cfg.agy_bin.to_string_lossy().into_owned(),
            "models".to_string(),
        ];
        if let Ok((rc, out, _)) = run_cmd(&args, Some(&self.cfg.agy_workspace), 45.0).await {
            if rc == 0 {
                let models = parse_models(&out);
                if !models.is_empty() {
                    let path = self.cfg.state_dir.join("models.json");
                    if let Err(err) = atomic_write_json(&path, &models, true) {
                        warn!(error = %err, "failed persisting models.json");
                    }
                    self.set_models_cache(models.clone());
                    return models;
                }
            }
        }
        self.get_models_cache()
    }

    /// The account the user's next turn will most likely use, and that account's models.
    /// Without a pool, falls back to the global catalog.
    pub fn models_for_user(&self, uid: i64) -> (Option<agy_core::accounts::Account>, Vec<ModelInfo>) {
        let Some(pool) = self.jobs.accounts() else {
            return (None, self.get_models_cache());
        };
        let Some(a) = pool.preferred_for(uid) else {
            return (None, self.get_models_cache());
        };
        let ms = crate::models_pool::load(&self.cfg.state_dir, &a.id);
        if ms.is_empty() && a.is_primary() {
            return (Some(a), self.get_models_cache());
        }
        (Some(a), ms)
    }

    /// Refresh the catalog of the user's active account (and the global cache when that is
    /// the primary account). No model request / quota: `agy models` only lists.
    pub async fn refresh_models_for_user(&self, uid: i64) -> Vec<ModelInfo> {
        let acct = self.jobs.accounts().and_then(|p| p.preferred_for(uid));
        let key = acct.as_ref().map(|a| a.id.clone()).unwrap_or_else(|| "primary".into());
        if !crate::models_pool::may_refresh_now(&key, self.acl.is_owner(uid)) {
            return self.models_for_user(uid).1;
        }
        match acct {
            Some(a) => {
                let px = match self.proxies.resolve(a.proxy_id.as_deref()) {
                    ResolvedProxy::Use { url, .. } => Some(url),
                    ResolvedProxy::Direct | ResolvedProxy::DirectFallback { .. } => None,
                    ResolvedProxy::Blocked { .. } => return self.models_for_user(uid).1,
                };
                let ms = crate::models_pool::refresh_with_proxy(&self.cfg, &a, px.as_deref()).await;
                if a.is_primary() && !ms.is_empty() {
                    self.set_models_cache(ms.clone());
                }
                ms
            }
            None => self.refresh_models().await,
        }
    }

    pub fn model_label(&self, mid: Option<&str>) -> String {
        let Some(id) = mid.filter(|s| !s.is_empty()) else {
            return "default".to_string();
        };
        let models = self.get_models_cache();
        for m in models {
            if m.id == id {
                return m.name;
            }
        }
        if let Some(p) = self.jobs.accounts() {
            for a in p.list() {
                if let Some(m) = crate::models_pool::load(&self.cfg.state_dir, &a.id).into_iter().find(|m| m.id == id) {
                    return m.name;
                }
            }
        }
        id.to_string()
    }

    pub fn dashboard_text(&self, uid: i64) -> String {
        self.dashboard_text_page(uid, 0)
    }

    pub fn dashboard_text_page(&self, uid: i64, page: usize) -> String {
        let lang = self.lang(uid);
        let tier = self.tier_of(uid);
        let is_owner = self.is_owner(uid);
        let tier_lbl = tier_badge_name(lang, tier);

        let st = match self.jobs.active_job_info(uid) {
            Some(info) => {
                let elapsed_s = info.started.elapsed().as_secs();
                format!("{} {} · {elapsed_s}s", self.e("work"), t(lang, Tx::StatusRunning))
            }
            None => format!("🟢 {}", t(lang, Tx::StatusIdle)),
        };

        // Locked Regular User -> Minimal chat-only card (no dashboard internals exposed).
        if !is_owner && !self.has_perm(uid, "dashboard_access") {
            return format!(
                "{} <b>{}</b>  <code>{}</code>\n\
                <blockquote><b>{}</b>  {}</blockquote>\n\
                <i>{}</i>\n\
                <code>{}</code>",
                self.e("brand"),
                t(lang, Tx::MinimalChatTitle),
                esc(&tier_lbl),
                t(lang, Tx::DashFieldStatus),
                st,
                t(lang, Tx::MinimalChatHint),
                t(lang, Tx::MinimalChatFooter),
            );
        }

        let cur_page = self.clamp_menu_page(uid, page);
        let total_pages = self.menu_page_count(uid);
        let page_pill = if total_pages > 1 {
            format!("  ·  <code>{}/{total_pages}</code>", cur_page + 1)
        } else {
            String::new()
        };

        if cur_page == 1 {
            let u = self.store.get_user(uid);
            let mcps = self.list_mcp_config();
            let mcp_en = mcps.iter().filter(|m| m.enabled).count();
            let skills_n = self.list_installed_skills().len();
            let px_ok = self.proxies.healthy_count();
            let px_tot = self.proxies.len();
            let bot_snap = self.pool.snapshot();
            let bot_ok = bot_snap.active_healthy;
            let bot_tot = bot_snap.routes.len();
            let smode = crate::jobs::effective_stream_mode(&u);
            let px_line = if is_owner || self.has_perm(uid, "status_net") {
                format!(
                    "\n<b>{}</b>  <code>{px_ok}/{px_tot}</code> AI · <code>{bot_ok}/{bot_tot}</code> Bot · <code>{}</code>",
                    t(lang, Tx::BtnProxies),
                    esc(self.proxies.fallback_policy().label())
                )
            } else {
                String::new()
            };
            return format!(
                "🧰 <b>{}</b>  <code>{}</code>{page_pill}\n\
                <blockquote><b>MCP</b>  <code>{mcp_en}/{}</code>  ·  <b>{}</b>  <code>{skills_n}</code>{px_line}\n\
                <b>Render</b>  <code>{}</code>  ·  <b>Stream</b>  <code>{}</code>\n\
                <b>{}</b>  {}</blockquote>\n\
                <i>{}</i>",
                t(lang, Tx::MenuTabTools),
                esc(&tier_lbl),
                mcps.len(),
                t(lang, Tx::BtnSkills),
                esc(&u.render),
                esc(smode),
                t(lang, Tx::DashFieldStatus),
                st,
                t(lang, Tx::DashSendTip),
            );
        }

        if cur_page == 2 {
            let px_ok = self.proxies.healthy_count();
            let px_tot = self.proxies.len();
            let grok_px = match self.proxies.resolve_grok() {
                ResolvedProxy::Direct => "direct".to_string(),
                ResolvedProxy::DirectFallback { safe_label, .. } => format!("⚠ {safe_label}→direct"),
                ResolvedProxy::Use { safe_label, .. } => safe_label,
                ResolvedProxy::Blocked { safe_label, .. } => format!("🔴 {safe_label}"),
            };
            let acct_block = match self.jobs.accounts() {
                Some(p) => {
                    let pol = p.policy();
                    let res = p.weekly_reserved_count();
                    let brk = if p.breaker_status().is_some() {
                        "  ·  🛑 <b>BREAKER ON</b>"
                    } else {
                        ""
                    };
                    format!(
                        "<b>{}</b>  <code>{}/{}</code> ready{} (🛡 {res} reserved){brk}\n\
                        <b>{}</b>  <code>{}</code> · <code>{:.1}%</code> 7d res · conc <code>{}</code> · gap <code>{}s</code>",
                        t(lang, Tx::BtnAccounts),
                        p.available_count(),
                        p.len(),
                        "",
                        t(lang, Tx::BtnPolicy),
                        esc(pol.preset.label()),
                        pol.weekly_reserve_pct,
                        pol.max_concurrency_per_account,
                        pol.min_gap_secs,
                    )
                }
                None => format!("<b>{}</b>  <code>single-account</code>", t(lang, Tx::BtnAccounts)),
            };
            let users_cnt = self.acl.approved_ids().len();
            return format!(
                "🛡 <b>{}</b>  <code>{}</code>{page_pill}\n\
                <blockquote>{acct_block}\n\
                <b>{}</b>  <code>{px_ok}/{px_tot}</code> · <code>{}</code> · Grok: <code>{}</code>\n\
                <b>{}</b>  <code>{users_cnt}</code> approved  ·  <b>{}</b>  {}</blockquote>\n\
                <i>{}</i>",
                t(lang, Tx::MenuTabAdmin),
                esc(&tier_lbl),
                t(lang, Tx::BtnProxies),
                esc(self.proxies.fallback_policy().label()),
                esc(&grok_px),
                t(lang, Tx::BtnUsers),
                t(lang, Tx::DashFieldStatus),
                st,
                t(lang, Tx::DashSendTip),
            );
        }

        let u = self.store.get_user(uid);
        let mode = u.mode.as_deref().filter(|s| !s.is_empty()).unwrap_or("auto");
        let effort = u
            .effort
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("default");
        let engine_extra = u.extra.get("engine").and_then(|v| v.as_str());
        let is_uncensored = self.has_perm(uid, "uncensored")
            && (engine_extra == Some("uncensored")
                || (engine_extra.is_none()
                    && u.model
                        .as_deref()
                        .is_some_and(agy_ext::uncensored::is_uncensored_model)));
        let is_grok_bot = !is_uncensored
            && self.has_perm(uid, "grok")
            && engine_extra == Some("grok_bot");
        let is_grok = !is_uncensored
            && !is_grok_bot
            && self.has_perm(uid, "grok")
            && (engine_extra == Some("grok")
                || (engine_extra.is_none()
                    && u.model
                        .as_deref()
                        .is_some_and(agy_ext::grok_oauth::is_grok_model)));

        let model = if is_uncensored {
            let m = u
                .model
                .as_deref()
                .filter(|s| agy_ext::uncensored::is_uncensored_model(s))
                .unwrap_or(agy_ext::uncensored::DEFAULT_UNCENSORED_MODEL);
            format!("{m} (Venice)")
        } else if is_grok_bot {
            let bot_name = crate::handlers_grok_bot::selected_grok_bot(&u)
                .map(|(_, name)| name)
                .unwrap_or_else(|| "default".to_string());
            format!("{bot_name} (Grok Bot)")
        } else if is_grok {
            let m = u
                .model
                .as_deref()
                .filter(|s| agy_ext::grok_oauth::is_grok_model(s))
                .unwrap_or(agy_ext::grok_oauth::DEFAULT_GROK_MODEL);
            format!("{m} (Grok OAuth)")
        } else {
            self.model_label(u.model.as_deref())
        };
        let sess = Self::short(u.conversation_id.as_deref(), 10);
        let acct_line = if is_uncensored {
            let kind = if crate::handlers_uncensored::uncensored_agent_mode(&u) {
                "Agent"
            } else {
                "Chat"
            };
            format!("\n<b>{}</b>  <code>Venice Uncensored ({kind})</code>", t(lang, Tx::DashFieldEngine))
        } else if is_grok_bot {
            let oauth_who = agy_ext::grok_bot::load_grok_bot_creds(&self.cfg.state_dir)
                .map(|c| {
                    if c.quarantined_reason.is_some() {
                        "reconnect".to_string()
                    } else if is_owner {
                        c.masked_email().unwrap_or_else(|| "connected".to_string())
                    } else {
                        "connected".to_string()
                    }
                })
                .unwrap_or_else(|| "disconnected".to_string());
            format!(
                "\n<b>{}</b>  <code>Grok Bot (Cloud)</code>  ·  <code>{}</code>",
                t(lang, Tx::DashFieldEngine),
                esc(&oauth_who)
            )
        } else if is_grok {
            let kind = if crate::handlers_grok::grok_agent_mode(&u) {
                "Agent"
            } else {
                "Chat"
            };
            let oauth_who = agy_ext::grok_oauth::load_grok_creds(&self.cfg.state_dir)
                .map(|c| {
                    if c.quarantined_reason.is_some() {
                        "reconnect".to_string()
                    } else if is_owner {
                        c.masked_email().unwrap_or_else(|| "connected".to_string())
                    } else {
                        "connected".to_string()
                    }
                })
                .unwrap_or_else(|| "disconnected".to_string());
            format!(
                "\n<b>{}</b>  <code>Grok OAuth ({kind})</code>  ·  <code>{}</code>",
                t(lang, Tx::DashFieldEngine),
                esc(&oauth_who)
            )
        } else if is_owner {
            match self.jobs.accounts() {
                Some(p) => {
                    let cur = p
                        .preferred_for(uid)
                        .map(|a| a.display_name())
                        .unwrap_or_else(|| "none".into());
                    let px_ok = self.proxies.healthy_count();
            let px_tot = self.proxies.len();
                    format!(
                        "\n<b>Account</b>  <code>{}</code>  ·  <b>Pool</b>  {}/{}  ·  <b>Proxies</b>  {px_ok}/{px_tot}",
                        esc(&cur),
                        p.available_count(),
                        p.len()
                    )
                }
                None => String::new(),
            }
        } else {
            String::new()
        };

        let mut mod_labels: Vec<&'static str> = Vec::new();
        for key in PERM_KEYS {
            if is_owner || self.has_perm(uid, key) {
                mod_labels.push(perm_label(lang, key));
            }
        }
        let mods_summary = if mod_labels.is_empty() {
            t(lang, Tx::NoneWord).to_string()
        } else {
            mod_labels.join(" · ")
        };

        let invalid = if !is_uncensored
            && !is_grok
            && u.extra.contains_key(crate::jobs::model_pick::MODEL_INVALID_KEY)
        {
            "  ⚠️"
        } else {
            ""
        };

        format!(
            "{} <b>{}</b>  <code>{}</code>{page_pill}\n\
            <blockquote><b>{}</b>  <code>{}</code>{}\n\
            <b>{}</b>  {}  ·  <b>{}</b>  {}\n\
            <b>{}</b>  <code>{}</code>{}\n\
            <b>{}</b>  <code>{}</code>\n\
            <b>{}</b>  {}</blockquote>\n\
            <i>{}</i>",
            self.e("brand"),
            t(lang, Tx::DashTitle),
            esc(&tier_lbl),
            t(lang, Tx::DashFieldModel),
            esc(&model),
            invalid,
            t(lang, Tx::DashFieldMode),
            esc(mode),
            t(lang, Tx::DashFieldEffort),
            esc(effort),
            t(lang, Tx::DashFieldSession),
            esc(&sess),
            acct_line,
            t(lang, Tx::DashFieldModules),
            esc(&mods_summary),
            t(lang, Tx::DashFieldStatus),
            st,
            t(lang, Tx::DashSendTip),
        )
    }

    pub fn list_installed_skills(&self) -> Vec<InstalledSkill> {
        list_installed_skills(&self.cfg.agy_skills_dir).unwrap_or_default()
    }

    pub fn list_mcp_config(&self) -> Vec<McpServerView> {
        list_mcp_servers(&self.cfg.mcp_config_path).unwrap_or_default()
    }

    /// Run a non-model `agy` subcommand (mcp list, agents, changelog, …) as the account the
    /// user's next turn will use (`HOME` = that account's shadow home). `uid = None` or no
    /// pool: the primary/server login.
    pub async fn agy_cmd_for(&self, uid: Option<i64>, sub: &[&str], timeout: f64) -> agy_core::Result<(i32, String, String)> {
        agy_cmd_as(
            &self.cfg.agy_bin,
            &self.cfg.agy_workspace,
            self.jobs.accounts().as_deref(),
            Some(self.proxies.as_ref()),
            uid,
            sub,
            timeout,
        )
        .await
    }

    /// Clear cached `agy mcp list` rows (called after MCP add/remove/toggle mutations).
    pub fn invalidate_mcp_rows_cache(&self) {
        self.mcp_rows_cache.clear();
    }

    /// Merge live `agy mcp list` status with `mcp_config.json` definitions (as `uid`'s account),
    /// cached for 30s in memory to avoid redundant `agy` CLI subprocess spawns.
    pub async fn mcp_rows_live(&self, uid: Option<i64>) -> Vec<(String, String)> {
        if let Some(entry) = self.mcp_rows_cache.get(&uid) {
            if entry.0.elapsed() < std::time::Duration::from_secs(30) {
                return entry.1.clone();
            }
        }
        if let Ok((rc, out, _)) = self.agy_cmd_for(uid, &["mcp", "list"], 30.0).await {
            if rc == 0 {
                let rows: Vec<(String, String)> = parse_mcp_list(&out)
                    .into_iter()
                    .map(|r| (r.name, r.status))
                    .collect();
                self.mcp_rows_cache.insert(uid, (Instant::now(), rows.clone()));
                return rows;
            }
        }
        Vec::new()
    }

    /// Build a sanitized list of MCP server entries for UI / WebApp consumption.
    ///
    /// Never exposes raw env secrets when `include_secret == false`.
    pub fn mcp_servers_for(&self, include_secret: bool) -> Vec<Value> {
        let mut servers = self.list_mcp_config();
        let disabled_set = self.store.meta("disabled_mcps").unwrap_or_else(|| json!([]));
        let _ = disabled_set;

        servers.sort_by(|a, b| a.name.cmp(&b.name));
        servers
            .into_iter()
            .map(|srv| {
                let env_val: BTreeMap<String, String> = if include_secret {
                    srv.env.clone()
                } else {
                    srv.env
                        .iter()
                        .map(|(k, v)| {
                            let val = if agy_ext::mcp_config::is_sensitive_key(k) {
                                "•••".to_string()
                            } else {
                                v.clone()
                            };
                            (k.clone(), val)
                        })
                        .collect()
                };
                json!({
                    "name": srv.name,
                    "type": srv.server_type,
                    "enabled": srv.enabled,
                    "command": srv.command,
                    "args": srv.args,
                    "url": srv.url,
                    "env_keys": srv.env_keys,
                    "env": env_val,
                    "config_redacted": srv.config_redacted,
                })
            })
            .collect()
    }

    pub fn sys_snapshot(&self, uid: i64) -> Value {
        let up = self.started_at.elapsed().as_secs();
        let (load_str, cpu_pct) = read_loadavg();
        let ram_pct = read_ram_pct();
        let disk_pct = read_disk_pct(&self.cfg.agy_workspace);

        let u = self.store.get_user(uid);
        let snap = self.health.snapshot();
        let stall_ms = (self.health.stall_secs() * 1000.0).round() as u64;

        json!({
            "host": self.host,
            "service": "active",
            "uptime": format!("{}h {}m", up / 3600, (up % 3600) / 60),
            "load": load_str,
            "cpu_pct": cpu_pct,
            "ram_pct": ram_pct,
            "disk_pct": disk_pct,
            "model": self.model_label(u.model.as_deref()),
            "mode": u.mode.as_deref().filter(|s| !s.is_empty()).unwrap_or("auto"),
            "effort": u.effort.as_deref().filter(|s| !s.is_empty()).unwrap_or("default"),
            "polling": {
                "mode": snap.mode,
                "updates": snap.updates,
                "errors": snap.total_poll_failures,
                "latency_ms": stall_ms,
            }
        })
    }

    pub async fn ack(&self, cq_id: &str, text: Option<&str>, show_alert: bool) {
        let params = AnswerCallbackQueryParams {
            callback_query_id: cq_id.to_string(),
            text: text.map(ToString::to_string),
            show_alert: if show_alert { Some(true) } else { None },
            url: None,
            cache_time: None,
        };
        let _ = self.client.answer_callback_query_with(params).await;
    }

    pub async fn edit_or_send(
        &self,
        cq: Option<&CallbackQuery>,
        chat_id: i64,
        html: &str,
        mk: Option<InlineKeyboardMarkup>,
    ) {
        let msg_id = cq.and_then(|c| c.message.as_ref()).map(|m| m.message_id);
        let _ = self
            .render
            .edit_or_send_html(chat_id, msg_id, html, mk)
            .await;
    }

    /// Builds the localized Telegram slash command menu strictly filtered by `uid`'s tier & permissions.
    pub fn effective_commands(&self, uid: i64) -> Vec<BotCommand> {
        let lang = self.lang(uid);
        let mk = |cmd: &str| BotCommand {
            command: cmd.to_string(),
            description: cmd_description(lang, cmd).to_string(),
        };

        if !self.is_approved(uid) {
            return vec![mk("lang"), mk("help")];
        }

        let is_owner = self.is_owner(uid);
        let has_dash = is_owner || self.has_perm(uid, "dashboard_access");
        let mut cmds = Vec::new();

        if is_owner {
            cmds.push(mk("users"));
            cmds.push(mk("accounts"));
            cmds.push(mk("proxies"));
            cmds.push(mk("secretary"));
            cmds.push(mk("updates"));
        }
        if has_dash {
            cmds.push(mk("menu"));
        }
        cmds.push(mk("new"));
        cmds.push(mk("lang"));
        cmds.push(mk("stop"));
        cmds.push(mk("cancel"));

        if self.has_perm(uid, "models_switch") {
            cmds.push(mk("model"));
        }
        if self.has_perm(uid, "uncensored") {
            cmds.push(mk("uncensored"));
            cmds.push(mk("uagent"));
        }
        if self.has_perm(uid, "grok") {
            cmds.push(mk("grok"));
            cmds.push(mk("gagent"));
        }
        if self.has_perm(uid, "parallel") {
            cmds.push(mk("parallel"));
        }
        if self.has_perm(uid, "automations") {
            cmds.push(mk("auto"));
        }
        if has_dash {
            cmds.push(mk("resume"));
        }
        if self.has_perm(uid, "status_net") {
            cmds.push(mk("status"));
            cmds.push(mk("net"));
            if !is_owner {
                cmds.push(mk("proxies"));
            }
            cmds.push(mk("cron"));
        }
        if self.has_perm(uid, "mcp_manage") {
            cmds.push(mk("mcp"));
        }
        if self.has_perm(uid, "skills_manage") {
            cmds.push(mk("skills"));
            cmds.push(mk("skillhub"));
        }
        if self.has_perm(uid, "settings_access") {
            cmds.push(mk("settings"));
            cmds.push(mk("effort"));
            cmds.push(mk("mode"));
            cmds.push(mk("cwd"));
            cmds.push(mk("agent"));
            cmds.push(mk("trace"));
            cmds.push(mk("changelog"));
        }
        if self.has_perm(uid, "widgets") {
            cmds.push(mk("widget"));
        }

        cmds.push(mk("help"));
        cmds
    }

    pub async fn sync_user_commands(&self, uid: i64) {
        let cmds = self.effective_commands(uid);
        if let Err(err) = self
            .client
            .set_my_commands(&cmds, Some(BotCommandScope::Chat { chat_id: uid }))
            .await
        {
            warn!(uid, error = %err, "setMyCommands failed for user");
            return;
        }
        let _ = self
            .client
            .set_chat_menu_button(Some(uid), Some(MenuButton::Commands))
            .await;
        self.commands_set.insert(uid, true);
    }

    pub async fn send_approved_welcome(&self, uid: i64) {
        let lang = self.lang(uid);
        let msg = if self.is_owner(uid) || self.has_perm(uid, "dashboard_access") {
            t(lang, Tx::ApprovedDashboardWelcome)
        } else {
            t(lang, Tx::ApprovedMinimalWelcome)
        };
        let txt = format!("{} {}", self.e("ok"), msg);
        let mk = self.main_kb(uid, false);
        let _ = self.render.send_html_simple(uid, &txt, Some(mk)).await;
    }
}

/// Run a non-model `agy` subcommand as `uid`'s account: a non-primary account runs with
/// HOME = its shadow home (so `mcp list`, `agents`, `changelog` reflect that account),
/// and respects any sticky egress proxy bound to that account.
pub(crate) async fn agy_cmd_as(
    bin: &Path,
    ws: &Path,
    pool: Option<&agy_core::accounts::AccountStore>,
    proxies: Option<&ProxyRegistry>,
    uid: Option<i64>,
    sub: &[&str],
    timeout: f64,
) -> agy_core::Result<(i32, String, String)> {
    let mut args = vec![bin.to_string_lossy().into_owned()];
    args.extend(sub.iter().map(|s| s.to_string()));
    let acct = uid.and_then(|u| pool.and_then(|p| p.preferred_for(u)));
    match (pool, acct) {
        (Some(p), Some(a)) => {
            let mut env: Vec<(String, String)> = Vec::new();
            if !a.is_primary() {
                if let Err(e) = p.prepare_home(&a) {
                    warn!(account = %a.id, error = %e, "shadow home refresh failed");
                }
                env.push(("HOME".to_string(), a.home.to_string_lossy().into_owned()));
            }
            if let Some(reg) = proxies {
                if let ResolvedProxy::Use { url, .. } = reg.resolve(a.proxy_id.as_deref()) {
                    for k in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"] {
                        env.push((k.to_string(), url.clone()));
                    }
                    for k in ["NO_PROXY", "no_proxy"] {
                        env.push((k.to_string(), "127.0.0.1,localhost,::1".to_string()));
                    }
                }
            }
            if env.is_empty() {
                run_cmd(&args, Some(ws), timeout).await
            } else {
                agy_ext::engines::run_cmd_env(&args, Some(ws), timeout, &env).await
            }
        }
        _ => run_cmd(&args, Some(ws), timeout).await,
    }
}

pub(crate) fn load_models_file(path: &Path) -> Vec<ModelInfo> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str::<Vec<ModelInfo>>(&raw).unwrap_or_default()
}

fn read_hostname() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        let t = h.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    if let Ok(raw) = std::fs::read_to_string("/etc/hostname") {
        let t = raw.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    "localhost".to_string()
}

fn read_loadavg() -> (String, u64) {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1) as f64;
    let Ok(raw) = std::fs::read_to_string("/proc/loadavg") else {
        return ("0.00 0.00 0.00".to_string(), 0);
    };
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.len() < 3 {
        return ("0.00 0.00 0.00".to_string(), 0);
    }
    let la0 = parts[0].parse::<f64>().unwrap_or(0.0);
    let la1 = parts[1].parse::<f64>().unwrap_or(0.0);
    let la2 = parts[2].parse::<f64>().unwrap_or(0.0);
    let cpu_pct = ((la0 * 100.0 / cpus).round() as i64).clamp(0, 100) as u64;
    (format!("{la0:.2} {la1:.2} {la2:.2}"), cpu_pct)
}

fn read_ram_pct() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total: Option<u64> = None;
    let mut avail: Option<u64> = None;
    for line in raw.lines() {
        if let Some((k, rest)) = line.split_once(':') {
            let num = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok());
            match k.trim() {
                "MemTotal" => total = num,
                "MemAvailable" => avail = num,
                _ => {}
            }
        }
    }
    let tot = total?;
    if tot == 0 {
        return None;
    }
    let used = tot.saturating_sub(avail.unwrap_or(0));
    let pct = ((used as f64 * 100.0 / tot as f64).round() as i64).clamp(0, 100) as u64;
    Some(pct)
}

fn read_disk_pct(path: &Path) -> u64 {
    let target = if path.exists() { path } else { Path::new("/") };
    let Ok(out) = Command::new("stat")
        .args(["-f", "-c", "%b %a"])
        .arg(target)
        .output()
    else {
        return 0;
    };
    if !out.status.success() {
        return 0;
    }
    let txt = String::from_utf8_lossy(&out.stdout);
    let mut parts = txt.split_whitespace();
    let total = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let avail = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    if total == 0 {
        return 0;
    }
    let used = total.saturating_sub(avail);
    ((used as f64 * 100.0 / total as f64).round() as i64).clamp(0, 100) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use agy_net::NetConfig;
    use tempfile::TempDir;

    #[tokio::test]
    async fn agy_cmd_runs_as_the_users_account_home() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let fake = dir.path().join("agy");
        std::fs::write(&fake, "#!/bin/sh\necho \"HOME=$HOME ARGS=$*\"\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let primary = dir.path().join("rootp");
        std::fs::create_dir_all(primary.join(".gemini/antigravity-cli")).unwrap();
        let state = dir.path().join("state");
        let pool = agy_core::accounts::AccountStore::open(state.join("accounts.json"), state.join("accounts"), &primary).unwrap();
        let a1 = pool.add_slot("b").unwrap();
        let cli = a1.home.join(".gemini/antigravity-cli");
        std::fs::create_dir_all(&cli).unwrap();
        std::fs::write(cli.join("antigravity-oauth-token"), r#"{"token":{"refresh_token":"r"},"id_token_email":"b@x.io"}"#).unwrap();
        pool.finish_login(&a1.id).unwrap();
        pool.record_success(&a1.id, Some(42));
        let (_, out, _) = agy_cmd_as(&fake, dir.path(), Some(&pool), None, Some(42), &["mcp", "list"], 10.0).await.unwrap();
        assert!(out.contains(&format!("HOME={}", a1.home.display())), "{out}");
        assert!(out.contains("ARGS=mcp list"));
        // no uid -> process HOME (primary)
        let (_, out, _) = agy_cmd_as(&fake, dir.path(), Some(&pool), None, None, &["agents"], 10.0).await.unwrap();
        assert!(!out.contains(&a1.home.display().to_string()), "{out}");
    }

    #[tokio::test]
    async fn bot_ctx_initializes_models_ui_and_snapshot() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(
            state_dir.join("models.json"),
            r#"[{"id":"gemini-3-pro","name":"Gemini 3 Pro"}]"#,
        )
        .unwrap();

        let cfg = Arc::new(Config {
            bot_token: "1:t".into(),
            state_dir: state_dir.clone(),
            agy_workspace: dir.path().to_path_buf(),
            owner_id: 1000000001,
            ..Default::default()
        });
        let store = Arc::new(StateStore::open(cfg.state_path()).unwrap());
        let acl = Arc::new(AclStore::open(cfg.acl_path(), 1000000001, &[], 300).unwrap());
        let outbox = Arc::new(OutQueue::open(cfg.outbox_path()).unwrap());
        let health = Arc::new(HealthTracker::new(cfg.health_path()));
        let premium = Arc::new(PremiumState::new(true));
        let pool = Arc::new(ProxyPool::new(NetConfig::default()).unwrap());
        let client = Arc::new(BotApiClient::new("1:t", NetConfig::default()).unwrap());
        let widgets = Arc::new(WidgetStore::from_state_dir(&state_dir).unwrap());
        let render = Arc::new(RenderBridge::new(
            Arc::clone(&client),
            Arc::clone(&premium),
            Arc::clone(&outbox),
        ));
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

        assert!(ctx.is_owner(1000000001));
        assert!(!ctx.is_owner(999));
        assert_eq!(ctx.model_label(Some("gemini-3-pro")), "Gemini 3 Pro");
        assert_eq!(BotCtx::short(Some("abcdefghijk"), 5), "abcde…");

        // Owner Page 0 (AI & Chat): models, proxies, and 3-tab switcher
        let mk_owner_p0 = ctx.main_kb_page(1000000001, false, 0);
        assert!(mk_owner_p0
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.callback_data.as_deref() == Some("px:list")));
        assert!(mk_owner_p0
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.callback_data.as_deref() == Some("home:2")));

        // Owner Page 1 (Tools & Net): MCP, Skills, Settings, Proxies
        let mk_owner_p1 = ctx.main_kb_page(1000000001, false, 1);
        assert!(mk_owner_p1
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.callback_data.as_deref() == Some("mcp")));
        assert!(mk_owner_p1
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.callback_data.as_deref() == Some("px:list")));

        // Owner Page 2 (Admin & Accounting): Accounts, Policy, Proxies, Users, Secretary
        let mk_owner_p2 = ctx.main_kb_page(1000000001, false, 2);
        assert!(mk_owner_p2
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.callback_data.as_deref() == Some("acct:list")));
        assert!(mk_owner_p2
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.callback_data.as_deref() == Some("acct:pol")));
        assert!(mk_owner_p2
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.callback_data.as_deref() == Some("uadm:list:all:0")));
        assert!(mk_owner_p2
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.callback_data.as_deref() == Some("biz:p")));

        // Locked non-owner user sees ONLY minimal chat buttons (no dashboard modules)
        let _ = ctx
            .acl
            .set_status(999, agy_core::acl::UserStatus::Approved, Some(1000000001), None);
        let mk_locked = ctx.main_kb(999, true);
        assert_eq!(mk_locked.inline_keyboard.len(), 2);
        assert!(mk_locked
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.style.as_deref() == Some("danger")));
        assert!(!mk_locked
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.callback_data.as_deref() == Some("models:0")));

        // Custom user with dashboard_access + uncensored sees only those modules (and page 2 is clamped!)
        ctx.acl.set_perm(999, "dashboard_access", Some(true)).unwrap();
        ctx.acl.set_perm(999, "uncensored", Some(true)).unwrap();
        let mk_custom = ctx.main_kb_page(999, false, 2);
        assert!(mk_custom
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.callback_data.as_deref() == Some("umodels:0")));
        assert!(!mk_custom
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.callback_data.as_deref() == Some("uadm:list:all:0")));
        assert!(!mk_custom
            .inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.callback_data.as_deref() == Some("acct:list")));

        // Persian localization changes dashboard text & commands
        crate::i18n::set_user_lang(&ctx, 1000000001, crate::i18n::Lang::Fa).unwrap();
        let dash_fa = ctx.dashboard_text(1000000001);
        assert!(dash_fa.contains("داشبورد"));
        let cmds_fa = ctx.effective_commands(1000000001);
        assert!(cmds_fa.iter().any(|c| c.command == "lang"));

        let snap = ctx.sys_snapshot(1000000001);
        assert_eq!(snap["service"], "active");
        assert!(snap["polling"]["mode"].is_string());
    }
}
