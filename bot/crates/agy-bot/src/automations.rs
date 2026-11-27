//! Scheduled automations: a saved prompt that the bot runs on a schedule as a normal agy turn
//! (fresh, isolated conversation; the user's current session is not touched) and delivers to
//! the user's private chat. Owner always allowed; other users need the `automations` permission.
//!
//! Schedules (UTC): `every 30m|2h|1d`, `daily HH:MM`, `weekly mon HH:MM`, `weekdays HH:MM`,
//! or a 5/6-field cron expression. Minimum interval: 15 min (owner 5 min).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use agy_core::tg::{CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message};
use agy_render::markdown::esc;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::ctx::BotCtx;
use crate::i18n::{t, Tx};
use crate::jobs::{EnqueueOutcome, JobRequest};

pub const PERM: &str = "automations";
const MAX_PER_USER: usize = 10;
const MAX_OWNER: usize = 30;
const MIN_INTERVAL_SECS: i64 = 15 * 60;
const MIN_INTERVAL_OWNER_SECS: i64 = 5 * 60;
const MAX_PROMPT_CHARS: usize = 3000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Automation {
    pub id: String,
    pub uid: i64,
    /// User-facing schedule text (as typed, normalised).
    pub schedule: String,
    /// `every:<secs>` or a 6-field cron expression understood by `cron::Schedule`.
    pub spec: String,
    pub prompt: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub created: i64,
    #[serde(default)]
    pub last_run: Option<i64>,
    #[serde(default)]
    pub next_run: Option<i64>,
    #[serde(default)]
    pub runs: u32,
    #[serde(default)]
    pub last_status: Option<String>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AutoFile {
    #[serde(default)]
    items: Vec<Automation>,
}

pub struct AutoStore {
    path: PathBuf,
    data: Mutex<AutoFile>,
}

static STORES: OnceLock<DashMap<PathBuf, Arc<AutoStore>>> = OnceLock::new();

impl AutoStore {
    pub fn open(path: PathBuf) -> Self {
        let data = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<AutoFile>(&b).ok())
            .unwrap_or_default();
        Self { path, data: Mutex::new(data) }
    }
    pub fn list(&self) -> Vec<Automation> {
        self.data.lock().map(|g| g.items.clone()).unwrap_or_default()
    }
    pub fn of_user(&self, uid: i64) -> Vec<Automation> {
        self.list().into_iter().filter(|a| a.uid == uid).collect()
    }
    pub fn mutate<R>(&self, f: impl FnOnce(&mut Vec<Automation>) -> R) -> R {
        let mut g = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let r = f(&mut g.items);
        if let Err(e) = agy_core::atomic::atomic_write_bytes(&self.path, &serde_json::to_vec_pretty(&*g).unwrap_or_default(), 0o600) {
            warn!(error = %e, "automations.json write failed");
        }
        r
    }
}

pub fn store(ctx: &BotCtx) -> Arc<AutoStore> {
    let map = STORES.get_or_init(DashMap::new);
    let path = ctx.cfg.state_dir.join("automations.json");
    map.entry(path.clone()).or_insert_with(|| Arc::new(AutoStore::open(path))).clone()
}

// ---------------------------------------------------------------------------------------------
// Schedule parsing
// ---------------------------------------------------------------------------------------------

fn hhmm(s: &str) -> Option<(u32, u32)> {
    let (h, m) = s.trim().split_once(':').unwrap_or((s.trim(), "0"));
    let (h, m) = (h.parse::<u32>().ok()?, m.parse::<u32>().ok()?);
    (h < 24 && m < 60).then_some((h, m))
}

fn dow(s: &str) -> Option<&'static str> {
    let d = s.trim().to_ascii_lowercase();
    let k = d.get(..3)?;
    Some(match k {
        "mon" => "Mon",
        "tue" => "Tue",
        "wed" => "Wed",
        "thu" => "Thu",
        "fri" => "Fri",
        "sat" => "Sat",
        "sun" => "Sun",
        _ => return None,
    })
}

/// Parse a schedule text into an internal spec.
pub fn parse_schedule(text: &str) -> Result<String, String> {
    let t = text.trim();
    let low = t.to_ascii_lowercase();
    let words: Vec<&str> = low.split_whitespace().collect();
    match words.as_slice() {
        ["every", n] => {
            let (num, unit) = n.split_at(n.find(|c: char| !c.is_ascii_digit()).unwrap_or(n.len()));
            let num: i64 = num.parse().map_err(|_| "use e.g. every 30m, every 2h, every 1d".to_string())?;
            let mult = match unit {
                "m" | "min" | "mins" => 60,
                "h" | "hr" | "hour" | "hours" => 3600,
                "d" | "day" | "days" => 86400,
                _ => return Err("unit must be m, h or d".into()),
            };
            if num <= 0 {
                return Err("interval must be positive".into());
            }
            let secs = num.checked_mul(mult).ok_or_else(|| "interval is too large".to_string())?;
            Ok(format!("every:{secs}"))
        }
        ["daily", at] => {
            let (h, m) = hhmm(at).ok_or("time must be HH:MM")?;
            Ok(format!("0 {m} {h} * * *"))
        }
        ["weekdays", at] => {
            let (h, m) = hhmm(at).ok_or("time must be HH:MM")?;
            Ok(format!("0 {m} {h} * * Mon-Fri"))
        }
        ["weekly", d, at] => {
            let d = dow(d).ok_or("day must be mon..sun")?;
            let (h, m) = hhmm(at).ok_or("time must be HH:MM")?;
            Ok(format!("0 {m} {h} * * {d}"))
        }
        _ => {
            crate::cron::parse_cron_schedule(t).map_err(|e| e.to_string())?;
            Ok(t.to_string())
        }
    }
}

/// Next fire time strictly after `after` (unix secs).
pub fn next_after(spec: &str, after: i64) -> Option<i64> {
    if let Some(secs) = spec.strip_prefix("every:") {
        let s: i64 = secs.parse().ok()?;
        return Some(after + s.max(60));
    }
    let sched = crate::cron::parse_cron_schedule(spec).ok()?;
    let dt = DateTime::<Utc>::from_timestamp(after, 0)?;
    sched.after(&dt).next().map(|d| d.timestamp())
}

/// Smallest gap between the next few fire times (used for the minimum interval check).
pub fn min_gap(spec: &str, now: i64) -> Option<i64> {
    let mut t = now;
    let mut prev: Option<i64> = None;
    let mut gap: Option<i64> = None;
    for _ in 0..6 {
        let n = next_after(spec, t)?;
        if let Some(p) = prev {
            gap = Some(gap.map_or(n - p, |g: i64| g.min(n - p)));
        }
        prev = Some(n);
        t = n;
    }
    gap
}

pub fn fmt_ts(ts: Option<i64>) -> String {
    ts.and_then(|t| DateTime::<Utc>::from_timestamp(t, 0))
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "—".into())
}

fn new_id() -> String {
    use rand::Rng;
    let n: u32 = rand::thread_rng().gen();
    format!("{:06x}", n & 0xff_ffff)
}

fn allowed(ctx: &BotCtx, uid: i64) -> bool {
    ctx.is_owner(uid) || ctx.has_perm(uid, PERM)
}

/// Create an automation after validation. Returns the record or a user-facing error.
pub fn create(ctx: &BotCtx, uid: i64, schedule: &str, prompt: &str, now: i64) -> Result<Automation, String> {
    let owner = ctx.is_owner(uid);
    let prompt = prompt.trim();
    if prompt.is_empty() {
        return Err("prompt is empty".into());
    }
    if prompt.chars().count() > MAX_PROMPT_CHARS {
        return Err(format!("prompt is longer than {MAX_PROMPT_CHARS} characters"));
    }
    let spec = parse_schedule(schedule)?;
    let min = if owner { MIN_INTERVAL_OWNER_SECS } else { MIN_INTERVAL_SECS };
    match min_gap(&spec, now) {
        Some(g) if g < min => return Err(format!("runs too often (every {} min); minimum is {} min", g / 60, min / 60)),
        None if next_after(&spec, now).is_none() => return Err("schedule never fires".into()),
        _ => {}
    }
    let st = store(ctx);
    let cap = if owner { MAX_OWNER } else { MAX_PER_USER };
    if st.of_user(uid).len() >= cap {
        return Err(format!("limit of {cap} automations reached"));
    }
    let a = Automation {
        id: new_id(),
        uid,
        schedule: schedule.trim().to_string(),
        next_run: next_after(&spec, now),
        spec,
        prompt: prompt.to_string(),
        enabled: true,
        created: now,
        last_run: None,
        runs: 0,
        last_status: None,
    };
    st.mutate(|v| v.push(a.clone()));
    Ok(a)
}

/// Items due at `now` (enabled, next_run <= now). Advances their next_run.
pub fn take_due(st: &AutoStore, now: i64) -> Vec<Automation> {
    st.mutate(|v| {
        let mut due = Vec::new();
        for a in v.iter_mut().filter(|a| a.enabled) {
            match a.next_run {
                Some(t) if t <= now => {
                    due.push(a.clone());
                    a.last_run = Some(now);
                    a.runs += 1;
                    a.next_run = next_after(&a.spec, now);
                }
                None => a.next_run = next_after(&a.spec, now),
                _ => {}
            }
        }
        due
    })
}

fn set_status(st: &AutoStore, id: &str, status: &str) {
    st.mutate(|v| {
        if let Some(a) = v.iter_mut().find(|a| a.id == id) {
            a.last_status = Some(status.to_string());
        }
    });
}

async fn fire(ctx: &Arc<BotCtx>, a: &Automation, manual: bool) {
    let st = store(ctx);
    if !ctx.is_approved(a.uid) || !allowed(ctx, a.uid) {
        st.mutate(|v| {
            if let Some(x) = v.iter_mut().find(|x| x.id == a.id) {
                x.enabled = false;
                x.last_status = Some("disabled: user lost access".into());
            }
        });
        return;
    }
    let label = ctx
        .acl
        .get_user(a.uid)
        .map(|u| {
            u.username
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| format!("@{s}"))
                .or_else(|| u.first_name.clone().filter(|s| !s.is_empty()))
                .unwrap_or_else(|| format!("uid:{}", a.uid))
        })
        .unwrap_or_else(|| format!("uid:{}", a.uid));
    let text = format!(
        "[automation #{} — {} run at {}; schedule: {}]\n{}",
        a.id,
        if manual { "manual" } else { "scheduled" },
        fmt_ts(Some(Utc::now().timestamp())),
        a.schedule,
        a.prompt
    );
    let _ = ctx
        .render
        .send_html(
            a.uid,
            &format!("⏰ <b>Automation</b> <code>#{}</code> started\n<i>{}</i>", esc(&a.id), esc(&clip(&a.prompt, 300))),
            None,
            None,
            Some(true),
            true,
        )
        .await;
    let mut req = JobRequest::new(a.uid, a.uid, label, text, Vec::new());
    req.overrides.isolated = true;
    req.overrides.force_engine = Some("agy".to_string());
    match ctx.jobs.enqueue(req).await {
        Ok(EnqueueOutcome::QueueFull) => set_status(&st, &a.id, "skipped: queue full"),
        Ok(EnqueueOutcome::RateLimited) => set_status(&st, &a.id, "skipped: burst limited"),
        Ok(EnqueueOutcome::Queued(n)) => {
            if manual {
                let now = Utc::now().timestamp();
                st.mutate(|v| {
                    if let Some(x) = v.iter_mut().find(|x| x.id == a.id) {
                        x.last_run = Some(now);
                        x.runs = x.runs.saturating_add(1);
                    }
                });
            }
            set_status(&st, &a.id, &format!("queued (#{n})"));
        }
        Ok(EnqueueOutcome::StartedImmediately) => {
            if manual {
                let now = Utc::now().timestamp();
                st.mutate(|v| {
                    if let Some(x) = v.iter_mut().find(|x| x.id == a.id) {
                        x.last_run = Some(now);
                        x.runs = x.runs.saturating_add(1);
                    }
                });
            }
            set_status(&st, &a.id, "started");
        }
        Err(e) => set_status(&st, &a.id, &format!("error: {}", clip(&e.to_string(), 120))),
    }
    info!(id = %a.id, uid = a.uid, manual, "automation fired");
}

fn clip(s: &str, n: usize) -> String {
    agy_core::text::clip_ellipsis(s, n)
}

/// Background loop: checks due automations every 20 s.
pub async fn run_loop(ctx: Arc<BotCtx>, mut shutdown: watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            break;
        }
        let st = store(&ctx);
        for a in take_due(&st, Utc::now().timestamp()) {
            fire(&ctx, &a, false).await;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(20)) => {}
            r = shutdown.changed() => { if r.is_err() || *shutdown.borrow() { break; } }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------------------------

const HELP: &str = "<b>⏰ Automations</b> — run a prompt on a schedule (UTC). Each run is a fresh agy turn delivered here; your current chat session is not touched.\n\
<b>Add:</b> <code>/auto add SCHEDULE | PROMPT</code>\n\
Schedules: <code>every 30m</code> · <code>every 2h</code> · <code>every 1d</code> · <code>daily 08:00</code> · <code>weekdays 09:30</code> · <code>weekly mon 10:00</code> · cron <code>0 */6 * * *</code>\n\
Example: <code>/auto add daily 07:30 | Summarise overnight server logs and disk usage</code>\n\
<b>Manage:</b> <code>/auto</code> (list + buttons) · <code>/auto del ID</code> · <code>/auto run ID</code> · <code>/auto off ID</code> · <code>/auto on ID</code>";

fn list_view(ctx: &BotCtx, uid: i64) -> (String, InlineKeyboardMarkup) {
    let st = store(ctx);
    let items = st.of_user(uid);
    let mut txt = String::from(HELP);
    txt.push_str("\n\n");
    if items.is_empty() {
        txt.push_str("<i>No automations yet.</i>");
    }
    let mut rows = Vec::new();
    for a in &items {
        txt.push_str(&format!(
            "{} <code>#{}</code> · <b>{}</b> · next {} · runs {}{}\n<i>{}</i>\n",
            if a.enabled { "🟢" } else { "⏸" },
            esc(&a.id),
            esc(&a.schedule),
            fmt_ts(a.next_run.filter(|_| a.enabled)),
            a.runs,
            a.last_status.as_deref().map(|s| format!(" · {}", esc(s))).unwrap_or_default(),
            esc(&clip(&a.prompt, 160))
        ));
        rows.push(vec![
            InlineKeyboardButton::callback(format!("▶ Run #{}", a.id), format!("auto:run:{}", a.id)),
            InlineKeyboardButton::callback(if a.enabled { "⏸ Pause" } else { "▶️ Resume" }, format!("auto:tog:{}", a.id)),
            InlineKeyboardButton::callback("🗑", format!("auto:del:{}", a.id)),
        ]);
    }
    let lang = ctx.lang(uid);
    rows.push(vec![
        InlineKeyboardButton::callback("🔄 Refresh", "auto:list"),
        ctx.btn("back", t(lang, Tx::BtnMenu), Some("home:1"), None, None),
    ]);
    (txt, InlineKeyboardMarkup::new(rows))
}

pub async fn cmd_auto(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let uid = msg.from_user.as_ref().map(|u| u.id).unwrap_or(0);
    let chat_id = msg.chat.id;
    if !allowed(ctx, uid) {
        let _ = ctx
            .render
            .send_html_simple(chat_id, &crate::i18n::missing_perm_html(ctx, uid, PERM), None)
            .await;
        return;
    }
    let arg = arg.trim();
    let (sub, rest) = arg.split_once(char::is_whitespace).map(|(a, b)| (a, b.trim())).unwrap_or((arg, ""));
    let st = store(ctx);
    let note: Option<String> = match sub.to_ascii_lowercase().as_str() {
        "" | "list" => None,
        "help" => {
            let lang = ctx.lang(uid);
            let mk = BotCtx::kb(vec![vec![
                InlineKeyboardButton::callback("📋 Automations", "auto:list"),
                ctx.btn("back", t(lang, Tx::BtnMenu), Some("home:1"), None, None),
            ]]);
            let _ = ctx.render.send_html_simple(chat_id, HELP, Some(mk)).await;
            return;
        }
        "add" | "new" => match rest.split_once('|') {
            Some((sch, prompt)) => match create(ctx, uid, sch, prompt, Utc::now().timestamp()) {
                Ok(a) => Some(format!("✅ Automation <code>#{}</code> created · next run {}", esc(&a.id), fmt_ts(a.next_run))),
                Err(e) => Some(format!("❌ {}", esc(&e))),
            },
            None => Some("❌ Format: <code>/auto add SCHEDULE | PROMPT</code>".into()),
        },
        "del" | "rm" | "delete" => {
            let target = rest.trim_start_matches('#');
            let n = st.mutate(|v| {
                let before = v.len();
                v.retain(|a| !(a.id == target && (a.uid == uid || ctx.is_owner(uid))));
                before - v.len()
            });
            Some(if n > 0 { format!("🗑 Deleted #{}", esc(target)) } else { "Not found".into() })
        }
        "on" | "off" => {
            let target = rest.trim_start_matches('#');
            let on = sub.eq_ignore_ascii_case("on");
            let now = Utc::now().timestamp();
            let ok = st.mutate(|v| {
                v.iter_mut().find(|a| a.id == target && (a.uid == uid || ctx.is_owner(uid))).map(|a| {
                    a.enabled = on;
                    if on {
                        a.next_run = next_after(&a.spec, now);
                    }
                })
            });
            Some(if ok.is_some() { format!("#{} {}", esc(target), if on { "resumed" } else { "paused" }) } else { "Not found".into() })
        }
        "run" => {
            let target = rest.trim_start_matches('#');
            match st.list().into_iter().find(|a| a.id == target && (a.uid == uid || ctx.is_owner(uid))) {
                Some(a) => {
                    fire(ctx, &a, true).await;
                    return;
                }
                None => Some("Not found".into()),
            }
        }
        _ => Some("Unknown option — /auto help".into()),
    };
    let (mut txt, mk) = list_view(ctx, uid);
    if let Some(n) = note {
        txt = format!("{n}\n\n{txt}");
    }
    let _ = ctx.render.send_html_simple(chat_id, &txt, Some(mk)).await;
}

pub async fn handle_auto_cb(ctx: &Arc<BotCtx>, cq: &CallbackQuery, uid: i64, chat_id: i64, data: &str) -> bool {
    let Some(rest) = data.strip_prefix("auto:") else { return false };
    if !allowed(ctx, uid) {
        ctx.ack(&cq.id, Some("No permission"), true).await;
        return true;
    }
    let st = store(ctx);
    let (verb, id) = rest.split_once(':').unwrap_or((rest, ""));
    let mut toast = None;
    match verb {
        "run" => {
            if let Some(a) = st.of_user(uid).into_iter().find(|a| a.id == id) {
                ctx.ack(&cq.id, Some("Started"), false).await;
                fire(ctx, &a, true).await;
                return true;
            }
            toast = Some("Not found");
        }
        "tog" => {
            let now = Utc::now().timestamp();
            st.mutate(|v| {
                if let Some(a) = v.iter_mut().find(|a| a.id == id && a.uid == uid) {
                    a.enabled = !a.enabled;
                    if a.enabled {
                        a.next_run = next_after(&a.spec, now);
                    }
                }
            });
        }
        "del" => {
            st.mutate(|v| v.retain(|a| !(a.id == id && a.uid == uid)));
            toast = Some("Deleted");
        }
        _ => {}
    }
    ctx.ack(&cq.id, toast, false).await;
    let (txt, mk) = list_view(ctx, uid);
    ctx.edit_or_send(Some(cq), chat_id, &txt, Some(mk)).await;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedules_parse_and_fire_times() {
        let t0 = DateTime::parse_from_rfc3339("2026-11-19T01:00:00Z").unwrap().timestamp();
        assert_eq!(parse_schedule("every 30m").unwrap(), "every:1800");
        assert_eq!(next_after("every:1800", t0), Some(t0 + 1800));
        let d = parse_schedule("daily 07:30").unwrap();
        assert_eq!(fmt_ts(next_after(&d, t0)), "2026-11-19 07:30 UTC");
        let w = parse_schedule("weekly mon 10:00").unwrap();
        assert_eq!(fmt_ts(next_after(&w, t0)), "2026-11-23 10:00 UTC"); // 2026-11-19 is a Thursday
        let wd = parse_schedule("weekdays 09:00").unwrap();
        assert_eq!(fmt_ts(next_after(&wd, t0)), "2026-11-19 09:00 UTC");
        let c = parse_schedule("0 */6 * * *").unwrap();
        assert_eq!(fmt_ts(next_after(&c, t0)), "2026-11-19 06:00 UTC");
        assert_eq!(min_gap(&c, t0), Some(6 * 3600));
        assert!(parse_schedule("every 5x").is_err());
        assert!(parse_schedule("daily 25:00").is_err());
        assert!(parse_schedule("weekly xyz 10:00").is_err());
        assert!(parse_schedule("nonsense here").is_err());
        assert_eq!(min_gap("every:600", t0), Some(600));
    }

    #[test]
    fn take_due_advances_and_persists() {
        let dir = tempfile::TempDir::new().unwrap();
        let st = AutoStore::open(dir.path().join("automations.json"));
        let now = 1_800_000_000;
        st.mutate(|v| {
            v.push(Automation {
                id: "a1".into(), uid: 1, schedule: "every 1h".into(), spec: "every:3600".into(), prompt: "p".into(),
                enabled: true, created: now, last_run: None, next_run: Some(now - 5), runs: 0, last_status: None,
            });
            v.push(Automation {
                id: "a2".into(), uid: 1, schedule: "every 1h".into(), spec: "every:3600".into(), prompt: "p".into(),
                enabled: false, created: now, last_run: None, next_run: Some(now - 5), runs: 0, last_status: None,
            });
        });
        let due = take_due(&st, now);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, "a1");
        assert!(take_due(&st, now + 10).is_empty());
        let back = AutoStore::open(dir.path().join("automations.json"));
        let a1 = back.list().into_iter().find(|a| a.id == "a1").unwrap();
        assert_eq!(a1.next_run, Some(now + 3600));
        assert_eq!(a1.runs, 1);
        assert_eq!(take_due(&back, now + 3600).len(), 1);
    }
}
