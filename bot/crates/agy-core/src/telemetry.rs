//! Native deterministic zero-token quota telemetry & burn advisor (adapted from
//! `IMYin/google-ultra-maximizer` `burn_advisor.py` & `telemetry.py`).
//!
//! Strictly local, zero network I/O, zero credential exposure (all emails are privacy-masked).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::accounts::{Account, AccountPolicy, HealthStatus, WINDOW_5H_SECS};

/// Global pool routing recommendation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    /// Both 5h and 7d headroom are plentiful across primary pools.
    DualReady,
    /// 5h window is resetting soon while weekly headroom is high: harvest remaining 5h quota.
    Harvest5h,
    /// Weekly usage is approaching the 1% reserve: shift overflow to Grok / Gemini Web / Venice.
    ProtectWeekly,
    /// Multiple pools are constrained or cooling down: conserve capacity and use lightweight modes.
    Conserve,
    /// Normal balanced load across pools.
    Balanced,
}

impl RoutingMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DualReady => "dual_ready",
            Self::Harvest5h => "harvest_5h",
            Self::ProtectWeekly => "protect_weekly",
            Self::Conserve => "conserve",
            Self::Balanced => "balanced",
        }
    }

    pub fn label_en(&self) -> &'static str {
        match self {
            Self::DualReady => "Dual Ready",
            Self::Harvest5h => "Harvest 5h Window",
            Self::ProtectWeekly => "Protect Weekly Reserve",
            Self::Conserve => "Conserve Capacity",
            Self::Balanced => "Balanced",
        }
    }

    pub fn label_fa(&self) -> &'static str {
        match self {
            Self::DualReady => "آماده (ظرفیت کامل)",
            Self::Harvest5h => "بهره‌برداری از پنجره ۵ ساعته",
            Self::ProtectWeekly => "محافظت از سهمیه هفتگی",
            Self::Conserve => "صرفه‌جویی در مصرف",
            Self::Balanced => "متعادل",
        }
    }
}

/// Snapshot of a single quota window (5-hour rolling or 7-day weekly).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolWindow {
    pub used_tokens: u64,
    pub budget_tokens: Option<u64>,
    pub used_pct: Option<f64>,
    pub remaining_pct: Option<f64>,
    pub reset_in_secs: u64,
    pub is_reserved: bool,
}

/// Operational status of one account or provider pool card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Ready,
    Cooldown,
    Reserved,
    Disabled,
    Unconfigured,
}

impl PoolStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Cooldown => "cooldown",
            Self::Reserved => "reserved",
            Self::Disabled => "disabled",
            Self::Unconfigured => "unconfigured",
        }
    }
}

/// One sanitized pool/account card rendered in `/quota` and the `telemetry` widget.
/// NEVER stores raw emails, tokens, or proxy passwords.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolCard {
    pub pool_id: String,
    pub engine: String,
    pub label: String,
    pub masked_identity: String,
    pub status: PoolStatus,
    pub window_5h: Option<PoolWindow>,
    pub window_7d: Option<PoolWindow>,
    pub in_flight: u32,
    pub sticky_proxy_ok: bool,
    pub cooldown_secs: u64,
    pub steps_24h: Option<u64>,
    pub source: String,
}

/// Severity level for deterministic burn-rate advice items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdviceSeverity {
    Info,
    Tip,
    Warn,
}

/// Actionable zero-token burn/routing recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnAdvice {
    pub severity: AdviceSeverity,
    pub pool_id: String,
    pub title_en: String,
    pub title_fa: String,
    pub detail_en: String,
    pub detail_fa: String,
}

/// Top-level routing verdict across all configured engines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingVerdict {
    pub mode: RoutingMode,
    pub recommended_pool: String,
    pub recommended_engine: String,
    pub reason_en: String,
    pub reason_fa: String,
}

/// Complete telemetry cockpit snapshot shared by `/quota`, `telemetry` widget, and WebApp bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub generated_at: i64,
    pub pools: Vec<PoolCard>,
    pub verdict: RoutingVerdict,
    pub advice: Vec<BurnAdvice>,
    pub active_jobs: usize,
    pub max_jobs: usize,
    pub ls_rpc_live: bool,
    pub sqlite_steps_24h: Option<u64>,
}

/// Build sanitized Antigravity [`PoolCard`]s from `AccountStore` state without exposing raw emails.
pub fn build_agy_pool_cards(
    accounts: &[Account],
    pol: &AccountPolicy,
    in_flight: &HashMap<String, u32>,
    proxy_ok_map: &HashMap<String, bool>,
    now: i64,
    steps_24h_by_acct: Option<&HashMap<String, u64>>,
) -> Vec<PoolCard> {
    let mut cards = Vec::with_capacity(accounts.len());
    for a in accounts {
        let mut usage = a.usage.clone();
        usage.roll_windows(now);
        let inf = *in_flight.get(&a.id).unwrap_or(&0);
        let px_ok = *proxy_ok_map.get(&a.id).unwrap_or(&true);
        let cooldown_secs = match (a.health.status, a.health.until_ts) {
            (HealthStatus::Cooldown, Some(u)) if u > now => (u - now) as u64,
            _ => 0,
        };
        let reserved = usage.is_weekly_reserved(now, pol);
        let status = if !a.enabled || a.health.status == HealthStatus::Disabled {
            PoolStatus::Disabled
        } else if !px_ok || cooldown_secs > 0 {
            PoolStatus::Cooldown
        } else if reserved {
            PoolStatus::Reserved
        } else {
            PoolStatus::Ready
        };

        let reset_5h = if usage.window_5h_start_ts > 0 {
            (usage.window_5h_start_ts + WINDOW_5H_SECS - now).max(0) as u64
        } else {
            WINDOW_5H_SECS as u64
        };
        let reset_7d = (usage.weekly_reset_ts(now) - now).max(0) as u64;
        let wk_budget = usage.effective_weekly_budget(pol);
        let wk_used_pct = usage.weekly_used_pct_at(now, pol);
        let wk_rem_pct = wk_used_pct.map(|p| (100.0 - p).clamp(0.0, 100.0));
        let steps = steps_24h_by_acct.and_then(|m| m.get(&a.id).copied());

        cards.push(PoolCard {
            pool_id: a.id.clone(),
            engine: "agy".to_string(),
            label: a.display_name(),
            masked_identity: a.masked_email().unwrap_or_else(|| a.id.clone()),
            status,
            window_5h: Some(PoolWindow {
                used_tokens: usage.tokens_5h,
                budget_tokens: None,
                used_pct: None,
                remaining_pct: None,
                reset_in_secs: reset_5h,
                is_reserved: false,
            }),
            window_7d: Some(PoolWindow {
                used_tokens: usage.tokens_week,
                budget_tokens: wk_budget,
                used_pct: wk_used_pct,
                remaining_pct: wk_rem_pct,
                reset_in_secs: reset_7d,
                is_reserved: reserved,
            }),
            in_flight: inf,
            sticky_proxy_ok: px_ok,
            cooldown_secs,
            steps_24h: steps,
            source: if steps.is_some() {
                "accounts.json+sqlite".to_string()
            } else {
                "accounts.json".to_string()
            },
        });
    }
    cards
}

/// Deterministic zero-token burn-rate advice across all pools.
pub fn build_burn_recommendations(pools: &[PoolCard]) -> Vec<BurnAdvice> {
    let mut advice = Vec::new();
    let ready_agy: Vec<&PoolCard> = pools
        .iter()
        .filter(|p| p.engine == "agy" && p.status == PoolStatus::Ready && p.sticky_proxy_ok)
        .collect();
    let alt_ready: Vec<&PoolCard> = pools
        .iter()
        .filter(|p| p.engine != "agy" && p.status == PoolStatus::Ready && p.sticky_proxy_ok)
        .collect();

    for p in pools {
        if !p.sticky_proxy_ok && p.status != PoolStatus::Disabled && p.status != PoolStatus::Unconfigured {
            advice.push(BurnAdvice {
                severity: AdviceSeverity::Warn,
                pool_id: p.pool_id.clone(),
                title_en: format!("{} sticky proxy blocked", p.label),
                title_fa: format!("پروکسی اختصاصی {} مسدود است", p.label),
                detail_en: "Fail-closed guard skipped this pool to prevent direct IP leakage. Check /proxies.".to_string(),
                detail_fa: "گارد Fail-Closed برای جلوگیری از نشت IP مستقیم این استخر را متوقف کرد. /proxies را بررسی کنید.".to_string(),
            });
            continue;
        }
        if let Some(ref w7) = p.window_7d {
            if w7.is_reserved {
                advice.push(BurnAdvice {
                    severity: AdviceSeverity::Warn,
                    pool_id: p.pool_id.clone(),
                    title_en: format!("{} parked at weekly reserve", p.label),
                    title_fa: format!("{} در رزرو هفتگی پارک شد", p.label),
                    detail_en: format!(
                        "Weekly reserve active (~{}h to reset). Route overflow to another healthy pool.",
                        (w7.reset_in_secs / 3600).max(1)
                    ),
                    detail_fa: format!(
                        "رزرو هفتگی فعال است (حدود {} ساعت تا ریست). درخواست‌های جدید را به استخر سالم دیگر هدایت کنید.",
                        (w7.reset_in_secs / 3600).max(1)
                    ),
                });
            } else if let Some(pct) = w7.used_pct {
                if pct >= 85.0 {
                    advice.push(BurnAdvice {
                        severity: AdviceSeverity::Warn,
                        pool_id: p.pool_id.clone(),
                        title_en: format!("{} weekly usage at {:.0}%", p.label, pct),
                        title_fa: format!("مصرف هفتگی {} به {:.0}% رسید", p.label, pct),
                        detail_en: "Offload lightweight chats to Grok or Gemini Web to protect weekly reserve.".to_string(),
                        detail_fa: "چت‌های سبک را به Grok یا Gemini Web منتقل کنید تا سهمیه هفتگی حفظ شود.".to_string(),
                    });
                } else if pct <= 55.0 {
                    if let Some(ref w5) = p.window_5h {
                        if w5.reset_in_secs <= 3600 && w5.used_tokens > 0 && p.status == PoolStatus::Ready {
                            advice.push(BurnAdvice {
                                severity: AdviceSeverity::Tip,
                                pool_id: p.pool_id.clone(),
                                title_en: format!("Harvest {} 5h window", p.label),
                                title_fa: format!("بهره‌برداری از پنجره ۵ ساعته {}", p.label),
                                detail_en: format!(
                                    "5h window resets in {}m while weekly usage is only {:.0}% — ideal for heavy coding turns now.",
                                    (w5.reset_in_secs / 60).max(1),
                                    pct
                                ),
                                detail_fa: format!(
                                    "پنجره ۵ ساعته تا {} دقیقه دیگر ریست می‌شود و مصرف هفتگی فقط {:.0}% است — زمان عالی برای تسک‌های سنگین.",
                                    (w5.reset_in_secs / 60).max(1),
                                    pct
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    if ready_agy.is_empty() && !alt_ready.is_empty() {
        let alt = alt_ready[0];
        advice.push(BurnAdvice {
            severity: AdviceSeverity::Tip,
            pool_id: alt.pool_id.clone(),
            title_en: format!("Use {} while Antigravity recovers", alt.label),
            title_fa: format!("استفاده از {} تا بازیابی Antigravity", alt.label),
            detail_en: "Zero Antigravity slots are ready right now; fallback pool is healthy.".to_string(),
            detail_fa: "هیچ اسلات Antigravity هم‌اکنون آماده نیست؛ استخر جایگزین سالم و آماده است.".to_string(),
        });
    } else if ready_agy.len() == 1 && !alt_ready.is_empty() {
        advice.push(BurnAdvice {
            severity: AdviceSeverity::Info,
            pool_id: ready_agy[0].pool_id.clone(),
            title_en: "Single active AGY account — pair with overflow pool".to_string(),
            title_fa: "فقط ۱ اکانت AGY فعال است — از استخر کمکی استفاده کنید".to_string(),
            detail_en: format!(
                "With 2 owners sharing 1 active AGY slot, use {} for concurrent tasks to avoid waiting.",
                alt_ready[0].label
            ),
            detail_fa: format!(
                "با ۲ اونر روی ۱ اکانت فعال AGY، برای کار هم‌زمان بدون انتظار از {} استفاده کنید.",
                alt_ready[0].label
            ),
        });
    }

    advice.truncate(6);
    advice
}

/// Compute a single deterministic routing verdict across all pools.
pub fn compute_routing_verdict(pools: &[PoolCard]) -> RoutingVerdict {
    let mut ready_agy: Vec<&PoolCard> = pools
        .iter()
        .filter(|p| p.engine == "agy" && p.status == PoolStatus::Ready && p.sticky_proxy_ok)
        .collect();
    ready_agy.sort_by(|a, b| {
        let pa = a.window_7d.as_ref().and_then(|w| w.used_pct).unwrap_or(0.0);
        let pb = b.window_7d.as_ref().and_then(|w| w.used_pct).unwrap_or(0.0);
        a.in_flight.cmp(&b.in_flight).then_with(|| pa.total_cmp(&pb))
    });

    let alt_ready: Vec<&PoolCard> = pools
        .iter()
        .filter(|p| p.engine != "agy" && p.status == PoolStatus::Ready && p.sticky_proxy_ok)
        .collect();

    if let Some(best_agy) = ready_agy.first() {
        let wk_pct = best_agy.window_7d.as_ref().and_then(|w| w.used_pct).unwrap_or(0.0);
        let reset_5h = best_agy.window_5h.as_ref().map(|w| w.reset_in_secs).unwrap_or(WINDOW_5H_SECS as u64);

        if wk_pct >= 88.0 {
            if let Some(alt) = alt_ready.first() {
                return RoutingVerdict {
                    mode: RoutingMode::ProtectWeekly,
                    recommended_pool: alt.pool_id.clone(),
                    recommended_engine: alt.engine.clone(),
                    reason_en: format!(
                        "{} is at {:.0}% weekly usage; route to {} to preserve weekly reserve.",
                        best_agy.label, wk_pct, alt.label
                    ),
                    reason_fa: format!(
                        "مصرف هفتگی {} به {:.0}% رسیده؛ برای حفظ رزرو هفتگی از {} استفاده کنید.",
                        best_agy.label, wk_pct, alt.label
                    ),
                };
            }
            return RoutingVerdict {
                mode: RoutingMode::Conserve,
                recommended_pool: best_agy.pool_id.clone(),
                recommended_engine: "agy".to_string(),
                reason_en: format!(
                    "{} is at {:.0}% weekly usage with no overflow pool ready; conserve quota.",
                    best_agy.label, wk_pct
                ),
                reason_fa: format!(
                    "مصرف هفتگی {} به {:.0}% رسیده و استخر کمکی آماده نیست؛ مصرف را کنترل کنید.",
                    best_agy.label, wk_pct
                ),
            };
        }

        if wk_pct <= 60.0 && reset_5h <= 3600 {
            return RoutingVerdict {
                mode: RoutingMode::Harvest5h,
                recommended_pool: best_agy.pool_id.clone(),
                recommended_engine: "agy".to_string(),
                reason_en: format!(
                    "{} 5h window resets in {}m with ample weekly headroom — ideal for deep tasks.",
                    best_agy.label,
                    (reset_5h / 60).max(1)
                ),
                reason_fa: format!(
                    "پنجره ۵ ساعته {} تا {} دقیقه دیگر ریست می‌شود و فضای هفتگی کافی است — مناسب تسک‌های سنگین.",
                    best_agy.label,
                    (reset_5h / 60).max(1)
                ),
            };
        }

        if ready_agy.len() >= 2 && wk_pct < 70.0 {
            return RoutingVerdict {
                mode: RoutingMode::DualReady,
                recommended_pool: best_agy.pool_id.clone(),
                recommended_engine: "agy".to_string(),
                reason_en: format!(
                    "{} healthy Antigravity pools ready; best pick is {}.",
                    ready_agy.len(),
                    best_agy.label
                ),
                reason_fa: format!(
                    "{} استخر سالم Antigravity آماده است؛ بهترین انتخاب {} می‌باشد.",
                    ready_agy.len(),
                    best_agy.label
                ),
            };
        }

        return RoutingVerdict {
            mode: RoutingMode::Balanced,
            recommended_pool: best_agy.pool_id.clone(),
            recommended_engine: "agy".to_string(),
            reason_en: format!(
                "{} is healthy and ready ({} overflow pool(s) available).",
                best_agy.label,
                alt_ready.len()
            ),
            reason_fa: format!(
                "{} سالم و آماده است ({} استخر کمکی نیز در دسترس است).",
                best_agy.label,
                alt_ready.len()
            ),
        };
    }

    if let Some(alt) = alt_ready.first() {
        return RoutingVerdict {
            mode: RoutingMode::ProtectWeekly,
            recommended_pool: alt.pool_id.clone(),
            recommended_engine: alt.engine.clone(),
            reason_en: format!(
                "No Antigravity slot is ready; routing to healthy overflow pool {}.",
                alt.label
            ),
            reason_fa: format!(
                "هیچ اسلات Antigravity آماده نیست؛ هدایت به استخر کمکی سالم {}.",
                alt.label
            ),
        };
    }

    RoutingVerdict {
        mode: RoutingMode::Conserve,
        recommended_pool: "none".to_string(),
        recommended_engine: "agy".to_string(),
        reason_en: "All pools are cooling down, reserved, or unconfigured. Check /accounts & /proxies.".to_string(),
        reason_fa: "همه استخرها در انتظار، رزرو یا غیرفعال هستند. /accounts و /proxies را بررسی کنید.".to_string(),
    }
}

/// Assemble a complete [`TelemetrySnapshot`].
pub fn assemble_snapshot(
    now: i64,
    pools: Vec<PoolCard>,
    active_jobs: usize,
    max_jobs: usize,
    ls_rpc_live: bool,
    sqlite_steps_24h: Option<u64>,
) -> TelemetrySnapshot {
    let verdict = compute_routing_verdict(&pools);
    let advice = build_burn_recommendations(&pools);
    TelemetrySnapshot {
        generated_at: now,
        pools,
        verdict,
        advice,
        active_jobs,
        max_jobs,
        ls_rpc_live,
        sqlite_steps_24h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::WINDOW_WEEK_SECS;

    fn mk_card(id: &str, engine: &str, status: PoolStatus, wk_pct: Option<f64>, reset_5h: u64) -> PoolCard {
        PoolCard {
            pool_id: id.into(),
            engine: engine.into(),
            label: id.into(),
            masked_identity: "ab…yz@example.com".into(),
            status,
            window_5h: Some(PoolWindow {
                used_tokens: 150_000,
                budget_tokens: None,
                used_pct: None,
                remaining_pct: None,
                reset_in_secs: reset_5h,
                is_reserved: false,
            }),
            window_7d: wk_pct.map(|p| PoolWindow {
                used_tokens: (p * 10_000.0) as u64,
                budget_tokens: Some(1_000_000),
                used_pct: Some(p),
                remaining_pct: Some((100.0 - p).max(0.0)),
                reset_in_secs: WINDOW_WEEK_SECS as u64,
                is_reserved: p >= 99.0,
            }),
            in_flight: 0,
            sticky_proxy_ok: true,
            cooldown_secs: 0,
            steps_24h: Some(12),
            source: "accounts.json".into(),
        }
    }

    #[test]
    fn routing_verdict_covers_dual_ready_harvest_protect_and_conserve() {
        let dual = vec![
            mk_card("acc1", "agy", PoolStatus::Ready, Some(20.0), 9000),
            mk_card("acc2", "agy", PoolStatus::Ready, Some(30.0), 9000),
        ];
        assert_eq!(compute_routing_verdict(&dual).mode, RoutingMode::DualReady);

        let harvest = vec![mk_card("acc1", "agy", PoolStatus::Ready, Some(40.0), 1800)];
        let hv = compute_routing_verdict(&harvest);
        assert_eq!(hv.mode, RoutingMode::Harvest5h);
        assert!(build_burn_recommendations(&harvest)
            .iter()
            .any(|a| a.severity == AdviceSeverity::Tip));

        let protect = vec![
            mk_card("acc1", "agy", PoolStatus::Ready, Some(92.0), 9000),
            mk_card("grok", "grok", PoolStatus::Ready, None, 0),
        ];
        let pv = compute_routing_verdict(&protect);
        assert_eq!(pv.mode, RoutingMode::ProtectWeekly);
        assert_eq!(pv.recommended_engine, "grok");

        let conserve = vec![mk_card("acc1", "agy", PoolStatus::Reserved, Some(99.5), 9000)];
        let cv = compute_routing_verdict(&conserve);
        assert_eq!(cv.mode, RoutingMode::Conserve);
        assert!(build_burn_recommendations(&conserve)
            .iter()
            .any(|a| a.severity == AdviceSeverity::Warn));
    }

    #[test]
    fn telemetry_snapshot_never_exposes_raw_emails() {
        let mut acc = Account {
            id: "acc3".into(),
            label: "work".into(),
            home: std::path::PathBuf::from("/tmp/acc3"),
            email: Some("supersecret.personal@example.com".into()),
            enabled: true,
            priority: 0,
            created_ts: 1000,
            health: Default::default(),
            usage: Default::default(),
            proxy_id: None,
        };
        acc.usage.tokens_5h = 50_000;
        let cards = build_agy_pool_cards(
            &[acc],
            &AccountPolicy::balanced(),
            &HashMap::new(),
            &HashMap::new(),
            2000,
            None,
        );
        let snap = assemble_snapshot(2000, cards, 0, 4, false, None);
        let serialized = serde_json::to_string(&snap).unwrap();
        assert!(!serialized.contains("supersecret.personal@example.com"));
        assert!(serialized.contains("su…al@example.com"));
    }
}
