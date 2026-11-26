//! Phase 4 local Rust zero-token fast-path responder with strict RBAC enforcement.
//!
//! Answers unambiguous standalone queries (ping/alive, Tehran+UTC time/date, quick status,
//! and pure arithmetic expressions) directly in Rust in <1ms using ZERO AI tokens and ZERO
//! account quota. Any ambiguous or multi-sentence message returns `None` and proceeds
//! transparently to the AI engine.

use std::sync::Arc;

use agy_core::tg::InlineKeyboardMarkup;
use agy_render::esc;
use chrono::{FixedOffset, Utc};

use crate::ctx::BotCtx;

/// Pre-rendered HTML response produced locally without invoking any AI backend.
#[derive(Debug, Clone)]
pub struct LocalFastReply {
    pub kind: &'static str,
    pub html: String,
    pub markup: Option<InlineKeyboardMarkup>,
}

fn normalize_query(raw: &str) -> String {
    raw.trim()
        .trim_end_matches(&['?', '؟', '!', '.', '،'][..])
        .trim()
        .to_ascii_lowercase()
}

fn is_ping_query(norm: &str) -> bool {
    matches!(
        norm,
        "ping"
            | "pong"
            | "alive"
            | "are you online"
            | "are you alive"
            | "پینگ"
            | "آنلاینی"
            | "آنلاین هستی"
            | "بیداری"
            | "زنده ای"
            | "زنده‌ای"
            | "ربات روشنه"
            | "ربات فعاله"
    )
}

fn is_time_query(norm: &str) -> bool {
    matches!(
        norm,
        "time"
            | "date"
            | "what time is it"
            | "current time"
            | "server time"
            | "today date"
            | "ساعت"
            | "ساعت چنده"
            | "الان ساعت چنده"
            | "تاریخ"
            | "تاریخ امروز"
            | "تاریخ امروز چنده"
            | "امروز چه روزیه"
    )
}

fn is_status_query(norm: &str) -> bool {
    matches!(
        norm,
        "bot status"
            | "server status"
            | "pool status"
            | "account status"
            | "proxy status"
            | "وضعیت"
            | "وضعیت ربات"
            | "وضعیت سرور"
            | "وضعیت اکانت"
            | "وضعیت اکانت‌ها"
            | "وضعیت اکانتها"
            | "وضعیت پروکسی"
            | "وضعیت پروکسی‌ها"
            | "وضعیت پروکسیها"
    )
}

/// Safe, panic-free recursive-descent arithmetic parser (`+`, `-`, `*`, `/`, `%`, parentheses).
///
/// Only accepts explicit math prefixes (`= ...`, `calc ...`, `محاسبه ...`) or pure arithmetic
/// strings (`<= 64` chars, at least one operator, only digits/operators/parentheses/spaces).
pub fn try_eval_arithmetic(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 80 || trimmed.contains('\n') {
        return None;
    }

    let expr = if let Some(rest) = trimmed.strip_prefix('=') {
        rest.trim()
    } else if let Some(rest) = trimmed.strip_prefix("calc ").or_else(|| trimmed.strip_prefix("CALC ")) {
        rest.trim()
    } else if let Some(rest) = trimmed.strip_prefix("محاسبه ") {
        rest.trim()
    } else {
        // Pure expression: must contain ONLY arithmetic characters and at least one binary operator + digit.
        if trimmed.len() > 64 {
            return None;
        }
        let has_op = trimmed.bytes().any(|b| matches!(b, b'+' | b'-' | b'*' | b'/' | b'%'));
        let has_digit = trimmed.bytes().any(|b| b.is_ascii_digit());
        let all_valid = trimmed
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b' ' | b'.' | b'+' | b'-' | b'*' | b'/' | b'%' | b'(' | b')'));
        if !has_op || !has_digit || !all_valid {
            return None;
        }
        // Avoid treating dates like "2026-11-24" or phone numbers as subtraction.
        let dash_count = trimmed.bytes().filter(|&b| b == b'-').count();
        let only_dashes = !trimmed.bytes().any(|b| matches!(b, b'+' | b'*' | b'/' | b'%' | b'(' | b')'));
        if only_dashes && dash_count >= 2 && !trimmed.contains(' ') {
            return None;
        }
        trimmed
    };

    if expr.is_empty() || expr.len() > 64 {
        return None;
    }
    if !expr
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b' ' | b'.' | b'+' | b'-' | b'*' | b'/' | b'%' | b'(' | b')'))
    {
        return None;
    }

    let mut parser = MathParser {
        bytes: expr.as_bytes(),
        pos: 0,
        depth: 0,
    };
    let val = parser.parse_expr()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() || !val.is_finite() {
        return None;
    }

    let formatted = if (val - val.round()).abs() < 1e-10 && val.abs() < 1e15 {
        format!("{}", val.round() as i64)
    } else {
        let s = format!("{val:.8}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    };
    Some((expr.to_string(), formatted))
}

struct MathParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> MathParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos] == b' ' {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.bytes.get(self.pos).copied()
    }

    fn parse_expr(&mut self) -> Option<f64> {
        let mut lhs = self.parse_term()?;
        while let Some(op) = self.peek() {
            if op == b'+' || op == b'-' {
                self.pos += 1;
                let rhs = self.parse_term()?;
                lhs = if op == b'+' { lhs + rhs } else { lhs - rhs };
                if !lhs.is_finite() {
                    return None;
                }
            } else {
                break;
            }
        }
        Some(lhs)
    }

    fn parse_term(&mut self) -> Option<f64> {
        let mut lhs = self.parse_factor()?;
        while let Some(op) = self.peek() {
            if op == b'*' || op == b'/' || op == b'%' {
                self.pos += 1;
                let rhs = self.parse_factor()?;
                if (op == b'/' || op == b'%') && rhs == 0.0 {
                    return None;
                }
                lhs = match op {
                    b'*' => lhs * rhs,
                    b'/' => lhs / rhs,
                    _ => lhs % rhs,
                };
                if !lhs.is_finite() {
                    return None;
                }
            } else {
                break;
            }
        }
        Some(lhs)
    }

    fn parse_factor(&mut self) -> Option<f64> {
        self.depth += 1;
        if self.depth > 32 {
            return None;
        }
        let res = match self.peek()? {
            b'+' => {
                self.pos += 1;
                self.parse_factor()
            }
            b'-' => {
                self.pos += 1;
                self.parse_factor().map(|v| -v)
            }
            b'(' => {
                self.pos += 1;
                let inner = self.parse_expr()?;
                if self.peek() != Some(b')') {
                    return None;
                }
                self.pos += 1;
                Some(inner)
            }
            _ => self.parse_number(),
        };
        self.depth -= 1;
        res
    }

    fn parse_number(&mut self) -> Option<f64> {
        self.skip_ws();
        let start = self.pos;
        let mut saw_dot = false;
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b.is_ascii_digit() {
                self.pos += 1;
            } else if b == b'.' && !saw_dot {
                saw_dot = true;
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return None;
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
        s.parse::<f64>().ok().filter(|v| v.is_finite())
    }
}

/// Attempt to answer `raw_text` locally in Rust (zero AI tokens), enforcing strict RBAC.
/// Returns `None` for any message that should proceed to the AI engine.
pub fn try_local_fast_reply(ctx: &Arc<BotCtx>, uid: i64, raw_text: &str) -> Option<LocalFastReply> {
    if !ctx.cfg.local_fast_path {
        return None;
    }
    let norm = normalize_query(raw_text);
    if norm.is_empty() {
        return None;
    }

    if is_ping_query(&norm) {
        let up = ctx.started_at.elapsed().as_secs();
        let h = up / 3600;
        let m = (up % 3600) / 60;
        let html = format!(
            "{} <b>آنلاین و آماده</b>\n\
            <blockquote>Uptime: <code>{h}h {m}m</code> · Active jobs: <code>{}/{}</code></blockquote>\n\
            <i>⚡ پاسخ محلی Rust (۰ توکن AI)</i>",
            ctx.e("ok"),
            ctx.jobs.active_global_jobs(),
            ctx.jobs.max_global_jobs(),
        );
        let mk = if ctx.is_owner(uid) || ctx.has_perm(uid, "dashboard_access") {
            Some(BotCtx::kb(vec![ctx.back_row_for(uid)]))
        } else {
            None
        };
        return Some(LocalFastReply {
            kind: "ping",
            html,
            markup: mk,
        });
    }

    if is_time_query(&norm) {
        let utc_now = Utc::now();
        let tehran_offset = FixedOffset::east_opt(3 * 3600 + 30 * 60);
        let tehran_line = match tehran_offset {
            Some(tz) => {
                let t = utc_now.with_timezone(&tz);
                format!("<b>Tehran (IRST):</b> <code>{}</code>", t.format("%Y-%m-%d %H:%M:%S"))
            }
            None => String::new(),
        };
        let html = format!(
            "🕒 <b>زمان و تاریخ سیستم</b>\n\
            <blockquote>{tehran_line}\n<b>UTC:</b> <code>{}</code></blockquote>\n\
            <i>⚡ پاسخ محلی Rust (۰ توکن AI)</i>",
            utc_now.format("%Y-%m-%d %H:%M:%S UTC"),
        );
        return Some(LocalFastReply {
            kind: "time",
            html,
            markup: None,
        });
    }

    if is_status_query(&norm) {
        // Strict RBAC: owner sees pool/proxy/host; status_net sees host only; chat-only sees minimal alive card.
        if ctx.is_owner(uid) {
            let snap = ctx.sys_snapshot(uid);
            let uptime = snap["uptime"].as_str().unwrap_or("0h 0m");
            let ram = snap["ram_pct"].as_u64().map(|p| format!("{p}%")).unwrap_or_else(|| "—".into());
            let disk = snap["disk_pct"].as_u64().unwrap_or(0);
            let acct_summary = match ctx.jobs.accounts() {
                Some(pool) => {
                    let pol = pool.policy();
                    let list = pool.list();
                    let now_i = Utc::now().timestamp();
                    let avail = list.iter().filter(|a| a.available_at_with_policy(now_i, &pol)).count();
                    let resv = pool.weekly_reserved_count();
                    let brk = if pool.breaker_status().is_some() { " · 🛡 BREAKER" } else { "" };
                    format!("{avail}/{} آماده (رزرو هفتگی: {resv} · {}{brk})", list.len(), pol.preset.as_str())
                }
                None => "single-account".to_string(),
            };
            let px_summary = format!(
                "{}/{} سالم ({})",
                ctx.proxies.healthy_count(),
                ctx.proxies.len(),
                ctx.proxies.fallback_policy().as_str()
            );
            let html = format!(
                "{} <b>وضعیت سریع ربات</b>\n\
                <blockquote><b>Uptime:</b> <code>{}</code> · <b>RAM/Disk:</b> <code>{} / {}%</code>\n\
                <b>AI Slots:</b> <code>{}/{}</code>\n\
                <b>Accounts:</b> <code>{}</code>\n\
                <b>Proxies:</b> <code>{}</code></blockquote>\n\
                <i>⚡ پاسخ محلی Rust (۰ توکن AI)</i>",
                ctx.e("status"),
                esc(uptime),
                esc(&ram),
                disk,
                ctx.jobs.active_global_jobs(),
                ctx.jobs.max_global_jobs(),
                esc(&acct_summary),
                esc(&px_summary),
            );
            let mk = BotCtx::kb(vec![
                vec![
                    ctx.btn("status", "Status", Some("status"), None, None),
                    ctx.btn("accounts", "Accounts", Some("acct:list"), None, None),
                    ctx.btn("net", "Proxies", Some("px:list"), None, None),
                ],
                ctx.back_row_for(uid),
            ]);
            return Some(LocalFastReply {
                kind: "status_owner",
                html,
                markup: Some(mk),
            });
        } else if ctx.has_perm(uid, "status_net") {
            let snap = ctx.sys_snapshot(uid);
            let uptime = snap["uptime"].as_str().unwrap_or("0h 0m");
            let ram = snap["ram_pct"].as_u64().map(|p| format!("{p}%")).unwrap_or_else(|| "—".into());
            let html = format!(
                "{} <b>وضعیت ربات</b>\n\
                <blockquote><b>Uptime:</b> <code>{}</code> · <b>RAM:</b> <code>{}</code> · <b>Jobs:</b> <code>{}/{}</code></blockquote>\n\
                <i>⚡ پاسخ محلی Rust (۰ توکن AI)</i>",
                ctx.e("status"),
                esc(uptime),
                esc(&ram),
                ctx.jobs.active_global_jobs(),
                ctx.jobs.max_global_jobs(),
            );
            return Some(LocalFastReply {
                kind: "status_net",
                html,
                markup: Some(BotCtx::kb(vec![vec![ctx.btn("status", "Status", Some("status"), None, None)]])),
            });
        } else {
            return Some(LocalFastReply {
                kind: "status_minimal",
                html: format!("{} <b>ربات آنلاین و آماده پاسخ‌گویی است.</b>\n<i>⚡ پاسخ محلی (۰ توکن AI)</i>", ctx.e("ok")),
                markup: None,
            });
        }
    }

    if let Some((expr, val)) = try_eval_arithmetic(raw_text) {
        let html = format!(
            "🧮 <code>{}</code> = <b><code>{}</code></b>\n<i>⚡ محاسبه محلی Rust (۰ توکن AI)</i>",
            esc(&expr),
            esc(&val),
        );
        return Some(LocalFastReply {
            kind: "math",
            html,
            markup: None,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_parser_handles_precedence_parens_errors_and_rejects_dates() {
        assert_eq!(try_eval_arithmetic("2 + 3 * 4"), Some(("2 + 3 * 4".into(), "14".into())));
        assert_eq!(try_eval_arithmetic("(2 + 3) * 4"), Some(("(2 + 3) * 4".into(), "20".into())));
        assert_eq!(try_eval_arithmetic("= 100 * 1.09"), Some(("100 * 1.09".into(), "109".into())));
        assert_eq!(try_eval_arithmetic("محاسبه (50 - 8) / 4"), Some(("(50 - 8) / 4".into(), "10.5".into())));
        assert_eq!(try_eval_arithmetic("-5 + 12"), Some(("-5 + 12".into(), "7".into())));

        // Division by zero, dates, plain text, and malformed parens return None
        assert!(try_eval_arithmetic("10 / 0").is_none());
        assert!(try_eval_arithmetic("2026-11-24").is_none());
        assert!(try_eval_arithmetic("((1+2)").is_none());
        assert!(try_eval_arithmetic("سلام 2+2 چنده؟").is_none());
    }

    #[test]
    fn query_matchers_are_strict_and_unambiguous() {
        assert!(is_ping_query(&normalize_query("پینگ؟")));
        assert!(is_ping_query(&normalize_query("  Ping! ")));
        assert!(!is_ping_query(&normalize_query("پینگ گوگل را تست کن")));

        assert!(is_time_query(&normalize_query("ساعت چنده؟")));
        assert!(is_time_query(&normalize_query("what time is it?")));
        assert!(!is_time_query(&normalize_query("ساعت کار بانک‌ها چقدره؟")));

        assert!(is_status_query(&normalize_query("وضعیت اکانت‌ها")));
        assert!(!is_status_query(&normalize_query("وضعیت پروژه و فاز ۴ چطوره؟")));
    }
}
