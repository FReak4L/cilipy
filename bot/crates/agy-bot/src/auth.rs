//! Authorization gate: allow-listed / ACL-approved users in private chats only.
//!
//! Unapproved updates are silently dropped (zero reply sent to the user), except
//! private `/start` attempts which record pending user state and optionally trigger
//! an owner notification subject to cooldown.

#[cfg(test)]
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use agy_core::acl::{AclStore, AclUser, Perms, UserStatus};
use agy_core::config::Config;
use agy_core::tg::{InlineKeyboardButton, InlineKeyboardMarkup, Update, User};
use agy_render::{md_cell, PremiumState};
use tracing::warn;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Outcome of evaluating an incoming Telegram [`Update`] through [`AuthGate`].
#[derive(Debug, Clone, PartialEq)]
pub enum AuthDecision {
    /// Actor is approved in a private chat; update may proceed to command/message handlers.
    Allowed(AclUser),
    /// Unapproved user sent private `/start` and passed notification cooldown; notify owner silently.
    NotifyOwnerStart(AclUser),
    /// Update must be silently dropped without sending any reply to the actor.
    Drop,
}

/// Parse `ALLOWED_USER_IDS` formatted string (`comma` or `semicolon` separated integers).
#[cfg(test)]
pub fn parse_allowed_ids(raw: &str) -> HashSet<i64> {
    raw.split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<i64>().ok())
        .collect()
}

/// Extract `(user_id, chat_type)` for the actor responsible for `update`.
pub fn update_actor(update: &Update, allow_inline_widgets: bool) -> (Option<i64>, Option<&str>) {
    if let Some(ref m) = update.message {
        let uid = m.from_user.as_ref().map(|u| u.id);
        return (uid, Some(m.chat.kind.as_str()));
    }
    if let Some(ref cq) = update.callback_query {
        let ctype = cq.message.as_ref().map(|m| m.chat.kind.as_str());
        return (Some(cq.from_user.id), ctype);
    }
    if let Some(ref smg) = update.stopped_message_generation {
        return (Some(smg.chat.id), Some(smg.chat.kind.as_str()));
    }
    if let Some(ref wq) = update.widget_query {
        let ctype = if let Some(ref ch) = wq.chat {
            Some(ch.kind.as_str())
        } else {
            match wq.chat_type.as_deref() {
                Some("private") | Some("sender") => Some("private"),
                other => other,
            }
        };
        return (Some(wq.from_user.id), ctype);
    }
    if let Some(ref swq) = update.shared_widget_query {
        return (Some(swq.from_user.id), Some("private"));
    }
    if allow_inline_widgets {
        if let Some(ref iq) = update.inline_query {
            return (Some(iq.from_user.id), Some("private"));
        }
    }
    (None, None)
}

/// Stateless allowlist helper checking private chat + membership in `allowed`.
#[cfg(test)]
pub fn is_allowed_in_set(
    update: &Update,
    allowed: &HashSet<i64>,
    allow_inline_widgets: bool,
) -> bool {
    let (uid, ctype) = update_actor(update, allow_inline_widgets);
    uid.is_some_and(|id| allowed.contains(&id)) && ctype == Some("private")
}

/// Return `true` only for a `/start` command message sent by a user in a private chat.
pub fn is_start_command(update: &Update) -> bool {
    let Some(ref m) = update.message else {
        return false;
    };
    if m.chat.kind != "private" || m.from_user.is_none() {
        return false;
    }
    let Some(text) = m.text.as_deref() else {
        return false;
    };
    let Some(first) = text.split_whitespace().next() else {
        return false;
    };
    let cmd = first.split('@').next().unwrap_or("");
    cmd.eq_ignore_ascii_case("/start")
}

/// Extract the [`User`] object from supported update payloads, if present.
pub fn actor_user(update: &Update, allow_inline_widgets: bool) -> Option<&User> {
    if let Some(ref m) = update.message {
        return m.from_user.as_ref();
    }
    if let Some(ref cq) = update.callback_query {
        return Some(&cq.from_user);
    }
    if let Some(ref wq) = update.widget_query {
        return Some(&wq.from_user);
    }
    if let Some(ref swq) = update.shared_widget_query {
        return Some(&swq.from_user);
    }
    if allow_inline_widgets {
        if let Some(ref iq) = update.inline_query {
            return Some(&iq.from_user);
        }
    }
    None
}

fn fallback_approved_user(acl: &AclStore, uid: i64, tg_user: Option<&User>, now: f64) -> AclUser {
    let is_owner = acl.is_owner(uid);
    AclUser {
        uid,
        status: UserStatus::Approved,
        role: if is_owner {
            "owner".to_string()
        } else {
            "user".to_string()
        },
        perms: if is_owner {
            Perms::owner()
        } else {
            Perms::default()
        },
        username: tg_user.and_then(|u| u.username.clone()),
        first_name: tg_user.and_then(|u| (!u.first_name.is_empty()).then(|| u.first_name.clone())),
        last_name: tg_user.and_then(|u| u.last_name.clone()),
        language_code: tg_user.and_then(|u| u.language_code.clone()),
        is_premium: tg_user.and_then(|u| u.is_premium).unwrap_or(false),
        first_seen: now,
        last_seen: now,
        last_start_notify_ts: None,
        status_by: None,
        status_at: None,
    }
}

/// Stateful authorization gate backed by [`AclStore`].
pub struct AuthGate {
    acl: Arc<AclStore>,
    allow_inline_widgets: bool,
    dropped: AtomicU64,
}

impl AuthGate {
    /// Create a new [`AuthGate`] wrapping `acl`.
    pub fn new(acl: Arc<AclStore>, allow_inline_widgets: bool) -> Self {
        Self {
            acl,
            allow_inline_widgets,
            dropped: AtomicU64::new(0),
        }
    }

    /// Create an [`AuthGate`] configured from [`Config`].
    pub fn from_config(acl: Arc<AclStore>, cfg: &Config) -> Self {
        Self::new(acl, cfg.allow_inline_widgets)
    }

    pub fn acl(&self) -> &Arc<AclStore> {
        &self.acl
    }

    pub fn allow_inline_widgets(&self) -> bool {
        self.allow_inline_widgets
    }

    /// Number of updates dropped since startup.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Evaluate an incoming Telegram update against ACL + private-chat rules.
    pub fn evaluate(&self, update: &Update) -> AuthDecision {
        self.evaluate_at(update, now_secs())
    }

    /// Deterministic timestamp variant of [`Self::evaluate`] for testing cooldowns.
    pub fn evaluate_at(&self, update: &Update, now: f64) -> AuthDecision {
        let (uid_opt, ctype_opt) = update_actor(update, self.allow_inline_widgets);
        let Some(uid) = uid_opt else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return AuthDecision::Drop;
        };
        if ctype_opt != Some("private") {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return AuthDecision::Drop;
        }

        if self.acl.is_approved(uid) {
            if let Some(user) = actor_user(update, self.allow_inline_widgets) {
                match self.acl.touch_user_at(user, now) {
                    Ok(rec) => return AuthDecision::Allowed(rec),
                    Err(err) => {
                        warn!(uid, error = %err, "acl touch_user failed; continuing with fallback");
                        let rec = self
                            .acl
                            .get_user(uid)
                            .unwrap_or_else(|| fallback_approved_user(&self.acl, uid, Some(user), now));
                        return AuthDecision::Allowed(rec);
                    }
                }
            }
            let rec = self
                .acl
                .get_user(uid)
                .unwrap_or_else(|| fallback_approved_user(&self.acl, uid, None, now));
            return AuthDecision::Allowed(rec);
        }

        self.dropped.fetch_add(1, Ordering::Relaxed);
        if is_start_command(update) {
            if let Some(user) = update.message.as_ref().and_then(|m| m.from_user.as_ref()) {
                match self.acl.record_start_attempt_at(user, now) {
                    Ok((rec, true)) => return AuthDecision::NotifyOwnerStart(rec),
                    Ok((_, false)) => return AuthDecision::Drop,
                    Err(err) => {
                        warn!(uid, error = %err, "acl record_start_attempt failed");
                        return AuthDecision::Drop;
                    }
                }
            }
        }
        AuthDecision::Drop
    }
}

/// Build the Rich Markdown card and inline approval keyboard sent to the owner when
/// an unapproved user sends `/start`.
pub fn owner_start_notice_card(
    rec: &AclUser,
    premium: &PremiumState,
) -> (String, InlineKeyboardMarkup) {
    let uname = rec
        .username
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|u| format!("@{u}"))
        .unwrap_or_else(|| "—".to_string());
    let full_raw = format!(
        "{} {}",
        rec.first_name.as_deref().unwrap_or(""),
        rec.last_name.as_deref().unwrap_or("")
    );
    let full = if full_raw.trim().is_empty() {
        "—"
    } else {
        full_raw.trim()
    };

    let md = [
        format!("### {} درخواست ورود کاربر جدید", premium.md("warn")),
        String::new(),
        "| مشخصه | مقدار |".to_string(),
        "|---|---|".to_string(),
        format!("| نام | {} |", md_cell(full)),
        format!("| یوزرنیم | `{}` |", md_cell(&uname)),
        format!("| شناسه | `{}` |", rec.uid),
        format!("| وضعیت | `{}` |", md_cell(rec.status.as_str())),
    ]
    .join("\n");

    let approve = InlineKeyboardButton {
        style: Some("success".to_string()),
        ..premium.callback_button(Some("ok"), "تایید", format!("uadm:ok:{}:std", rec.uid))
    };
    let block = InlineKeyboardButton {
        style: Some("danger".to_string()),
        ..premium.callback_button(Some("err"), "مسدود", format!("uadm:blk:{}", rec.uid))
    };
    let perms = premium.callback_button(Some("settings"), "دسترسی‌ها", format!("uadm:u:{}", rec.uid));

    (md, InlineKeyboardMarkup::new(vec![vec![approve, block, perms]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agy_core::tg::{
        CallbackQuery, Chat, InlineQuery, Message, MessageGenerationStopped, SharedWidgetQuery,
        WidgetQuery, WidgetQueryType,
    };
    use serde_json::json;
    use tempfile::TempDir;

    const OWNER: i64 = 1_000_000_001;
    const FRIEND: i64 = 1_000_000_002;

    fn mk_user(id: i64, username: Option<&str>) -> User {
        User {
            id,
            is_bot: false,
            first_name: "U".to_string(),
            last_name: None,
            username: username.map(ToString::to_string),
            language_code: None,
            is_premium: Some(false),
        }
    }

    fn msg_update(uid: i64, text: Option<&str>, ctype: &str, chat_id: i64, username: Option<&str>, with_from: bool) -> Update {
        Update {
            update_id: 1,
            message: Some(Message {
                message_id: 10,
                from_user: if with_from { Some(mk_user(uid, username)) } else { None },
                chat: Chat {
                    id: chat_id,
                    kind: ctype.to_string(),
                    username: None,
                    first_name: None,
                },
                message_thread_id: None,
                text: text.map(ToString::to_string),
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
            widget_query: None,
            shared_widget_query: None,
            inline_query: None,
            business: Default::default(),
            stopped_message_generation: None,
        }
    }

    fn cq_update(uid: i64, ctype: &str) -> Update {
        Update {
            update_id: 2,
            message: None,
            callback_query: Some(CallbackQuery {
                id: "cq1".to_string(),
                from_user: mk_user(uid, None),
                message: Some(Message {
                    message_id: 5,
                    from_user: None,
                    chat: Chat {
                        id: uid,
                        kind: ctype.to_string(),
                        username: None,
                        first_name: None,
                    },
                    message_thread_id: None,
                    text: Some("t".to_string()),
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
                inline_message_id: None,
                data: Some("m".to_string()),
            }),
            widget_query: None,
            shared_widget_query: None,
            inline_query: None,
            business: Default::default(),
            stopped_message_generation: None,
        }
    }

    fn wq_update(uid: i64, chat: Option<Chat>, chat_type: Option<&str>, inline_message_id: Option<&str>) -> Update {
        Update {
            update_id: 4,
            message: None,
            callback_query: None,
            widget_query: Some(WidgetQuery {
                id: "wq1".to_string(),
                from_user: mk_user(uid, None),
                chat,
                chat_type: chat_type.map(ToString::to_string),
                message_id: Some(10),
                inline_message_id: inline_message_id.map(ToString::to_string),
                widget_id: None,
                data: Some("d".to_string()),
                kind: WidgetQueryType::Data { wallet_card: None },
            }),
            shared_widget_query: None,
            inline_query: None,
            business: Default::default(),
            stopped_message_generation: None,
        }
    }

    fn swq_update(uid: i64) -> Update {
        Update {
            update_id: 5,
            message: None,
            callback_query: None,
            widget_query: None,
            shared_widget_query: Some(SharedWidgetQuery {
                id: "swq1".to_string(),
                from_user: mk_user(uid, None),
                widget_id: "w1".to_string(),
                data: Some("d".to_string()),
                kind: WidgetQueryType::Data { wallet_card: None },
            }),
            inline_query: None,
            business: Default::default(),
            stopped_message_generation: None,
        }
    }

    fn iq_update(uid: i64) -> Update {
        Update {
            update_id: 6,
            message: None,
            callback_query: None,
            widget_query: None,
            shared_widget_query: None,
            inline_query: Some(InlineQuery {
                id: "iq1".to_string(),
                from_user: mk_user(uid, None),
                query: String::new(),
                chat_type: None,
            }),
            business: Default::default(),
            stopped_message_generation: None,
        }
    }

    #[test]
    fn stateless_allowlist_parity() {
        let allowed = parse_allowed_ids("1000000001; 1000000002, invalid");
        assert_eq!(allowed, HashSet::from([OWNER, FRIEND]));

        assert!(is_allowed_in_set(&msg_update(OWNER, Some("hi"), "private", OWNER, None, true), &allowed, false));
        assert!(is_allowed_in_set(&msg_update(FRIEND, Some("hi"), "private", FRIEND, None, true), &allowed, false));
        assert!(!is_allowed_in_set(&msg_update(123, Some("hi"), "private", 123, None, true), &allowed, false));
        assert!(!is_allowed_in_set(&msg_update(OWNER, Some("hi"), "supergroup", -100123, None, true), &allowed, false));

        assert!(is_allowed_in_set(&cq_update(FRIEND, "private"), &allowed, false));
        assert!(!is_allowed_in_set(&cq_update(42, "private"), &allowed, false));
        assert!(!is_allowed_in_set(&cq_update(FRIEND, "group"), &allowed, false));

        // widget_query private, group, inline sender vs inline group
        assert!(is_allowed_in_set(
            &wq_update(OWNER, Some(Chat { id: OWNER, kind: "private".into(), username: None, first_name: None }), None, None),
            &allowed,
            false
        ));
        assert!(!is_allowed_in_set(
            &wq_update(OWNER, Some(Chat { id: -100, kind: "supergroup".into(), username: None, first_name: None }), None, None),
            &allowed,
            false
        ));
        assert!(is_allowed_in_set(&wq_update(OWNER, None, Some("sender"), Some("im1")), &allowed, false));
        assert!(!is_allowed_in_set(&wq_update(OWNER, None, Some("group"), Some("im1")), &allowed, false));
        assert!(!is_allowed_in_set(&wq_update(123, None, Some("sender"), Some("im1")), &allowed, false));

        // shared_widget_query
        assert!(is_allowed_in_set(&swq_update(OWNER), &allowed, false));
        assert!(is_allowed_in_set(&swq_update(FRIEND), &allowed, false));
        assert!(!is_allowed_in_set(&swq_update(123), &allowed, false));

        // inline_query gate
        assert!(!is_allowed_in_set(&iq_update(OWNER), &allowed, false));
        assert!(is_allowed_in_set(&iq_update(OWNER), &allowed, true));
        assert!(!is_allowed_in_set(&iq_update(123), &allowed, true));
    }

    #[test]
    fn start_command_detection_parity() {
        assert!(is_start_command(&msg_update(111, Some("/start"), "private", 111, None, true)));
        assert!(is_start_command(&msg_update(111, Some("  /start ref123 "), "private", 111, None, true)));
        assert!(is_start_command(&msg_update(111, Some("/START@MyTestBot payload"), "private", 111, None, true)));
        assert!(!is_start_command(&msg_update(111, Some("/help"), "private", 111, None, true)));
        assert!(!is_start_command(&msg_update(111, Some("   "), "private", 111, None, true)));
        assert!(!is_start_command(&msg_update(111, None, "private", 111, None, true)));
        assert!(!is_start_command(&msg_update(111, Some("/start"), "group", -100, None, true)));
        assert!(!is_start_command(&msg_update(111, Some("/start"), "private", 111, None, false)));
        assert!(!is_start_command(&cq_update(111, "private")));
    }

    #[test]
    fn auth_gate_silent_gating_cooldown_blocked_and_approved_touch() {
        let dir = TempDir::new().unwrap();
        let acl = Arc::new(AclStore::open(dir.path().join("acl.json"), OWNER, &[FRIEND], 300).unwrap());
        let gate = AuthGate::new(Arc::clone(&acl), false);

        // 1. Stranger regular text -> silently dropped, no ACL record
        assert_eq!(
            gate.evaluate_at(&msg_update(9001, Some("hello"), "private", 9001, Some("stranger"), true), 1000.0),
            AuthDecision::Drop
        );
        assert_eq!(gate.dropped_count(), 1);
        assert!(acl.get_user(9001).is_none());

        // 2. Stranger callback & widget_query -> silently dropped
        assert_eq!(gate.evaluate_at(&cq_update(9001, "private"), 1000.0), AuthDecision::Drop);
        assert_eq!(
            gate.evaluate_at(
                &wq_update(9001, Some(Chat { id: 9001, kind: "private".into(), username: None, first_name: None }), None, None),
                1000.0
            ),
            AuthDecision::Drop
        );
        assert_eq!(gate.dropped_count(), 3);

        // 3. Stranger /start in supergroup -> dropped before recording
        assert_eq!(
            gate.evaluate_at(&msg_update(9001, Some("/start"), "supergroup", -999, Some("stranger"), true), 1000.0),
            AuthDecision::Drop
        );
        assert_eq!(gate.dropped_count(), 4);
        assert!(acl.get_user(9001).is_none());

        // 4. Stranger /start in private -> recorded pending + NotifyOwnerStart once
        let d4 = gate.evaluate_at(
            &msg_update(9001, Some("/start"), "private", 9001, Some("stranger"), true),
            1000.0,
        );
        match d4 {
            AuthDecision::NotifyOwnerStart(rec) => {
                assert_eq!(rec.uid, 9001);
                assert_eq!(rec.status, UserStatus::Pending);
                assert_eq!(rec.username.as_deref(), Some("stranger"));
            }
            other => panic!("expected NotifyOwnerStart, got {other:?}"),
        }
        assert_eq!(gate.dropped_count(), 5);

        // 5. Repeated /start within cooldown -> Drop, updates metadata
        assert_eq!(
            gate.evaluate_at(&msg_update(9001, Some("/start@bot"), "private", 9001, Some("stranger2"), true), 1100.0),
            AuthDecision::Drop
        );
        assert_eq!(gate.dropped_count(), 6);
        assert_eq!(acl.get_user(9001).unwrap().username.as_deref(), Some("stranger2"));

        // 6. /start after cooldown -> notifies again
        assert!(matches!(
            gate.evaluate_at(&msg_update(9001, Some("/start"), "private", 9001, Some("stranger2"), true), 1301.0),
            AuthDecision::NotifyOwnerStart(_)
        ));

        // 7. Blocked user sending /start -> silent Drop, never notifies
        acl.set_status(9001, UserStatus::Blocked, Some(OWNER), None).unwrap();
        assert_eq!(
            gate.evaluate_at(&msg_update(9001, Some("/start"), "private", 9001, Some("stranger2"), true), 2000.0),
            AuthDecision::Drop
        );

        // 8. Approved user / owner passes across update types and updates metadata
        match gate.evaluate_at(&msg_update(FRIEND, Some("/start"), "private", FRIEND, Some("friend"), true), 2001.0) {
            AuthDecision::Allowed(u) => assert_eq!(u.username.as_deref(), Some("friend")),
            other => panic!("expected Allowed, got {other:?}"),
        }
        assert!(matches!(gate.evaluate_at(&cq_update(FRIEND, "private"), 2002.0), AuthDecision::Allowed(_)));
        assert!(matches!(
            gate.evaluate_at(
                &wq_update(FRIEND, Some(Chat { id: FRIEND, kind: "private".into(), username: None, first_name: None }), None, None),
                2003.0
            ),
            AuthDecision::Allowed(_)
        ));
        assert!(matches!(gate.evaluate_at(&swq_update(OWNER), 2004.0), AuthDecision::Allowed(_)));

        // 9. stopped_message_generation without from_user passes for approved/owner
        let smg = Update {
            update_id: 99,
            message: None,
            callback_query: None,
            widget_query: None,
            shared_widget_query: None,
            inline_query: None,
            business: Default::default(),
            stopped_message_generation: Some(MessageGenerationStopped {
                chat: Chat {
                    id: OWNER,
                    kind: "private".into(),
                    username: None,
                    first_name: None,
                },
                draft_id: 5,
                message_thread_id: None,
            }),
        };
        assert!(matches!(gate.evaluate_at(&smg, 2005.0), AuthDecision::Allowed(_)));

        // 10. Message without from_user is dropped cleanly
        assert_eq!(
            gate.evaluate_at(&msg_update(9001, Some("/start"), "private", 9001, None, false), 2006.0),
            AuthDecision::Drop
        );

        // 11. Inline query respects allow_inline_widgets
        let gate_inline = AuthGate::new(Arc::clone(&acl), true);
        assert!(matches!(gate_inline.evaluate_at(&iq_update(OWNER), 2007.0), AuthDecision::Allowed(_)));
        assert_eq!(gate_inline.evaluate_at(&iq_update(123), 2007.0), AuthDecision::Drop);

        // 12. owner_start_notice_card renders table & callbacks cleanly
        let pending = acl.get_user(9001).unwrap();
        let (card_md, mk) = owner_start_notice_card(&pending, &PremiumState::new(false));
        assert!(card_md.contains("9001"));
        assert_eq!(mk.inline_keyboard[0].len(), 3);
        let _ = json!(mk);
    }
}
