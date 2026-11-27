//! Pause a job when the account it moved to doesn't offer the user's model. The account's
//! models are shown as inline buttons, the user picks one, and the same session continues on
//! that account with that model. Nothing is substituted automatically.
//!
//! Declared as a child module of `jobs`.

use std::sync::Arc;
use std::time::Duration;

use agy_core::accounts::Account;
use agy_core::tg::{InlineKeyboardButton, InlineKeyboardMarkup};
use agy_ext::engines::ModelInfo;
use agy_render::markdown::esc;
use tokio::sync::oneshot;
use tracing::info;

use super::JobManager;
use crate::models_pool;

/// How long a paused job waits for the user's choice.
pub const MODEL_PICK_TIMEOUT_SECS: u64 = 600;
/// `UserState.extra` flag: the saved model is not offered by any account.
pub const MODEL_INVALID_KEY: &str = "model_invalid";
const MAX_BUTTONS: usize = 24;

pub struct ModelWait {
    pub nonce: String,
    pub ids: Vec<String>,
    pub tx: std::sync::Mutex<Option<oneshot::Sender<Option<String>>>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ModelDecision {
    /// Account offers the model (or its list is unknown): run unchanged.
    Keep,
    /// Run with this model on this account (chosen by the user).
    Use(String),
    /// User cancelled, timed out or stopped the job.
    Cancelled(String),
}

impl JobManager {
    /// Make sure `wanted` is usable on `a`; otherwise pause and ask the user.
    pub(super) async fn resolve_model_for_account(
        &self,
        uid: i64,
        chat_id: i64,
        a: &Account,
        wanted: Option<&str>,
        stop: &(dyn Fn() -> bool + Send + Sync),
        force_refresh: bool,
    ) -> ModelDecision {
        // `force_refresh` is set after agy rejected the model on this account: the list is
        // re-read and the user is asked even if the id still appears in it.
        let rejected = force_refresh;
        let wanted = wanted.filter(|m| !m.is_empty());
        if wanted.is_none() && !rejected {
            return ModelDecision::Keep;
        }
        let list: Vec<ModelInfo> = if force_refresh {
            models_pool::refresh(&self.cfg, a).await
        } else {
            if models_pool::is_stale(&self.cfg.state_dir, &a.id) && !models_pool::load(&self.cfg.state_dir, &a.id).is_empty() {
                let cfg = Arc::clone(&self.cfg);
                let a2 = a.clone();
                tokio::spawn(async move {
                    models_pool::refresh(&cfg, &a2).await;
                });
            }
            models_pool::ensure(&self.cfg, a).await
        };
        if list.is_empty() {
            return ModelDecision::Keep;
        }
        if !rejected && wanted.is_some_and(|w| list.iter().any(|m| m.id == w)) {
            return ModelDecision::Keep;
        }
        let wanted = wanted.unwrap_or("(account default)");
        let key = (uid, a.id.clone(), wanted.to_string());
        if let Some(c) = self.model_choice.get(&key).map(|v| v.clone()) {
            if list.iter().any(|m| m.id == c) && !(rejected && c == wanted) {
                return ModelDecision::Use(c);
            }
        }
        // One model-pick question at a time per user (so concurrent owners never block each other).
        let user_lock = self
            .model_pick_locks
            .entry(uid)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = user_lock.lock().await;
        if let Some(c) = self.model_choice.get(&key).map(|v| v.clone()) {
            if list.iter().any(|m| m.id == c) && !(rejected && c == wanted) {
                return ModelDecision::Use(c);
            }
        }
        match self.ask_model_pick(uid, chat_id, a, wanted, &list, stop).await {
            Ok(c) => {
                self.model_choice.insert(key, c.clone());
                // A saved model that no account offers any more is stale: replace it.
                if !self.model_known_anywhere(wanted) {
                    let c2 = c.clone();
                    let _ = self.store.update_user(uid, move |u| {
                        u.model = Some(c2);
                        u.extra.remove(MODEL_INVALID_KEY);
                    });
                    info!(uid, model = %c, "stale saved model replaced by the user's choice");
                }
                ModelDecision::Use(c)
            }
            Err(why) => ModelDecision::Cancelled(why),
        }
    }

    async fn ask_model_pick(
        &self,
        uid: i64,
        chat_id: i64,
        a: &Account,
        wanted: &str,
        list: &[ModelInfo],
        stop: &(dyn Fn() -> bool + Send + Sync),
    ) -> std::result::Result<String, String> {
        let nonce = format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos() ^ (d.as_secs() as u32))
                .unwrap_or(0)
        );
        let shown: Vec<&ModelInfo> = list.iter().take(MAX_BUTTONS).collect();
        let (tx, mut rx) = oneshot::channel::<Option<String>>();
        self.model_waits.insert(
            uid,
            Arc::new(ModelWait {
                nonce: nonce.clone(),
                ids: shown.iter().map(|m| m.id.clone()).collect(),
                tx: std::sync::Mutex::new(Some(tx)),
            }),
        );
        let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
        for (i, pair) in shown.chunks(2).enumerate() {
            rows.push(
                pair.iter()
                    .enumerate()
                    .map(|(j, m)| InlineKeyboardButton {
                        text: m.name.chars().take(32).collect(),
                        callback_data: Some({
                            let by_id = format!("mpk:{nonce}:{}", m.id);
                            if by_id.len() <= 64 { by_id } else { format!("mpk:{nonce}:#{}", i * 2 + j) }
                        }),
                        ..Default::default()
                    })
                    .collect(),
            );
        }
        rows.push(vec![InlineKeyboardButton {
            text: "✖ Cancel task".into(),
            callback_data: Some(format!("mpk:{nonce}:x")),
            style: Some("danger".into()),
            ..Default::default()
        }]);
        let acct_name = if self.acl.is_owner(uid) { a.display_name() } else { a.id.clone() };
        let wanted_name = list.iter().find(|m| m.id == wanted).map(|m| m.name.clone()).unwrap_or_else(|| wanted.to_string());
        let html = format!(
            "🧩 <b>Choose a model to continue</b>\nAccount <code>{}</code> does not offer your model <code>{}</code> (it may be retired, or this account cannot use it).\n<blockquote>Pick one of this account's {} models. The same session continues on it with your choice. Nothing is switched automatically. (Waits {} min.)</blockquote>",
            esc(&acct_name),
            esc(&wanted_name),
            list.len(),
            (self.model_pick_timeout.load(std::sync::atomic::Ordering::Relaxed) / 60).max(1)
        );
        let msg = self
            .render
            .send_html(chat_id, &html, Some(InlineKeyboardMarkup::new(rows)), None, None, false)
            .await
            .ok()
            .flatten();
        info!(uid, account = %a.id, wanted, "job paused for model choice");
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(self.model_pick_timeout.load(std::sync::atomic::Ordering::Relaxed));
        let outcome: std::result::Result<String, String> = loop {
            tokio::select! {
                r = &mut rx => {
                    break match r {
                        Ok(Some(id)) => Ok(id),
                        _ => Err("cancelled".to_string()),
                    };
                }
                _ = tokio::time::sleep(Duration::from_millis(700)) => {
                    if stop() {
                        break Err("stopped".to_string());
                    }
                    if tokio::time::Instant::now() >= deadline {
                        break Err("timeout".to_string());
                    }
                }
            }
        };
        self.model_waits.remove_if(&uid, |_, w| w.nonce == nonce);
        if let Some(m) = msg {
            let done = match &outcome {
                Ok(id) => format!(
                    "🧩 Model for account <code>{}</code>: <b>{}</b>. Continuing the same session…",
                    esc(&acct_name),
                    esc(&list.iter().find(|x| &x.id == id).map(|x| x.name.clone()).unwrap_or_else(|| id.clone()))
                ),
                Err(w) if w == "timeout" => "⏱ <b>No model chosen in time</b>. The task was cancelled; your session is kept. Send your message again to continue.".to_string(),
                Err(_) => "✖ <b>Task cancelled</b>. Your session is kept.".to_string(),
            };
            let _ = self.render.edit_html(chat_id, m.message_id, &done, None).await;
        }
        outcome
    }

    /// Callback `mpk:<nonce>:<idx|x>`. Returns the toast text, or `None` when stale.
    pub fn resolve_model_pick(&self, uid: i64, nonce: &str, choice: &str) -> Option<&'static str> {
        let w = self.model_waits.get(&uid).map(|v| Arc::clone(v.value()))?;
        if w.nonce != nonce {
            return None;
        }
        let pick = if choice == "x" {
            None
        } else if let Some(idx) = choice.strip_prefix('#') {
            Some(w.ids.get(idx.parse::<usize>().ok()?)?.clone())
        } else {
            Some(w.ids.iter().find(|i| i.as_str() == choice)?.clone())
        };
        let cancelled = pick.is_none();
        let tx = w.tx.lock().ok()?.take()?;
        let _ = tx.send(pick);
        Some(if cancelled { "Cancelled" } else { "Model selected" })
    }

    /// The model to pass explicitly when the user has none saved: the shared settings.json
    /// default if this account offers it, otherwise the first model of the account's list.
    /// `None` when the account's list is unknown (agy then uses its own default).
    pub fn account_default_model(&self, a: &Account) -> Option<String> {
        let list = models_pool::load(&self.cfg.state_dir, &a.id);
        let list = if list.is_empty() && a.is_primary() {
            crate::ctx::load_models_file(&self.cfg.state_dir.join("models.json"))
        } else {
            list
        };
        if list.is_empty() {
            return None;
        }
        let shared_default = self
            .accounts()
            .map(|p| p.primary_home().join(".gemini/antigravity-cli/settings.json"))
            .and_then(|f| std::fs::read_to_string(f).ok())
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .and_then(|v| v.get("model").and_then(|m| m.as_str()).map(str::to_string));
        if let Some(d) = shared_default {
            if let Some(m) = list.iter().find(|m| m.id == d || m.name == d) {
                return Some(m.id.clone());
            }
        }
        list.first().map(|m| m.id.clone())
    }

    /// Whether any account's cached list (or the global one) offers `model`.
    pub fn model_known_anywhere(&self, model: &str) -> bool {
        let mut ids: Vec<String> = vec![agy_core::accounts::PRIMARY_ACCOUNT_ID.to_string()];
        if let Some(p) = self.accounts() {
            ids.extend(p.list().into_iter().map(|a| a.id));
        }
        let mut any_list = false;
        for id in ids {
            let l = models_pool::load(&self.cfg.state_dir, &id);
            any_list |= !l.is_empty();
            if l.iter().any(|m| m.id == model) {
                return true;
            }
        }
        !any_list
    }

    /// Override the wait (tests).
    pub fn set_model_pick_timeout(&self, secs: u64) {
        self.model_pick_timeout.store(secs, std::sync::atomic::Ordering::Relaxed);
    }

    /// True while a job of `uid` waits for a model choice.
    pub fn is_waiting_model(&self, uid: i64) -> bool {
        self.model_waits.contains_key(&uid)
    }

    /// Clear cached per-account fallback model picks for `uid` after a manual model change.
    pub fn clear_model_choices(&self, uid: i64) {
        self.model_choice.retain(|(u, _, _), _| *u != uid);
    }
}
