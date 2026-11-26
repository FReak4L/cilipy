//! Premium UI helpers: custom emoji (`<tg-emoji>`), button icons, and message effects.
//!
//! Bot API 9.4+: bots may use custom emoji in messages they send directly to
//! private/group/supergroup chats (and `icon_custom_emoji_id` on buttons) if the
//! bot owner has Telegram Premium. Everything degrades gracefully: on the first
//! rejection, premium is switched off without requiring a restart.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, RwLock};

use agy_core::error::{BridgeError, Result};
use agy_core::tg::{InlineKeyboardButton, InlineKeyboardMarkup};
use regex::{Captures, Regex};
use serde_json::Value;

/// Public message effect IDs (private chats only; Bot API `message_effect_id`).
pub const EFFECTS: &[(&str, &str)] = &[
    ("fire", "5104841245755180586"),
    ("like", "5107584321108051014"),
    ("heart", "5159385139981059251"),
    ("party", "5046509860389126442"),
];

/// Vetted `RestrictedEmoji` custom_emoji_ids (official Telegram set) so Premium
/// works out-of-the-box without requiring `emoji.json` on disk.
pub const DEFAULT_IDS: &[(&str, &str)] = &[
    ("ok", "5427009714745517609"),
    ("err", "5465665476971471368"),
    ("warn", "5467928559664242360"),
    ("work", "5451732530048802485"),
    ("rocket", "5445284980978621387"),
    ("party", "5436040291507247633"),
    ("idea", "5472146462362048818"),
    ("hot", "5420315771991497307"),
    ("fire", "5420315771991497307"),
    ("bolt", "5420315771991497307"),
    ("grok", "5420315771991497307"),
    ("file", "5377844313575150051"),
    ("doc", "5334882760735598374"),
    ("model", "5237799019329105246"),
    ("status", "5431577498364158238"),
    ("mcp", "5375129357373165375"),
    ("skills", "5472164874886846699"),
    ("new", "5472164874886846699"),
    ("brand", "5445284980978621387"),
    // Extended UI & commerce icon pack (21 entries)
    ("products", "5294385600000956892"),
    ("search", "5433651413517360422"),
    ("cart", "5192844064793327232"),
    ("orders", "6334602442591700514"),
    ("wallet", "5215275686842869661"),
    ("back", "5215675024312117374"),
    ("exit", "5017058788604117831"),
    ("support", "5438246259724925761"),
    ("add", "5235472087652510235"),
    ("remove", "5904542823167824187"),
    ("refresh", "5017470156276761427"),
    ("checkout", "5444856076954520455"),
    ("check", "5294336053258233678"),
    ("pay", "5195410990652474023"),
    ("cancel", "5828156683779576757"),
    ("admin", "5852967837970206643"),
    ("watch", "5339051047971203310"),
    ("phone", "5219748160842247251"),
    ("account", "6032693626394382504"),
    ("web", "4940645878684713890"),
    ("share", "5884343982816759327"),
];

/// Mapping from logical UI key to fallback plain Unicode emoji.
pub const FALLBACK: &[(&str, &str)] = &[
    ("brand", "🛰"),
    ("new", "🆕"),
    ("model", "🧠"),
    ("status", "📊"),
    ("mcp", "🔗"),
    ("skills", "✨"),
    ("settings", "⚙️"),
    ("stop", "⏹"),
    ("help", "❔"),
    ("sessions", "🗂"),
    ("ok", "✅"),
    ("err", "❌"),
    ("work", "⏳"),
    ("file", "📎"),
    ("doc", "📝"),
    ("warn", "❗"),
    ("menu", "🏠"),
    ("refresh", "🔄"),
    ("party", "🎉"),
    ("rocket", "🚀"),
    ("bolt", "⚡"),
    ("folder", "📁"),
    ("idea", "💡"),
    ("hot", "🔥"),
    ("fire", "🔥"),
    ("grok", "⚡"),
    ("products", "🛍️"),
    ("search", "🔍"),
    ("cart", "🛒"),
    ("orders", "📦"),
    ("wallet", "👛"),
    ("back", "🔙"),
    ("exit", "✖️"),
    ("support", "💬"),
    ("add", "➕"),
    ("remove", "🗑️"),
    ("checkout", "🧾"),
    ("check", "✅"),
    ("pay", "💳"),
    ("cancel", "❌"),
    ("admin", "🛠️"),
    ("watch", "🔔"),
    ("phone", "📱"),
    ("account", "👤"),
    ("web", "🌐"),
    ("share", "📤"),
];

static RE_STRIP_TG_EMOJI: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?s)<tg-emoji\s+emoji-id=["'][^"']*["']>(.*?)</tg-emoji>"#).ok());

static RE_STRIP_MD_EMOJI: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"!\[([^\]]*)\]\(tg://emoji\?id=[0-9]+\)").ok());

fn lookup_const(table: &[(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    table
        .iter()
        .find_map(|&(k, v)| if k == key { Some(v) } else { None })
}

/// Look up a public Telegram message effect ID by short name.
pub fn effect_id(name: &str) -> Option<&'static str> {
    lookup_const(EFFECTS, name)
}

/// Look up the vetted default custom emoji ID for a key.
pub fn default_id(key: &str) -> Option<&'static str> {
    lookup_const(DEFAULT_IDS, key)
}

/// Look up the plain fallback emoji for a key.
pub fn fallback_emoji(key: &str) -> Option<&'static str> {
    lookup_const(FALLBACK, key)
}

/// Parse `$STATE_DIR/emoji.json` into `(ids, extra_fallbacks)`.
///
/// Accepts either a flat `{ "<key>": { "id": "...", "emoji"|"alt": "..." } }` map or
/// `{ "icons": { ... } }`, supporting `"id"` as string or positive integer and
/// fallback glyphs under `"emoji"` or `"alt"`.
pub fn load_emoji_overrides(
    path: &Path,
) -> Result<(HashMap<String, String>, HashMap<String, String>)> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| BridgeError::io(format!("reading {}", path.display()), e))?;
    let val: Value = serde_json::from_str(&raw)
        .map_err(|e| BridgeError::json(format!("parsing {}", path.display()), e))?;

    let mut ids = HashMap::new();
    let mut extra_fb = HashMap::new();

    fn ingest_entry(
        k: &str,
        obj: &serde_json::Map<String, Value>,
        ids: &mut HashMap<String, String>,
        extra_fb: &mut HashMap<String, String>,
    ) {
        if let Some(id_val) = obj.get("id") {
            match id_val {
                Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
                    ids.insert(k.to_string(), s.clone());
                }
                Value::Number(n) if n.as_u64().is_some_and(|v| v > 0) => {
                    ids.insert(k.to_string(), n.to_string());
                }
                _ => {}
            }
        }
        let fb_opt = obj
            .get("emoji")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                obj.get("alt")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            });
        if let Some(fb) = fb_opt {
            extra_fb.insert(k.to_string(), fb.to_string());
        }
    }

    if let Some(map) = val.as_object() {
        for (k, v) in map {
            if k == "icons" {
                if let Some(icons_map) = v.as_object() {
                    for (ik, iv) in icons_map {
                        if let Some(obj) = iv.as_object() {
                            ingest_entry(ik, obj, &mut ids, &mut extra_fb);
                        }
                    }
                }
                continue;
            }
            if let Some(obj) = v.as_object() {
                ingest_entry(k, obj, &mut ids, &mut extra_fb);
            }
        }
    }
    Ok((ids, extra_fb))
}

/// Thread-safe Premium UI state supporting runtime graceful degradation.
#[derive(Debug)]
pub struct PremiumState {
    ids: HashMap<String, String>,
    extra_fb: HashMap<String, String>,
    fallback_by_id: HashMap<String, String>,
    enabled: AtomicBool,
    effects_ok: AtomicBool,
    reason: RwLock<Option<String>>,
}

impl PremiumState {
    /// Construct a `PremiumState` using only the built-in `DEFAULT_IDS`.
    pub fn new(enabled: bool) -> Self {
        let ids: HashMap<String, String> = DEFAULT_IDS
            .iter()
            .map(|&(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let extra_fb = HashMap::new();
        let fallback_by_id = build_fallback_by_id(&ids, &extra_fb);
        Self {
            ids,
            extra_fb,
            fallback_by_id,
            enabled: AtomicBool::new(enabled),
            effects_ok: AtomicBool::new(enabled),
            reason: RwLock::new(None),
        }
    }

    /// Initialize from `DEFAULT_IDS`, optionally overlaying `$state_dir/emoji.json`.
    ///
    /// Missing, unreadable, or invalid `emoji.json` files are ignored cleanly.
    pub fn load_from_state_dir(state_dir: &Path, enabled_env: bool) -> Self {
        let mut ids: HashMap<String, String> = DEFAULT_IDS
            .iter()
            .map(|&(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut extra_fb = HashMap::new();

        let emoji_path = state_dir.join("emoji.json");
        match load_emoji_overrides(&emoji_path) {
            Ok((ov_ids, ov_fb)) => {
                ids.extend(ov_ids);
                extra_fb = ov_fb;
            }
            Err(BridgeError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::debug!(error = %err, "ignoring emoji.json override failure");
            }
        }

        let fallback_by_id = build_fallback_by_id(&ids, &extra_fb);
        Self {
            ids,
            extra_fb,
            fallback_by_id,
            enabled: AtomicBool::new(enabled_env),
            effects_ok: AtomicBool::new(enabled_env),
            reason: RwLock::new(None),
        }
    }

    /// Resolve fallback plain emoji for `key`, checking `emoji.json` overrides first.
    pub fn fallback_for<'a>(&'a self, key: &str) -> Option<&'a str> {
        self.extra_fb
            .get(key)
            .map(String::as_str)
            .or_else(|| fallback_emoji(key))
    }

    /// Whether custom emoji / button icons are currently enabled and configured.
    pub fn active(&self) -> bool {
        self.enabled.load(Ordering::Relaxed) && !self.ids.is_empty()
    }

    /// Current raw `enabled` flag.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Whether message effects are still allowed.
    pub fn effects_ok(&self) -> bool {
        self.effects_ok.load(Ordering::Relaxed)
    }

    /// Disable custom emoji UI at runtime after a Telegram rejection.
    pub fn disable(&self, reason: &str) {
        self.enabled.store(false, Ordering::Relaxed);
        match self.reason.write() {
            Ok(mut guard) => *guard = Some(reason.to_string()),
            Err(poisoned) => *poisoned.into_inner() = Some(reason.to_string()),
        }
        tracing::warn!(reason = %reason, "premium UI disabled");
    }

    /// Disable Telegram message effects at runtime without disabling custom emoji.
    pub fn disable_effects(&self) {
        self.effects_ok.store(false, Ordering::Relaxed);
    }

    /// Reason recorded by [`Self::disable`], if any.
    pub fn reason(&self) -> Option<String> {
        match self.reason.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Configured key -> custom_emoji_id map.
    pub fn ids(&self) -> &HashMap<String, String> {
        &self.ids
    }

    /// Custom emoji ID -> plain fallback emoji map for stripping icons.
    pub fn fallback_by_id(&self) -> &HashMap<String, String> {
        &self.fallback_by_id
    }

    /// True if `md` references at least one custom emoji ID registered in this `PremiumState`.
    pub fn has_known_emoji_in_md(&self, md: &str) -> bool {
        if !md.contains("tg://emoji?id=") {
            return false;
        }
        let Some(re) = RE_STRIP_MD_EMOJI.as_ref() else {
            return false;
        };
        re.captures_iter(md).any(|caps| {
            let id = caps.get(0).map_or("", |m| m.as_str());
            id.rsplit("id=")
                .next()
                .and_then(|tail| tail.strip_suffix(')'))
                .is_some_and(|eid| self.fallback_by_id.contains_key(eid))
        })
    }

    /// Inline emoji for HTML text: `<tg-emoji>` when active, else plain emoji.
    pub fn e(&self, key: &str) -> String {
        let fb = self.fallback_for(key).unwrap_or("");
        if self.active() {
            if let Some(cid) = self.ids.get(key) {
                if !fb.is_empty() {
                    return format!(r#"<tg-emoji emoji-id="{cid}">{fb}</tg-emoji>"#);
                }
            }
        }
        fb.to_string()
    }

    /// Inline emoji for Telegram Rich Markdown: `![fb](tg://emoji?id=...)` or plain.
    pub fn md(&self, key: &str) -> String {
        let fb = self.fallback_for(key).unwrap_or("");
        if self.active() {
            if let Some(cid) = self.ids.get(key) {
                if !fb.is_empty() {
                    return format!("![{fb}](tg://emoji?id={cid})");
                }
            }
        }
        fb.to_string()
    }

    /// Build an `InlineKeyboardButton` with `icon_custom_emoji_id` when active,
    /// or `"{fb} {label}"` plain text fallback when inactive or unmapped.
    pub fn button(&self, key_opt: Option<&str>, label: &str) -> InlineKeyboardButton {
        let fb = key_opt.and_then(|k| self.fallback_for(k)).unwrap_or("");
        let cid = key_opt.and_then(|k| self.ids.get(k));
        if self.active() {
            if let Some(cid) = cid {
                return InlineKeyboardButton {
                    text: label.to_string(),
                    icon_custom_emoji_id: Some(cid.clone()),
                    ..Default::default()
                };
            }
        }
        let text = if fb.is_empty() {
            label.trim().to_string()
        } else {
            format!("{fb} {label}").trim().to_string()
        };
        InlineKeyboardButton {
            text,
            ..Default::default()
        }
    }

    /// Convenience helper creating a callback button with optional Premium icon.
    pub fn callback_button(
        &self,
        key_opt: Option<&str>,
        label: &str,
        data: impl Into<String>,
    ) -> InlineKeyboardButton {
        let mut btn = self.button(key_opt, label);
        btn.callback_data = Some(data.into());
        btn
    }

    /// Convenience helper creating a URL button with optional Premium icon.
    pub fn url_button(
        &self,
        key_opt: Option<&str>,
        label: &str,
        url: impl Into<String>,
    ) -> InlineKeyboardButton {
        let mut btn = self.button(key_opt, label);
        btn.url = Some(url.into());
        btn
    }

    /// Resolve a message effect ID if effects are enabled.
    pub fn effect(&self, name: &str) -> Option<&'static str> {
        if self.effects_ok.load(Ordering::Relaxed) {
            effect_id(name)
        } else {
            None
        }
    }

    /// Strip custom emoji icons from a markup using this state's fallback table.
    pub fn strip_markup_icons(&self, mk: InlineKeyboardMarkup) -> InlineKeyboardMarkup {
        strip_icons(mk, &self.fallback_by_id)
    }
}

fn build_fallback_by_id(
    ids: &HashMap<String, String>,
    extra_fb: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();

    // Process DEFAULT_IDS keys first in deterministic order so shared IDs pick
    // the same primary fallback emoji as Python's insertion-ordered dict.
    for &(k, _) in DEFAULT_IDS {
        if let Some(cid) = ids.get(k) {
            let fb = extra_fb
                .get(k)
                .map(String::as_str)
                .or_else(|| fallback_emoji(k))
                .unwrap_or("");
            if !fb.is_empty() {
                map.entry(cid.clone()).or_insert_with(|| fb.to_string());
            }
        }
    }

    let mut extra_keys: Vec<&String> = ids
        .keys()
        .filter(|k| default_id(k.as_str()).is_none())
        .collect();
    extra_keys.sort();
    for k in extra_keys {
        if let Some(cid) = ids.get(k) {
            let fb = extra_fb
                .get(k)
                .map(String::as_str)
                .or_else(|| fallback_emoji(k))
                .unwrap_or("");
            if !fb.is_empty() {
                map.entry(cid.clone()).or_insert_with(|| fb.to_string());
            }
        }
    }

    for &(k, cid) in DEFAULT_IDS {
        if let Some(fb) = fallback_emoji(k) {
            if !fb.is_empty() {
                map.entry(cid.to_string()).or_insert_with(|| fb.to_string());
            }
        }
    }

    for (k, cid) in ids {
        map.entry(cid.clone())
            .or_insert_with(|| fallback_emoji(k).unwrap_or("").to_string());
    }

    map
}

/// Replace `<tg-emoji emoji-id="...">inner</tg-emoji>` with `inner`.
pub fn strip_custom_emoji(text: &str) -> String {
    let Some(re) = RE_STRIP_TG_EMOJI.as_ref() else {
        return text.to_string();
    };
    re.replace_all(text, |caps: &Captures| {
        caps.get(1).map_or("", |m| m.as_str()).to_string()
    })
    .into_owned()
}

/// Replace `![alt](tg://emoji?id=12345)` with `alt`.
pub fn strip_md_custom_emoji(md: &str) -> String {
    let Some(re) = RE_STRIP_MD_EMOJI.as_ref() else {
        return md.to_string();
    };
    re.replace_all(md, |caps: &Captures| {
        caps.get(1).map_or("", |m| m.as_str()).to_string()
    })
    .into_owned()
}

/// Strip `icon_custom_emoji_id` from every button in `mk`, prepending fallback emoji if known.
pub fn strip_icons(
    mut mk: InlineKeyboardMarkup,
    fallback_by_id: &HashMap<String, String>,
) -> InlineKeyboardMarkup {
    for row in &mut mk.inline_keyboard {
        for btn in row {
            if let Some(cid) = btn.icon_custom_emoji_id.take() {
                let fb = fallback_by_id.get(&cid).map(String::as_str).unwrap_or("");
                btn.text = format!("{fb} {}", btn.text).trim().to_string();
            }
        }
    }
    mk
}

/// Whether a Telegram API error message looks like a Premium custom-emoji / icon / effect rejection.
pub fn looks_premium_error(msg: &str) -> bool {
    let low = msg.to_ascii_lowercase();
    [
        "custom_emoji",
        "emoji",
        "effect",
        "icon",
        "premium",
        "document_invalid",
        "sticker_id",
        "button_user_privacy_restricted",
    ]
    .iter()
    .any(|kw| low.contains(kw))
}

/// Whether a `BridgeError` indicates Telegram rejected a Premium UI feature.
pub fn is_premium_error(err: &BridgeError) -> bool {
    err.looks_like_premium_rejection() || looks_premium_error(&err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_python_parity() {
        assert_eq!(EFFECTS.len(), 4);
        assert_eq!(DEFAULT_IDS.len(), 40);
        assert_eq!(FALLBACK.len(), 46);
        assert_eq!(effect_id("fire"), Some("5104841245755180586"));
        assert_eq!(effect_id("party"), Some("5046509860389126442"));
        assert_eq!(effect_id("unknown"), None);
        assert_eq!(default_id("ok"), Some("5427009714745517609"));
        assert_eq!(default_id("fire"), Some("5420315771991497307"));
        assert_eq!(default_id("grok"), Some("5420315771991497307"));
        assert_eq!(default_id("products"), Some("5294385600000956892"));
        assert_eq!(default_id("refresh"), Some("5017470156276761427"));
        assert_eq!(default_id("share"), Some("5884343982816759327"));
        assert_eq!(fallback_emoji("ok"), Some("✅"));
        assert_eq!(fallback_emoji("fire"), Some("🔥"));
        assert_eq!(fallback_emoji("grok"), Some("⚡"));
        assert_eq!(fallback_emoji("settings"), Some("⚙️"));
        assert_eq!(fallback_emoji("products"), Some("🛍️"));
        assert_eq!(fallback_emoji("web"), Some("🌐"));
    }

    #[test]
    fn emoji_json_supports_nested_icons_and_alt_fallback() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("emoji.json"),
            r#"{"icons":{"cart":{"id":"5192844064793327232","alt":"🛒"},"empty":{"id":"","alt":"❓"}}}"#,
        )
        .unwrap();
        let (ids, fb) = load_emoji_overrides(&dir.path().join("emoji.json")).unwrap();
        assert_eq!(ids.get("cart").map(String::as_str), Some("5192844064793327232"));
        assert!(!ids.contains_key("empty"));
        assert_eq!(fb.get("cart").map(String::as_str), Some("🛒"));
        assert_eq!(fb.get("empty").map(String::as_str), Some("❓"));
    }

    #[test]
    fn premium_fallback_and_emoji_json_overlay() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("emoji.json"),
            r#"{"ok": {"id": "123"}, "custom": {"id": 999, "emoji": "🌟"}, "bad": "ignore"}"#,
        )
        .unwrap();

        let p = PremiumState::load_from_state_dir(dir.path(), true);
        assert!(p.active());
        assert_eq!(p.e("ok"), r#"<tg-emoji emoji-id="123">✅</tg-emoji>"#);
        assert_eq!(p.md("ok"), "![✅](tg://emoji?id=123)");
        assert_eq!(
            strip_custom_emoji(&format!("a {}", p.e("ok"))),
            "a ✅"
        );
        assert_eq!(
            strip_md_custom_emoji(&format!("### {} Title", p.md("ok"))),
            "### ✅ Title"
        );

        let b = p.callback_button(Some("ok"), "Done", "x");
        assert_eq!(b.icon_custom_emoji_id.as_deref(), Some("123"));
        assert_eq!(b.text, "Done");
        assert_eq!(b.callback_data.as_deref(), Some("x"));

        let mut fb_map = HashMap::new();
        fb_map.insert("123".to_string(), "✅".to_string());
        let mk = strip_icons(InlineKeyboardMarkup::new(vec![vec![b]]), &fb_map);
        assert_eq!(mk.inline_keyboard[0][0].text, "✅ Done");
        assert_eq!(mk.inline_keyboard[0][0].icon_custom_emoji_id, None);

        // Built-in fallback_by_id also maps custom overlaid ID 999 -> 🌟 and default IDs
        assert_eq!(
            p.fallback_by_id().get("999").map(String::as_str),
            Some("🌟")
        );
        assert_eq!(
            p.fallback_by_id()
                .get("5427009714745517609")
                .map(String::as_str),
            Some("✅")
        );

        // Custom fallback emoji from emoji.json works in e(), md(), and button()
        assert_eq!(p.e("custom"), r#"<tg-emoji emoji-id="999">🌟</tg-emoji>"#);
        assert_eq!(p.md("custom"), "![🌟](tg://emoji?id=999)");

        // Disable at runtime
        p.disable("CUSTOM_EMOJI_INVALID");
        assert!(!p.active());
        assert_eq!(p.reason().as_deref(), Some("CUSTOM_EMOJI_INVALID"));
        assert_eq!(p.e("ok"), "✅");
        assert_eq!(p.md("ok"), "✅");
        assert_eq!(p.e("custom"), "🌟");
        assert_eq!(p.button(Some("custom"), "Star").text, "🌟 Star");
        let b_plain = p.callback_button(Some("ok"), "Done", "x");
        assert_eq!(b_plain.text, "✅ Done");
        assert_eq!(b_plain.icon_custom_emoji_id, None);
    }

    #[test]
    fn missing_or_corrupt_emoji_json_falls_back_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let p_missing = PremiumState::load_from_state_dir(dir.path(), true);
        assert!(p_missing.active());
        assert_eq!(
            p_missing.e("ok"),
            r#"<tg-emoji emoji-id="5427009714745517609">✅</tg-emoji>"#
        );

        std::fs::write(dir.path().join("emoji.json"), "{not-valid-json").unwrap();
        let p_bad = PremiumState::load_from_state_dir(dir.path(), true);
        assert!(p_bad.active());
        assert_eq!(
            p_bad.ids().get("ok").map(String::as_str),
            Some("5427009714745517609")
        );

        let p_off = PremiumState::load_from_state_dir(dir.path(), false);
        assert!(!p_off.active());
        assert!(!p_off.effects_ok());
        assert_eq!(p_off.effect("fire"), None);
        assert_eq!(p_off.e("ok"), "✅");
    }

    #[test]
    fn effects_and_button_edge_cases() {
        let p = PremiumState::new(true);
        assert_eq!(p.effect("fire"), Some("5104841245755180586"));
        assert_eq!(p.effect("nope"), None);
        p.disable_effects();
        assert_eq!(p.effect("fire"), None);
        assert!(p.active());

        // Key with fallback only (no custom ID in DEFAULT_IDS)
        let btn_settings = p.button(Some("settings"), "Settings");
        assert_eq!(btn_settings.text, "⚙️ Settings");
        assert_eq!(btn_settings.icon_custom_emoji_id, None);

        // Key = None
        let btn_plain = p.button(None, "Plain");
        assert_eq!(btn_plain.text, "Plain");
        assert_eq!(btn_plain.icon_custom_emoji_id, None);

        // Unknown key
        let btn_unk = p.button(Some("nonexistent"), "Go");
        assert_eq!(btn_unk.text, "Go");
        assert_eq!(btn_unk.icon_custom_emoji_id, None);

        // strip_custom_emoji multiline
        let multi = "<tg-emoji emoji-id=\"1\">line1\nline2</tg-emoji>";
        assert_eq!(strip_custom_emoji(multi), "line1\nline2");

        // strip_md_custom_emoji preserves normal markdown images
        assert_eq!(
            strip_md_custom_emoji("![alt](https://example.com/a.png) ![✅](tg://emoji?id=123)"),
            "![alt](https://example.com/a.png) ✅"
        );
    }

    #[test]
    fn premium_error_detection() {
        assert!(looks_premium_error("Bad Request: DOCUMENT_INVALID"));
        assert!(looks_premium_error("MESSAGE_EFFECT_ID_INVALID"));
        assert!(looks_premium_error("invalid custom emoji"));
        assert!(looks_premium_error("CUSTOM_EMOJI_INVALID"));
        assert!(looks_premium_error("ICON_INVALID"));
        // Generic HTML entity errors must NOT globally disable Premium UI
        assert!(!looks_premium_error("Bad Request: ENTITY_BOUNDS_INVALID"));
        assert!(!looks_premium_error("Bad Request: can't parse entities: Can't find end tag"));
        assert!(!looks_premium_error("Bad Request: message is not modified"));

        let api_err = BridgeError::BotApi {
            code: 400,
            message: "Bad Request: PREMIUM_ACCOUNT_REQUIRED".to_string(),
            retryable: false,
        };
        assert!(is_premium_error(&api_err));
    }

    #[test]
    fn thread_safe_shared_state_across_threads() {
        use std::sync::Arc;
        let state = Arc::new(PremiumState::new(true));
        let s2 = Arc::clone(&state);
        let handle = std::thread::spawn(move || {
            assert!(s2.active());
            s2.disable("WORKER_REJECTED");
        });
        assert!(handle.join().is_ok());
        assert!(!state.active());
        assert_eq!(state.reason().as_deref(), Some("WORKER_REJECTED"));
        assert_eq!(state.e("ok"), "✅");
    }
}
