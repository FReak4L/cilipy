//! Thread-safe persistent JSON store (`$STATE_DIR/widgets.json`) for Bot API 10.4 widgets.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use agy_core::atomic::atomic_write_json;
use agy_core::error::{BridgeError, Result};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::spec::{
    clamp_cache_time, encode_widget_data, WidgetData, WidgetSpec, LEGACY_WIDGET_HANDLERS,
    LEGACY_WIDGET_SLUGS, WIDGET_CACHE_TIME_DEFAULT, WIDGET_DATA_LIMIT,
    WIDGET_SHARED_EDIT_MIN_INTERVAL_SECS,
};

const MESSAGES_CAP: usize = 500;
const WALLET_EVENTS_CAP: usize = 200;
const WEBAPP_WIDGETS_CAP: usize = 300;

static WID_COUNTER: AtomicU64 = AtomicU64::new(1);

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn generate_wid() -> String {
    let mut raw = [0u8; 12];
    let urandom_ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut raw))
        .is_ok();
    if !urandom_ok {
        let mut hasher = Sha256::new();
        let seq = WID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0u128, |d| d.as_nanos());
        hasher.update(seq.to_le_bytes());
        hasher.update(nanos.to_le_bytes());
        hasher.update(std::process::id().to_le_bytes());
        let digest = hasher.finalize();
        raw.copy_from_slice(&digest[..12]);
    }
    encode_base64url_12(&raw)
}

fn encode_base64url_12(bytes: &[u8; 12]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(16);
    for chunk in bytes.as_chunks::<3>().0 {
        let b0 = chunk[0] as u32;
        let b1 = chunk[1] as u32;
        let b2 = chunk[2] as u32;
        let combined = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((combined >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((combined >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((combined >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(combined & 0x3f) as usize] as char);
    }
    out
}

fn de_btree_or_default<'de, D, V>(deserializer: D) -> std::result::Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    Ok(Option::<BTreeMap<String, V>>::deserialize(deserializer)?.unwrap_or_default())
}

fn de_vec_or_default<'de, D, V>(deserializer: D) -> std::result::Result<Vec<V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    Ok(Option::<Vec<V>>::deserialize(deserializer)?.unwrap_or_default())
}

fn de_opt_i64_flexible<'de, D>(deserializer: D) -> std::result::Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Value>::deserialize(deserializer)? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => Ok(n.as_i64()),
        Some(Value::String(s)) => Ok(s.trim().parse::<i64>().ok()),
        _ => Ok(None),
    }
}

fn de_cache_time_default<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<u32>::deserialize(deserializer)?
        .filter(|&v| v > 0)
        .unwrap_or(WIDGET_CACHE_TIME_DEFAULT))
}

fn value_as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// Patch directive for updating `chat_data` or `public_data` while preserving `""` clear semantics.
#[derive(Debug, Clone, Copy, Default)]
pub enum DataPatch<'a> {
    #[default]
    Unchanged,
    Clear,
    Set(WidgetData<'a>),
}

impl<'a> DataPatch<'a> {
    /// Convert an optional string/JSON payload into a [`DataPatch`], treating `""` as `Clear`.
    pub fn from_opt(val: Option<impl Into<WidgetData<'a>>>) -> Self {
        match val {
            None => Self::Unchanged,
            Some(v) => match v.into() {
                WidgetData::Str("") | WidgetData::Value(Value::Null) => Self::Clear,
                WidgetData::Value(Value::String(s)) if s.is_empty() => Self::Clear,
                other => Self::Set(other),
            },
        }
    }

    fn resolve(self) -> Result<Option<Option<String>>> {
        match self {
            Self::Unchanged => Ok(None),
            Self::Clear => Ok(Some(None)),
            Self::Set(WidgetData::Str("")) | Self::Set(WidgetData::Value(Value::Null)) => {
                Ok(Some(None))
            }
            Self::Set(WidgetData::Value(Value::String(s))) if s.is_empty() => Ok(Some(None)),
            Self::Set(other) => {
                let encoded = encode_widget_data(Some(other), false)?;
                Ok(Some(encoded))
            }
        }
    }
}

/// Persisted message record in `widgets.json -> messages`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct MessageRecord {
    #[serde(default, deserialize_with = "de_opt_i64_flexible")]
    pub chat_id: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_i64_flexible")]
    pub message_id: Option<i64>,
    #[serde(default)]
    pub inline_message_id: Option<String>,
    #[serde(default)]
    pub widget_id: Option<String>,
    #[serde(default)]
    pub slug: Option<String>,
    #[serde(default)]
    pub handler: Option<String>,
    #[serde(default)]
    pub caption: Option<String>,
    #[serde(default)]
    pub is_shared: bool,
    #[serde(default)]
    pub allow_queries: Option<bool>,
    #[serde(default)]
    pub public_data: Option<String>,
    #[serde(default)]
    pub chat_data: Option<String>,
    #[serde(default)]
    pub ts: f64,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Persisted shared widget record in `widgets.json -> shared`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SharedWidgetRecord {
    #[serde(default)]
    pub widget_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    #[serde(default)]
    pub public_data: Option<String>,
    #[serde(default = "default_cache_time", deserialize_with = "de_cache_time_default")]
    pub cache_time: u32,
    #[serde(default)]
    pub ts: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_edit_ts: Option<f64>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

fn default_cache_time() -> u32 {
    WIDGET_CACHE_TIME_DEFAULT
}

/// Persisted poll vote state in `widgets.json -> votes`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct VoteRecord {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub opts: Vec<String>,
    #[serde(default)]
    pub voters: BTreeMap<String, usize>,
    #[serde(default)]
    pub r: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Computed vote summary returned by [`WidgetStore::record_vote`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteResult {
    pub q: String,
    pub opts: Vec<String>,
    pub v: Vec<usize>,
    pub r: i64,
}

/// Persisted TON wallet widget event in `widgets.json -> wallet_events`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalletEvent {
    pub uid: i64,
    pub kind: String,
    pub payload: Value,
    pub ts: f64,
}

/// Persisted WebApp widget record in `widgets.json -> webapp_widgets`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WebAppWidgetRecord {
    #[serde(default)]
    pub wid: String,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub caption: Option<String>,
    #[serde(default)]
    pub slug: Option<String>,
    #[serde(default)]
    pub handler: Option<String>,
    #[serde(default)]
    pub is_shared: bool,
    #[serde(default)]
    pub allow_queries: Option<bool>,
    #[serde(default = "default_cache_time", deserialize_with = "de_cache_time_default")]
    pub cache_time: u32,
    #[serde(default)]
    pub public_data: Option<String>,
    #[serde(default)]
    pub chat_data: Option<String>,
    #[serde(default)]
    pub shared_widget_id: Option<String>,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default, deserialize_with = "de_opt_i64_flexible")]
    pub chat_id: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_i64_flexible")]
    pub message_id: Option<i64>,
    #[serde(default)]
    pub tab: Option<String>,
    #[serde(default = "default_true")]
    pub rich: bool,
    #[serde(default)]
    pub ts: f64,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

fn default_true() -> bool {
    true
}

/// Top-level JSON structure of `$STATE_DIR/widgets.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WidgetStoreData {
    #[serde(default, deserialize_with = "de_btree_or_default")]
    pub messages: BTreeMap<String, MessageRecord>,
    #[serde(default, deserialize_with = "de_btree_or_default")]
    pub shared: BTreeMap<String, SharedWidgetRecord>,
    #[serde(default, deserialize_with = "de_btree_or_default")]
    pub slugs: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "de_btree_or_default")]
    pub votes: BTreeMap<String, VoteRecord>,
    #[serde(default, deserialize_with = "de_vec_or_default")]
    pub wallet_events: Vec<WalletEvent>,
    #[serde(default, deserialize_with = "de_btree_or_default")]
    pub webapp_widgets: BTreeMap<String, WebAppWidgetRecord>,
}

/// Recent widget snapshot returned by [`WidgetStore::list_recent`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RecentWidgets {
    pub messages: Vec<MessageRecord>,
    pub shared: Vec<SharedWidgetRecord>,
    pub wallet_events: Vec<WalletEvent>,
    pub slugs: BTreeMap<String, String>,
}

/// Optional parameters for [`WidgetStore::record_sent_with`].
#[derive(Debug, Clone, Default)]
pub struct RecordSentOpts<'a> {
    pub chat_id: Option<i64>,
    pub message_id: Option<i64>,
    pub inline_message_id: Option<&'a str>,
    pub spec: Option<&'a WidgetSpec>,
    pub widget_id: Option<&'a str>,
    pub slug: Option<&'a str>,
    pub handler: Option<&'a str>,
    pub caption: Option<&'a str>,
    pub is_shared: Option<bool>,
    pub allow_queries: Option<bool>,
    pub public_data: Option<WidgetData<'a>>,
    pub chat_data: Option<WidgetData<'a>>,
    pub cache_time: Option<u32>,
}

/// Result returned by [`WidgetStore::record_sent_with`].
#[derive(Debug, Clone, PartialEq)]
pub enum RecordSentOutcome {
    Message(MessageRecord),
    Shared(SharedWidgetRecord),
    None,
}

fn msg_key(chat_id: Option<i64>, message_id: Option<i64>, inline_message_id: Option<&str>) -> String {
    if let Some(imid) = inline_message_id {
        if !imid.is_empty() {
            return format!("inline:{imid}");
        }
    }
    let cid = chat_id.map_or_else(|| "None".to_string(), |v| v.to_string());
    let mid = message_id.map_or_else(|| "None".to_string(), |v| v.to_string());
    format!("{cid}:{mid}")
}

fn load_store_data(path: &Path) -> WidgetStoreData {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return WidgetStoreData::default(),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed reading widgets.json; starting fresh");
            return WidgetStoreData::default();
        }
    };
    match serde_json::from_str::<WidgetStoreData>(&raw) {
        Ok(data) => data,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed parsing widgets.json; starting fresh");
            WidgetStoreData::default()
        }
    }
}

/// Thread-safe persistent JSON store for Bot API 10.4 widget messages, shared widgets, votes, and WebApp records.
pub struct WidgetStore {
    path: PathBuf,
    inner: RwLock<WidgetStoreData>,
}

impl WidgetStore {
    /// Open `widgets.json` at `path`, recovering gracefully if missing or corrupt.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let data = load_store_data(&path);
        Ok(Self {
            path,
            inner: RwLock::new(data),
        })
    }

    /// Open `state_dir.join("widgets.json")`.
    pub fn from_state_dir(state_dir: &Path) -> Result<Self> {
        Self::open(state_dir.join("widgets.json"))
    }

    /// Open `$STATE_DIR/widgets.json` (defaulting `STATE_DIR` to `/var/lib/agy-telegram`).
    pub fn open_from_env() -> Result<Self> {
        let state_dir =
            std::env::var("STATE_DIR").unwrap_or_else(|_| "/var/lib/agy-telegram".to_string());
        Self::from_state_dir(Path::new(&state_dir))
    }

    /// Path to the backing `widgets.json` file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Atomically persist the store to disk with mode `0o600`.
    pub fn save(&self) -> Result<()> {
        let guard = self
            .inner
            .read()
            .map_err(|e| BridgeError::Internal(format!("widget store read lock poisoned: {e}")))?;
        atomic_write_json(&self.path, &*guard, true)
    }

    /// Return a cloned snapshot of all in-memory widget store tables.
    pub fn snapshot(&self) -> WidgetStoreData {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.clone()
    }

    /// Mutate the store under write lock (for tests or migrations) and atomically save.
    pub fn mutate<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut WidgetStoreData) -> R,
    {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("widget store write lock poisoned: {e}")))?;
        let res = f(&mut guard);
        atomic_write_json(&self.path, &*guard, true)?;
        Ok(res)
    }

    fn trim_messages_locked(data: &mut WidgetStoreData) {
        while data.messages.len() > MESSAGES_CAP {
            let oldest_key = data
                .messages
                .iter()
                .min_by(|a, b| {
                    a.1.ts
                        .partial_cmp(&b.1.ts)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.0.cmp(b.0))
                })
                .map(|(k, _)| k.clone());
            match oldest_key {
                Some(k) => {
                    data.messages.remove(&k);
                }
                None => break,
            }
        }
    }

    fn trim_webapp_widgets_locked(data: &mut WidgetStoreData) {
        while data.webapp_widgets.len() > WEBAPP_WIDGETS_CAP {
            let oldest_key = data
                .webapp_widgets
                .iter()
                .min_by(|a, b| {
                    a.1.ts
                        .partial_cmp(&b.1.ts)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.0.cmp(b.0))
                })
                .map(|(k, _)| k.clone());
            match oldest_key {
                Some(k) => {
                    data.webapp_widgets.remove(&k);
                }
                None => break,
            }
        }
    }

    /// Record a sent widget message and/or shared widget registration.
    pub fn record_sent(
        &self,
        chat_id: Option<i64>,
        message_id: Option<i64>,
        spec: Option<&WidgetSpec>,
        inline_message_id: Option<&str>,
    ) -> Result<Option<MessageRecord>> {
        let outcome = self.record_sent_with(RecordSentOpts {
            chat_id,
            message_id,
            inline_message_id,
            spec,
            ..Default::default()
        })?;
        match outcome {
            RecordSentOutcome::Message(m) => Ok(Some(m)),
            _ => Ok(None),
        }
    }

    /// Record a sent widget message with explicit field overrides.
    pub fn record_sent_with(&self, opts: RecordSentOpts<'_>) -> Result<RecordSentOutcome> {
        let eff_widget_id = opts
            .widget_id
            .map(str::to_string)
            .or_else(|| opts.spec.and_then(|s| s.widget_id.clone()));
        let eff_slug = opts
            .slug
            .map(str::to_string)
            .or_else(|| opts.spec.and_then(|s| s.slug.clone()));
        let eff_handler = opts
            .handler
            .map(str::to_string)
            .or_else(|| opts.spec.and_then(|s| s.handler.clone()));
        let eff_caption = opts
            .caption
            .map(str::to_string)
            .or_else(|| opts.spec.and_then(|s| s.caption.clone()));
        let eff_is_shared = opts
            .is_shared
            .or_else(|| opts.spec.and_then(|s| s.is_shared));
        let eff_allow_queries = opts
            .allow_queries
            .or_else(|| opts.spec.and_then(|s| s.allow_queries));

        let eff_public = match opts.public_data {
            Some(pd) => encode_widget_data(Some(pd), false)?,
            None => encode_widget_data(
                opts.spec.and_then(|s| s.public_data.as_deref()),
                false,
            )?,
        };
        let eff_chat = match opts.chat_data {
            Some(cd) => encode_widget_data(Some(cd), false)?,
            None => encode_widget_data(
                opts.spec.and_then(|s| s.chat_data.as_deref()),
                false,
            )?,
        };
        let eff_cache_time = clamp_cache_time(
            opts.cache_time
                .or_else(|| opts.spec.and_then(|s| s.cache_time)),
        );

        let now = now_secs();
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("widget store write lock poisoned: {e}")))?;

        let has_inline = opts.inline_message_id.is_some_and(|s| !s.is_empty());
        let has_msg = has_inline || (opts.chat_id.is_some() && opts.message_id.is_some());

        let mut msg_entry: Option<MessageRecord> = None;
        if has_msg {
            let key = msg_key(opts.chat_id, opts.message_id, opts.inline_message_id);
            let entry = MessageRecord {
                chat_id: opts.chat_id,
                message_id: opts.message_id,
                inline_message_id: opts.inline_message_id.map(str::to_string),
                widget_id: eff_widget_id.clone(),
                slug: eff_slug.clone(),
                handler: eff_handler.clone(),
                caption: eff_caption.clone(),
                is_shared: eff_is_shared.unwrap_or(false)
                    || eff_widget_id.as_deref().is_some_and(|w| !w.is_empty()),
                allow_queries: eff_allow_queries,
                public_data: eff_public.clone(),
                chat_data: eff_chat,
                ts: now,
                extra: BTreeMap::new(),
            };
            guard.messages.insert(key, entry.clone());
            Self::trim_messages_locked(&mut guard);
            msg_entry = Some(entry);
        }

        let mut shared_entry: Option<SharedWidgetRecord> = None;
        if let Some(ref wid) = eff_widget_id {
            if !wid.is_empty() && eff_is_shared != Some(false) {
                let mut rec = guard.shared.get(wid).cloned().unwrap_or_default();
                rec.widget_id = wid.clone();
                if let Some(ref sl) = eff_slug {
                    rec.slug = Some(sl.clone());
                }
                if let Some(ref h) = eff_handler {
                    rec.handler = Some(h.clone());
                }
                if let Some(ref cap) = eff_caption {
                    rec.caption = Some(cap.clone());
                }
                if let Some(ref pd) = eff_public {
                    rec.public_data = Some(pd.clone());
                }
                if let Some(ct) = eff_cache_time {
                    rec.cache_time = ct;
                } else if rec.cache_time == 0 {
                    rec.cache_time = WIDGET_CACHE_TIME_DEFAULT;
                }
                rec.ts = now;
                guard.shared.insert(wid.clone(), rec.clone());
                if let Some(ref sl) = eff_slug {
                    if !sl.is_empty() {
                        guard.slugs.insert(sl.clone(), wid.clone());
                    }
                }
                shared_entry = Some(rec);
            }
        }

        atomic_write_json(&self.path, &*guard, true)?;

        if let Some(m) = msg_entry {
            Ok(RecordSentOutcome::Message(m))
        } else if let Some(s) = shared_entry {
            Ok(RecordSentOutcome::Shared(s))
        } else {
            Ok(RecordSentOutcome::None)
        }
    }

    /// Fetch a recorded widget message by `(chat_id, message_id)` or `inline_message_id`.
    pub fn get_message(
        &self,
        chat_id: Option<i64>,
        message_id: Option<i64>,
        inline_message_id: Option<&str>,
    ) -> Option<MessageRecord> {
        let key = msg_key(chat_id, message_id, inline_message_id);
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.messages.get(&key).cloned()
    }

    /// Resolve a widget slug or raw `widget_id` to a known `widget_id`.
    pub fn resolve_widget_id(&self, id_or_slug: &str) -> Option<String> {
        if id_or_slug.is_empty() {
            return None;
        }
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(wid) = guard.slugs.get(id_or_slug) {
            return Some(wid.clone());
        }
        if guard.shared.contains_key(id_or_slug) {
            return Some(id_or_slug.to_string());
        }
        None
    }

    /// Fetch a shared widget record by `widget_id` or `slug`.
    pub fn get_shared(&self, widget_id_or_slug: &str) -> Option<SharedWidgetRecord> {
        if widget_id_or_slug.is_empty() {
            return None;
        }
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let wid = if let Some(mapped) = guard.slugs.get(widget_id_or_slug) {
            mapped.as_str()
        } else if guard.shared.contains_key(widget_id_or_slug) {
            widget_id_or_slug
        } else {
            return None;
        };
        guard.shared.get(wid).cloned()
    }

    /// Update `chat_data` and/or `public_data` on a tracked message (and propagate `public_data` to `shared`).
    pub fn update_message_state(
        &self,
        chat_id: Option<i64>,
        message_id: Option<i64>,
        inline_message_id: Option<&str>,
        chat_data: DataPatch<'_>,
        public_data: DataPatch<'_>,
    ) -> Result<MessageRecord> {
        let new_cd = chat_data.resolve()?;
        let new_pd = public_data.resolve()?;
        let key = msg_key(chat_id, message_id, inline_message_id);

        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("widget store write lock poisoned: {e}")))?;

        let mut rec = guard.messages.remove(&key).unwrap_or_else(|| MessageRecord {
            chat_id,
            message_id,
            inline_message_id: inline_message_id.map(str::to_string),
            ..Default::default()
        });

        if let Some(cd_val) = new_cd {
            rec.chat_data = cd_val;
        }
        if let Some(pd_val) = new_pd {
            rec.public_data = pd_val.clone();
            if let Some(ref wid) = rec.widget_id {
                if let Some(shared_rec) = guard.shared.get_mut(wid) {
                    shared_rec.public_data = pd_val;
                }
            }
        }
        rec.ts = now_secs();
        guard.messages.insert(key, rec.clone());
        Self::trim_messages_locked(&mut guard);
        atomic_write_json(&self.path, &*guard, true)?;
        Ok(rec)
    }

    /// Alias for [`Self::update_message_state`] with `public_data` first.
    pub fn update_message_data(
        &self,
        chat_id: Option<i64>,
        message_id: Option<i64>,
        inline_message_id: Option<&str>,
        public_data: DataPatch<'_>,
        chat_data: DataPatch<'_>,
    ) -> Result<MessageRecord> {
        self.update_message_state(chat_id, message_id, inline_message_id, chat_data, public_data)
    }

    /// Update `public_data` and optional `cache_time` on a shared widget (recording `last_edit_ts`).
    pub fn update_shared_state<'a>(
        &self,
        widget_id: &str,
        public_data: Option<impl Into<WidgetData<'a>>>,
        cache_time: Option<u32>,
    ) -> Result<SharedWidgetRecord> {
        let new_pd = match public_data {
            None => None,
            Some(v) => match v.into() {
                WidgetData::Str("") | WidgetData::Value(Value::Null) => None,
                WidgetData::Value(Value::String(s)) if s.is_empty() => None,
                other => encode_widget_data(Some(other), false)?,
            },
        };
        let ct = clamp_cache_time(cache_time);
        let now = now_secs();

        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("widget store write lock poisoned: {e}")))?;
        let wid = guard
            .slugs
            .get(widget_id)
            .cloned()
            .unwrap_or_else(|| widget_id.to_string());
        let mut rec = guard
            .shared
            .get(&wid)
            .cloned()
            .unwrap_or_else(|| SharedWidgetRecord {
                widget_id: wid.clone(),
                cache_time: WIDGET_CACHE_TIME_DEFAULT,
                ..Default::default()
            });
        rec.widget_id = wid.clone();
        rec.public_data = new_pd;
        if let Some(c) = ct {
            rec.cache_time = c;
        } else if rec.cache_time == 0 {
            rec.cache_time = WIDGET_CACHE_TIME_DEFAULT;
        }
        rec.ts = now;
        rec.last_edit_ts = Some(now);
        guard.shared.insert(wid, rec.clone());
        atomic_write_json(&self.path, &*guard, true)?;
        Ok(rec)
    }

    /// Seconds to wait before the next `editSharedWidgetData` call on `widget_id` (1 req/s rate limit).
    pub fn shared_edit_delay(&self, widget_id: &str, now: Option<f64>) -> f64 {
        let cur = now.unwrap_or_else(now_secs);
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let wid = guard
            .slugs
            .get(widget_id)
            .map(String::as_str)
            .unwrap_or(widget_id);
        let Some(rec) = guard.shared.get(wid) else {
            return 0.0;
        };
        let Some(last) = rec.last_edit_ts else {
            return 0.0;
        };
        let remaining = WIDGET_SHARED_EDIT_MIN_INTERVAL_SECS - (cur - last);
        if remaining > 0.0 {
            remaining
        } else {
            0.0
        }
    }

    /// Whether `editSharedWidgetData` can run immediately without waiting.
    pub fn can_edit_shared(&self, widget_id: &str, now: Option<f64>) -> bool {
        self.shared_edit_delay(widget_id, now) <= 0.0
    }

    /// Stamp `last_edit_ts` on an existing shared widget record and persist.
    pub fn mark_shared_edited(&self, widget_id: &str, now: Option<f64>) -> Result<bool> {
        let ts = now.unwrap_or_else(now_secs);
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("widget store write lock poisoned: {e}")))?;
        let wid = guard
            .slugs
            .get(widget_id)
            .cloned()
            .unwrap_or_else(|| widget_id.to_string());
        if let Some(rec) = guard.shared.get_mut(&wid) {
            rec.last_edit_ts = Some(ts);
            rec.ts = ts;
            atomic_write_json(&self.path, &*guard, true)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Find all WebApp widget tokens (`wid`) referencing a shared widget ID or slug.
    pub fn find_shared_targets(&self, wid_or_slug: &str) -> Vec<String> {
        if wid_or_slug.is_empty() {
            return Vec::new();
        }
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let resolved = guard
            .slugs
            .get(wid_or_slug)
            .map(String::as_str)
            .unwrap_or(wid_or_slug);
        guard
            .webapp_widgets
            .iter()
            .filter_map(|(wid, rec)| {
                let matches = wid == resolved
                    || rec.shared_widget_id.as_deref() == Some(resolved)
                    || (rec.is_shared && rec.slug.as_deref() == Some(wid_or_slug));
                if matches {
                    Some(wid.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find all WebApp widget tokens bound to `(chat_id, message_id)`.
    pub fn find_message_targets(&self, chat_id: i64, message_id: i64) -> Vec<String> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .webapp_widgets
            .iter()
            .filter_map(|(wid, rec)| {
                if rec.chat_id == Some(chat_id) && rec.message_id == Some(message_id) {
                    Some(wid.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Increment revision counter `"r"` and trim overflowing fields so serialized JSON fits <= 1024 bytes.
    pub fn bump_rev(data_dict: &Map<String, Value>) -> Result<(String, i64)> {
        let mut d = data_dict.clone();
        let new_rev = d.get("r").and_then(value_as_i64).unwrap_or(0) + 1;
        d.insert("r".to_string(), json!(new_rev));

        let mut s = serde_json::to_string(&d).map_err(|e| BridgeError::json("bump_rev", e))?;
        if s.len() <= WIDGET_DATA_LIMIT {
            return Ok((s, new_rev));
        }

        // Trim kv entries if present
        if let Some(Value::Object(kv)) = d.get_mut("kv") {
            let mut kv_owned = kv.clone();
            while !kv_owned.is_empty() && s.len() > WIDGET_DATA_LIMIT {
                if let Some(first_key) = kv_owned.keys().next().cloned() {
                    kv_owned.remove(&first_key);
                } else {
                    break;
                }
                d.insert("kv".to_string(), Value::Object(kv_owned.clone()));
                s = serde_json::to_string(&d).map_err(|e| BridgeError::json("bump_rev", e))?;
            }
        }

        // Trim long strings in non-structural keys
        let keys: Vec<String> = d.keys().cloned().collect();
        for k in keys {
            if s.len() <= WIDGET_DATA_LIMIT {
                break;
            }
            if matches!(k.as_str(), "r" | "q" | "opts" | "v" | "count") {
                continue;
            }
            if let Some(Value::String(st)) = d.get(&k) {
                if st.chars().count() > 64 {
                    let truncated: String = st.chars().take(64).collect();
                    d.insert(k, Value::String(truncated));
                    s = serde_json::to_string(&d).map_err(|e| BridgeError::json("bump_rev", e))?;
                }
            }
        }

        // Drop largest non-revision keys until within limit
        while s.len() > WIDGET_DATA_LIMIT {
            let victim = d
                .iter()
                .filter(|(k, _)| k.as_str() != "r")
                .max_by_key(|(_, v)| serde_json::to_string(v).map_or(0, |txt| txt.len()))
                .map(|(k, _)| k.clone());
            match victim {
                Some(k) => {
                    d.remove(&k);
                    s = serde_json::to_string(&d).map_err(|e| BridgeError::json("bump_rev", e))?;
                }
                None => break,
            }
        }

        Ok((s, new_rev))
    }

    /// Record or update a deduplicated user vote for a poll widget.
    pub fn record_vote(
        &self,
        key: &str,
        user_id: i64,
        option_idx: usize,
        num_options: usize,
    ) -> Result<VoteResult> {
        if num_options == 0 {
            return Err(BridgeError::Validation(
                "num_options must be positive".to_string(),
            ));
        }
        if option_idx >= num_options {
            return Err(BridgeError::Validation(format!(
                "option_idx {option_idx} out of range 0..{}",
                num_options - 1
            )));
        }

        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("widget store write lock poisoned: {e}")))?;

        let poll_key = guard
            .slugs
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.to_string());

        let mut poll = match guard.votes.get(&poll_key).cloned() {
            Some(existing) => existing,
            None => {
                let mut q_val = String::new();
                let mut opts_val: Vec<String> = Vec::new();
                let mut rev_val: i64 = 0;

                let raw_pd = guard
                    .shared
                    .get(&poll_key)
                    .and_then(|r| r.public_data.clone())
                    .or_else(|| {
                        guard
                            .messages
                            .get(&poll_key)
                            .and_then(|r| r.public_data.clone())
                    })
                    .or_else(|| {
                        guard
                            .webapp_widgets
                            .get(&poll_key)
                            .and_then(|r| r.public_data.clone())
                    });

                if let Some(pd) = raw_pd {
                    if let Ok(Value::Object(parsed)) = serde_json::from_str::<Value>(&pd) {
                        if let Some(Value::String(qv)) = parsed.get("q") {
                            q_val = qv.clone();
                        }
                        if let Some(Value::Array(arr)) = parsed.get("opts") {
                            opts_val = arr
                                .iter()
                                .map(|v| match v {
                                    Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                })
                                .collect();
                        }
                        if let Some(rv) = parsed.get("r").and_then(value_as_i64) {
                            rev_val = rv;
                        }
                    }
                }
                if opts_val.len() != num_options {
                    opts_val = (0..num_options).map(|i| format!("Option {}", i + 1)).collect();
                }
                VoteRecord {
                    q: q_val,
                    opts: opts_val,
                    voters: BTreeMap::new(),
                    r: rev_val,
                    handler: None,
                    slug: None,
                    extra: BTreeMap::new(),
                }
            }
        };

        if poll.opts.len() != num_options {
            poll.opts = (0..num_options).map(|i| format!("Option {}", i + 1)).collect();
        }
        poll.voters.insert(user_id.to_string(), option_idx);

        let mut counts = vec![0usize; num_options];
        for &idx in poll.voters.values() {
            if idx < num_options {
                counts[idx] += 1;
            }
        }
        poll.r += 1;

        let res = VoteResult {
            q: poll.q.clone(),
            opts: poll.opts.clone(),
            v: counts,
            r: poll.r,
        };
        guard.votes.insert(poll_key, poll);
        atomic_write_json(&self.path, &*guard, true)?;
        Ok(res)
    }

    /// Apply a `counter:*` or `kv:*` mutation query and bump revision within 1024 bytes.
    pub fn apply_kv_mutation<'a>(
        current_json: Option<WidgetData<'a>>,
        query_data: &str,
    ) -> Result<(String, Value)> {
        let mut state: Map<String, Value> = match current_json {
            None => Map::new(),
            Some(WidgetData::Str("")) => Map::new(),
            Some(WidgetData::Str(s)) => match serde_json::from_str::<Value>(s) {
                Ok(Value::Object(m)) => m,
                _ => Map::new(),
            },
            Some(WidgetData::Value(Value::Object(m))) => m.clone(),
            Some(WidgetData::Value(Value::String(s))) => match serde_json::from_str::<Value>(s) {
                Ok(Value::Object(m)) => m,
                _ => Map::new(),
            },
            Some(WidgetData::Value(_)) => Map::new(),
        };

        if query_data == "counter:inc" {
            let cur = state.get("count").and_then(value_as_i64).unwrap_or(0);
            state.insert("count".to_string(), json!(cur + 1));
        } else if query_data == "counter:dec" {
            let cur = state.get("count").and_then(value_as_i64).unwrap_or(0);
            state.insert("count".to_string(), json!(cur - 1));
        } else if query_data == "counter:reset" {
            state.insert("count".to_string(), json!(0));
        } else if let Some(rest) = query_data.strip_prefix("kv:set:") {
            let Some((k, v)) = rest.split_once('=') else {
                return Err(BridgeError::Validation(format!(
                    "kv:set requires key=value, got {query_data:?}"
                )));
            };
            if k.is_empty() {
                return Err(BridgeError::Validation(
                    "kv:set key must not be empty".to_string(),
                ));
            }
            let mut kv = match state.get("kv") {
                Some(Value::Object(m)) => m.clone(),
                _ => Map::new(),
            };
            kv.insert(k.to_string(), Value::String(v.to_string()));
            state.insert("kv".to_string(), Value::Object(kv));
        } else if let Some(k) = query_data.strip_prefix("kv:del:") {
            let mut kv = match state.get("kv") {
                Some(Value::Object(m)) => m.clone(),
                _ => Map::new(),
            };
            kv.remove(k);
            state.insert("kv".to_string(), Value::Object(kv));
        } else if query_data == "kv:get" {
            if let Some(v) = state.get("kv") {
                if !v.is_object() {
                    state.insert("kv".to_string(), Value::Object(Map::new()));
                }
            }
        } else {
            return Err(BridgeError::Validation(format!(
                "Unsupported KV mutation query: {query_data:?}"
            )));
        }

        let (encoded, _) = Self::bump_rev(&state)?;
        let parsed: Value = serde_json::from_str(&encoded)
            .map_err(|e| BridgeError::json("apply_kv_mutation", e))?;
        Ok((encoded, parsed))
    }

    /// Record a TON wallet event (capped at 200 most recent events).
    pub fn record_wallet_event(&self, uid: i64, kind: &str, payload: Value) -> Result<WalletEvent> {
        let event = WalletEvent {
            uid,
            kind: kind.to_string(),
            payload,
            ts: now_secs(),
        };
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("widget store write lock poisoned: {e}")))?;
        guard.wallet_events.push(event.clone());
        if guard.wallet_events.len() > WALLET_EVENTS_CAP {
            let drain = guard.wallet_events.len() - WALLET_EVENTS_CAP;
            guard.wallet_events.drain(0..drain);
        }
        atomic_write_json(&self.path, &*guard, true)?;
        Ok(event)
    }

    /// Return the most recent `limit` messages, shared widgets, wallet events, and slugs.
    pub fn list_recent(&self, limit: usize) -> RecentWidgets {
        if limit == 0 {
            return RecentWidgets::default();
        }
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut msgs: Vec<MessageRecord> = guard.messages.values().cloned().collect();
        msgs.sort_by(|a, b| b.ts.partial_cmp(&a.ts).unwrap_or(std::cmp::Ordering::Equal));
        msgs.truncate(limit);

        let mut shared: Vec<SharedWidgetRecord> = guard.shared.values().cloned().collect();
        shared.sort_by(|a, b| b.ts.partial_cmp(&a.ts).unwrap_or(std::cmp::Ordering::Equal));
        shared.truncate(limit);

        let wallet_events: Vec<WalletEvent> =
            guard.wallet_events.iter().rev().take(limit).cloned().collect();

        RecentWidgets {
            messages: msgs,
            shared,
            wallet_events,
            slugs: guard.slugs.clone(),
        }
    }

    /// Register an interactive WebApp widget instance and return its widget token ID.
    pub fn register_webapp_widget(
        &self,
        spec: &WidgetSpec,
        chat_id: Option<i64>,
        message_id: Option<i64>,
        wid: Option<&str>,
    ) -> Result<String> {
        let eff_wid = wid.map(str::to_string).unwrap_or_else(generate_wid);
        let tab = if spec
            .handler
            .as_deref()
            .is_some_and(|h| h.trim().eq_ignore_ascii_case("skills"))
        {
            Some("inst".to_string())
        } else {
            None
        };
        let rec = WebAppWidgetRecord {
            wid: eff_wid.clone(),
            html: spec.html.clone(),
            caption: spec.caption.clone(),
            slug: spec.slug.clone(),
            handler: spec.handler.clone(),
            is_shared: spec.is_shared.unwrap_or(false),
            allow_queries: spec.allow_queries,
            cache_time: spec
                .cache_time
                .filter(|&v| v > 0)
                .unwrap_or(WIDGET_CACHE_TIME_DEFAULT),
            public_data: spec.public_data.clone(),
            chat_data: spec.chat_data.clone(),
            shared_widget_id: spec.widget_id.clone(),
            width: spec.width,
            height: spec.height,
            chat_id,
            message_id,
            tab,
            rich: true,
            ts: now_secs(),
            extra: BTreeMap::new(),
        };

        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("widget store write lock poisoned: {e}")))?;
        guard.webapp_widgets.insert(eff_wid.clone(), rec);
        Self::trim_webapp_widgets_locked(&mut guard);
        atomic_write_json(&self.path, &*guard, true)?;
        Ok(eff_wid)
    }

    /// Alias for [`Self::register_webapp_widget`].
    pub fn record_webapp_widget(
        &self,
        spec: &WidgetSpec,
        chat_id: Option<i64>,
        message_id: Option<i64>,
        wid: Option<&str>,
    ) -> Result<String> {
        self.register_webapp_widget(spec, chat_id, message_id, wid)
    }

    /// Fetch a registered WebApp widget record by token ID.
    pub fn get_webapp_widget(&self, wid: &str) -> Option<WebAppWidgetRecord> {
        if wid.is_empty() {
            return None;
        }
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.webapp_widgets.get(wid).cloned()
    }

    /// List all registered WebApp widgets sorted newest-first.
    pub fn list_webapp_widgets(&self) -> Vec<WebAppWidgetRecord> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut items: Vec<WebAppWidgetRecord> = guard.webapp_widgets.values().cloned().collect();
        items.sort_by(|a, b| b.ts.partial_cmp(&a.ts).unwrap_or(std::cmp::Ordering::Equal));
        items
    }

    /// Bind a registered WebApp widget to a sent Telegram `(chat_id, message_id)`.
    pub fn bind_webapp_message(
        &self,
        wid: &str,
        chat_id: i64,
        message_id: i64,
        rich: bool,
        tab: Option<&str>,
    ) -> Result<Option<WebAppWidgetRecord>> {
        if wid.is_empty() {
            return Ok(None);
        }
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("widget store write lock poisoned: {e}")))?;
        let Some(rec) = guard.webapp_widgets.get_mut(wid) else {
            return Ok(None);
        };
        rec.chat_id = Some(chat_id);
        rec.message_id = Some(message_id);
        rec.rich = rich;
        if let Some(t) = tab {
            rec.tab = Some(t.to_string());
        }
        rec.ts = now_secs();
        let updated = rec.clone();
        atomic_write_json(&self.path, &*guard, true)?;
        Ok(Some(updated))
    }

    /// Update `chat_data`, `public_data`, or active `tab` on a registered WebApp widget.
    pub fn update_webapp_widget_state(
        &self,
        wid: &str,
        chat_data: DataPatch<'_>,
        public_data: DataPatch<'_>,
        tab: Option<&str>,
    ) -> Result<Option<WebAppWidgetRecord>> {
        if wid.is_empty() {
            return Ok(None);
        }
        let new_cd = chat_data.resolve()?;
        let new_pd = public_data.resolve()?;

        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("widget store write lock poisoned: {e}")))?;
        let Some(rec) = guard.webapp_widgets.get_mut(wid) else {
            return Ok(None);
        };
        if let Some(cd_val) = new_cd {
            rec.chat_data = cd_val;
        }
        if let Some(pd_val) = new_pd {
            rec.public_data = pd_val;
        }
        if let Some(t) = tab {
            rec.tab = Some(t.to_string());
        }
        rec.ts = now_secs();
        let updated = rec.clone();
        atomic_write_json(&self.path, &*guard, true)?;
        Ok(Some(updated))
    }

    /// Delete default legacy widget entries (`status`, `poll`, `control`, `wallet`, `sys`, `ctl`) transitively.
    pub fn purge_legacy_widgets(&self) -> Result<usize> {
        self.purge_legacy_widgets_with(&LEGACY_WIDGET_HANDLERS, &LEGACY_WIDGET_SLUGS)
    }

    /// Delete legacy widget entries matching `legacy_handlers` or `legacy_slugs` transitively across all 5 tables.
    pub fn purge_legacy_widgets_with(
        &self,
        legacy_handlers: &[&str],
        legacy_slugs: &[&str],
    ) -> Result<usize> {
        let h_set: HashSet<String> = legacy_handlers
            .iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        let s_set: HashSet<String> = legacy_slugs
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let matches_hs = |handler: Option<&str>, slug: Option<&str>| -> bool {
            let h = handler.unwrap_or("").trim().to_ascii_lowercase();
            let s = slug.unwrap_or("").trim().to_ascii_lowercase();
            (!h.is_empty() && h_set.contains(&h)) || (!s.is_empty() && s_set.contains(&s))
        };

        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("widget store write lock poisoned: {e}")))?;

        let mut legacy_wids: HashSet<String> = HashSet::new();
        for (sl, wid) in &guard.slugs {
            if s_set.contains(&sl.trim().to_ascii_lowercase()) && !wid.is_empty() {
                legacy_wids.insert(wid.clone());
            }
        }

        let mut changed = true;
        while changed {
            changed = false;
            for (wid, rec) in &guard.shared {
                if (matches_hs(rec.handler.as_deref(), rec.slug.as_deref())
                    || legacy_wids.contains(wid))
                    && legacy_wids.insert(wid.clone())
                {
                    changed = true;
                }
            }
            for (k, rec) in &guard.messages {
                let m_wid = rec.widget_id.as_deref().filter(|w| !w.is_empty());
                if matches_hs(rec.handler.as_deref(), rec.slug.as_deref())
                    || legacy_wids.contains(k)
                    || m_wid.is_some_and(|w| legacy_wids.contains(w))
                {
                    if legacy_wids.insert(k.clone()) {
                        changed = true;
                    }
                    if let Some(w) = m_wid {
                        if legacy_wids.insert(w.to_string()) {
                            changed = true;
                        }
                    }
                }
            }
            for (wid, rec) in &guard.webapp_widgets {
                let sh_id = rec.shared_widget_id.as_deref().filter(|w| !w.is_empty());
                if matches_hs(rec.handler.as_deref(), rec.slug.as_deref())
                    || legacy_wids.contains(wid)
                    || sh_id.is_some_and(|w| legacy_wids.contains(w))
                {
                    if legacy_wids.insert(wid.clone()) {
                        changed = true;
                    }
                    if let Some(sh) = sh_id {
                        if legacy_wids.insert(sh.to_string()) {
                            changed = true;
                        }
                    }
                }
            }
        }

        let mut removed = 0usize;

        let msg_del: Vec<String> = guard
            .messages
            .iter()
            .filter_map(|(k, rec)| {
                if matches_hs(rec.handler.as_deref(), rec.slug.as_deref())
                    || legacy_wids.contains(k)
                    || rec
                        .widget_id
                        .as_deref()
                        .is_some_and(|w| legacy_wids.contains(w))
                {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        for k in msg_del {
            guard.messages.remove(&k);
            removed += 1;
        }

        let shared_del: Vec<String> = guard
            .shared
            .iter()
            .filter_map(|(wid, rec)| {
                if matches_hs(rec.handler.as_deref(), rec.slug.as_deref())
                    || legacy_wids.contains(wid)
                {
                    Some(wid.clone())
                } else {
                    None
                }
            })
            .collect();
        for wid in shared_del {
            guard.shared.remove(&wid);
            removed += 1;
        }

        let slug_del: Vec<String> = guard
            .slugs
            .iter()
            .filter_map(|(sl, wid)| {
                if s_set.contains(&sl.trim().to_ascii_lowercase()) || legacy_wids.contains(wid) {
                    Some(sl.clone())
                } else {
                    None
                }
            })
            .collect();
        for sl in slug_del {
            guard.slugs.remove(&sl);
            removed += 1;
        }

        let h_prefixes: Vec<String> = h_set.iter().map(|h| format!("{h}:")).collect();
        let vote_del: Vec<String> = guard
            .votes
            .iter()
            .filter_map(|(vk, vrec)| {
                let vk_low = vk.trim().to_ascii_lowercase();
                if legacy_wids.contains(vk)
                    || s_set.contains(&vk_low)
                    || h_set.contains(&vk_low)
                    || h_prefixes.iter().any(|p| vk_low.starts_with(p))
                    || matches_hs(vrec.handler.as_deref(), vrec.slug.as_deref())
                {
                    Some(vk.clone())
                } else {
                    None
                }
            })
            .collect();
        for vk in vote_del {
            guard.votes.remove(&vk);
            removed += 1;
        }

        let ww_del: Vec<String> = guard
            .webapp_widgets
            .iter()
            .filter_map(|(wid, rec)| {
                if matches_hs(rec.handler.as_deref(), rec.slug.as_deref())
                    || legacy_wids.contains(wid)
                    || rec
                        .shared_widget_id
                        .as_deref()
                        .is_some_and(|sh| legacy_wids.contains(sh))
                {
                    Some(wid.clone())
                } else {
                    None
                }
            })
            .collect();
        for wid in ww_del {
            guard.webapp_widgets.remove(&wid);
            removed += 1;
        }

        atomic_write_json(&self.path, &*guard, true)?;
        Ok(removed)
    }
}
