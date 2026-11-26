//! Markdown `<tg-widget>` extractor, `.widget.html` parser, and `.widget.json` action parser.

use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

use agy_core::error::{BridgeError, Result};
use agy_core::tg::{InlineKeyboardMarkup, MessageEntity};
use html_escape::decode_html_entities;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::builtins::builtin_widget;
use crate::spec::{clamp_cache_time, encode_widget_data, WidgetData, WidgetSpec};

static RE_MULTI_NEWLINES: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"\n{3,}").ok());
static RE_CLOSE_WIDGET: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)</tg-widget\s*>").ok());
static RE_CLOSE_SHARED_WIDGET: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)</tg-shared-widget\s*>").ok());
static RE_TOP_WIDGET_META: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?is)^\x{feff}?\s*<!--\s*widget\s*:\s*(\{.*?\})\s*-->\s*").ok()
});

/// Input accepted by [`parse_widget_json`].
#[derive(Debug, Clone, Copy)]
pub enum WidgetJsonInput<'a> {
    Str(&'a str),
    Value(&'a Value),
}

impl<'a> From<&'a str> for WidgetJsonInput<'a> {
    fn from(value: &'a str) -> Self {
        Self::Str(value)
    }
}

impl<'a> From<&'a String> for WidgetJsonInput<'a> {
    fn from(value: &'a String) -> Self {
        Self::Str(value.as_str())
    }
}

impl<'a> From<&'a Value> for WidgetJsonInput<'a> {
    fn from(value: &'a Value) -> Self {
        Self::Value(value)
    }
}

/// Normalized `edit_message_data` action payload (preserving `Some("")` clear semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditMessageDataAction {
    pub chat_id: Option<i64>,
    pub message_id: Option<i64>,
    pub inline_message_id: Option<String>,
    pub chat_data: Option<String>,
    pub public_data: Option<String>,
}

/// Normalized `edit_shared_data` action payload (preserving `Some("")` clear semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditSharedDataAction {
    pub widget_id: Option<String>,
    pub slug: Option<String>,
    pub public_data: Option<String>,
    pub cache_time: Option<u32>,
}

/// Parsed `.widget.json` action variant.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedWidgetAction {
    Send(Box<WidgetSpec>),
    EditMessageData(EditMessageDataAction),
    EditSharedData(EditSharedDataAction),
}

fn parse_bool_str(val: &str) -> Result<bool> {
    match val.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(BridgeError::Validation(format!(
            "Invalid boolean attribute value: {val:?}"
        ))),
    }
}

fn parse_tag_attrs(src: &str, start: usize) -> Option<(HashMap<String, String>, bool, usize)> {
    let bytes = src.as_bytes();
    let n = src.len();
    let mut i = start;
    let mut attrs = HashMap::new();

    while i < n {
        while i < n {
            let ch = src[i..].chars().next()?;
            if ch.is_whitespace() {
                i += ch.len_utf8();
            } else {
                break;
            }
        }
        if i >= n {
            return None;
        }
        if src[i..].starts_with("/>") {
            return Some((attrs, true, i + 2));
        }
        if bytes[i] == b'>' {
            return Some((attrs, false, i + 1));
        }

        let name_start = i;
        while i < n {
            let Some(ch) = src[i..].chars().next() else {
                break;
            };
            if ch.is_alphanumeric() || matches!(ch, '-' | '_' | ':') {
                i += ch.len_utf8();
            } else {
                break;
            }
        }
        if i == name_start {
            return None;
        }
        let name = src[name_start..i].to_ascii_lowercase();

        while i < n {
            let Some(ch) = src[i..].chars().next() else {
                break;
            };
            if ch.is_whitespace() {
                i += ch.len_utf8();
            } else {
                break;
            }
        }

        if i < n && bytes[i] == b'=' {
            i += 1;
            while i < n {
                let Some(ch) = src[i..].chars().next() else {
                    break;
                };
                if ch.is_whitespace() {
                    i += ch.len_utf8();
                } else {
                    break;
                }
            }
            if i >= n {
                return None;
            }
            let val = if bytes[i] == b'"' || bytes[i] == b'\'' {
                let q = bytes[i];
                i += 1;
                let v_start = i;
                while i < n && bytes[i] != q {
                    i += 1;
                }
                if i >= n {
                    return None;
                }
                let decoded = decode_html_entities(&src[v_start..i]).into_owned();
                i += 1;
                decoded
            } else {
                let v_start = i;
                while i < n {
                    let Some(ch) = src[i..].chars().next() else {
                        break;
                    };
                    if ch.is_whitespace() || ch == '>' || ch == '/' {
                        break;
                    }
                    i += ch.len_utf8();
                }
                decode_html_entities(&src[v_start..i]).into_owned()
            };
            attrs.insert(name, val);
        } else {
            attrs.insert(name, String::new());
        }
    }

    None
}

fn opt_i64_attr(attrs: &HashMap<String, String>, key: &str) -> Result<Option<i64>> {
    match attrs.get(key) {
        None => Ok(None),
        Some(v) if v.is_empty() => Ok(None),
        Some(v) => v.trim().parse::<i64>().map(Some).map_err(|_| {
            BridgeError::Validation(format!("Invalid integer attribute {key}={v:?}"))
        }),
    }
}

fn opt_u32_dim_attr(attrs: &HashMap<String, String>, key: &str) -> Result<Option<u32>> {
    match opt_i64_attr(attrs, key)? {
        None => Ok(None),
        Some(v) if v <= 0 => Ok(Some(0)),
        Some(v) => Ok(Some(u32::try_from(v).unwrap_or(u32::MAX))),
    }
}

fn opt_bool_attr(attrs: &HashMap<String, String>, key: &str) -> Result<Option<bool>> {
    match attrs.get(key) {
        None => Ok(None),
        Some(v) => parse_bool_str(v).map(Some),
    }
}

fn attrs_to_spec(
    attrs: &HashMap<String, String>,
    html: Option<String>,
    default_shared: bool,
) -> Result<WidgetSpec> {
    let mut is_shared = opt_bool_attr(attrs, "is-shared")?;
    if is_shared.is_none() && default_shared {
        is_shared = Some(true);
    }

    let parse_mode = match attrs.get("parse-mode") {
        Some(pm) if pm.eq_ignore_ascii_case("none") => None,
        Some(pm) => Some(pm.clone()),
        None => Some("HTML".to_string()),
    };

    Ok(WidgetSpec {
        html,
        widget_id: attrs.get("widget-id").cloned(),
        width: opt_u32_dim_attr(attrs, "width")?,
        height: opt_u32_dim_attr(attrs, "height")?,
        public_data: attrs.get("public-data").cloned(),
        chat_data: attrs.get("chat-data").cloned(),
        caption: attrs.get("caption").cloned(),
        parse_mode,
        caption_entities: None,
        show_caption_above_media: opt_bool_attr(attrs, "show-caption-above")?,
        allow_queries: opt_bool_attr(attrs, "allow-queries")?,
        is_shared,
        cache_time: opt_u32_dim_attr(attrs, "cache-time")?,
        message_thread_id: opt_i64_attr(attrs, "thread-id")?,
        disable_notification: opt_bool_attr(attrs, "silent")?,
        protect_content: opt_bool_attr(attrs, "protect-content")?,
        allow_paid_broadcast: None,
        message_effect_id: attrs.get("effect").cloned(),
        reply_to_message_id: opt_i64_attr(attrs, "reply-to")?,
        reply_markup: None,
        slug: attrs.get("slug").cloned(),
        handler: attrs.get("handler").cloned(),
    })
}

fn match_fence_open(line: &str) -> Option<(u8, usize)> {
    let stripped = line.trim_start_matches(' ');
    if line.len() - stripped.len() > 3 || stripped.is_empty() {
        return None;
    }
    let ch = stripped.as_bytes()[0];
    if ch != b'`' && ch != b'~' {
        return None;
    }
    let k = stripped.bytes().take_while(|&b| b == ch).count();
    if k < 3 {
        return None;
    }
    let rest = &stripped[k..];
    if ch == b'`' && rest.contains('`') {
        return None;
    }
    Some((ch, k))
}

fn is_fence_close(line: &str, ch: u8, min_len: usize) -> bool {
    let stripped = line.trim_start_matches(' ');
    if line.len() - stripped.len() > 3 {
        return false;
    }
    let k = stripped.bytes().take_while(|&b| b == ch).count();
    if k < min_len {
        return false;
    }
    stripped[k..]
        .trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
        .is_empty()
}

fn find_closing_backticks(md: &str, start: usize, count: usize) -> Option<usize> {
    let bytes = md.as_bytes();
    let n = bytes.len();
    let mut i = start;
    while i < n {
        if bytes[i] == b'\n' {
            let mut j = i + 1;
            if j < n && bytes[j] == b'\r' {
                j += 1;
            }
            if j < n && bytes[j] == b'\n' {
                return None;
            }
        }
        if bytes[i] == b'`' {
            let mut run = 0;
            while i + run < n && bytes[i + run] == b'`' {
                run += 1;
            }
            if run == count {
                return Some(i + run);
            }
            i += run;
            continue;
        }
        i += 1;
    }
    None
}

fn starts_with_ignore_ascii_case(haystack: &str, prefix: &str) -> bool {
    haystack
        .get(..prefix.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
}

/// Extract `<tg-widget>` and `<tg-shared-widget>` tags outside fenced and inline code.
pub fn extract_widgets_from_markdown(md: &str) -> Result<(String, Vec<WidgetSpec>)> {
    let mut specs = Vec::new();
    let mut out = String::with_capacity(md.len());
    let bytes = md.as_bytes();
    let n = md.len();
    let mut i = 0;

    while i < n {
        // 1. Check fenced code block at line start
        let at_line_start = i == 0 || bytes[i - 1] == b'\n';
        if at_line_start {
            let nl_rel = md[i..].find('\n');
            let line = match nl_rel {
                Some(rel) => &md[i..i + rel],
                None => &md[i..],
            };
            if let Some((f_ch, f_len)) = match_fence_open(line) {
                out.push_str(line);
                let Some(rel) = nl_rel else {
                    break;
                };
                out.push('\n');
                i = i + rel + 1;
                while i < n {
                    let nl2_rel = md[i..].find('\n');
                    let ln2 = match nl2_rel {
                        Some(r) => &md[i..i + r],
                        None => &md[i..],
                    };
                    out.push_str(ln2);
                    if let Some(r) = nl2_rel {
                        out.push('\n');
                        i = i + r + 1;
                    } else {
                        i = n;
                    }
                    if is_fence_close(ln2, f_ch, f_len) {
                        break;
                    }
                }
                continue;
            }
        }

        // 2. Inline code span
        if bytes[i] == b'`' {
            let mut run = 0;
            while i + run < n && bytes[i + run] == b'`' {
                run += 1;
            }
            if let Some(end) = find_closing_backticks(md, i + run, run) {
                out.push_str(&md[i..end]);
                i = end;
            } else {
                out.push_str(&md[i..i + run]);
                i += run;
            }
            continue;
        }

        // 3. <tg-widget ...> or <tg-shared-widget ...>
        if bytes[i] == b'<' {
            let tag_name: Option<&str> = if starts_with_ignore_ascii_case(
                &md[i..],
                "<tg-shared-widget",
            ) {
                let after = i + "<tg-shared-widget".len();
                if md[after..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_whitespace() || c == '>' || c == '/')
                {
                    Some("tg-shared-widget")
                } else {
                    None
                }
            } else if starts_with_ignore_ascii_case(&md[i..], "<tg-widget") {
                let after = i + "<tg-widget".len();
                if md[after..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_whitespace() || c == '>' || c == '/')
                {
                    Some("tg-widget")
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(tname) = tag_name {
                if let Some((attrs, self_closing, body_start)) =
                    parse_tag_attrs(md, i + 1 + tname.len())
                {
                    let is_shared_tag = tname == "tg-shared-widget";
                    if self_closing {
                        specs.push(attrs_to_spec(&attrs, None, is_shared_tag)?);
                        i = body_start;
                        continue;
                    }
                    let close_re = if is_shared_tag {
                        RE_CLOSE_SHARED_WIDGET.as_ref()
                    } else {
                        RE_CLOSE_WIDGET.as_ref()
                    };
                    if let Some(close_m) = close_re.and_then(|re| re.find_at(md, body_start)) {
                        let inner = md[body_start..close_m.start()].trim();
                        let html_val = if inner.is_empty() {
                            None
                        } else {
                            Some(inner.to_string())
                        };
                        specs.push(attrs_to_spec(&attrs, html_val, is_shared_tag)?);
                        i = close_m.end();
                        continue;
                    }
                    if is_shared_tag {
                        specs.push(attrs_to_spec(&attrs, None, true)?);
                        i = body_start;
                        continue;
                    }
                }
            }
        }

        if let Some(ch) = md[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    if !specs.is_empty() {
        let collapsed = match RE_MULTI_NEWLINES.as_ref() {
            Some(re) => re.replace_all(&out, "\n\n").into_owned(),
            None => out,
        };
        return Ok((collapsed.trim().to_string(), specs));
    }

    Ok((out, specs))
}

// --------------------------------------------------------------------------- HTML file & JSON parsers

fn value_as_opt_string(v: &Value) -> Result<Option<String>> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        other => Err(BridgeError::Validation(format!(
            "Expected string or null, got {other}"
        ))),
    }
}

fn value_as_opt_i64(v: &Value, field: &str) -> Result<Option<i64>> {
    match v {
        Value::Null => Ok(None),
        Value::Number(n) => n.as_i64().map(Some).ok_or_else(|| {
            BridgeError::Validation(format!("Invalid integer for {field}: {n}"))
        }),
        Value::String(s) => {
            if s.trim().is_empty() {
                Ok(None)
            } else {
                s.trim().parse::<i64>().map(Some).map_err(|_| {
                    BridgeError::Validation(format!("Invalid integer for {field}: {s:?}"))
                })
            }
        }
        other => Err(BridgeError::Validation(format!(
            "Invalid integer for {field}: {other}"
        ))),
    }
}

fn value_as_opt_u32_dim(v: &Value, field: &str) -> Result<Option<u32>> {
    match value_as_opt_i64(v, field)? {
        None => Ok(None),
        Some(n) if n <= 0 => Ok(Some(0)),
        Some(n) => Ok(Some(u32::try_from(n).unwrap_or(u32::MAX))),
    }
}

fn value_as_opt_bool(v: &Value, field: &str) -> Result<Option<bool>> {
    match v {
        Value::Null => Ok(None),
        Value::Bool(b) => Ok(Some(*b)),
        Value::Number(n) => Ok(Some(n.as_i64() != Some(0))),
        Value::String(s) => parse_bool_str(s).map(Some),
        other => Err(BridgeError::Validation(format!(
            "Invalid boolean for {field}: {other}"
        ))),
    }
}

fn build_spec_from_map(
    meta: &Map<String, Value>,
    html_override: Option<String>,
    base: Option<&WidgetSpec>,
) -> Result<WidgetSpec> {
    let mut norm_meta: Map<String, Value> = Map::new();
    for (k, v) in meta {
        norm_meta.insert(k.replace('-', "_"), v.clone());
    }

    let mut spec = base.cloned().unwrap_or_default();

    if let Some(h) = html_override {
        spec.html = Some(h);
    } else if let Some(v) = norm_meta.get("html") {
        spec.html = value_as_opt_string(v)?;
    }

    if let Some(v) = norm_meta.get("widget_id") {
        spec.widget_id = value_as_opt_string(v)?;
    }
    if let Some(v) = norm_meta.get("width") {
        spec.width = value_as_opt_u32_dim(v, "width")?;
    }
    if let Some(v) = norm_meta.get("height") {
        spec.height = value_as_opt_u32_dim(v, "height")?;
    }
    if let Some(v) = norm_meta.get("caption") {
        spec.caption = value_as_opt_string(v)?;
    }
    if let Some(v) = norm_meta.get("parse_mode") {
        spec.parse_mode = value_as_opt_string(v)?;
    }
    if let Some(v) = norm_meta.get("caption_entities") {
        spec.caption_entities = match v {
            Value::Null => None,
            other => Some(serde_json::from_value::<Vec<MessageEntity>>(other.clone()).map_err(
                |e| BridgeError::json("caption_entities", e),
            )?),
        };
    }
    if let Some(v) = norm_meta.get("show_caption_above_media") {
        spec.show_caption_above_media = value_as_opt_bool(v, "show_caption_above_media")?;
    } else if let Some(v) = norm_meta.get("show_caption_above") {
        spec.show_caption_above_media = value_as_opt_bool(v, "show_caption_above")?;
    }

    if let Some(v) = norm_meta.get("allow_queries") {
        spec.allow_queries = value_as_opt_bool(v, "allow_queries")?;
    }
    if let Some(v) = norm_meta.get("is_shared") {
        spec.is_shared = value_as_opt_bool(v, "is_shared")?;
    }
    if let Some(v) = norm_meta.get("cache_time") {
        spec.cache_time = value_as_opt_u32_dim(v, "cache_time")?;
    }

    if let Some(v) = norm_meta.get("message_thread_id") {
        spec.message_thread_id = value_as_opt_i64(v, "message_thread_id")?;
    } else if let Some(v) = norm_meta.get("thread_id") {
        spec.message_thread_id = value_as_opt_i64(v, "thread_id")?;
    }

    if let Some(v) = norm_meta.get("disable_notification") {
        spec.disable_notification = value_as_opt_bool(v, "disable_notification")?;
    } else if let Some(v) = norm_meta.get("silent") {
        spec.disable_notification = value_as_opt_bool(v, "silent")?;
    }

    if let Some(v) = norm_meta.get("protect_content") {
        spec.protect_content = value_as_opt_bool(v, "protect_content")?;
    }
    if let Some(v) = norm_meta.get("allow_paid_broadcast") {
        spec.allow_paid_broadcast = value_as_opt_bool(v, "allow_paid_broadcast")?;
    }

    if let Some(v) = norm_meta.get("message_effect_id") {
        spec.message_effect_id = value_as_opt_string(v)?;
    } else if let Some(v) = norm_meta.get("effect") {
        spec.message_effect_id = value_as_opt_string(v)?;
    }

    if let Some(v) = norm_meta.get("reply_to_message_id") {
        spec.reply_to_message_id = value_as_opt_i64(v, "reply_to_message_id")?;
    } else if let Some(v) = norm_meta.get("reply_to") {
        spec.reply_to_message_id = value_as_opt_i64(v, "reply_to")?;
    }

    if let Some(v) = norm_meta.get("reply_markup") {
        spec.reply_markup = match v {
            Value::Null => None,
            other => Some(
                serde_json::from_value::<InlineKeyboardMarkup>(other.clone())
                    .map_err(|e| BridgeError::json("reply_markup", e))?,
            ),
        };
    }
    if let Some(v) = norm_meta.get("slug") {
        spec.slug = value_as_opt_string(v)?;
    }
    if let Some(v) = norm_meta.get("handler") {
        spec.handler = value_as_opt_string(v)?;
    }

    if let Some(pd) = norm_meta.get("public_data") {
        spec.public_data = encode_widget_data(Some(WidgetData::Value(pd)), false)?;
    }
    if let Some(cd) = norm_meta.get("chat_data") {
        spec.chat_data = encode_widget_data(Some(WidgetData::Value(cd)), false)?;
    }

    Ok(spec)
}

/// Parse a standalone `.widget.html` file with optional sibling `.json` or top `<!-- widget: {...} -->`.
pub fn parse_widget_html_file(path: impl AsRef<Path>) -> Result<WidgetSpec> {
    let p = path.as_ref();
    let raw_html_full = std::fs::read_to_string(p)
        .map_err(|e| BridgeError::io(format!("reading widget html {}", p.display()), e))?;

    let mut meta = Map::new();
    let mut candidates = vec![p.with_extension("json")];
    let stem = p
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string();
    if let Some(stripped_stem) = stem.strip_suffix(".widget") {
        let alt = p.with_file_name(format!("{stripped_stem}.json"));
        if !candidates.contains(&alt) {
            candidates.push(alt);
        }
    }
    let wjson = p.with_extension("widget.json");
    if !candidates.contains(&wjson) {
        candidates.push(wjson);
    }

    for cand in candidates {
        if cand.is_file() {
            let txt = std::fs::read_to_string(&cand).map_err(|e| {
                BridgeError::io(format!("reading sibling json {}", cand.display()), e)
            })?;
            let loaded: Value = serde_json::from_str(&txt)
                .map_err(|e| BridgeError::json(format!("parsing {}", cand.display()), e))?;
            if let Value::Object(obj) = loaded {
                for (k, v) in obj {
                    meta.insert(k, v);
                }
                break;
            }
        }
    }

    let mut raw_html = raw_html_full;
    if let Some(re_top) = RE_TOP_WIDGET_META.as_ref() {
        if let Some(caps) = re_top.captures(&raw_html) {
            if let (Some(full_m), Some(json_m)) = (caps.get(0), caps.get(1)) {
                let header_val: Value = serde_json::from_str(json_m.as_str())
                    .map_err(|e| BridgeError::json("top <!-- widget: {...} --> comment", e))?;
                let Value::Object(header_obj) = header_val else {
                    return Err(BridgeError::Validation(
                        "Top <!-- widget: {...} --> comment must be a JSON object".to_string(),
                    ));
                };
                for (k, v) in header_obj {
                    meta.insert(k, v);
                }
                raw_html = raw_html[full_m.end()..].to_string();
            }
        }
    }

    let mut spec = build_spec_from_map(&meta, Some(raw_html.clone()), None)?;
    let has_caption_key = meta.keys().any(|k| k.replace('-', "_") == "caption");
    if !has_caption_key {
        let default_cap = stem.strip_suffix(".widget").unwrap_or(&stem).to_string();
        spec.caption = Some(default_cap);
    }

    let has_allow_queries = meta.keys().any(|k| k.replace('-', "_") == "allow_queries");
    if !has_allow_queries && raw_html.contains("TelegramWidget.request") {
        spec.allow_queries = Some(true);
    }

    Ok(spec)
}

/// Parse a widget action JSON string or object into a [`ParsedWidgetAction`].
pub fn parse_widget_json<'a, T: Into<WidgetJsonInput<'a>>>(
    input: T,
    base_dir: Option<&Path>,
) -> Result<ParsedWidgetAction> {
    let val: Value = match input.into() {
        WidgetJsonInput::Str(raw) => serde_json::from_str(raw)
            .map_err(|e| BridgeError::json("parse_widget_json", e))?,
        WidgetJsonInput::Value(v) => v.clone(),
    };

    let Value::Object(obj) = val else {
        return Err(BridgeError::Validation(
            "Widget JSON must decode to an object".to_string(),
        ));
    };

    let action = match obj.get("action") {
        None | Some(Value::Null) => "send",
        Some(Value::String(s)) if s.is_empty() => "send",
        Some(Value::String(s)) => s.as_str(),
        Some(other) => {
            return Err(BridgeError::Validation(format!(
                "Unknown widget action: {other}"
            )));
        }
    };

    if action == "edit_message_data" {
        let chat_id = obj
            .get("chat_id")
            .map(|v| value_as_opt_i64(v, "chat_id"))
            .transpose()?
            .flatten();
        let message_id = obj
            .get("message_id")
            .map(|v| value_as_opt_i64(v, "message_id"))
            .transpose()?
            .flatten();
        let inline_message_id = obj
            .get("inline_message_id")
            .map(value_as_opt_string)
            .transpose()?
            .flatten();
        let chat_data = match obj.get("chat_data") {
            Some(v) => encode_widget_data(Some(WidgetData::Value(v)), true)?,
            None => None,
        };
        let public_data = match obj.get("public_data") {
            Some(v) => encode_widget_data(Some(WidgetData::Value(v)), true)?,
            None => None,
        };
        return Ok(ParsedWidgetAction::EditMessageData(EditMessageDataAction {
            chat_id,
            message_id,
            inline_message_id,
            chat_data,
            public_data,
        }));
    }

    if action == "edit_shared_data" {
        let widget_id = obj
            .get("widget_id")
            .map(value_as_opt_string)
            .transpose()?
            .flatten();
        let slug = obj
            .get("slug")
            .map(value_as_opt_string)
            .transpose()?
            .flatten();
        let public_data = match obj.get("public_data") {
            Some(v) => encode_widget_data(Some(WidgetData::Value(v)), true)?,
            None => None,
        };
        let ct = obj
            .get("cache_time")
            .map(|v| value_as_opt_u32_dim(v, "cache_time"))
            .transpose()?
            .flatten();
        return Ok(ParsedWidgetAction::EditSharedData(EditSharedDataAction {
            widget_id,
            slug,
            public_data,
            cache_time: clamp_cache_time(ct),
        }));
    }

    if action != "send" && action != "send_shared" {
        return Err(BridgeError::Validation(format!(
            "Unknown widget action: {action:?}"
        )));
    }

    let base_spec: Option<WidgetSpec> = match obj.get("html_file") {
        Some(Value::String(rel)) if !rel.is_empty() => {
            let rel_path = Path::new(rel);
            if rel_path.is_absolute()
                || rel_path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::RootDir | std::path::Component::Prefix(_)))
            {
                return Err(BridgeError::PermissionDenied(format!(
                    "Widget html_file must be a relative path inside outbox: {rel}"
                )));
            }
            let Some(bd) = base_dir else {
                return Err(BridgeError::PermissionDenied(
                    "Widget html_file is not allowed without a base directory".to_string(),
                ));
            };
            let canon_base = std::fs::canonicalize(bd).map_err(|e| {
                BridgeError::io(format!("canonicalizing widget base_dir {}", bd.display()), e)
            })?;
            let f_path = canon_base.join(rel_path);
            let canon_target = std::fs::canonicalize(&f_path).map_err(|e| {
                BridgeError::io(format!("resolving widget html_file {}", f_path.display()), e)
            })?;
            if !canon_target.starts_with(&canon_base) {
                return Err(BridgeError::PermissionDenied(format!(
                    "Widget html_file escapes base directory: {rel}"
                )));
            }
            Some(parse_widget_html_file(&canon_target)?)
        }
        _ => match obj.get("builtin") {
            Some(Value::String(kind)) if !kind.is_empty() => {
                Some(builtin_widget(kind, obj.get("initial_state"))?)
            }
            _ => None,
        },
    };

    let mut overlay = Map::new();
    for (k, v) in &obj {
        if !matches!(
            k.as_str(),
            "action" | "html_file" | "builtin" | "initial_state"
        ) {
            overlay.insert(k.clone(), v.clone());
        }
    }

    let mut spec = build_spec_from_map(&overlay, None, base_spec.as_ref())?;
    if action == "send_shared" && spec.is_shared.is_none() {
        spec.is_shared = Some(true);
    }

    if spec.html.is_none()
        && spec.widget_id.as_deref().unwrap_or("").is_empty()
        && spec.slug.as_deref().unwrap_or("").is_empty()
    {
        return Err(BridgeError::Validation(
            "Widget JSON must supply html, html_file, builtin, widget_id, or slug".to_string(),
        ));
    }

    Ok(ParsedWidgetAction::Send(Box::new(spec)))
}
