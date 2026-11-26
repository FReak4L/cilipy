//! Bot API 10.4 Widget specification, validation, Profile-1 minifier, and linter.

use std::collections::HashSet;
use std::io::Write;
use std::sync::LazyLock;

use agy_core::error::{BridgeError, Result};
use agy_core::tg::{InlineKeyboardMarkup, MessageEntity};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum UTF-8 raw byte length of Bot API 10.4 widget HTML.
pub const WIDGET_HTML_RAW_LIMIT: usize = 32_768;
/// Maximum zlib level-9 compressed byte length of Bot API 10.4 widget HTML.
pub const WIDGET_HTML_ZLIB_LIMIT: usize = 4_096;
/// Maximum UTF-8 byte length of `public_data` / `chat_data` payloads.
pub const WIDGET_DATA_LIMIT: usize = 1_024;
/// Maximum UTF-8 byte length of `TelegramWidget.request(data)` payload.
pub const WIDGET_QUERY_DATA_LIMIT: usize = 64;
/// Alias for [`WIDGET_QUERY_DATA_LIMIT`].
pub const WIDGET_REQUEST_DATA_LIMIT: usize = WIDGET_QUERY_DATA_LIMIT;
/// Maximum UTF-8 byte length of `answerWidgetQuery` `data` payload.
pub const WIDGET_ANSWER_DATA_LIMIT: usize = 1_024;
/// Maximum character length of a widget caption.
pub const WIDGET_CAPTION_LIMIT: usize = 1_024;

/// Minimum clamped logical width in pixels for `sendWidget`.
pub const WIDGET_WIDTH_MIN: u32 = 200;
/// Minimum clamped logical height in pixels for `sendWidget`.
pub const WIDGET_HEIGHT_MIN: u32 = 50;
/// Maximum clamped logical height in pixels for `sendWidget`.
pub const WIDGET_HEIGHT_MAX: u32 = 600;
/// Minimum widget dimension constant.
pub const WIDGET_MIN_SIZE: u32 = 50;
/// Maximum general widget dimension constant.
pub const WIDGET_MAX_SIZE: u32 = 2048;

/// Minimum shared widget `cache_time` in seconds.
pub const WIDGET_CACHE_TIME_MIN: u32 = 5;
/// Maximum shared widget `cache_time` in seconds.
pub const WIDGET_CACHE_TIME_MAX: u32 = 3600;
/// Alias for [`WIDGET_CACHE_TIME_MIN`].
pub const WIDGET_SHARED_MIN_CACHE: u32 = WIDGET_CACHE_TIME_MIN;
/// Alias for [`WIDGET_CACHE_TIME_MAX`].
pub const WIDGET_SHARED_MAX_CACHE: u32 = WIDGET_CACHE_TIME_MAX;
/// Default shared widget `cache_time` in seconds.
pub const WIDGET_CACHE_TIME_DEFAULT: u32 = 30;
/// Bot API deadline for answering a `widget_query` in seconds.
pub const WIDGET_QUERY_TIMEOUT_SECS: f64 = 15.0;
/// Minimum interval between `editSharedWidgetData` calls in seconds.
pub const WIDGET_SHARED_EDIT_MIN_INTERVAL_SECS: f64 = 1.0;

/// Legacy widget handler names purged on startup.
pub const LEGACY_WIDGET_HANDLERS: [&str; 6] =
    ["status", "poll", "control", "wallet", "sys", "ctl"];
/// Legacy widget slug names purged on startup.
pub const LEGACY_WIDGET_SLUGS: [&str; 4] =
    ["sys_status", "shared_poll", "agy_control", "ton_inspector"];
/// Official built-in interactive hub widget kinds.
pub const BUILTIN_WIDGET_KINDS: [&str; 4] = ["skills", "mcp", "models", "memory"];

const FORBIDDEN_TAGS: [&str; 14] = [
    "audio",
    "dialog",
    "embed",
    "fencedframe",
    "frame",
    "iframe",
    "input",
    "meta",
    "meter",
    "object",
    "portal",
    "progress",
    "select",
    "textarea",
];

fn is_js_regex_prev_keyword(word: &str) -> bool {
    matches!(
        word,
        "return"
            | "throw"
            | "case"
            | "delete"
            | "void"
            | "typeof"
            | "await"
            | "yield"
            | "in"
            | "instanceof"
            | "new"
            | "else"
            | "do"
            | "of"
    )
}

fn default_parse_mode() -> Option<String> {
    Some("HTML".to_string())
}

/// Complete Bot API 10.4 widget specification across send, inline, and bridge flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widget_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat_data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    #[serde(default = "default_parse_mode", skip_serializing_if = "Option::is_none")]
    pub parse_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption_entities: Option<Vec<MessageEntity>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_caption_above_media: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_queries: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_shared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_time: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_thread_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_notification: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protect_content: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_paid_broadcast: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_effect_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_markup: Option<InlineKeyboardMarkup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<String>,
}

impl Default for WidgetSpec {
    fn default() -> Self {
        Self {
            html: None,
            widget_id: None,
            width: None,
            height: None,
            public_data: None,
            chat_data: None,
            caption: None,
            parse_mode: default_parse_mode(),
            caption_entities: None,
            show_caption_above_media: None,
            allow_queries: None,
            is_shared: None,
            cache_time: None,
            message_thread_id: None,
            disable_notification: None,
            protect_content: None,
            allow_paid_broadcast: None,
            message_effect_id: None,
            reply_to_message_id: None,
            reply_markup: None,
            slug: None,
            handler: None,
        }
    }
}

fn entity_eq(a: &MessageEntity, b: &MessageEntity) -> bool {
    a.kind == b.kind
        && a.offset == b.offset
        && a.length == b.length
        && a.url == b.url
        && a.custom_emoji_id == b.custom_emoji_id
}

impl PartialEq for WidgetSpec {
    fn eq(&self, other: &Self) -> bool {
        let ents_eq = match (&self.caption_entities, &other.caption_entities) {
            (None, None) => true,
            (Some(a), Some(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| entity_eq(x, y)),
            _ => false,
        };
        self.html == other.html
            && self.widget_id == other.widget_id
            && self.width == other.width
            && self.height == other.height
            && self.public_data == other.public_data
            && self.chat_data == other.chat_data
            && self.caption == other.caption
            && self.parse_mode == other.parse_mode
            && ents_eq
            && self.show_caption_above_media == other.show_caption_above_media
            && self.allow_queries == other.allow_queries
            && self.is_shared == other.is_shared
            && self.cache_time == other.cache_time
            && self.message_thread_id == other.message_thread_id
            && self.disable_notification == other.disable_notification
            && self.protect_content == other.protect_content
            && self.allow_paid_broadcast == other.allow_paid_broadcast
            && self.message_effect_id == other.message_effect_id
            && self.reply_to_message_id == other.reply_to_message_id
            && self.reply_markup == other.reply_markup
            && self.slug == other.slug
            && self.handler == other.handler
    }
}

/// Borrowed widget data input supporting both raw strings and JSON values.
#[derive(Debug, Clone, Copy)]
pub enum WidgetData<'a> {
    Str(&'a str),
    Value(&'a Value),
}

impl<'a> From<&'a str> for WidgetData<'a> {
    fn from(value: &'a str) -> Self {
        Self::Str(value)
    }
}

impl<'a> From<&'a String> for WidgetData<'a> {
    fn from(value: &'a String) -> Self {
        Self::Str(value.as_str())
    }
}

impl<'a> From<&'a Value> for WidgetData<'a> {
    fn from(value: &'a Value) -> Self {
        Self::Value(value)
    }
}

/// Size and NUL-byte diagnostics for a widget HTML document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WidgetSizeReport {
    pub raw_bytes: usize,
    pub zlib_bytes: usize,
    pub has_nul: bool,
    pub ok: bool,
    pub raw_ok: bool,
    pub zlib_ok: bool,
}

/// Encode string/JSON widget data into a compact UTF-8 string <= 1024 bytes.
pub fn encode_widget_data<'a, T: Into<WidgetData<'a>>>(
    data: Option<T>,
    allow_empty: bool,
) -> Result<Option<String>> {
    let Some(item) = data else {
        return Ok(None);
    };

    let s = match item.into() {
        WidgetData::Str(raw) => raw.to_owned(),
        WidgetData::Value(val) => match val {
            Value::Null => return Ok(None),
            Value::String(st) => st.clone(),
            Value::Object(_) | Value::Array(_) => serde_json::to_string(val)
                .map_err(|e| BridgeError::json("encode_widget_data", e))?,
            Value::Bool(b) => {
                if *b {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            Value::Number(n) => n.to_string(),
        },
    };

    if s.is_empty() {
        return Ok(if allow_empty { Some(String::new()) } else { None });
    }
    if s.contains('\0') {
        return Err(BridgeError::Validation(
            "Widget data must not contain NUL bytes".to_string(),
        ));
    }
    let byte_len = s.len();
    if byte_len > WIDGET_DATA_LIMIT {
        return Err(BridgeError::Validation(format!(
            "Widget data exceeds {WIDGET_DATA_LIMIT} bytes ({byte_len} bytes)"
        )));
    }
    Ok(Some(s))
}

/// Measure raw UTF-8 bytes, zlib level-9 compressed bytes, NUL presence, and Telegram limit compliance.
pub fn count_widget_size(html: &str) -> WidgetSizeReport {
    let raw = html.as_bytes();
    let raw_bytes = raw.len();
    let has_nul = raw.contains(&0);

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    let zlib_bytes = match encoder.write_all(raw).and_then(|()| encoder.finish()) {
        Ok(compressed) => compressed.len(),
        Err(_) => usize::MAX,
    };

    let raw_ok = (1..=WIDGET_HTML_RAW_LIMIT).contains(&raw_bytes);
    let zlib_ok = zlib_bytes <= WIDGET_HTML_ZLIB_LIMIT;
    let ok = raw_ok && zlib_ok && !has_nul;

    WidgetSizeReport {
        raw_bytes,
        zlib_bytes,
        has_nul,
        ok,
        raw_ok,
        zlib_ok,
    }
}

// --------------------------------------------------------------------------- CSS/JS/HTML lexers & minifier

static RE_DEV_BLOCK: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?is)<!--\s*tg-widget-dev-start\s*-->.*?<!--\s*tg-widget-dev-end\s*-->").ok()
});
static RE_HTML_COMMENT: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?s)<!--.*?-->").ok());
static RE_TAG_OPEN: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?is)<(script|style|pre|textarea)\b([^>]*)>").ok());

struct TagBlock<'a> {
    start: usize,
    end: usize,
    tag_lower: String,
    attrs: &'a str,
    body: &'a str,
    full: &'a str,
}

fn find_closing_tag_end(html: &str, from: usize, tag_lower: &str) -> Option<(usize, usize)> {
    let bytes = html.as_bytes();
    let tag_bytes = tag_lower.as_bytes();
    let mut i = from;
    while i + 2 + tag_bytes.len() < bytes.len() {
        if bytes[i] == b'<' && bytes[i + 1] == b'/' {
            let candidate_end = i + 2 + tag_bytes.len();
            if candidate_end <= bytes.len()
                && bytes[i + 2..candidate_end].eq_ignore_ascii_case(tag_bytes)
            {
                let mut k = candidate_end;
                while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                if k < bytes.len() && bytes[k] == b'>' {
                    return Some((i, k + 1));
                }
            }
        }
        i += 1;
    }
    None
}

fn find_tag_blocks(html: &str) -> Vec<TagBlock<'_>> {
    let Some(re_open) = RE_TAG_OPEN.as_ref() else {
        return Vec::new();
    };
    let mut blocks = Vec::new();
    let mut pos = 0;
    while pos < html.len() {
        let Some(m) = re_open.find_at(html, pos) else {
            break;
        };
        let Some(caps) = re_open.captures(&html[m.start()..m.end()]) else {
            pos = m.end();
            continue;
        };
        let tag_lower = caps
            .get(1)
            .map(|c| c.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        let attrs = caps.get(2).map_or("", |c| c.as_str());
        if let Some((body_end, tag_end)) = find_closing_tag_end(html, m.end(), &tag_lower) {
            blocks.push(TagBlock {
                start: m.start(),
                end: tag_end,
                tag_lower,
                attrs,
                body: &html[m.end()..body_end],
                full: &html[m.start()..tag_end],
            });
            pos = tag_end;
        } else {
            pos = m.end();
        }
    }
    blocks
}

fn next_char_at(s: &str, byte_idx: usize) -> Option<char> {
    s.get(byte_idx..)?.chars().next()
}

/// Strip CSS `/* ... */` comments while preserving single- and double-quoted strings.
pub fn strip_css_comments(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut i = 0;
    let n = css.len();
    while i < n {
        let Some(ch) = next_char_at(css, i) else {
            break;
        };
        if ch == '\'' || ch == '"' {
            let quote = ch;
            out.push(ch);
            i += ch.len_utf8();
            while i < n {
                let Some(c) = next_char_at(css, i) else {
                    break;
                };
                out.push(c);
                i += c.len_utf8();
                if c == '\\' {
                    if let Some(esc_ch) = next_char_at(css, i) {
                        out.push(esc_ch);
                        i += esc_ch.len_utf8();
                    }
                    continue;
                }
                if c == quote {
                    break;
                }
            }
        } else if ch == '/' && css[i..].starts_with("/*") {
            if let Some(rel_end) = css[i + 2..].find("*/") {
                i = i + 2 + rel_end + 2;
            } else {
                break;
            }
        } else {
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn trim_lines_preserving(text: &str) -> String {
    let mut kept = Vec::new();
    for line in text.lines() {
        let s = line.trim();
        if !s.is_empty() {
            kept.push(s);
        }
    }
    kept.join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrevJsKind {
    Start,
    Op,
    Close,
    Word,
    Keyword,
}

impl PrevJsKind {
    fn can_start_regex(self) -> bool {
        matches!(self, Self::Start | Self::Op | Self::Keyword)
    }
}

/// Scan JS cleanly across strings, template literals, and regex literals.
pub fn process_js(js: &str, strip_comments: bool, trim_lines: bool) -> String {
    let mut out = String::with_capacity(js.len());
    let mut i = 0;
    let n = js.len();
    let mut prev_kind = PrevJsKind::Start;
    let mut template_brace_stack: Vec<usize> = Vec::new();
    let mut line_unsafe_trim: HashSet<usize> = HashSet::new();
    let mut cur_line: usize = 0;

    fn scan_template_text(
        js: &str,
        i: &mut usize,
        cur_line: &mut usize,
        prev_kind: &mut PrevJsKind,
        template_brace_stack: &mut Vec<usize>,
        line_unsafe_trim: &mut HashSet<usize>,
        out: &mut String,
    ) {
        let n = js.len();
        while *i < n {
            let Some(tc) = next_char_at(js, *i) else {
                break;
            };
            if tc == '\n' {
                *cur_line += 1;
                line_unsafe_trim.insert(*cur_line);
                out.push('\n');
                *i += 1;
            } else if tc == '\\' {
                out.push('\\');
                *i += 1;
                if let Some(nxt) = next_char_at(js, *i) {
                    if nxt == '\n' {
                        *cur_line += 1;
                        line_unsafe_trim.insert(*cur_line);
                    }
                    out.push(nxt);
                    *i += nxt.len_utf8();
                }
            } else if tc == '`' {
                out.push('`');
                *i += 1;
                *prev_kind = PrevJsKind::Close;
                return;
            } else if tc == '$' && js[*i..].starts_with("${") {
                out.push_str("${");
                *i += 2;
                template_brace_stack.push(0);
                *prev_kind = PrevJsKind::Op;
                return;
            } else {
                out.push(tc);
                *i += tc.len_utf8();
            }
        }
    }

    while i < n {
        let Some(ch) = next_char_at(js, i) else {
            break;
        };

        // Track template expression closing '}' returning into template text.
        if let Some(top) = template_brace_stack.last_mut() {
            if ch == '}' {
                if *top == 0 {
                    template_brace_stack.pop();
                    out.push('}');
                    i += 1;
                    scan_template_text(
                        js,
                        &mut i,
                        &mut cur_line,
                        &mut prev_kind,
                        &mut template_brace_stack,
                        &mut line_unsafe_trim,
                        &mut out,
                    );
                    continue;
                }
                *top -= 1;
                out.push('}');
                i += 1;
                prev_kind = PrevJsKind::Op;
                continue;
            }
            if ch == '{' {
                *top += 1;
                out.push('{');
                i += 1;
                prev_kind = PrevJsKind::Op;
                continue;
            }
        }

        // Single / double quoted string
        if ch == '\'' || ch == '"' {
            let quote = ch;
            out.push(ch);
            i += 1;
            while i < n {
                let Some(c) = next_char_at(js, i) else {
                    break;
                };
                out.push(c);
                i += c.len_utf8();
                if c == '\\' {
                    if let Some(nxt) = next_char_at(js, i) {
                        out.push(nxt);
                        i += nxt.len_utf8();
                        if nxt == '\n' {
                            cur_line += 1;
                            line_unsafe_trim.insert(cur_line);
                        } else if nxt == '\r' && next_char_at(js, i) == Some('\n') {
                            out.push('\n');
                            i += 1;
                            cur_line += 1;
                            line_unsafe_trim.insert(cur_line);
                        }
                    }
                    continue;
                }
                if c == '\n' {
                    cur_line += 1;
                }
                if c == quote {
                    break;
                }
            }
            prev_kind = PrevJsKind::Close;
            continue;
        }

        // Template literal
        if ch == '`' {
            out.push('`');
            i += 1;
            scan_template_text(
                js,
                &mut i,
                &mut cur_line,
                &mut prev_kind,
                &mut template_brace_stack,
                &mut line_unsafe_trim,
                &mut out,
            );
            continue;
        }

        // Single-line comment
        if ch == '/' && js[i..].starts_with("//") {
            if let Some(rel_end) = js[i + 2..].find('\n') {
                let end = i + 2 + rel_end;
                if !strip_comments {
                    out.push_str(&js[i..end]);
                }
                i = end;
            } else {
                if !strip_comments {
                    out.push_str(&js[i..]);
                }
                break;
            }
            continue;
        }

        // Multi-line comment
        if ch == '/' && js[i..].starts_with("/*") {
            if let Some(rel_end) = js[i + 2..].find("*/") {
                let end = i + 2 + rel_end + 2;
                let comment_body = &js[i..end];
                let nl_count = comment_body.bytes().filter(|&b| b == b'\n').count();
                if strip_comments {
                    if nl_count > 0 {
                        for _ in 0..nl_count {
                            out.push('\n');
                        }
                        cur_line += nl_count;
                    } else {
                        out.push(' ');
                    }
                } else {
                    out.push_str(comment_body);
                    cur_line += nl_count;
                }
                i = end;
            } else {
                if !strip_comments {
                    out.push_str(&js[i..]);
                }
                break;
            }
            continue;
        }

        // Regex literal
        if ch == '/' && prev_kind.can_start_regex() {
            out.push('/');
            i += 1;
            let mut in_class = false;
            while i < n {
                let Some(rc) = next_char_at(js, i) else {
                    break;
                };
                out.push(rc);
                i += rc.len_utf8();
                if rc == '\\' {
                    if let Some(esc_ch) = next_char_at(js, i) {
                        out.push(esc_ch);
                        if esc_ch == '\n' {
                            cur_line += 1;
                        }
                        i += esc_ch.len_utf8();
                    }
                    continue;
                }
                if rc == '[' {
                    in_class = true;
                } else if rc == ']' {
                    in_class = false;
                } else if rc == '/' && !in_class {
                    while let Some(fc) = next_char_at(js, i) {
                        if fc.is_alphabetic() {
                            out.push(fc);
                            i += fc.len_utf8();
                        } else {
                            break;
                        }
                    }
                    break;
                } else if rc == '\n' {
                    cur_line += 1;
                    break;
                }
            }
            prev_kind = PrevJsKind::Close;
            continue;
        }

        // Newline / horizontal whitespace
        if ch == '\n' {
            cur_line += 1;
            out.push('\n');
            i += 1;
            continue;
        }
        if matches!(ch, ' ' | '\t' | '\r' | '\x0c' | '\x0b') {
            out.push(ch);
            i += 1;
            continue;
        }

        // Identifier / keyword
        if ch.is_alphabetic() || ch == '_' || ch == '$' {
            let start = i;
            i += ch.len_utf8();
            while let Some(c) = next_char_at(js, i) {
                if c.is_alphanumeric() || c == '_' || c == '$' {
                    i += c.len_utf8();
                } else {
                    break;
                }
            }
            let word = &js[start..i];
            out.push_str(word);
            prev_kind = if is_js_regex_prev_keyword(word) {
                PrevJsKind::Keyword
            } else {
                PrevJsKind::Word
            };
            continue;
        }

        // Number literal
        if ch.is_ascii_digit()
            || (ch == '.' && next_char_at(js, i + 1).is_some_and(|c| c.is_ascii_digit()))
        {
            let start = i;
            i += ch.len_utf8();
            while let Some(c) = next_char_at(js, i) {
                if c.is_alphanumeric() || c == '.' || c == '_' {
                    i += c.len_utf8();
                } else {
                    break;
                }
            }
            out.push_str(&js[start..i]);
            prev_kind = PrevJsKind::Word;
            continue;
        }

        // Increment / decrement operators
        if (ch == '+' || ch == '-') && next_char_at(js, i + 1) == Some(ch) {
            out.push(ch);
            out.push(ch);
            i += 2;
            prev_kind = PrevJsKind::Close;
            continue;
        }

        out.push(ch);
        prev_kind = if ch == ')' || ch == ']' {
            PrevJsKind::Close
        } else {
            PrevJsKind::Op
        };
        i += ch.len_utf8();
    }

    if !trim_lines {
        return out;
    }

    let mut kept: Vec<&str> = Vec::new();
    for (idx, ln) in out.split('\n').enumerate() {
        let cur_unsafe = line_unsafe_trim.contains(&idx);
        let next_unsafe = line_unsafe_trim.contains(&(idx + 1));
        if cur_unsafe && next_unsafe {
            kept.push(ln);
        } else if cur_unsafe {
            kept.push(ln.trim_end());
        } else if next_unsafe {
            kept.push(ln.trim_start());
        } else {
            let s = ln.trim();
            if !s.is_empty() {
                kept.push(s);
            }
        }
    }
    kept.join("\n")
}

/// Safely minify widget HTML without corrupting `<pre>`, `<textarea>`, JS strings, or JS regexes.
pub fn minify_widget_html(html: &str) -> String {
    let cleaned = match RE_DEV_BLOCK.as_ref() {
        Some(re) => re.replace_all(html, "").into_owned(),
        None => html.to_string(),
    };

    let mut out = Vec::new();
    let mut pos = 0;

    for block in find_tag_blocks(&cleaned) {
        if block.start > pos {
            let raw_chunk = &cleaned[pos..block.start];
            let no_comments = match RE_HTML_COMMENT.as_ref() {
                Some(re) => re.replace_all(raw_chunk, "").into_owned(),
                None => raw_chunk.to_string(),
            };
            let trimmed = trim_lines_preserving(&no_comments);
            if !trimmed.is_empty() {
                out.push(trimmed);
            }
        }

        if block.tag_lower == "style" {
            let body_clean = trim_lines_preserving(&strip_css_comments(block.body));
            out.push(format!(
                "<{}{}>{}</{}>",
                block.tag_lower, block.attrs, body_clean, block.tag_lower
            ));
        } else if block.tag_lower == "script" {
            let body_clean = process_js(block.body, true, true);
            out.push(format!(
                "<{}{}>{}</{}>",
                block.tag_lower, block.attrs, body_clean, block.tag_lower
            ));
        } else {
            // <pre> and <textarea>: preserve inner whitespace verbatim.
            out.push(block.full.to_string());
        }
        pos = block.end;
    }

    if pos < cleaned.len() {
        let raw_chunk = &cleaned[pos..];
        let no_comments = match RE_HTML_COMMENT.as_ref() {
            Some(re) => re.replace_all(raw_chunk, "").into_owned(),
            None => raw_chunk.to_string(),
        };
        let trimmed = trim_lines_preserving(&no_comments);
        if !trimmed.is_empty() {
            out.push(trimmed);
        }
    }

    out.join("\n")
}

// --------------------------------------------------------------------------- Profile-1 linter

static RE_FORBIDDEN_TAG: LazyLock<Option<Regex>> = LazyLock::new(|| {
    let alts = FORBIDDEN_TAGS.join("|");
    Regex::new(&format!(r"(?i)<\s*({alts})(?:\s|>|/)")).ok()
});
static RE_EXT_SCRIPT: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?i)<script\b[^>]*\bsrc\s*=\s*(?:["']\s*)?(?:https?:)?//"#).ok()
});
static RE_EXT_LINK: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?i)<link\b[^>]*\b(?:href|src)\s*=\s*(?:["']\s*)?(?:https?:)?//"#).ok()
});
static RE_EXT_IMG: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?i)<img\b[^>]*\bsrc\s*=\s*(?:["']\s*)?(?:https?:)?//"#).ok()
});
static RE_INLINE_STYLE_ATTR: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?i)\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')"#).ok());
static RE_INLINE_EVENT_ATTR: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?i)\bon[a-z]+\s*=\s*(?:"([^"]*)"|'([^']*)')"#).ok());

static RE_CSS_URL_EXT: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?i)url\(\s*["']?\s*(?:https?:)?//"#).ok());
static RE_CSS_AT_RULE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)@(?:font-face|import)\b").ok());
static RE_CSS_BAD_UNIT: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)(?:\d+(?:\.\d+)?|\.\d+)\s*(dvh|svh|lvh|vh|vb)\b").ok());
static RE_CSS_HAS: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"(?i):has\s*\(").ok());
static RE_CSS_FOCUS: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"(?i):focus\b").ok());
static RE_CSS_BACKDROP: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?i)backdrop-filter\s*:\s*([^;}"']+)"#).ok());
static RE_CSS_FILTER: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?i)filter\s*:\s*([^;}"']+)"#).ok());
static RE_CSS_BOX_SHADOW: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?i)box-shadow\s*:\s*([^;}"']+)"#).ok());
static RE_CSS_OPACITY: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)opacity\s*:\s*([0-9]*\.?[0-9]+)(%?)").ok());
static RE_CSS_OPACITY_TAIL: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"^\s*(?:!|[;}"']|$)"#).ok());
static RE_PARENS: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"\([^)]*\)").ok());
static RE_SHADOW_LEN: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^-?(?:\d+(?:\.\d+)?|\.\d+)(?:px|em|rem|pt|%)?$").ok());
static RE_SHADOW_NUM: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^-?(\d+(?:\.\d+)?|\.\d+)").ok());

static RE_JS_FETCH: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"\bfetch\s*\(").ok());
static RE_JS_XHR: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"\bXMLHttpRequest\b").ok());
static RE_JS_WS: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"\bWebSocket\b").ok());
static RE_JS_ES: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"\bEventSource\b").ok());
static RE_JS_CLIP: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\bnavigator\s*\.\s*clipboard\b").ok());
static RE_JS_SENDMSG: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\bTelegramWidget\s*\.\s*sendMessage\b").ok());

fn strip_css_strings(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut i = 0;
    let n = css.len();
    while i < n {
        let Some(ch) = next_char_at(css, i) else {
            break;
        };
        if ch == '\'' || ch == '"' {
            let quote = ch;
            out.push(ch);
            i += 1;
            while i < n {
                let Some(c) = next_char_at(css, i) else {
                    break;
                };
                i += c.len_utf8();
                if c == '\\' {
                    if let Some(esc_ch) = next_char_at(css, i) {
                        i += esc_ch.len_utf8();
                    }
                    continue;
                }
                if c == quote {
                    break;
                }
            }
            out.push(quote);
        } else {
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn prev_byte_not_ident(s: &str, start: usize, allow_digit_underscore: bool) -> bool {
    if start == 0 {
        return true;
    }
    let b = s.as_bytes()[start - 1];
    if allow_digit_underscore {
        !matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-')
    } else {
        !matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'-')
    }
}

fn box_shadow_has_blur(val: &str) -> bool {
    let v = val.trim().to_ascii_lowercase();
    if matches!(v.as_str(), "" | "none" | "inherit" | "initial" | "unset") {
        return false;
    }
    let has_var = v.contains("var(");
    let stripped = match RE_PARENS.as_ref() {
        Some(re) => re.replace_all(&v, "").into_owned(),
        None => v,
    };
    let Some(re_len) = RE_SHADOW_LEN.as_ref() else {
        return false;
    };
    let Some(re_num) = RE_SHADOW_NUM.as_ref() else {
        return false;
    };
    for layer in stripped.split(',') {
        let tokens: Vec<&str> = layer
            .split_whitespace()
            .filter(|&t| t != "inset" && re_len.is_match(t))
            .collect();
        if tokens.len() >= 3 {
            if let Some(caps) = re_num.captures(tokens[2]) {
                if let Some(num_m) = caps.get(1) {
                    if let Ok(parsed) = num_m.as_str().parse::<f64>() {
                        if parsed > 0.0 {
                            return true;
                        }
                    }
                }
            }
        } else if has_var {
            return true;
        }
    }
    false
}

/// Lint HTML against Telegram Bot API 10.4 Profile-1 widget constraints.
pub fn lint_widget_profile(html: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut html_parts = Vec::new();
    let mut css_parts = Vec::new();
    let mut js_parts = Vec::new();

    let mut pos = 0;
    for block in find_tag_blocks(html) {
        if block.start > pos {
            html_parts.push(&html[pos..block.start]);
        }
        if block.tag_lower == "style" {
            css_parts.push(strip_css_comments(block.body));
        } else if block.tag_lower == "script" {
            js_parts.push(process_js(block.body, true, false));
        } else {
            html_parts.push(block.full);
        }
        pos = block.end;
    }
    if pos < html.len() {
        html_parts.push(&html[pos..]);
    }

    let joined_html = html_parts.join("\n");
    let markup = match RE_HTML_COMMENT.as_ref() {
        Some(re) => re.replace_all(&joined_html, "").into_owned(),
        None => joined_html,
    };

    if let Some(re) = RE_INLINE_STYLE_ATTR.as_ref() {
        for caps in re.captures_iter(&markup) {
            let val = caps.get(1).or_else(|| caps.get(2)).map_or("", |m| m.as_str());
            css_parts.push(strip_css_comments(val));
        }
    }
    if let Some(re) = RE_INLINE_EVENT_ATTR.as_ref() {
        for caps in re.captures_iter(&markup) {
            let val = caps.get(1).or_else(|| caps.get(2)).map_or("", |m| m.as_str());
            js_parts.push(val.to_string());
        }
    }

    // 1. Forbidden HTML tags
    if let Some(re) = RE_FORBIDDEN_TAG.as_ref() {
        let mut seen_tags = HashSet::new();
        for caps in re.captures_iter(&markup) {
            if let Some(m) = caps.get(1) {
                let tname = m.as_str().to_ascii_lowercase();
                if seen_tags.insert(tname.clone()) {
                    warnings.push(format!("Forbidden Profile-1 HTML tag: <{tname}>"));
                }
            }
        }
    }

    // 2. External URLs in markup (<script src>, <link>, <img src>)
    if RE_EXT_SCRIPT.as_ref().is_some_and(|re| re.is_match(html)) {
        warnings.push("External URL in <script src> is forbidden in Profile-1 widgets".to_string());
    }
    if RE_EXT_LINK.as_ref().is_some_and(|re| re.is_match(&markup)) {
        warnings.push("External URL in <link> is forbidden in Profile-1 widgets".to_string());
    }
    if RE_EXT_IMG.as_ref().is_some_and(|re| re.is_match(&markup)) {
        warnings.push("External URL in <img src> is forbidden in Profile-1 widgets".to_string());
    }

    // 3. CSS checks
    let raw_css = css_parts.join("\n");
    if RE_CSS_URL_EXT.as_ref().is_some_and(|re| re.is_match(&raw_css)) {
        warnings.push("External CSS url(http(s)://...) is forbidden in Profile-1 widgets".to_string());
    }

    let css_no_str = strip_css_strings(&raw_css);
    if let Some(re) = RE_CSS_AT_RULE.as_ref() {
        let mut seen_at = HashSet::new();
        for m in re.find_iter(&css_no_str) {
            let rule = m.as_str().to_ascii_lowercase();
            if seen_at.insert(rule.clone()) {
                warnings.push(format!("CSS {rule} is forbidden in Profile-1 widgets"));
            }
        }
    }

    if let Some(re) = RE_CSS_BAD_UNIT.as_ref() {
        let mut seen_units = HashSet::new();
        for caps in re.captures_iter(&css_no_str) {
            if let Some(full) = caps.get(0) {
                if !prev_byte_not_ident(&css_no_str, full.start(), true) {
                    continue;
                }
                if let Some(u_m) = caps.get(1) {
                    let u = u_m.as_str().to_ascii_lowercase();
                    if seen_units.insert(u.clone()) {
                        warnings.push(format!(
                            "CSS viewport unit '{u}' is forbidden in Profile-1 widgets"
                        ));
                    }
                }
            }
        }
    }

    if RE_CSS_HAS.as_ref().is_some_and(|re| re.is_match(&css_no_str)) {
        warnings.push("CSS ':has()' selector is forbidden in Profile-1 widgets".to_string());
    }
    if RE_CSS_FOCUS.as_ref().is_some_and(|re| re.is_match(&css_no_str)) {
        warnings.push("CSS ':focus' selector is forbidden in Profile-1 widgets".to_string());
    }

    let mut backdrop_count: usize = 0;
    if let Some(re) = RE_CSS_BACKDROP.as_ref() {
        for caps in re.captures_iter(&css_no_str) {
            if let Some(full) = caps.get(0) {
                if !prev_byte_not_ident(&css_no_str, full.start(), false) {
                    continue;
                }
                let val = caps.get(1).map_or("", |m| m.as_str().trim());
                if !matches!(
                    val.to_ascii_lowercase().as_str(),
                    "none" | "initial" | "unset"
                ) {
                    backdrop_count += 1;
                }
            }
        }
    }
    if backdrop_count > 2 {
        warnings.push(format!(
            "Profile-1 limit exceeded: {backdrop_count} backdrop-filter declarations (max 2)"
        ));
    }

    let mut blur_opacity_count = backdrop_count;
    if let Some(re) = RE_CSS_FILTER.as_ref() {
        for caps in re.captures_iter(&css_no_str) {
            if let Some(full) = caps.get(0) {
                if !prev_byte_not_ident(&css_no_str, full.start(), false) {
                    continue;
                }
                let v = caps.get(1).map_or("", |m| m.as_str()).to_ascii_lowercase();
                if v.contains("blur(") || v.contains("drop-shadow(") {
                    blur_opacity_count += 1;
                }
            }
        }
    }
    if let Some(re) = RE_CSS_BOX_SHADOW.as_ref() {
        for caps in re.captures_iter(&css_no_str) {
            if let Some(full) = caps.get(0) {
                if !prev_byte_not_ident(&css_no_str, full.start(), false) {
                    continue;
                }
                let v = caps.get(1).map_or("", |m| m.as_str());
                if box_shadow_has_blur(v) {
                    blur_opacity_count += 1;
                }
            }
        }
    }
    if let Some(re) = RE_CSS_OPACITY.as_ref() {
        for caps in re.captures_iter(&css_no_str) {
            if let Some(full) = caps.get(0) {
                if !prev_byte_not_ident(&css_no_str, full.start(), false) {
                    continue;
                }
                let tail = &css_no_str[full.end()..];
                if !RE_CSS_OPACITY_TAIL
                    .as_ref()
                    .is_some_and(|rt| rt.is_match(tail))
                {
                    continue;
                }
                if let Some(num_m) = caps.get(1) {
                    if let Ok(mut val) = num_m.as_str().parse::<f64>() {
                        if caps.get(2).is_some_and(|m| m.as_str() == "%") {
                            val /= 100.0;
                        }
                        if val < 1.0 {
                            blur_opacity_count += 1;
                        }
                    }
                }
            }
        }
    }
    if blur_opacity_count > 16 {
        warnings.push(format!(
            "Profile-1 limit exceeded: {blur_opacity_count} blur/shadow/opacity<1 effects (max 16)"
        ));
    }

    // 4. Forbidden JS APIs
    let raw_js = js_parts.join("\n");
    let js_checks: [(&str, Option<&Regex>); 6] = [
        ("fetch()", RE_JS_FETCH.as_ref()),
        ("XMLHttpRequest", RE_JS_XHR.as_ref()),
        ("WebSocket", RE_JS_WS.as_ref()),
        ("EventSource", RE_JS_ES.as_ref()),
        ("navigator.clipboard", RE_JS_CLIP.as_ref()),
        ("TelegramWidget.sendMessage", RE_JS_SENDMSG.as_ref()),
    ];
    for (label, pat_opt) in js_checks {
        if pat_opt.is_some_and(|re| re.is_match(&raw_js)) {
            warnings.push(format!("Forbidden JS API '{label}' in Profile-1 widget"));
        }
    }

    warnings
}

// --------------------------------------------------------------------------- validation

pub(crate) fn clamp_width(w: Option<u32>) -> Option<u32> {
    match w {
        None | Some(0) => None,
        Some(v) => Some(v.max(WIDGET_WIDTH_MIN)),
    }
}

pub(crate) fn clamp_height(h: Option<u32>) -> Option<u32> {
    match h {
        None | Some(0) => None,
        Some(v) => Some(v.clamp(WIDGET_HEIGHT_MIN, WIDGET_HEIGHT_MAX)),
    }
}

pub(crate) fn clamp_cache_time(ct: Option<u32>) -> Option<u32> {
    ct.map(|v| v.clamp(WIDGET_CACHE_TIME_MIN, WIDGET_CACHE_TIME_MAX))
}

/// Normalize a copy of `WidgetSpec` and enforce Telegram Bot API 10.4 limits.
pub fn validate_widget_spec(spec: &WidgetSpec) -> Result<(WidgetSpec, Vec<String>)> {
    let mut norm = spec.clone();
    norm.width = clamp_width(norm.width);
    norm.height = clamp_height(norm.height);
    norm.cache_time = clamp_cache_time(norm.cache_time);
    norm.public_data = encode_widget_data(norm.public_data.as_deref(), false)?;
    norm.chat_data = encode_widget_data(norm.chat_data.as_deref(), false)?;

    if let Some(ref cap) = norm.caption {
        if cap.contains('\0') {
            return Err(BridgeError::Validation(
                "Widget caption must not contain NUL bytes".to_string(),
            ));
        }
        let utf16_len = cap.encode_utf16().count();
        if utf16_len > WIDGET_CAPTION_LIMIT {
            return Err(BridgeError::Validation(format!(
                "Widget caption exceeds {WIDGET_CAPTION_LIMIT} UTF-16 code units ({utf16_len})"
            )));
        }
    }

    let mut warnings = Vec::new();
    if let Some(ref html) = norm.html {
        if html.contains('\0') {
            return Err(BridgeError::Validation(
                "Widget HTML must not contain NUL bytes".to_string(),
            ));
        }
        if html.is_empty() {
            return Err(BridgeError::Validation(
                "Widget HTML must not be empty".to_string(),
            ));
        }
        let sizes = count_widget_size(html);
        if !sizes.ok {
            let minified = minify_widget_html(html);
            let sizes2 = count_widget_size(&minified);
            if !sizes2.ok {
                return Err(BridgeError::Validation(format!(
                    "Widget HTML exceeds Telegram limits after minification (raw={}/{WIDGET_HTML_RAW_LIMIT}, zlib={}/{WIDGET_HTML_ZLIB_LIMIT})",
                    sizes2.raw_bytes, sizes2.zlib_bytes
                )));
            }
            norm.html = Some(minified);
        }
        if let Some(ref final_html) = norm.html {
            warnings = lint_widget_profile(final_html);
        }
    } else if norm.widget_id.as_deref().unwrap_or("").is_empty()
        && norm.slug.as_deref().unwrap_or("").is_empty()
    {
        return Err(BridgeError::Validation(
            "WidgetSpec must specify html, widget_id, or slug".to_string(),
        ));
    }

    Ok((norm, warnings))
}
