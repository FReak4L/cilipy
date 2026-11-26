//! Markdown -> Telegram HTML and Rich Markdown rendering helpers.
//!
//! Primary path: agy Markdown is sent as a Telegram *Rich Message* (Bot API 10.1+,
//! `sendRichMessage` with `InputRichMessage.markdown`) which natively supports
//! headings, lists, tables, code, quotes, details, and math.
//! Fallback path: [`md_to_html`] converts to classic Telegram HTML (`parse_mode=HTML`)
//! with tables rendered as aligned monospace `<pre>` blocks, then [`split_html`]
//! splits into `<= 4096` UTF-16 unit chunks keeping tags balanced.

use std::sync::LazyLock;

use agy_core::tg::{CopyTextButton, InlineKeyboardButton, InlineKeyboardMarkup};
use regex::{Captures, Regex};
use unicode_width::UnicodeWidthChar;

use crate::premium::strip_md_custom_emoji;

/// Telegram Bot API classic `sendMessage` text limit (UTF-16 code units).
pub const TG_TEXT_LIMIT: usize = 4096;
/// Telegram Bot API media caption limit (UTF-16 code units).
pub const TG_CAPTION_LIMIT: usize = 1024;
/// Telegram Bot API 10.1+ Rich Message character limit (UTF-16 code units).
pub const RICH_TEXT_LIMIT: usize = 32768;
/// Telegram Bot API 10.1+ Rich Message maximum block count.
pub const RICH_BLOCK_LIMIT: usize = 500;

/// Default soft limit used by [`split_html`] (`TG_TEXT_LIMIT - 96`).
pub const DEFAULT_HTML_SPLIT_LIMIT: usize = TG_TEXT_LIMIT - 96;
/// Default character limit used by [`split_markdown`] (`RICH_TEXT_LIMIT - 768`).
pub const DEFAULT_MD_SPLIT_LIMIT: usize = RICH_TEXT_LIMIT - 768;
/// Default block-proxy line limit used by [`split_markdown`] (`RICH_BLOCK_LIMIT - 60`).
pub const DEFAULT_MD_SPLIT_LINES: usize = RICH_BLOCK_LIMIT - 60;

static RE_SEP: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)+\|?\s*$|^\s*\|\s*:?-{1,}:?\s*\|\s*$")
        .ok()
});
static RE_STRIP_CODE: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"`([^`]*)`").ok());
static RE_STRIP_BOLD: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\*\*(.+?)\*\*|__(.+?)__").ok());
static RE_STRIP_LINK: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\[([^\]]+)\]\(([^)\s]+)\)").ok());

static RE_CODE_SPAN: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"`([^`\n]+)`").ok());
static RE_MD_CUSTOM_EMOJI: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"!\[([^\]\n]*)\]\(tg://emoji\?id=([0-9]+)\)").ok());
static RE_MD_IMAGE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"!\[([^\]\n]*)\]\(([^)\s]+)\)").ok());
static RE_MD_LINK: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\[([^\]\n]+)\]\(([^)\s]+)\)").ok());
static RE_RAW_TG_EMOJI: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"<tg-emoji\s+emoji-id="([0-9]+)">([^<\n]*)</tg-emoji>"#).ok());
static RE_RAW_TG_SPOILER: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"<tg-spoiler>([^<\n]+)</tg-spoiler>").ok());
static RE_RAW_TG_U: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"<u>([^<\n]+)</u>").ok());
static RE_RAW_TG_SUB: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"<sub>([^<\n]+)</sub>").ok());
static RE_RAW_TG_SUP: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"<sup>([^<\n]+)</sup>").ok());
static RE_RAW_TG_TIME: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"<tg-time\b([^>]*)>([^<\n]*)</tg-time>"#).ok()
});
static RE_PAREN_MATH: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\\\(([^()\n]+(?:\([^()\n]*\)[^()\n]*)*)\\\)").ok());
static RE_STRIP_MD_CUSTOM_EMOJI: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"!\[([^\]\n]*)\]\(tg://emoji\?id=[0-9]+\)").ok());
static RE_STRIP_TG_EMOJI_INLINE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"<tg-emoji\s+emoji-id="[0-9]+">([^<\n]*)</tg-emoji>"#).ok());
static RE_TG_BTN_ROW: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?is)<tg-button-row\b[^>]*>(.*?)</tg-button-row>").ok());
static RE_TG_BTN: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?is)<tg-button\b([^>]*)>(.*?)</tg-button>"#).ok());
static RE_ATTR_PAIR: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"([a-zA-Z_][\w-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')"#).ok());
static RE_HTML_TR: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?is)<tr\b[^>]*>(.*?)</tr>").ok());
static RE_HTML_TD: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?is)<t[hd]\b[^>]*>(.*?)</t[hd]>").ok());

static RE_FENCE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^\s*(```+|~~~+)\s*([\w+#.-]*)\s*$").ok());
static RE_QUOTE_PREFIX: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"^\s*>\s?").ok());
static RE_DETAILS: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^\s*<details[^>]*>\s*(?:<summary>(.*?)</summary>)?\s*$").ok()
});
static RE_SUMMARY_LINE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^\s*<summary>(.*?)</summary>\s*$").ok());
static RE_HEADING: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^\s*(#{1,6})\s+(.*?)\s*#*\s*$").ok());
static RE_TASK_LIST: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^(\s*)[-*+]\s+\[([ xX])\]\s+(.*)$").ok());
static RE_BULLET_LIST: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^(\s*)[-*+]\s+(.*)$").ok());
static RE_ORDERED_LIST: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^(\s*)(\d+)[.)]\s+(.*)$").ok());

static RE_HTML_TAG: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^<(/?)([a-zA-Z][\w-]*)([^>]*)>$").ok());
static RE_ALL_TAGS: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"<[^>]+>").ok());

/// Escape text for Telegram HTML (`&`, `<`, `>`).
pub fn esc(s: &str) -> String {
    if !s.bytes().any(|b| matches!(b, b'&' | b'<' | b'>')) {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() + 8);
    let mut last = 0;
    for (i, b) in s.bytes().enumerate() {
        let rep = match b {
            b'&' => "&amp;",
            b'<' => "&lt;",
            b'>' => "&gt;",
            _ => continue,
        };
        out.push_str(&s[last..i]);
        out.push_str(rep);
        last = i + 1;
    }
    out.push_str(&s[last..]);
    out
}

/// Escape text for Telegram HTML attributes (`&`, `<`, `>`, `"`, `'`).
///
/// Matches Python `html.escape(s, quote=True)` (`"` -> `&quot;`, `'` -> `&#x27;`).
pub fn esc_attr(s: &str) -> String {
    if !s
        .bytes()
        .any(|b| matches!(b, b'&' | b'<' | b'>' | b'"' | b'\''))
    {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() + 8);
    let mut last = 0;
    for (i, b) in s.bytes().enumerate() {
        let rep = match b {
            b'&' => "&amp;",
            b'<' => "&lt;",
            b'>' => "&gt;",
            b'"' => "&quot;",
            b'\'' => "&#x27;",
            _ => continue,
        };
        out.push_str(&s[last..i]);
        out.push_str(rep);
        last = i + 1;
    }
    out.push_str(&s[last..]);
    out
}

/// Exact UTF-16 code unit count (what Telegram Bot API measures for limits).
pub fn utf16_len(s: &str) -> usize {
    if s.is_ascii() {
        return s.len();
    }
    s.encode_utf16().count()
}

/// Longest UTF-8 prefix of `s` whose UTF-16 length is `<= units`.
pub fn cut_utf16(s: &str, units: usize) -> &str {
    if s.is_ascii() {
        return &s[..units.min(s.len())];
    }
    let mut n = 0usize;
    for (i, ch) in s.char_indices() {
        let w = ch.len_utf16();
        if n + w > units {
            return &s[..i];
        }
        n += w;
    }
    s
}

/// Escape Telegram Bot API `MarkdownV2` special characters.
pub fn escape_markdown_v2(s: &str) -> String {
    const SPECIAL: &[u8] = b"_*[]()~`>#+-=|{}.!\\";
    if !s.bytes().any(|b| SPECIAL.contains(&b)) {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() + 8);
    let mut last = 0;
    for (i, b) in s.bytes().enumerate() {
        if SPECIAL.contains(&b) {
            out.push_str(&s[last..i]);
            out.push('\\');
            out.push(b as char);
            last = i + 1;
        }
    }
    out.push_str(&s[last..]);
    out
}

/// Collapse `\r`/`\n` to spaces and trim whitespace for Rich Markdown text fields.
pub fn md_text(val: &str) -> String {
    val.replace(['\r', '\n'], " ").trim().to_string()
}

/// Sanitize a value for use inside a GFM table cell with a custom empty fallback.
///
/// Collapses `\r`/`\n` to spaces, trims, escapes `|` as `\|`, and replaces
/// backticks `` ` `` with `'`.
pub fn md_cell_with_fallback(val: &str, empty_fallback: &str) -> String {
    let collapsed = val.replace(['\r', '\n'], " ");
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        return empty_fallback.to_string();
    }
    let escaped = trimmed.replace('|', "\\|").replace('`', "'");
    if escaped.is_empty() {
        empty_fallback.to_string()
    } else {
        escaped
    }
}

/// Sanitize a value for use inside a GFM table cell (defaults empty values to `"—"`).
pub fn md_cell(val: &str) -> String {
    md_cell_with_fallback(val, "—")
}

// ---------------------------------------------------------------- tables

fn is_zero_width_display_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FE0E}' | '\u{FE0F}'
    )
}

fn cell_width(s: &str) -> usize {
    s.chars()
        .filter(|ch| !is_zero_width_display_char(*ch))
        .map(|ch| ch.width().unwrap_or(0))
        .sum()
}

fn strip_inline_md(s: &str) -> String {
    let mut out = s.to_string();
    if let Some(re) = RE_STRIP_MD_CUSTOM_EMOJI.as_ref() {
        out = re.replace_all(&out, "$1").into_owned();
    }
    if let Some(re) = RE_STRIP_TG_EMOJI_INLINE.as_ref() {
        out = re.replace_all(&out, "$1").into_owned();
    }
    if let Some(re) = RE_STRIP_CODE.as_ref() {
        out = re.replace_all(&out, "$1").into_owned();
    }
    if let Some(re) = RE_STRIP_BOLD.as_ref() {
        out = re
            .replace_all(&out, |caps: &Captures| {
                caps.get(1)
                    .or_else(|| caps.get(2))
                    .map_or("", |m| m.as_str())
                    .to_string()
            })
            .into_owned();
    }
    out = replace_delim_boundary(&out, "*", "", "", true, false);
    out = replace_pair_delim(&out, "~~", "", "");
    out = replace_pair_delim(&out, "==", "", "");
    out = replace_pair_delim(&out, "||", "", "");
    if let Some(re) = RE_STRIP_LINK.as_ref() {
        out = re.replace_all(&out, "$1").into_owned();
    }
    out.trim().to_string()
}

fn split_row(line: &str) -> Vec<String> {
    let mut line = line.trim();
    if let Some(rest) = line.strip_prefix('|') {
        line = rest;
    }
    if line.ends_with('|') && !line.ends_with("\\|") {
        line = &line[..line.len() - 1];
    }

    let bytes = line.as_bytes();
    let mut cells = Vec::new();
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'|' && (i == 0 || bytes[i - 1] != b'\\') {
            cells.push(strip_inline_md(&line[start..i].replace("\\|", "|")));
            start = i + 1;
        }
    }
    cells.push(strip_inline_md(&line[start..].replace("\\|", "|")));
    cells
}

/// Whether `line` is a GFM table separator row (e.g. `|---|:---:|---:|`).
pub fn is_table_sep(line: &str) -> bool {
    if !line.contains('-') {
        return false;
    }
    RE_SEP.as_ref().is_some_and(|re| re.is_match(line))
}

#[derive(Clone, Copy)]
enum Align {
    Left,
    Center,
    Right,
}

/// Render GFM table lines (`header`, `separator`, `rows`) as aligned monospace text.
pub fn table_to_pre<S: AsRef<str>>(lines: &[S]) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut header = split_row(lines[0].as_ref());
    let mut aligns: Vec<Align> = if lines.len() >= 2 {
        split_row(lines[1].as_ref())
            .into_iter()
            .map(|c| {
                let c = c.trim();
                if c.ends_with(':') && !c.starts_with(':') {
                    Align::Right
                } else if c.starts_with(':') && c.ends_with(':') {
                    Align::Center
                } else {
                    Align::Left
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut rows: Vec<Vec<String>> = if lines.len() > 2 {
        lines[2..].iter().map(|l| split_row(l.as_ref())).collect()
    } else {
        Vec::new()
    };

    let ncol = header
        .len()
        .max(rows.iter().map(Vec::len).max().unwrap_or(0));
    if ncol == 0 {
        return String::new();
    }

    header.resize(ncol, String::new());
    aligns.resize(ncol, Align::Left);
    for row in &mut rows {
        row.resize(ncol, String::new());
    }

    let mut widths = vec![0usize; ncol];
    for (col, w) in widths.iter_mut().enumerate() {
        let mut max_w = cell_width(&header[col]);
        for row in &rows {
            max_w = max_w.max(cell_width(&row[col]));
        }
        *w = max_w;
    }

    let fmt = |cells: &[String]| -> String {
        let mut out = Vec::with_capacity(ncol);
        for (i, c) in cells.iter().enumerate() {
            let pad = widths[i].saturating_sub(cell_width(c));
            let formatted = match aligns[i] {
                Align::Right => format!("{}{}", " ".repeat(pad), c),
                Align::Center => {
                    let left = pad / 2;
                    let right = pad - left;
                    format!("{}{}{}", " ".repeat(left), c, " ".repeat(right))
                }
                Align::Left => format!("{}{}", c, " ".repeat(pad)),
            };
            out.push(formatted);
        }
        out.join(" │ ").trim_end().to_string()
    };

    let sep = widths
        .iter()
        .map(|&w| "─".repeat(w))
        .collect::<Vec<_>>()
        .join("─┼─");

    let mut body = Vec::with_capacity(2 + rows.len());
    body.push(fmt(&header));
    body.push(sep);
    for row in &rows {
        body.push(fmt(row));
    }
    body.join("\n")
}

// ---------------------------------------------------------------- inline

fn is_word_or_delim(ch: char, delim_char: char) -> bool {
    ch.is_alphanumeric() || ch == '_' || ch == delim_char
}

/// Non-greedy pair delimiter replacement (`||..||`, `**..**`, `~~..~~`, `==..==`),
/// not crossing `\n`.
fn replace_pair_delim(s: &str, delim: &str, open_tag: &str, close_tag: &str) -> String {
    if !s.contains(delim) {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() + 16);
    let mut pos = 0usize;
    while pos < s.len() {
        let Some(rel_i) = s[pos..].find(delim) else {
            out.push_str(&s[pos..]);
            break;
        };
        let i = pos + rel_i;
        let line_end = s[i..].find('\n').map_or(s.len(), |n| i + n);
        let after_open = i + delim.len();
        if after_open >= line_end {
            out.push_str(&s[pos..line_end]);
            pos = line_end;
            continue;
        }
        let first_char_len = s[after_open..line_end]
            .chars()
            .next()
            .map_or(0, char::len_utf8);
        let search_start = after_open + first_char_len;
        if search_start < line_end {
            if let Some(rel_k) = s[search_start..line_end].find(delim) {
                let k = search_start + rel_k;
                out.push_str(&s[pos..i]);
                out.push_str(open_tag);
                out.push_str(&s[after_open..k]);
                out.push_str(close_tag);
                pos = k + delim.len();
                continue;
            }
        }
        // No closing delimiter remains on this line.
        out.push_str(&s[pos..line_end]);
        pos = line_end;
    }
    out
}

/// Boundary-aware delimiter replacement equivalent to Python lookarounds for
/// `__`, `*`, and `_`, running in linear time without regex backtracking.
fn replace_delim_boundary(
    s: &str,
    delim: &str,
    open_tag: &str,
    close_tag: &str,
    disallow_inner_ws: bool,
    disallow_inner_delim: bool,
) -> String {
    let Some(delim_char) = delim.chars().next() else {
        return s.to_owned();
    };
    if !s.contains(delim) {
        return s.to_owned();
    }

    let mut out = String::with_capacity(s.len() + 16);
    let mut pos = 0usize;
    let mut scan = 0usize;
    while scan < s.len() {
        let Some(rel_i) = s[scan..].find(delim) else {
            break;
        };
        let i = scan + rel_i;
        let line_end = s[i..].find('\n').map_or(s.len(), |n| i + n);

        // Check `(?<![\w<delim>])`
        let prev_ok = s[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word_or_delim(c, delim_char));
        let after_open = i + delim.len();
        let next_ch = s[after_open..line_end].chars().next();
        let next_ok = match next_ch {
            Some(c) => {
                !(disallow_inner_ws && c.is_whitespace())
                    && !(disallow_inner_delim && c == delim_char)
            }
            None => false,
        };

        if !prev_ok || !next_ok {
            let step = s[i..].chars().next().map_or(1, char::len_utf8);
            scan = i + step;
            continue;
        }

        let first_char_len = next_ch.map_or(0, char::len_utf8);
        let mut search = after_open + first_char_len;
        let mut matched_close: Option<usize> = None;

        while search < line_end {
            let Some(rel_k) = s[search..line_end].find(delim) else {
                break;
            };
            let k = search + rel_k;
            let close_prev_ok = s[after_open..k].chars().next_back().is_some_and(|c| {
                !(disallow_inner_ws && c.is_whitespace())
                    && !(disallow_inner_delim && c == delim_char)
            });
            let after_close = k + delim.len();
            let close_next_ok = s[after_close..line_end]
                .chars()
                .next()
                .is_none_or(|c| !is_word_or_delim(c, delim_char));

            if close_prev_ok && close_next_ok {
                matched_close = Some(k);
                break;
            }
            let step = s[k..line_end].chars().next().map_or(1, char::len_utf8);
            search = k + step;
        }

        if let Some(k) = matched_close {
            out.push_str(&s[pos..i]);
            out.push_str(open_tag);
            out.push_str(&s[after_open..k]);
            out.push_str(close_tag);
            pos = k + delim.len();
            scan = pos;
        } else {
            // No valid closing delimiter exists anywhere on [after_open..line_end].
            scan = line_end;
        }
    }

    out.push_str(&s[pos..]);
    out
}

fn inline_basic(t: &str) -> String {
    let mut s = replace_pair_delim(t, "||", "<tg-spoiler>", "</tg-spoiler>");
    s = replace_pair_delim(&s, "***", "<b><i>", "</i></b>");
    s = replace_pair_delim(&s, "**", "<b>", "</b>");
    s = replace_delim_boundary(&s, "__", "<b>", "</b>", false, false);
    s = replace_pair_delim(&s, "~~", "<s>", "</s>");
    s = replace_pair_delim(&s, "==", "<u>", "</u>");
    s = replace_delim_boundary(&s, "*", "<i>", "</i>", true, true);
    s = replace_delim_boundary(&s, "_", "<i>", "</i>", true, true);
    s
}

fn pick_sentinel(text: &str) -> char {
    for ch in ['\0', '\u{E000}', '\u{E001}', '\u{F000}', '\u{FFFD}'] {
        if !text.contains(ch) {
            return ch;
        }
    }
    '\u{E002}'
}

fn expand_placeholders(s: &str, sentinel: char, holders: &[String]) -> String {
    if holders.is_empty() || !s.contains(sentinel) {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut pos = 0usize;
    let slen = sentinel.len_utf8();
    while pos < s.len() {
        let Some(rel) = s[pos..].find(sentinel) else {
            out.push_str(&s[pos..]);
            break;
        };
        let start = pos + rel;
        let digits_start = start + slen;
        if let Some(rel_end) = s[digits_start..].find(sentinel) {
            let digits = &s[digits_start..digits_start + rel_end];
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(idx) = digits.parse::<usize>() {
                    if let Some(val) = holders.get(idx) {
                        out.push_str(&s[pos..start]);
                        out.push_str(val);
                        pos = digits_start + rel_end + slen;
                        continue;
                    }
                }
            }
        }
        out.push_str(&s[pos..digits_start]);
        pos = digits_start;
    }
    out
}

fn is_safe_url(url: &str) -> bool {
    url.starts_with("http://")
        || url.starts_with("https://")
        || url.starts_with("tg://")
        || url.starts_with("mailto:")
        || url.starts_with("tel:")
}

fn latex_braced_arg(s: &str, start: usize) -> Option<(String, usize)> {
    let rest = &s[start..];
    if let Some(inner_start) = rest.strip_prefix('{') {
        let mut depth = 1usize;
        for (idx, ch) in inner_start.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        let content = inner_start[..idx].to_string();
                        return Some((content, start + 1 + idx + 1));
                    }
                }
                _ => {}
            }
        }
        None
    } else {
        rest.chars().next().map(|ch| (ch.to_string(), start + ch.len_utf8()))
    }
}

fn to_superscript_str(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let mapped = match ch {
            '0' => '⁰',
            '1' => '¹',
            '2' => '²',
            '3' => '³',
            '4' => '⁴',
            '5' => '⁵',
            '6' => '⁶',
            '7' => '⁷',
            '8' => '⁸',
            '9' => '⁹',
            '+' => '⁺',
            '-' => '⁻',
            '=' => '⁼',
            '(' => '⁽',
            ')' => '⁾',
            'n' => 'ⁿ',
            'i' => 'ⁱ',
            _ => return None,
        };
        out.push(mapped);
    }
    (!out.is_empty()).then_some(out)
}

fn to_subscript_str(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let mapped = match ch {
            '0' => '₀',
            '1' => '₁',
            '2' => '₂',
            '3' => '₃',
            '4' => '₄',
            '5' => '₅',
            '6' => '₆',
            '7' => '₇',
            '8' => '₈',
            '9' => '₉',
            '+' => '₊',
            '-' => '₋',
            '=' => '₌',
            '(' => '₍',
            ')' => '₎',
            'a' => 'ₐ',
            'e' => 'ₑ',
            'o' => 'ₒ',
            'x' => 'ₓ',
            'h' => 'ₕ',
            'k' => 'ₖ',
            'l' => 'ₗ',
            'm' => 'ₘ',
            'n' => 'ₙ',
            'p' => 'ₚ',
            's' => 'ₛ',
            't' => 'ₜ',
            'i' => 'ᵢ',
            'j' => 'ⱼ',
            'r' => 'ᵣ',
            'u' => 'ᵤ',
            'v' => 'ᵥ',
            _ => return None,
        };
        out.push(mapped);
    }
    (!out.is_empty()).then_some(out)
}

fn needs_parens_in_frac(s: &str) -> bool {
    let t = s.trim();
    t.len() > 2 && t.chars().any(|c| matches!(c, '+' | '-' | ' ' | '·' | '×'))
}

/// Convert common LaTeX math expressions into clean, readable Unicode plain text.
pub fn latex_to_unicode(expr: &str) -> String {
    let mut s = expr.trim().to_string();
    if s.is_empty() {
        return String::new();
    }
    // Strip structural noise first
    for noise in ["\\left", "\\right", "\\displaystyle", "\\textstyle"] {
        s = s.replace(noise, "");
    }
    s = s
        .replace("\\quad", " ")
        .replace("\\qquad", "  ")
        .replace("\\;", " ")
        .replace("\\:", " ")
        .replace("\\,", " ")
        .replace("\\%", "%");

    // Iterative expansion for `\frac`, `\sqrt`, `\text` etc.
    for _pass in 0..4 {
        let mut out = String::with_capacity(s.len());
        let mut i = 0usize;
        let mut changed = false;
        while i < s.len() {
            if s[i..].starts_with("\\frac") && !s[i + 5..].starts_with(|c: char| c.is_ascii_alphabetic()) {
                let mut p = i + 5;
                while p < s.len() && s.as_bytes()[p].is_ascii_whitespace() {
                    p += 1;
                }
                if let Some((num_raw, after_num)) = latex_braced_arg(&s, p) {
                    let mut q = after_num;
                    while q < s.len() && s.as_bytes()[q].is_ascii_whitespace() {
                        q += 1;
                    }
                    if let Some((den_raw, after_den)) = latex_braced_arg(&s, q) {
                        let num = num_raw.trim();
                        let den = den_raw.trim();
                        let n_fmt = if needs_parens_in_frac(num) {
                            format!("({num})")
                        } else {
                            num.to_string()
                        };
                        let d_fmt = if needs_parens_in_frac(den) {
                            format!("({den})")
                        } else {
                            den.to_string()
                        };
                        out.push_str(&format!("{n_fmt}/{d_fmt}"));
                        i = after_den;
                        changed = true;
                        continue;
                    }
                }
            } else if s[i..].starts_with("\\sqrt") && !s[i + 5..].starts_with(|c: char| c.is_ascii_alphabetic()) {
                let mut p = i + 5;
                while p < s.len() && s.as_bytes()[p].is_ascii_whitespace() {
                    p += 1;
                }
                let mut root_pfx = String::new();
                if s[p..].starts_with('[') {
                    if let Some(close) = s[p + 1..].find(']') {
                        let deg = s[p + 1..p + 1 + close].trim();
                        root_pfx = to_superscript_str(deg).unwrap_or_else(|| format!("{deg}-"));
                        p = p + 1 + close + 1;
                    }
                }
                while p < s.len() && s.as_bytes()[p].is_ascii_whitespace() {
                    p += 1;
                }
                if let Some((inner, after)) = latex_braced_arg(&s, p) {
                    let inner = inner.trim();
                    if inner.chars().count() <= 2 && inner.chars().all(|c| c.is_alphanumeric()) {
                        out.push_str(&format!("{root_pfx}√{inner}"));
                    } else {
                        out.push_str(&format!("{root_pfx}√({inner})"));
                    }
                    i = after;
                    changed = true;
                    continue;
                }
            } else {
                let mut matched_wrap = false;
                for cmd in ["\\text", "\\mathrm", "\\mathbf", "\\mathit", "\\mathsf", "\\operatorname"] {
                    let clen = cmd.len();
                    if s[i..].starts_with(cmd)
                        && !s[i + clen..].starts_with(|c: char| c.is_ascii_alphabetic())
                    {
                        let mut p = i + clen;
                        while p < s.len() && s.as_bytes()[p].is_ascii_whitespace() {
                            p += 1;
                        }
                        if let Some((inner, after)) = latex_braced_arg(&s, p) {
                            out.push_str(&inner);
                            i = after;
                            changed = true;
                            matched_wrap = true;
                            break;
                        }
                    }
                }
                if matched_wrap {
                    continue;
                }
            }
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
        s = out;
        if !changed {
            break;
        }
    }

    const SYMBOLS: &[(&str, &str)] = &[
        ("\\Leftrightarrow", "⇔"),
        ("\\leftrightarrow", "↔"),
        ("\\Rightarrow", "⇒"),
        ("\\rightarrow", "→"),
        ("\\leftarrow", "←"),
        ("\\subseteq", "⊆"),
        ("\\supseteq", "⊇"),
        ("\\approx", "≈"),
        ("\\equiv", "≡"),
        ("\\partial", "∂"),
        ("\\forall", "∀"),
        ("\\exists", "∃"),
        ("\\emptyset", "∅"),
        ("\\infty", "∞"),
        ("\\nabla", "∇"),
        ("\\notin", "∉"),
        ("\\subset", "⊂"),
        ("\\supset", "⊃"),
        ("\\lambda", "λ"),
        ("\\Lambda", "Λ"),
        ("\\epsilon", "ε"),
        ("\\varphi", "φ"),
        ("\\omega", "ω"),
        ("\\Omega", "Ω"),
        ("\\alpha", "α"),
        ("\\beta", "β"),
        ("\\gamma", "γ"),
        ("\\Gamma", "Γ"),
        ("\\delta", "δ"),
        ("\\Delta", "Δ"),
        ("\\theta", "θ"),
        ("\\Theta", "Θ"),
        ("\\sigma", "σ"),
        ("\\Sigma", "Σ"),
        ("\\kappa", "κ"),
        ("\\times", "×"),
        ("\\cdot", "·"),
        ("\\prod", "∏"),
        ("\\zeta", "ζ"),
        ("\\eta", "η"),
        ("\\iota", "ι"),
        ("\\phi", "φ"),
        ("\\Phi", "Φ"),
        ("\\psi", "ψ"),
        ("\\Psi", "Ψ"),
        ("\\rho", "ρ"),
        ("\\tau", "τ"),
        ("\\chi", "χ"),
        ("\\sum", "∑"),
        ("\\int", "∫"),
        ("\\leq", "≤"),
        ("\\geq", "≥"),
        ("\\neq", "≠"),
        ("\\div", "÷"),
        ("\\cup", "∪"),
        ("\\cap", "∩"),
        ("\\sim", "∼"),
        ("\\iff", "⇔"),
        ("\\to", "→"),
        ("\\in", "∈"),
        ("\\le", "≤"),
        ("\\ge", "≥"),
        ("\\ne", "≠"),
        ("\\pm", "±"),
        ("\\mp", "∓"),
        ("\\mu", "μ"),
        ("\\nu", "ν"),
        ("\\xi", "ξ"),
        ("\\pi", "π"),
        ("\\Pi", "Π"),
        ("\\\\", "\n"),
    ];
    for (pat, rep) in SYMBOLS {
        if s.contains(pat) {
            s = s.replace(pat, rep);
        }
    }

    // Replace `^{...}` / `_{...}` and single-char `^x` / `_x`
    let mut final_out = String::with_capacity(s.len());
    let mut pos = 0usize;
    while pos < s.len() {
        let ch = s[pos..].chars().next().unwrap();
        if (ch == '^' || ch == '_') && pos + 1 < s.len() {
            let is_sup = ch == '^';
            if let Some((arg, next_pos)) = latex_braced_arg(&s, pos + 1) {
                let converted = if is_sup {
                    to_superscript_str(arg.trim())
                } else {
                    to_subscript_str(arg.trim())
                };
                if let Some(u) = converted {
                    final_out.push_str(&u);
                    pos = next_pos;
                    continue;
                } else if arg.len() == 1 {
                    final_out.push(ch);
                    final_out.push_str(&arg);
                    pos = next_pos;
                    continue;
                } else {
                    final_out.push(ch);
                    final_out.push('(');
                    final_out.push_str(arg.trim());
                    final_out.push(')');
                    pos = next_pos;
                    continue;
                }
            }
        }
        final_out.push(ch);
        pos += ch.len_utf8();
    }
    final_out.trim().to_string()
}

fn looks_like_currency(inner: &str) -> bool {
    let t = inner.trim();
    if t.is_empty() {
        return true;
    }
    // `$5`, `$12.50`, `$1,000` -> currency, never LaTeX
    t.chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | ',' | '%' | ' '))
}

fn replace_pair_delim_to_holders(
    input: &str,
    delim: &str,
    sentinel: char,
    holders: &mut Vec<String>,
) -> String {
    if !input.contains(delim) {
        return input.to_owned();
    }
    let mut out = String::with_capacity(input.len());
    let mut pos = 0usize;
    while pos < input.len() {
        let Some(rel_i) = input[pos..].find(delim) else {
            out.push_str(&input[pos..]);
            break;
        };
        let i = pos + rel_i;
        let line_end = input[i..].find('\n').map_or(input.len(), |n| i + n);
        let after_open = i + delim.len();
        if after_open >= line_end {
            out.push_str(&input[pos..line_end]);
            pos = line_end;
            continue;
        }
        if let Some(rel_k) = input[after_open..line_end].find(delim) {
            let k = after_open + rel_k;
            let inner = input[after_open..k].trim();
            if !inner.is_empty() {
                let idx = holders.len();
                holders.push(format!("<code>{}</code>", esc(&latex_to_unicode(inner))));
                out.push_str(&input[pos..i]);
                out.push_str(&format!("{sentinel}{idx}{sentinel}"));
                pos = k + delim.len();
                continue;
            }
        }
        out.push_str(&input[pos..after_open]);
        pos = after_open;
    }
    out
}

fn starts_like_currency_token(s: &str) -> bool {
    let mut chars = s.chars().peekable();
    let Some(first) = chars.peek().copied() else {
        return false;
    };
    if !first.is_ascii_digit() {
        return false;
    }
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() || matches!(c, '.' | ',') {
            chars.next();
        } else {
            break;
        }
    }
    match chars.peek().copied() {
        None => true,
        Some(c) => c.is_whitespace() || matches!(c, '-' | ',' | ';' | ':' | ')' | ']' | '!' | '?'),
    }
}

/// Replace valid single-dollar `$inline math$` (while leaving `$5 and $10` / `$5-$10` currency untouched).
fn protect_single_dollar_math(
    input: &str,
    sentinel: char,
    holders: &mut Vec<String>,
) -> String {
    if !input.contains('$') {
        return input.to_owned();
    }
    let mut out = String::with_capacity(input.len());
    let mut pos = 0usize;
    while pos < input.len() {
        let Some(rel) = input[pos..].find('$') else {
            out.push_str(&input[pos..]);
            break;
        };
        let open = pos + rel;
        let before = input[..open].chars().next_back();
        let after_idx = open + 1;
        let next = input[after_idx..].chars().next();
        if before == Some('\\')
            || before.is_some_and(|c| c.is_alphanumeric())
            || next.is_none_or(|c| c == '$' || c.is_whitespace())
            || starts_like_currency_token(&input[after_idx..])
        {
            out.push_str(&input[pos..after_idx]);
            pos = after_idx;
            continue;
        }
        let line_end = input[after_idx..]
            .find('\n')
            .map_or(input.len(), |n| after_idx + n);
        let mut scan = after_idx;
        let mut close_match: Option<usize> = None;
        while scan < line_end {
            let Some(rel_c) = input[scan..line_end].find('$') else {
                break;
            };
            let c_idx = scan + rel_c;
            let prev_escaped = input[..c_idx].ends_with('\\');
            if prev_escaped {
                scan = c_idx + 1;
                continue;
            }
            let prev_c = input[after_idx..c_idx].chars().next_back();
            let after_c = input[c_idx + 1..line_end].chars().next();
            if prev_c.is_some_and(|c| !c.is_whitespace() && c != '$')
                && after_c.is_none_or(|c| !c.is_alphanumeric() && c != '$')
            {
                let inner = &input[after_idx..c_idx];
                if !looks_like_currency(inner) {
                    close_match = Some(c_idx);
                }
            }
            // First unescaped `$` either closes this math span or invalidates it
            // (prevents `$a ... $b` currency phrases from eating up to a later `$math$`).
            break;
        }
        if let Some(close) = close_match {
            let inner = &input[after_idx..close];
            let rendered = latex_to_unicode(inner);
            let idx = holders.len();
            holders.push(format!("<code>{}</code>", esc(&rendered)));
            out.push_str(&input[pos..open]);
            out.push_str(&format!("{sentinel}{idx}{sentinel}"));
            pos = close + 1;
        } else {
            out.push_str(&input[pos..after_idx]);
            pos = after_idx;
        }
    }
    out
}

fn inline(text: &str) -> String {
    let sentinel = pick_sentinel(text);
    let mut holders: Vec<String> = Vec::new();
    let mut work = text.to_owned();

    if let Some(re) = RE_CODE_SPAN.as_ref() {
        work = re
            .replace_all(&work, |caps: &Captures| {
                let inner = caps.get(1).map_or("", |m| m.as_str());
                let idx = holders.len();
                holders.push(format!("<code>{}</code>", esc(inner)));
                format!("{sentinel}{idx}{sentinel}")
            })
            .into_owned();
    }

    if let Some(re) = RE_PAREN_MATH.as_ref() {
        work = re
            .replace_all(&work, |caps: &Captures| {
                let inner = caps.get(1).map_or("", |m| m.as_str());
                let idx = holders.len();
                holders.push(format!("<code>{}</code>", esc(&latex_to_unicode(inner))));
                format!("{sentinel}{idx}{sentinel}")
            })
            .into_owned();
    }

    work = replace_pair_delim_to_holders(&work, "$$", sentinel, &mut holders);
    work = protect_single_dollar_math(&work, sentinel, &mut holders);

    if let Some(re) = RE_MD_CUSTOM_EMOJI.as_ref() {
        work = re
            .replace_all(&work, |caps: &Captures| {
                let alt = caps.get(1).map_or("", |m| m.as_str());
                let id = caps.get(2).map_or("", |m| m.as_str());
                let idx = holders.len();
                let alt_esc = if alt.is_empty() {
                    "⭐".to_string()
                } else {
                    esc(alt)
                };
                holders.push(format!(r#"<tg-emoji emoji-id="{id}">{alt_esc}</tg-emoji>"#));
                format!("{sentinel}{idx}{sentinel}")
            })
            .into_owned();
    }

    if let Some(re) = RE_MD_IMAGE.as_ref() {
        work = re
            .replace_all(&work, |caps: &Captures| {
                let full = caps.get(0).map_or("", |m| m.as_str());
                let alt = caps.get(1).map_or("", |m| m.as_str());
                let url = caps.get(2).map_or("", |m| m.as_str());
                let idx = holders.len();
                if !is_safe_url(url) {
                    let resolved = expand_placeholders(&esc(full), sentinel, &holders);
                    holders.push(resolved);
                } else {
                    let lbl = if alt.trim().is_empty() { url } else { alt };
                    let label_html =
                        expand_placeholders(&inline_basic(&esc(lbl)), sentinel, &holders);
                    holders.push(format!(r#"<a href="{}">{}</a>"#, esc_attr(url), label_html));
                }
                format!("{sentinel}{idx}{sentinel}")
            })
            .into_owned();
    }

    if let Some(re) = RE_MD_LINK.as_ref() {
        work = re
            .replace_all(&work, |caps: &Captures| {
                let full = caps.get(0).map_or("", |m| m.as_str());
                let label = caps.get(1).map_or("", |m| m.as_str());
                let url = caps.get(2).map_or("", |m| m.as_str());
                let idx = holders.len();
                if !is_safe_url(url) {
                    let resolved = expand_placeholders(&esc(full), sentinel, &holders);
                    holders.push(resolved);
                } else {
                    let label_html =
                        expand_placeholders(&inline_basic(&esc(label)), sentinel, &holders);
                    holders.push(format!(r#"<a href="{}">{}</a>"#, esc_attr(url), label_html));
                }
                format!("{sentinel}{idx}{sentinel}")
            })
            .into_owned();
    }

    if let Some(re) = RE_RAW_TG_EMOJI.as_ref() {
        work = re
            .replace_all(&work, |caps: &Captures| {
                let id = caps.get(1).map_or("", |m| m.as_str());
                let inner = caps.get(2).map_or("", |m| m.as_str());
                let idx = holders.len();
                holders.push(format!(r#"<tg-emoji emoji-id="{id}">{}</tg-emoji>"#, esc(inner)));
                format!("{sentinel}{idx}{sentinel}")
            })
            .into_owned();
    }

    if let Some(re) = RE_RAW_TG_TIME.as_ref() {
        work = re
            .replace_all(&work, |caps: &Captures| {
                let attrs = caps.get(1).map_or("", |m| m.as_str());
                let inner = caps.get(2).map_or("", |m| m.as_str());
                let idx = holders.len();
                holders.push(format!("<tg-time{attrs}>{}</tg-time>", esc(inner)));
                format!("{sentinel}{idx}{sentinel}")
            })
            .into_owned();
    }

    for (re_opt, tag) in [
        (RE_RAW_TG_SPOILER.as_ref(), "tg-spoiler"),
        (RE_RAW_TG_U.as_ref(), "u"),
        (RE_RAW_TG_SUB.as_ref(), "sub"),
        (RE_RAW_TG_SUP.as_ref(), "sup"),
    ] {
        if let Some(re) = re_opt {
            work = re
                .replace_all(&work, |caps: &Captures| {
                    let inner = caps.get(1).map_or("", |m| m.as_str());
                    let idx = holders.len();
                    let body = expand_placeholders(&inline_basic(&esc(inner)), sentinel, &holders);
                    holders.push(format!("<{tag}>{body}</{tag}>"));
                    format!("{sentinel}{idx}{sentinel}")
                })
                .into_owned();
        }
    }

    let escaped = esc(&work);
    let formatted = inline_basic(&escaped);
    expand_placeholders(&formatted, sentinel, &holders)
}

/// CommonMark closing fence check: same fence character, length >= opening fence, no info-string.
fn is_closing_fence(line: &str, open_fence: &str) -> bool {
    let trimmed = line.trim();
    let Some(fch) = open_fence.chars().next() else {
        return false;
    };
    trimmed.len() >= open_fence.len() && trimmed.chars().all(|c| c == fch)
}

// ---------------------------------------------------------------- blocks

fn is_hr(line: &str) -> bool {
    let trimmed = line.trim();
    let Some(first) = trimmed.chars().next() else {
        return false;
    };
    if !matches!(first, '-' | '*' | '_') {
        return false;
    }
    let mut count = 0usize;
    for ch in trimmed.chars() {
        if ch == first {
            count += 1;
        } else if !ch.is_whitespace() {
            return false;
        }
    }
    count >= 3
}

fn collapse_triple_newlines(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut nl_run = 0usize;
    for ch in s.chars() {
        if ch == '\n' {
            nl_run += 1;
            if nl_run <= 2 {
                out.push('\n');
            }
        } else {
            nl_run = 0;
            out.push(ch);
        }
    }
    out
}

fn strip_quote_prefix(line: &str) -> String {
    if let Some(re) = RE_QUOTE_PREFIX.as_ref() {
        re.replace(line, "").into_owned()
    } else {
        line.trim_start()
            .strip_prefix('>')
            .map_or(line, |r| r.strip_prefix(' ').unwrap_or(r))
            .to_string()
    }
}

fn decode_basic_entities(s: &str) -> String {
    s.replace("&nbsp;", " ")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn html_table_to_pre(raw_html_table: &str) -> String {
    let Some(tr_re) = RE_HTML_TR.as_ref() else {
        return String::new();
    };
    let Some(td_re) = RE_HTML_TD.as_ref() else {
        return String::new();
    };
    let mut gfm_lines: Vec<String> = Vec::new();
    let mut col_count = 0usize;
    for tr_caps in tr_re.captures_iter(raw_html_table) {
        let row_html = tr_caps.get(1).map_or("", |m| m.as_str());
        let mut cells: Vec<String> = Vec::new();
        for td_caps in td_re.captures_iter(row_html) {
            let raw_cell = td_caps.get(1).map_or("", |m| m.as_str());
            let stripped = match RE_ALL_TAGS.as_ref() {
                Some(re) => re.replace_all(raw_cell, "").into_owned(),
                None => raw_cell.to_string(),
            };
            let cell = md_cell_with_fallback(&decode_basic_entities(&stripped), "");
            cells.push(cell);
        }
        if !cells.is_empty() {
            col_count = col_count.max(cells.len());
            gfm_lines.push(format!("| {} |", cells.join(" | ")));
            if gfm_lines.len() == 1 {
                let sep = vec!["---"; col_count.max(1)].join(" | ");
                gfm_lines.push(format!("| {sep} |"));
            }
        }
    }
    if gfm_lines.is_empty() {
        return String::new();
    }
    table_to_pre(&gfm_lines)
}

fn render_details_body(buf: &[&str]) -> String {
    if !buf.iter().any(|l| RE_FENCE.as_ref().is_some_and(|re| re.is_match(l))) {
        return buf
            .iter()
            .map(|b| inline(b))
            .collect::<Vec<_>>()
            .join("\n");
    }
    let mut out: Vec<String> = Vec::with_capacity(buf.len());
    let mut i = 0usize;
    while i < buf.len() {
        let line = buf[i];
        if let Some(fm) = RE_FENCE.as_ref().and_then(|re| re.captures(line)) {
            let fence = fm.get(1).map_or("", |m| m.as_str());
            let lang = fm.get(2).map_or("", |m| m.as_str());
            let mut j = i + 1;
            let mut code_lines: Vec<&str> = Vec::new();
            while j < buf.len() && !is_closing_fence(buf[j], fence) {
                code_lines.push(buf[j]);
                j += 1;
            }
            let code = esc(&code_lines.join("\n"));
            if lang.eq_ignore_ascii_case("math") || lang.eq_ignore_ascii_case("latex") {
                out.push(format!("<code>{}</code>", esc(&latex_to_unicode(&code_lines.join("\n")))));
            } else if !lang.is_empty() {
                out.push(format!(
                    r#"<pre><code class="language-{}">{code}</code></pre>"#,
                    esc_attr(lang)
                ));
            } else {
                out.push(format!("<pre>{code}</pre>"));
            }
            i = j + 1;
            continue;
        }
        out.push(inline(line));
        i += 1;
    }
    out.join("\n")
}

/// Convert Markdown to classic Telegram HTML (`parse_mode=HTML`).
///
/// Blockquotes longer than `expand_quote_lines` lines (default in Python: `6`)
/// are rendered with `<blockquote expandable>`.
pub fn md_to_html(md: &str, expand_quote_lines: usize) -> String {
    let normalized = md.replace("\r\n", "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    let n = lines.len();
    let mut out: Vec<String> = Vec::with_capacity(n);
    let mut i = 0usize;

    while i < n {
        let line = lines[i];
        let trimmed = line.trim();

        if let Some(fm) = RE_FENCE.as_ref().and_then(|re| re.captures(line)) {
            let fence = fm.get(1).map_or("", |m| m.as_str());
            let lang = fm.get(2).map_or("", |m| m.as_str());
            let mut j = i + 1;
            let mut buf: Vec<&str> = Vec::new();
            while j < n && !is_closing_fence(lines[j], fence) {
                buf.push(lines[j]);
                j += 1;
            }
            let raw_body = buf.join("\n");
            if lang.eq_ignore_ascii_case("math") || lang.eq_ignore_ascii_case("latex") {
                out.push(format!(
                    "<blockquote><code>{}</code></blockquote>",
                    esc(&latex_to_unicode(&raw_body))
                ));
            } else {
                let code = esc(&raw_body);
                if !lang.is_empty() {
                    out.push(format!(
                        r#"<pre><code class="language-{}">{code}</code></pre>"#,
                        esc_attr(lang)
                    ));
                } else {
                    out.push(format!("<pre>{code}</pre>"));
                }
            }
            i = j + 1;
            continue;
        }

        // Display math block: `$$...$$`, `\[...\]`, or `<tg-math-block>...</tg-math-block>`
        if trimmed == "$$" || (trimmed.starts_with("$$") && !trimmed[2..].contains("$$")) {
            let first_tail = trimmed.strip_prefix("$$").unwrap_or("").trim();
            let mut buf: Vec<String> = Vec::new();
            if !first_tail.is_empty() {
                buf.push(first_tail.to_string());
            }
            let mut j = i + 1;
            while j < n {
                let lt = lines[j].trim();
                if let Some(end_pos) = lt.find("$$") {
                    let before = lt[..end_pos].trim();
                    if !before.is_empty() {
                        buf.push(before.to_string());
                    }
                    break;
                }
                buf.push(lines[j].to_string());
                j += 1;
            }
            out.push(format!(
                "<blockquote><code>{}</code></blockquote>",
                esc(&latex_to_unicode(&buf.join("\n")))
            ));
            i = (j + 1).min(n);
            continue;
        }
        if let Some(rest_br) = trimmed.strip_prefix("\\[") {
            if let Some(end_pos) = rest_br.find("\\]") {
                let expr = &rest_br[..end_pos];
                out.push(format!(
                    "<blockquote><code>{}</code></blockquote>",
                    esc(&latex_to_unicode(expr))
                ));
                i += 1;
                continue;
            }
            let mut buf: Vec<String> = Vec::new();
            let head = rest_br.trim();
            if !head.is_empty() {
                buf.push(head.to_string());
            }
            let mut j = i + 1;
            while j < n {
                if let Some(end_pos) = lines[j].find("\\]") {
                    let before = lines[j][..end_pos].trim();
                    if !before.is_empty() {
                        buf.push(before.to_string());
                    }
                    break;
                }
                buf.push(lines[j].to_string());
                j += 1;
            }
            out.push(format!(
                "<blockquote><code>{}</code></blockquote>",
                esc(&latex_to_unicode(&buf.join("\n")))
            ));
            i = (j + 1).min(n);
            continue;
        }
        if trimmed.starts_with("<tg-math-block>") {
            let rest = trimmed.strip_prefix("<tg-math-block>").unwrap_or("");
            if let Some(end_pos) = rest.find("</tg-math-block>") {
                let expr = &rest[..end_pos];
                out.push(format!(
                    "<blockquote><code>{}</code></blockquote>",
                    esc(&latex_to_unicode(expr))
                ));
                i += 1;
                continue;
            }
            let mut buf: Vec<String> = Vec::new();
            if !rest.trim().is_empty() {
                buf.push(rest.trim().to_string());
            }
            let mut j = i + 1;
            while j < n {
                if let Some(end_pos) = lines[j].find("</tg-math-block>") {
                    let before = lines[j][..end_pos].trim();
                    if !before.is_empty() {
                        buf.push(before.to_string());
                    }
                    break;
                }
                buf.push(lines[j].to_string());
                j += 1;
            }
            out.push(format!(
                "<blockquote><code>{}</code></blockquote>",
                esc(&latex_to_unicode(&buf.join("\n")))
            ));
            i = (j + 1).min(n);
            continue;
        }

        // Strip `<tg-button-row>` and `<tg-button>` tags outside fences (real buttons go into reply_markup)
        let low_trim = trimmed.to_ascii_lowercase();
        if low_trim.starts_with("<tg-button-row") {
            let mut j = i;
            if !low_trim.contains("</tg-button-row>") {
                j += 1;
                while j < n && !lines[j].to_ascii_lowercase().contains("</tg-button-row>") {
                    j += 1;
                }
            }
            i = (j + 1).min(n);
            continue;
        }
        if low_trim.starts_with("<tg-button") && low_trim.ends_with("</tg-button>") {
            i += 1;
            continue;
        }

        // `<aside>...</aside>` block -> blockquote
        if low_trim.starts_with("<aside>") || low_trim.starts_with("<aside ") {
            if let Some(open_end) = line.find('>') {
                let after = &line[open_end + 1..];
                if let Some(close_pos) = after.to_ascii_lowercase().find("</aside>") {
                    let inner = after[..close_pos].trim();
                    out.push(format!("<blockquote>{}</blockquote>", inline(inner)));
                    i += 1;
                    continue;
                }
                let mut buf: Vec<String> = Vec::new();
                if !after.trim().is_empty() {
                    buf.push(inline(after.trim()));
                }
                let mut j = i + 1;
                while j < n {
                    if let Some(cp) = lines[j].to_ascii_lowercase().find("</aside>") {
                        let before = lines[j][..cp].trim();
                        if !before.is_empty() {
                            buf.push(inline(before));
                        }
                        break;
                    }
                    buf.push(inline(lines[j]));
                    j += 1;
                }
                let tag = if buf.len() > expand_quote_lines {
                    "<blockquote expandable>"
                } else {
                    "<blockquote>"
                };
                out.push(format!("{tag}{}</blockquote>", buf.join("\n")));
                i = (j + 1).min(n);
                continue;
            }
        }

        // HTML `<table>...</table>` -> monospace `<pre>`
        if low_trim.starts_with("<table") && (low_trim.starts_with("<table ") || low_trim.starts_with("<table>")) {
            let mut tbl_buf = vec![line];
            let mut j = i;
            if !low_trim.contains("</table>") {
                j += 1;
                while j < n {
                    tbl_buf.push(lines[j]);
                    if lines[j].to_ascii_lowercase().contains("</table>") {
                        break;
                    }
                    j += 1;
                }
            }
            let rendered = html_table_to_pre(&tbl_buf.join("\n"));
            if !rendered.is_empty() {
                out.push(format!("<pre>{}</pre>", esc(&rendered)));
            }
            i = (j + 1).min(n);
            continue;
        }

        if line.contains('|') && i + 1 < n && is_table_sep(lines[i + 1]) {
            let mut j = i + 2;
            while j < n && lines[j].contains('|') && !lines[j].trim().is_empty() {
                j += 1;
            }
            out.push(format!("<pre>{}</pre>", esc(&table_to_pre(&lines[i..j]))));
            i = j;
            continue;
        }

        if line.trim_start().starts_with('>') {
            let mut buf: Vec<String> = Vec::new();
            while i < n && lines[i].trim_start().starts_with('>') {
                buf.push(strip_quote_prefix(lines[i]));
                i += 1;
            }
            let body = buf
                .iter()
                .map(|b| inline(b))
                .collect::<Vec<_>>()
                .join("\n");
            let tag = if buf.len() > expand_quote_lines {
                "<blockquote expandable>"
            } else {
                "<blockquote>"
            };
            out.push(format!("{tag}{body}</blockquote>"));
            continue;
        }

        if let Some(dm) = RE_DETAILS.as_ref().and_then(|re| re.captures(line)) {
            let mut j = i + 1;
            let mut buf: Vec<&str> = Vec::new();
            while j < n && !lines[j].trim().starts_with("</details>") {
                buf.push(lines[j]);
                j += 1;
            }
            let mut title = dm
                .get(1)
                .map(|m| m.as_str())
                .filter(|s| !s.is_empty());
            if title.is_none() {
                if let Some(first_idx) = buf.iter().position(|l| !l.trim().is_empty()) {
                    if let Some(sm) = RE_SUMMARY_LINE
                        .as_ref()
                        .and_then(|re| re.captures(buf[first_idx]))
                    {
                        title = sm.get(1).map(|m| m.as_str()).filter(|s| !s.is_empty());
                        buf.remove(first_idx);
                    }
                }
            }
            out.push(format!("<b>{}</b>", inline(title.unwrap_or("Details"))));
            let body = render_details_body(&buf);
            out.push(format!("<blockquote expandable>{body}</blockquote>"));
            i = j + 1;
            continue;
        }

        if let Some(hm) = RE_HEADING.as_ref().and_then(|re| re.captures(line)) {
            let level = hm.get(1).map_or(1, |m| m.as_str().len());
            let txt = inline(hm.get(2).map_or("", |m| m.as_str()));
            if level > 1 {
                out.push(format!("<b>{txt}</b>"));
            } else {
                out.push(format!("<b><u>{txt}</u></b>"));
            }
            i += 1;
            continue;
        }

        if is_hr(line) {
            out.push("──────────".to_string());
            i += 1;
            continue;
        }

        if let Some(tm) = RE_TASK_LIST.as_ref().and_then(|re| re.captures(line)) {
            let indent = tm.get(1).map_or("", |m| m.as_str());
            let mark = tm.get(2).map_or("", |m| m.as_str());
            let rest = tm.get(3).map_or("", |m| m.as_str());
            let box_ch = if mark.eq_ignore_ascii_case("x") {
                "☑"
            } else {
                "☐"
            };
            out.push(format!("{indent}{box_ch} {}", inline(rest)));
            i += 1;
            continue;
        }

        if let Some(bm) = RE_BULLET_LIST.as_ref().and_then(|re| re.captures(line)) {
            let raw_indent = bm.get(1).map_or("", |m| m.as_str());
            let rest = bm.get(2).map_or("", |m| m.as_str());
            let spaces = raw_indent.replace('\t', "  ").chars().count() / 2;
            let indent = "  ".repeat(spaces);
            out.push(format!("{indent}• {}", inline(rest)));
            i += 1;
            continue;
        }

        if let Some(om) = RE_ORDERED_LIST.as_ref().and_then(|re| re.captures(line)) {
            let raw_indent = om.get(1).map_or("", |m| m.as_str());
            let num = om.get(2).map_or("", |m| m.as_str());
            let rest = om.get(3).map_or("", |m| m.as_str());
            let spaces = raw_indent.chars().count() / 2;
            let indent = "  ".repeat(spaces);
            out.push(format!("{indent}{num}. {}", inline(rest)));
            i += 1;
            continue;
        }

        out.push(inline(line));
        i += 1;
    }

    let joined = out.join("\n");
    collapse_triple_newlines(&joined).trim().to_string()
}

// ---------------------------------------------------------------- splitting

fn match_tag_token(s: &str) -> Option<usize> {
    if !s.starts_with('<') {
        return None;
    }
    let gt = s[1..].find('>')?;
    if gt == 0 {
        return None;
    }
    Some(1 + gt + 1)
}

fn match_entity_token(s: &str) -> Option<usize> {
    if !s.starts_with('&') {
        return None;
    }
    let mut len = 0usize;
    for (idx, ch) in s[1..].char_indices() {
        if ch == ';' {
            if len > 0 {
                return Some(1 + idx + 1);
            }
            return None;
        }
        if ch == '#' || ch.is_alphanumeric() || ch == '_' {
            len += 1;
        } else {
            return None;
        }
    }
    None
}

fn tokenize_html(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut plain_start = 0usize;
    let mut i = 0usize;
    let bytes = text.as_bytes();

    while i < bytes.len() {
        let tok_len = match bytes[i] {
            b'\n' => Some(1),
            b'<' => {
                // Keep `<tg-emoji ...>...</tg-emoji>` as one atomic indivisible token so
                // `split_html` never emits empty `<tg-emoji></tg-emoji>` or splits surrogate/ZWJ glyphs.
                if text[i..].starts_with("<tg-emoji") {
                    if let Some(close_rel) = text[i..].find("</tg-emoji>") {
                        Some(close_rel + "</tg-emoji>".len())
                    } else {
                        match_tag_token(&text[i..])
                    }
                } else {
                    match_tag_token(&text[i..])
                }
            }
            b'&' => match_entity_token(&text[i..]),
            _ => None,
        };
        if let Some(len) = tok_len {
            if i > plain_start {
                tokens.push(&text[plain_start..i]);
            }
            tokens.push(&text[i..i + len]);
            i += len;
            plain_start = i;
        } else {
            let ch_len = text[i..].chars().next().map_or(1, char::len_utf8);
            i += ch_len;
        }
    }
    if plain_start < bytes.len() {
        tokens.push(&text[plain_start..]);
    }
    tokens
}

fn has_non_ws_outside_tags(s: &str) -> bool {
    let mut rest = s;
    while !rest.is_empty() {
        let Some(lt) = rest.find('<') else {
            return rest.chars().any(|c| !c.is_whitespace());
        };
        if rest[..lt].chars().any(|c| !c.is_whitespace()) {
            return true;
        }
        let after_lt = &rest[lt + 1..];
        let Some(gt) = after_lt.find('>') else {
            return true;
        };
        if gt == 0 {
            return true;
        }
        rest = &after_lt[gt + 1..];
    }
    false
}

fn closing_u16(stack: &[(String, String)]) -> usize {
    stack
        .iter()
        .map(|(name, _)| 3 + utf16_len(name))
        .sum()
}

fn html_budget(stack: &[(String, String)], limit: usize) -> usize {
    limit.saturating_sub(closing_u16(stack) + 8)
}

fn flush_html_chunk(
    cur: &mut String,
    cur_u16: &mut usize,
    stack: &[(String, String)],
    chunks: &mut Vec<String>,
) -> bool {
    let prev_len = cur.len();
    let pushed = if has_non_ws_outside_tags(cur) {
        let mut out = String::with_capacity(cur.len() + stack.len() * 8);
        out.push_str(cur);
        for (name, _) in stack.iter().rev() {
            out.push_str("</");
            out.push_str(name);
            out.push('>');
        }
        chunks.push(out);
        true
    } else {
        false
    };
    cur.clear();
    for (_, open_tag) in stack {
        cur.push_str(open_tag);
    }
    *cur_u16 = utf16_len(cur);
    pushed || cur.len() != prev_len
}

/// Split Telegram HTML into chunks of `<= limit` UTF-16 code units, keeping tags balanced.
///
/// Prefers newline and space boundaries, never splits inside `<tag>` or `&entity;`,
/// and closes open tags at the end of each chunk before reopening them in the next.
pub fn split_html(text: &str, limit: usize) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    if utf16_len(text) <= limit {
        return vec![text.to_string()];
    }

    let tokens = tokenize_html(text);
    let mut chunks: Vec<String> = Vec::new();
    let mut stack: Vec<(String, String)> = Vec::new();
    let mut cur = String::new();
    let mut cur_u16 = 0usize;

    for mut tok in tokens {
        if let Some(m) = RE_HTML_TAG.as_ref().and_then(|re| re.captures(tok)) {
            let is_close = !m.get(1).map_or("", |c| c.as_str()).is_empty();
            let name = m.get(2).map_or("", |c| c.as_str()).to_lowercase();
            if is_close {
                cur.push_str(tok);
                cur_u16 += utf16_len(tok);
                if let Some(k) = stack.iter().rposition(|(n, _)| n == &name) {
                    stack.remove(k);
                }
            } else {
                let tok_u16 = utf16_len(tok);
                let name_u16 = utf16_len(&name);
                if cur_u16 + tok_u16 + closing_u16(&stack) + name_u16 + 12 > limit {
                    flush_html_chunk(&mut cur, &mut cur_u16, &stack, &mut chunks);
                }
                cur.push_str(tok);
                cur_u16 += tok_u16;
                if !tok.ends_with("/>") {
                    stack.push((name, tok.to_string()));
                }
            }
            continue;
        }

        let is_atomic_entity =
            tok.starts_with('&') && match_entity_token(tok) == Some(tok.len());
        let is_atomic_emoji = tok.starts_with("<tg-emoji") && tok.ends_with("</tg-emoji>");
        while cur_u16 + utf16_len(tok) > html_budget(&stack, limit) {
            let budget = html_budget(&stack, limit);
            let mut room = budget.saturating_sub(cur_u16);
            if is_atomic_entity || is_atomic_emoji || tok == "\n" || room < 1 {
                let progressed = flush_html_chunk(&mut cur, &mut cur_u16, &stack, &mut chunks);
                let budget2 = html_budget(&stack, limit);
                if cur_u16 + utf16_len(tok) <= budget2 {
                    break;
                }
                if !progressed {
                    if is_atomic_entity || is_atomic_emoji || tok == "\n" {
                        cur.push_str(tok);
                        cur_u16 += utf16_len(tok);
                        tok = "";
                        flush_html_chunk(&mut cur, &mut cur_u16, &stack, &mut chunks);
                        break;
                    }
                    let take = tok.chars().next().map_or(0, char::len_utf8);
                    if take == 0 {
                        break;
                    }
                    let piece = &tok[..take];
                    cur.push_str(piece);
                    cur_u16 += utf16_len(piece);
                    tok = &tok[take..];
                    flush_html_chunk(&mut cur, &mut cur_u16, &stack, &mut chunks);
                    continue;
                }
                room = budget2.saturating_sub(cur_u16);
            }

            let mut piece = cut_utf16(tok, room);
            if let Some(sp) = piece.rfind(' ') {
                if sp > piece.len() / 2 {
                    piece = &piece[..=sp];
                }
            }
            if piece.is_empty() {
                let progressed = flush_html_chunk(&mut cur, &mut cur_u16, &stack, &mut chunks);
                if progressed {
                    continue;
                }
                let take = tok.chars().next().map_or(0, char::len_utf8);
                if take == 0 {
                    break;
                }
                piece = &tok[..take];
            }
            cur.push_str(piece);
            cur_u16 += utf16_len(piece);
            tok = &tok[piece.len()..];
            flush_html_chunk(&mut cur, &mut cur_u16, &stack, &mut chunks);
        }

        if !tok.is_empty() {
            cur.push_str(tok);
            cur_u16 += utf16_len(tok);
            let budget = html_budget(&stack, limit);
            if tok == "\n" && cur_u16 * 5 > budget * 4 {
                flush_html_chunk(&mut cur, &mut cur_u16, &stack, &mut chunks);
            }
        }
    }

    flush_html_chunk(&mut cur, &mut cur_u16, &stack, &mut chunks);
    chunks
}

/// Split Markdown for Telegram Rich Messages on blank lines outside code fences, tables,
/// display math blocks, `<details>`, and `<tg-button-row>`.
///
/// `max_lines` is a conservative proxy for the 500-block limit.
pub fn split_markdown(md: &str, limit: usize, max_lines: usize) -> Vec<String> {
    let lines: Vec<&str> = md.split('\n').collect();
    let n = lines.len();
    let mut parts: Vec<String> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    let mut cur_len = 0usize;
    let mut in_fence: Option<(String, String)> = None;
    let mut in_math_block = false;
    let mut in_bracket_math = false;
    let mut in_details = false;
    let mut in_button_row = false;
    let mut in_table = false;

    for (idx, &line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let fm = RE_FENCE.as_ref().and_then(|re| re.captures(line));

        let starting_table = in_fence.is_none()
            && !in_table
            && line.contains('|')
            && idx + 1 < n
            && is_table_sep(lines[idx + 1]);
        if in_table && (!line.contains('|') || trimmed.is_empty()) {
            in_table = false;
        }

        let ln = utf16_len(line) + 1;
        let would_overflow = (cur_len + ln > limit || cur.len() >= max_lines) && !cur.is_empty();
        // Flush cleanly BEFORE starting a new table if keeping the whole table together might overflow
        // or when overflowing outside atomic blocks.
        if would_overflow {
            if let Some((ref fence, _)) = in_fence {
                cur.push(fence.clone());
            }
            parts.push(cur.join("\n").trim_matches('\n').to_string());
            if let Some((ref fence, ref lang)) = in_fence {
                let reopen = format!("{fence}{lang}");
                cur_len = utf16_len(&reopen) + 1;
                cur = vec![reopen];
            } else {
                cur = Vec::new();
                cur_len = 0;
            }
        } else if starting_table && !cur.is_empty() {
            // Peak ahead to see table byte/line footprint; if the table won't fit alongside `cur`, flush first so the table stays intact.
            let mut tbl_len = ln;
            let mut tbl_rows = 1usize;
            let mut j = idx + 1;
            while j < n && lines[j].contains('|') && !lines[j].trim().is_empty() {
                tbl_len += utf16_len(lines[j]) + 1;
                tbl_rows += 1;
                j += 1;
            }
            if tbl_len <= limit
                && tbl_rows <= max_lines
                && (cur_len + tbl_len > limit || cur.len() + tbl_rows > max_lines)
            {
                parts.push(cur.join("\n").trim_matches('\n').to_string());
                cur = Vec::new();
                cur_len = 0;
            }
        }

        cur.push(line.to_string());
        cur_len += ln;

        if let Some(caps) = fm {
            let f_str = caps.get(1).map_or("", |m| m.as_str());
            let l_str = caps.get(2).map_or("", |m| m.as_str());
            if let Some((ref active_fence, _)) = in_fence {
                if is_closing_fence(line, active_fence) {
                    in_fence = None;
                }
            } else {
                in_fence = Some((f_str.to_string(), l_str.to_string()));
            }
        } else if in_fence.is_none() {
            if starting_table {
                in_table = true;
            }
            if trimmed == "$$" || (trimmed.starts_with("$$") && !trimmed[2..].contains("$$")) {
                in_math_block = !in_math_block;
            } else if in_math_block && trimmed.contains("$$") {
                in_math_block = false;
            }
            if !in_bracket_math && trimmed.starts_with("\\[") && !trimmed.contains("\\]") {
                in_bracket_math = true;
            } else if in_bracket_math && trimmed.contains("\\]") {
                in_bracket_math = false;
            }
            let low_t = trimmed.to_ascii_lowercase();
            if low_t.starts_with("<details") && !low_t.contains("</details>") {
                in_details = true;
            } else if in_details && low_t.contains("</details>") {
                in_details = false;
            }
            if low_t.starts_with("<tg-button-row") && !low_t.contains("</tg-button-row>") {
                in_button_row = true;
            } else if in_button_row && low_t.contains("</tg-button-row>") {
                in_button_row = false;
            }
        }

        let in_atomic =
            in_fence.is_some() || in_math_block || in_bracket_math || in_details || in_button_row || in_table;
        if !in_atomic && trimmed.is_empty() && cur_len * 100 > limit * 85 {
            parts.push(cur.join("\n").trim_matches('\n').to_string());
            cur.clear();
            cur_len = 0;
        }
    }

    if !cur.is_empty() && !cur.join("\n").trim().is_empty() {
        parts.push(cur.join("\n").trim_matches('\n').to_string());
    }
    parts.into_iter().filter(|p| !p.trim().is_empty()).collect()
}

/// Apply `f` only outside inline `` `...` `` spans on a single line.
fn transform_outside_code_spans<F>(line: &str, mut f: F) -> String
where
    F: FnMut(&str) -> String,
{
    if !line.contains('`') {
        return f(line);
    }
    let Some(re) = RE_CODE_SPAN.as_ref() else {
        return f(line);
    };
    let mut out = String::with_capacity(line.len());
    let mut last = 0usize;
    for m in re.find_iter(line) {
        if m.start() > last {
            out.push_str(&f(&line[last..m.start()]));
        }
        out.push_str(m.as_str());
        last = m.end();
    }
    if last < line.len() {
        out.push_str(&f(&line[last..]));
    }
    out
}

/// Normalize Markdown for Telegram Rich Messages outside code fences/spans:
/// - `<tg-emoji emoji-id="ID">ALT</tg-emoji>` -> `![ALT](tg://emoji?id=ID)`
/// - `\(...\)` -> `$...$`, `\[...\]` -> `\n$$\n...\n$$\n`
/// - Ensures a blank line before GFM table headers when preceded immediately by non-table text.
pub fn normalize_rich_markdown(md: &str) -> String {
    let normalized = md.replace("\r\n", "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    let n = lines.len();
    let mut out: Vec<String> = Vec::with_capacity(n + 8);
    let mut in_fence: Option<String> = None;
    let mut i = 0usize;

    while i < n {
        let line = lines[i];
        if let Some(fm) = RE_FENCE.as_ref().and_then(|re| re.captures(line)) {
            let f_str = fm.get(1).map_or("", |m| m.as_str());
            if let Some(ref active) = in_fence {
                if is_closing_fence(line, active) {
                    in_fence = None;
                }
            } else {
                in_fence = Some(f_str.to_string());
            }
            out.push(line.to_string());
            i += 1;
            continue;
        }
        if in_fence.is_some() {
            out.push(line.to_string());
            i += 1;
            continue;
        }

        let trimmed = line.trim();
        // Multi-line or standalone `\[...\]` block
        if trimmed.starts_with("\\[") {
            let after = trimmed.strip_prefix("\\[").unwrap_or("");
            if let Some(end_pos) = after.find("\\]") {
                let inner = after[..end_pos].trim();
                let tail = after[end_pos + 2..].trim();
                if out.last().is_some_and(|l| !l.trim().is_empty()) {
                    out.push(String::new());
                }
                out.push("$$".to_string());
                if !inner.is_empty() {
                    out.push(inner.to_string());
                }
                out.push("$$".to_string());
                if !tail.is_empty() {
                    out.push(tail.to_string());
                }
                i += 1;
                continue;
            }
            if out.last().is_some_and(|l| !l.trim().is_empty()) {
                out.push(String::new());
            }
            out.push("$$".to_string());
            if !after.trim().is_empty() {
                out.push(after.trim().to_string());
            }
            let mut j = i + 1;
            while j < n {
                if let Some(end_pos) = lines[j].find("\\]") {
                    let before = lines[j][..end_pos].trim();
                    if !before.is_empty() {
                        out.push(before.to_string());
                    }
                    break;
                }
                out.push(lines[j].to_string());
                j += 1;
            }
            out.push("$$".to_string());
            i = (j + 1).min(n);
            continue;
        }

        // Ensure blank line before GFM table header
        if line.contains('|')
            && i + 1 < n
            && is_table_sep(lines[i + 1])
            && out.last().is_some_and(|prev| {
                let pt = prev.trim();
                !pt.is_empty() && !pt.starts_with('|')
            })
        {
            out.push(String::new());
        }

        let converted = transform_outside_code_spans(line, |seg| {
            let mut s = seg.to_string();
            if let Some(re) = RE_RAW_TG_EMOJI.as_ref() {
                s = re
                    .replace_all(&s, |caps: &Captures| {
                        let id = caps.get(1).map_or("", |m| m.as_str());
                        let alt = caps.get(2).map_or("", |m| m.as_str());
                        let alt_use = if alt.is_empty() { "⭐" } else { alt };
                        format!("![{alt_use}](tg://emoji?id={id})")
                    })
                    .into_owned();
            }
            if let Some(re) = RE_PAREN_MATH.as_ref() {
                s = re.replace_all(&s, "$$$1$$").into_owned();
            }
            // Inline `\[...\]` mid-sentence
            while let Some(open) = s.find("\\[") {
                if let Some(rel_close) = s[open + 2..].find("\\]") {
                    let close = open + 2 + rel_close;
                    let inner = s[open + 2..close].trim().to_string();
                    let rep = format!("$${inner}$$");
                    s.replace_range(open..close + 2, &rep);
                } else {
                    break;
                }
            }
            s
        });
        out.push(converted);
        i += 1;
    }

    out.join("\n")
}

/// Truncate `s` cleanly to at most `max_bytes` UTF-8 bytes without splitting codepoints.
pub fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn parse_tag_attrs(raw: &str) -> Vec<(String, String)> {
    let Some(re) = RE_ATTR_PAIR.as_ref() else {
        return Vec::new();
    };
    re.captures_iter(raw)
        .filter_map(|caps| {
            let k = caps.get(1)?.as_str().to_ascii_lowercase();
            let v = caps
                .get(2)
                .or_else(|| caps.get(3))
                .map_or("", |m| m.as_str())
                .to_string();
            Some((k, decode_basic_entities(&v)))
        })
        .collect()
}

fn attr_val<'a>(attrs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn normalize_callback_data<F>(raw: &str, map_cb: &mut F) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
{
    let cleaned: String = raw
        .chars()
        .filter_map(|c| {
            if matches!(c, '\n' | '\r' | '\t') {
                Some(' ')
            } else if c.is_control() {
                None
            } else {
                Some(c)
            }
        })
        .collect();
    let t = cleaned.trim();
    if t.is_empty() {
        return None;
    }
    let needs_map = t.len() > 64
        || esc_attr(t).len() > 64
        || (t.starts_with("ask:") && t.contains(['"', '&', '<', '>', '\'']));
    if !needs_map {
        return Some(t.to_string());
    }
    if let Some(short) = map_cb(t) {
        let st = short.trim();
        if !st.is_empty() && st.len() <= 64 && esc_attr(st).len() <= 64 {
            return Some(st.to_string());
        }
    }
    let mut cut = truncate_utf8_bytes(t, 64).trim();
    while esc_attr(cut).len() > 64 && !cut.is_empty() {
        let next_len = cut.len().saturating_sub(1);
        cut = truncate_utf8_bytes(cut, next_len).trim();
    }
    (!cut.is_empty()).then(|| cut.to_string())
}

fn sanitize_single_tg_button<F>(attrs_raw: &str, label_raw: &str, map_cb: &mut F) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
{
    let label = decode_basic_entities(label_raw).trim().to_string();
    if label.is_empty() {
        return None;
    }
    let attrs = parse_tag_attrs(attrs_raw);
    let url = attr_val(&attrs, "url");
    let data = attr_val(&attrs, "data");
    let copy_txt = attr_val(&attrs, "text");
    let style = attr_val(&attrs, "style").filter(|s| matches!(*s, "primary" | "success" | "danger"));
    let explicit_kind = attr_val(&attrs, "type").map(str::to_ascii_lowercase);
    let kind = explicit_kind.as_deref().unwrap_or_else(|| {
        if url.is_some() {
            "url"
        } else if copy_txt.is_some() && data.is_none() {
            "copy_text"
        } else {
            "callback_data"
        }
    });

    let mut out = String::from("<tg-button");
    match kind {
        "callback_data" => {
            let safe_data = normalize_callback_data(data?, map_cb)?;
            out.push_str(r#" type="callback_data""#);
            if let Some(st) = style {
                out.push_str(&format!(r#" style="{}""#, esc_attr(st)));
            }
            out.push_str(&format!(r#" data="{}""#, esc_attr(&safe_data)));
        }
        "url" => {
            let u = url?.trim();
            if !is_safe_url(u) {
                return None;
            }
            out.push_str(r#" type="url""#);
            if let Some(st) = style {
                out.push_str(&format!(r#" style="{}""#, esc_attr(st)));
            }
            out.push_str(&format!(r#" url="{}""#, esc_attr(u)));
        }
        "copy_text" => {
            let ct = copy_txt?.trim();
            if ct.is_empty() {
                return None;
            }
            let clamped = truncate_utf8_bytes(ct, 256);
            out.push_str(r#" type="copy_text""#);
            if let Some(st) = style {
                out.push_str(&format!(r#" style="{}""#, esc_attr(st)));
            }
            out.push_str(&format!(r#" text="{}""#, esc_attr(clamped)));
        }
        _ => return None,
    }
    out.push('>');
    out.push_str(&esc(&label));
    out.push_str("</tg-button>");
    Some(out)
}

fn button_struct_from_tag<F>(attrs_raw: &str, label_raw: &str, map_cb: &mut F) -> Option<InlineKeyboardButton>
where
    F: FnMut(&str) -> Option<String>,
{
    let label = decode_basic_entities(label_raw).trim().to_string();
    if label.is_empty() {
        return None;
    }
    let attrs = parse_tag_attrs(attrs_raw);
    let url = attr_val(&attrs, "url");
    let data = attr_val(&attrs, "data");
    let copy_txt = attr_val(&attrs, "text");
    let style = attr_val(&attrs, "style")
        .filter(|s| matches!(*s, "primary" | "success" | "danger"))
        .map(ToString::to_string);
    let explicit_kind = attr_val(&attrs, "type").map(str::to_ascii_lowercase);
    let kind = explicit_kind.as_deref().unwrap_or_else(|| {
        if url.is_some() {
            "url"
        } else if copy_txt.is_some() && data.is_none() {
            "copy_text"
        } else {
            "callback_data"
        }
    });
    match kind {
        "callback_data" => {
            let safe_data = normalize_callback_data(data?, map_cb)?;
            Some(InlineKeyboardButton {
                text: label,
                callback_data: Some(safe_data),
                style,
                ..Default::default()
            })
        }
        "url" => {
            let u = url?.trim();
            if !is_safe_url(u) {
                return None;
            }
            Some(InlineKeyboardButton {
                text: label,
                url: Some(u.to_string()),
                style,
                ..Default::default()
            })
        }
        "copy_text" => {
            let ct = copy_txt?.trim();
            if ct.is_empty() {
                return None;
            }
            Some(InlineKeyboardButton {
                text: label,
                copy_text: Some(CopyTextButton {
                    text: truncate_utf8_bytes(ct, 256).to_string(),
                }),
                style,
                ..Default::default()
            })
        }
        _ => None,
    }
}

/// Sanitize `<tg-button>` / `<tg-button-row>` markup inside Rich Markdown outside fenced code blocks:
/// enforces Telegram's 64-byte UTF-8 `callback_data` limit via `map_cb` or safe UTF-8 truncation,
/// validates URLs/labels, and drops empty rows so `sendRichMessage` never fails with `BUTTON_DATA_INVALID`.
pub fn sanitize_rich_buttons<F>(md: &str, mut map_cb: F) -> String
where
    F: FnMut(&str) -> Option<String>,
{
    if !md.contains("<tg-button") {
        return md.to_owned();
    }
    let Some(row_re) = RE_TG_BTN_ROW.as_ref() else {
        return md.to_owned();
    };
    let Some(btn_re) = RE_TG_BTN.as_ref() else {
        return md.to_owned();
    };
    process_outside_code_fences(md, |chunk| {
        let mut saved_rows: Vec<String> = Vec::new();
        let mut s = row_re
            .replace_all(chunk, |caps: &Captures| {
                let inner = caps.get(1).map_or("", |m| m.as_str());
                let btns: Vec<String> = btn_re
                    .captures_iter(inner)
                    .filter_map(|bc| {
                        sanitize_single_tg_button(
                            bc.get(1).map_or("", |m| m.as_str()),
                            bc.get(2).map_or("", |m| m.as_str()),
                            &mut map_cb,
                        )
                    })
                    .collect();
                if btns.is_empty() {
                    String::new()
                } else {
                    let row_html = format!("<tg-button-row>\n {}\n</tg-button-row>", btns.join("\n "));
                    let idx = saved_rows.len();
                    saved_rows.push(row_html);
                    format!("\u{E000}TGBROW_{idx}\u{E001}")
                }
            })
            .into_owned();
        // Sanitize any standalone `<tg-button>` outside `<tg-button-row>` even when rows are also present.
        if s.contains("<tg-button") {
            s = btn_re
                .replace_all(&s, |bc: &Captures| {
                    sanitize_single_tg_button(
                        bc.get(1).map_or("", |m| m.as_str()),
                        bc.get(2).map_or("", |m| m.as_str()),
                        &mut map_cb,
                    )
                    .unwrap_or_default()
                })
                .into_owned();
        }
        for (idx, row_html) in saved_rows.into_iter().enumerate() {
            let tok = format!("\u{E000}TGBROW_{idx}\u{E001}");
            s = s.replace(&tok, &row_html);
        }
        s
    })
}

/// Extract `<tg-button-row>` / `<tg-button>` tags outside fenced code blocks into real
/// Telegram [`InlineKeyboardMarkup`] rows and return the stripped Markdown text.
pub fn extract_tg_button_rows<F>(md: &str, mut map_cb: F) -> (String, Option<InlineKeyboardMarkup>)
where
    F: FnMut(&str) -> Option<String>,
{
    if !md.contains("<tg-button") {
        return (md.to_owned(), None);
    }
    let Some(row_re) = RE_TG_BTN_ROW.as_ref() else {
        return (md.to_owned(), None);
    };
    let Some(btn_re) = RE_TG_BTN.as_ref() else {
        return (md.to_owned(), None);
    };
    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
    let stripped = process_outside_code_fences(md, |chunk| {
        let after_rows = row_re
            .replace_all(chunk, |caps: &Captures| {
                let inner = caps.get(1).map_or("", |m| m.as_str());
                let btns: Vec<InlineKeyboardButton> = btn_re
                    .captures_iter(inner)
                    .filter_map(|bc| {
                        button_struct_from_tag(
                            bc.get(1).map_or("", |m| m.as_str()),
                            bc.get(2).map_or("", |m| m.as_str()),
                            &mut map_cb,
                        )
                    })
                    .collect();
                if !btns.is_empty() {
                    rows.push(btns);
                }
                String::new()
            })
            .into_owned();
        btn_re
            .replace_all(&after_rows, |bc: &Captures| {
                if let Some(btn) = button_struct_from_tag(
                    bc.get(1).map_or("", |m| m.as_str()),
                    bc.get(2).map_or("", |m| m.as_str()),
                    &mut map_cb,
                ) {
                    rows.push(vec![btn]);
                }
                String::new()
            })
            .into_owned()
    });
    let clean = collapse_triple_newlines(&stripped).trim().to_string();
    let mk = (!rows.is_empty()).then(|| InlineKeyboardMarkup::new(rows));
    (clean, mk)
}

fn process_outside_code_fences<F>(text: &str, mut f: F) -> String
where
    F: FnMut(&str) -> String,
{
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out: Vec<String> = Vec::new();
    let mut plain_buf: Vec<&str> = Vec::new();
    let mut in_fence: Option<String> = None;

    for line in lines {
        if let Some(fm) = RE_FENCE.as_ref().and_then(|re| re.captures(line)) {
            let f_str = fm.get(1).map_or("", |m| m.as_str());
            if let Some(ref active) = in_fence {
                if is_closing_fence(line, active) {
                    in_fence = None;
                }
                out.push(line.to_string());
                continue;
            } else {
                if !plain_buf.is_empty() {
                    out.push(f(&plain_buf.join("\n")));
                    plain_buf.clear();
                }
                in_fence = Some(f_str.to_string());
                out.push(line.to_string());
                continue;
            }
        }
        if in_fence.is_some() {
            out.push(line.to_string());
        } else {
            plain_buf.push(line);
        }
    }
    if !plain_buf.is_empty() {
        out.push(f(&plain_buf.join("\n")));
    }
    out.join("\n")
}

fn is_rtl_char(ch: char) -> bool {
    matches!(
        ch as u32,
        0x0590..=0x05FF
            | 0x0600..=0x06FF
            | 0x0750..=0x077F
            | 0x08A0..=0x08FF
            | 0xFB50..=0xFDFF
            | 0xFE70..=0xFEFF
    )
}

/// Heuristic: returns `true` when natural prose outside code/URLs/tags is predominantly RTL
/// (Persian, Arabic, Hebrew) so Telegram Rich Messages can enable `is_rtl: true`.
pub fn is_rtl_dominant(text: &str) -> bool {
    let mut rtl = 0usize;
    let mut ltr = 0usize;
    let mut in_fence: Option<String> = None;
    for line in text.lines() {
        if let Some(fm) = RE_FENCE.as_ref().and_then(|re| re.captures(line)) {
            let f_str = fm.get(1).map_or("", |m| m.as_str());
            if let Some(ref active) = in_fence {
                if is_closing_fence(line, active) {
                    in_fence = None;
                }
            } else {
                in_fence = Some(f_str.to_string());
            }
            continue;
        }
        if in_fence.is_some() {
            continue;
        }
        let mut in_code = false;
        let mut in_tag = false;
        for ch in line.chars() {
            if ch == '`' {
                in_code = !in_code;
                continue;
            }
            if in_code {
                continue;
            }
            if ch == '<' {
                in_tag = true;
                continue;
            }
            if ch == '>' && in_tag {
                in_tag = false;
                continue;
            }
            if in_tag {
                continue;
            }
            if is_rtl_char(ch) {
                rtl += 1;
            } else if ch.is_ascii_alphabetic() {
                ltr += 1;
            }
        }
    }
    rtl >= 4 && rtl * 3 >= ltr
}

/// Convert a Rich Markdown card into classic Telegram HTML clamped to `<= 4096` UTF-16 units.
pub fn rich_to_html_card(md: &str) -> String {
    let stripped = strip_md_custom_emoji(md);
    let html = md_to_html(&stripped, 6);
    if utf16_len(&html) <= TG_TEXT_LIMIT {
        return html;
    }
    let chunks = split_html(&html, 4000);
    chunks
        .into_iter()
        .next()
        .unwrap_or_else(|| cut_utf16(&html, TG_TEXT_LIMIT).to_string())
}

/// Render Markdown to plain unformatted text by stripping HTML tags and unescaping entities.
pub fn strip_md(md: &str) -> String {
    let html = md_to_html(md, 6);
    let plain = match RE_ALL_TAGS.as_ref() {
        Some(re) => re.replace_all(&html, "").into_owned(),
        None => html,
    };
    plain
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_html_balanced(html: &str) {
        let tag_re = Regex::new(r"<(/?)([a-zA-Z][\w-]*)[^>]*?(/?)>").unwrap();
        let mut stack: Vec<String> = Vec::new();
        for caps in tag_re.captures_iter(html) {
            let self_close = !caps.get(3).map_or("", |m| m.as_str()).is_empty();
            if self_close {
                continue;
            }
            let is_close = !caps.get(1).map_or("", |m| m.as_str()).is_empty();
            let name = caps.get(2).unwrap().as_str().to_string();
            if is_close {
                assert_eq!(
                    stack.pop().as_deref(),
                    Some(name.as_str()),
                    "unbalanced closing tag </{name}> in {html}"
                );
            } else {
                stack.push(name);
            }
        }
        assert!(stack.is_empty(), "unclosed tags {stack:?} in {html}");
    }

    #[test]
    fn test_escape() {
        assert_eq!(md_to_html("a < b & c > d", 6), "a &lt; b &amp; c &gt; d");
        assert_eq!(esc("<b>"), "&lt;b&gt;");
        assert_eq!(esc_attr(r#"a&b<"c">'d'"#), "a&amp;b&lt;&quot;c&quot;&gt;&#x27;d&#x27;");
    }

    #[test]
    fn test_inline_and_links() {
        let h = md_to_html(
            "**bold** *it* `x<y` ~~s~~ ==u== ||sp|| [l](https://t.me)",
            6,
        );
        assert!(h.contains("<b>bold</b>"));
        assert!(h.contains("<i>it</i>"));
        assert!(h.contains("<code>x&lt;y</code>"));
        assert!(h.contains("<s>s</s>"));
        assert!(h.contains("<u>u</u>"));
        assert!(h.contains("<tg-spoiler>sp</tg-spoiler>"));
        assert!(h.contains(r#"<a href="https://t.me">l</a>"#));
    }

    #[test]
    fn test_inline_lookaround_parity() {
        assert_eq!(
            md_to_html("a_b_c __foo__ foo_bar _bar_baz_ *a * b* **a** * b*", 6),
            "a_b_c <b>foo</b> foo_bar <i>bar_baz</i> <i>a * b</i> <b>a</b> * b*"
        );
        assert_eq!(
            md_to_html("***a*** **a *b* c** __a_b__ __a__b__", 6),
            "<b><i>a</i></b> <b>a <i>b</i> c</b> <b>a_b</b> <b>a__b</b>"
        );
        assert_eq!(
            md_to_html("`code *with* __md__` [lbl **b**](https://a.b?x=1&y=2)", 6),
            r#"<code>code *with* __md__</code> <a href="https://a.b?x=1&amp;y=2">lbl <b>b</b></a>"#
        );
        assert_eq!(md_to_html("___a___ __ foo __ _ foo _", 6), "<b><i>a</i></b> <b> foo </b> _ foo _");
        assert_eq!(md_to_html("2 * 3 * 4", 6), "2 * 3 * 4");
        assert_eq!(md_to_html("`a`_b_ **x**_y_", 6), "<code>a</code><i>b</i> <b>x</b><i>y</i>");
        assert_eq!(
            md_to_html("[`code`](https://t.me)", 6),
            r#"<a href="https://t.me"><code>code</code></a>"#
        );
    }

    #[test]
    fn test_unsafe_link_kept_as_text() {
        let h = md_to_html("[x](javascript:alert(1)) *ok*", 6);
        assert!(!h.contains("<a"));
        assert_eq!(h, "[x](javascript:alert(1)) <i>ok</i>");
    }

    #[test]
    fn test_code_block_lang_and_tilde() {
        let h = md_to_html("```python\nprint('<hi>')\n```", 6);
        assert_eq!(
            h,
            r#"<pre><code class="language-python">print('&lt;hi&gt;')</code></pre>"#
        );
        assert_eq!(md_to_html("~~~\n```\n~~~", 6), "<pre>```</pre>");
        assert_eq!(
            md_to_html("```rust\nfn main() {}", 6),
            r#"<pre><code class="language-rust">fn main() {}</code></pre>"#
        );
    }

    #[test]
    fn test_heading_list_quote_details_hr() {
        let h = md_to_html("# T\n## S\n- a\n- [x] done\n- [ ] todo\n1. one\n---\n> q", 6);
        assert!(h.contains("<b><u>T</u></b>"));
        assert!(h.contains("<b>S</b>"));
        assert!(h.contains("• a"));
        assert!(h.contains("☑ done"));
        assert!(h.contains("☐ todo"));
        assert!(h.contains("1. one"));
        assert!(h.contains("──────────"));
        assert!(h.contains("<blockquote>q</blockquote>"));

        assert_eq!(
            md_to_html("<details open>\nline 1\n</details>", 6),
            "<b>Details</b>\n<blockquote expandable>line 1</blockquote>"
        );
        assert_eq!(
            md_to_html("<details><summary>**Title**</summary>\n`code` & <tag>\n</details>", 6),
            "<b><b>Title</b></b>\n<blockquote expandable><code>code</code> &amp; &lt;tag&gt;</blockquote>"
        );
        assert_eq!(
            md_to_html("<details>\n<summary>Multi Line</summary>\nbody\n</details>", 6),
            "<b>Multi Line</b>\n<blockquote expandable>body</blockquote>"
        );
        // Custom emoji markdown, markdown images, allowed raw Telegram tags, and 4-backtick nested fences
        assert_eq!(
            md_to_html("![✅](tg://emoji?id=5427009714745517609) ![Logo](https://example.com/a.png)", 6),
            r#"<tg-emoji emoji-id="5427009714745517609">✅</tg-emoji> <a href="https://example.com/a.png">Logo</a>"#
        );
        assert_eq!(
            md_to_html(r#"<tg-emoji emoji-id="123">🔥</tg-emoji> <u>under</u> <tg-spoiler>secret</tg-spoiler>"#, 6),
            r#"<tg-emoji emoji-id="123">🔥</tg-emoji> <u>under</u> <tg-spoiler>secret</tg-spoiler>"#
        );
        let nested = "````markdown\n```python\nprint(1)\n```\n````";
        assert_eq!(
            md_to_html(nested, 6),
            "<pre><code class=\"language-markdown\">```python\nprint(1)\n```</code></pre>"
        );
        let split_nested = split_markdown(nested, 1000, 100);
        assert_eq!(split_nested.len(), 1);
        assert_eq!(split_nested[0], nested);
    }

    #[test]
    fn test_expandable_quote_threshold() {
        let q6: String = (0..6).map(|i| format!(">l{i}")).collect::<Vec<_>>().join("\n");
        assert!(md_to_html(&q6, 6).starts_with("<blockquote>"));

        let q10: String = (0..10).map(|i| format!(">l{i}")).collect::<Vec<_>>().join("\n");
        assert!(md_to_html(&q10, 6).starts_with("<blockquote expandable>"));
    }

    #[test]
    fn test_table_alignment_and_wide_chars() {
        let md = "| Name | Qty |\n|:--|--:|\n| apple | 3 |\n| kiwi | 12 |";
        let h = md_to_html(md, 6);
        assert!(h.starts_with("<pre>") && h.contains('│'));
        let lines: Vec<&str> = md.split('\n').collect();
        let t = table_to_pre(&lines);
        let rows: Vec<&str> = t.split('\n').collect();
        assert!(rows[2].ends_with(" 3"));
        assert!(rows[3].ends_with("12"));
        let char_lens: std::collections::HashSet<usize> =
            rows.iter().map(|r| r.chars().count()).collect();
        assert_eq!(char_lens.len(), 1);

        let wide = table_to_pre(&["|a|b|", "|-|-|", "|中文|x|", "|ab|y|"]);
        let wrows: Vec<&str> = wide.split('\n').collect();
        assert_eq!(wrows[2].chars().position(|c| c == '│'), Some(3));
        assert_eq!(wrows[3].chars().position(|c| c == '│'), Some(5));

        // Combining mark has width 0
        let comb = table_to_pre(&["|a|b|", "|-|-|", "|e\u{0301}|x|", "|fg|y|"]);
        let crows: Vec<&str> = comb.split('\n').collect();
        assert_eq!(crows[2].chars().position(|c| c == '│'), Some(4));
        assert_eq!(crows[3].chars().position(|c| c == '│'), Some(3));

        // Inline markdown stripped and escaped pipe preserved inside cells
        let inline_tbl = "| `a` | **b** | [c](https://x) | e\\|f |\n|:---|:---:|---:|---|\n| *hi* | ~~no~~ | x | y |";
        assert_eq!(
            md_to_html(inline_tbl, 6),
            "<pre>a  │ b  │ c │ e|f\n───┼────┼───┼────\nhi │ no │ x │ y</pre>"
        );
    }

    #[test]
    fn test_utf16_helpers() {
        assert_eq!(utf16_len("abc"), 3);
        assert_eq!(utf16_len("😀"), 2);
        assert_eq!(utf16_len("a😀b"), 4);
        assert_eq!(cut_utf16("a😀b", 0), "");
        assert_eq!(cut_utf16("a😀b", 1), "a");
        assert_eq!(cut_utf16("a😀b", 2), "a"); // never splits surrogate pair
        assert_eq!(cut_utf16("a😀b", 3), "a😀");
        assert_eq!(cut_utf16("a😀b", 4), "a😀b");
        assert_eq!(cut_utf16("a😀b", 99), "a😀b");
    }

    #[test]
    fn test_split_short_and_long_balanced() {
        assert_eq!(split_html("", DEFAULT_HTML_SPLIT_LIMIT), Vec::<String>::new());
        assert_eq!(split_html("hi", DEFAULT_HTML_SPLIT_LIMIT), vec!["hi"]);

        let body = format!(
            "<b>{}</b>\n<pre>{}</pre>",
            "word ".repeat(3000),
            "x = 1\n".repeat(2000)
        );
        let parts = split_html(&body, DEFAULT_HTML_SPLIT_LIMIT);
        assert!(parts.len() > 2);
        for p in &parts {
            assert!(utf16_len(p) <= TG_TEXT_LIMIT);
            assert_html_balanced(p);
        }
        let strip_re = Regex::new(r"<[^>]+>").unwrap();
        let joined: String = parts
            .iter()
            .map(|p| strip_re.replace_all(p, "").into_owned())
            .collect();
        assert_eq!(joined.matches("word").count(), 3000);
        assert_eq!(joined.matches("x = 1").count(), 2000);
    }

    #[test]
    fn test_split_entities_and_emoji_utf16() {
        let ent_body = "&lt;".repeat(3000);
        let ent_tail_re = Regex::new(r"&[a-zA-Z#0-9]*$").unwrap();
        for p in split_html(&ent_body, DEFAULT_HTML_SPLIT_LIMIT) {
            assert!(!ent_tail_re.is_match(&p), "broken entity in {p}");
            assert!(utf16_len(&p) <= TG_TEXT_LIMIT);
        }

        let emoji_body = "😀".repeat(5000);
        let parts = split_html(&emoji_body, DEFAULT_HTML_SPLIT_LIMIT);
        assert!(parts.len() >= 3);
        let total_emojis: usize = parts.iter().map(|p| p.matches('😀').count()).sum();
        assert_eq!(total_emojis, 5000);
        for p in parts {
            assert!(utf16_len(&p) <= TG_TEXT_LIMIT);
        }
    }

    #[test]
    fn test_split_html_tiny_limits_never_hang() {
        let p1 = split_html("a\nb\nc\nd\ne\nf", 8);
        assert!(!p1.is_empty());
        let p2 = split_html("😀😀😀😀😀", 6);
        assert!(!p2.is_empty());
        let p3 = split_html("<b>&amp;&lt;hello😀</b>", 10);
        assert!(!p3.is_empty());
        for p in p3 {
            assert_html_balanced(&p);
        }
    }

    #[test]
    fn test_split_markdown_fences() {
        let md = format!("```py\n{}```\n\ntext", "a=1\n".repeat(20000));
        let parts = split_markdown(&md, DEFAULT_MD_SPLIT_LIMIT, DEFAULT_MD_SPLIT_LINES);
        assert!(parts.len() >= 2);
        for p in &parts {
            assert_eq!(p.matches("```").count() % 2, 0);
            assert!(utf16_len(p) <= RICH_TEXT_LIMIT);
        }
    }

    #[test]
    fn test_mdv2_md_cell_md_text_strip_md_and_rich_card() {
        assert_eq!(escape_markdown_v2("a.b_c!\\d"), r"a\.b\_c\!\\d");
        assert_eq!(md_text("  hello\r\nworld  "), "hello  world");
        assert_eq!(md_cell("a|b`c\nd"), "a\\|b'c d");
        assert_eq!(md_cell("   \r\n "), "—");
        assert_eq!(md_cell_with_fallback("", "-"), "-");

        assert_eq!(strip_md("# Title\n**bold** `a < b & c`"), "Title\nbold a < b & c");

        let card_short = "### ![✅](tg://emoji?id=5427009714745517609) **Done**\n`ok`";
        assert_eq!(
            rich_to_html_card(card_short),
            "<b>✅ <b>Done</b></b>\n<code>ok</code>"
        );

        let card_long = format!("### ![✅](tg://emoji?id=1) Big\n\n{}", "word ".repeat(2000));
        let clamped = rich_to_html_card(&card_long);
        assert!(utf16_len(&clamped) <= TG_TEXT_LIMIT);
        assert_html_balanced(&clamped);
        assert!(!clamped.contains("tg://emoji"));
    }

    #[test]
    fn test_crlf_persian_and_edge_cases() {
        assert_eq!(md_to_html("", 6), "");
        assert_eq!(md_to_html("   \n\n\n  ", 6), "");
        assert_eq!(
            md_to_html("# سلام\r\n\r\n\r\n- **مورد** _اول_\r\n1) دوم", 6),
            "<b><u>سلام</u></b>\n\n• <b>مورد</b> <i>اول</i>\n1. دوم"
        );
        // Horizontal rules vs non-HR
        assert_eq!(md_to_html("- - -\n* * *\n___\n--\n-*-", 6), "──────────\n──────────\n──────────\n--\n-*-");
        // Split HTML with nested anchor + surrogate emojis
        let long_link = format!(
            r#"<a href="https://example.com">{}</a>"#,
            "سلام 😀 ".repeat(800)
        );
        let chunks = split_html(&long_link, DEFAULT_HTML_SPLIT_LIMIT);
        assert!(chunks.len() >= 2);
        for c in chunks {
            assert!(utf16_len(&c) <= TG_TEXT_LIMIT);
            assert_html_balanced(&c);
            assert!(c.starts_with(r#"<a href="https://example.com">"#));
        }
    }

    #[test]
    fn test_latex_currency_aside_html_table_buttons_and_rtl() {
        // 1. Inline & display LaTeX -> readable Unicode <code>, currency untouched
        let h_math = md_to_html(
            "Price is $5 and $10 (or $5-$10), while $a_1^2 + b_2^2 = c_n^2$ and \\(\\frac{x+1}{y} \\leq \\infty\\).\n\n$$\n\\sum_{i=1}^{n} x_i \\times \\alpha\n$$\n\n\\[\n\\sqrt{a^2 + b^2}\n\\]",
            6,
        );
        assert!(h_math.contains("Price is $5 and $10 (or $5-$10),"));
        assert!(h_math.contains("<code>a₁² + b₂² = cₙ²</code>"));
        assert!(h_math.contains("<code>(x+1)/y ≤ ∞</code>"));
        assert!(h_math.contains("<blockquote><code>∑ᵢ₌₁ⁿ xᵢ × α</code></blockquote>"));
        assert!(h_math.contains("<blockquote><code>√(a² + b²)</code></blockquote>"));

        // 2. HTML <table>, <aside>, <tg-time>, <tg-button-row> stripped in HTML fallback
        let h_extra = md_to_html(
            "<aside>Note: *ok*</aside>\n<table><tr><th>Col</th><th>Val</th></tr><tr><td>A</td><td>12</td></tr></table>\n<tg-time unix=\"1700000000\" format=\"r\">soon</tg-time>\n<tg-button-row>\n<tg-button type=\"callback_data\" data=\"ask:go\">Go</tg-button>\n</tg-button-row>",
            6,
        );
        assert!(h_extra.contains("<blockquote>Note: <i>ok</i></blockquote>"));
        assert!(h_extra.contains("<pre>Col │ Val\n────┼────\nA   │ 12</pre>"));
        assert!(h_extra.contains(r#"<tg-time unix="1700000000" format="r">soon</tg-time>"#));
        assert!(!h_extra.contains("<tg-button"));

        // 3. normalize_rich_markdown converts \(\) & \[\] & <tg-emoji> outside code fences/spans, inserts blank line before table
        let norm = normalize_rich_markdown(
            "سلام:\n| A | B |\n|---|---|\n| <tg-emoji emoji-id=\"123\">✅</tg-emoji> | ok |\n\\(E=mc^2\\)\n`\\(literal\\)`\n\\[\nx^2\n\\]",
        );
        assert!(norm.contains("سلام:\n\n| A | B |"));
        assert!(norm.contains("![✅](tg://emoji?id=123)"));
        assert!(norm.contains("$E=mc^2$\n`\\(literal\\)`"));
        assert!(norm.contains("$$\nx^2\n$$"));

        // 4. sanitize_rich_buttons + extract_tg_button_rows handle >64B Persian callback_data safely
        let persian_long = "ask:لطفاً گزارش کامل مصرف هفتگی و سلامت اکانت‌ها را با جزئیات کامل نمایش بده";
        assert!(persian_long.len() > 64);
        let raw_btns = format!(
            "گزینه:\n<tg-button-row>\n<tg-button type=\"callback_data\" style=\"primary\" data=\"{persian_long}\">گزارش</tg-button>\n<tg-button type=\"url\" url=\"https://example.com\">لینک</tg-button>\n</tg-button-row>"
        );
        let sanitized = sanitize_rich_buttons(&raw_btns, |_| Some("askr:abc123".to_string()));
        assert!(sanitized.contains(r#"data="askr:abc123""#));
        let (stripped, mk) = extract_tg_button_rows(&raw_btns, |_| Some("askr:abc123".to_string()));
        assert!(!stripped.contains("<tg-button"));
        let kb = mk.unwrap();
        assert_eq!(kb.inline_keyboard[0][0].callback_data.as_deref(), Some("askr:abc123"));
        assert_eq!(kb.inline_keyboard[0][1].url.as_deref(), Some("https://example.com"));

        // Without custom mapper, fallback truncates safely <= 64 UTF-8 bytes without panicking
        let clamped = sanitize_rich_buttons(&raw_btns, |_| None);
        assert!(!clamped.contains(persian_long));

        // 5. split_markdown never slices mid-table
        let tbl_md = format!(
            "{}\n\n| K | V |\n|---|---|\n| a | 1 |\n| b | 2 |",
            "x".repeat(80)
        );
        let chunks = split_markdown(&tbl_md, 100, 20);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[1].starts_with("| K | V |\n|---|---|\n| a | 1 |\n| b | 2 |"));

        // 6. RTL detector skips code fences/inline tags
        assert!(is_rtl_dominant("سلام دنیا `code_here` این متن فارسی است."));
        assert!(!is_rtl_dominant("Hello world, this is English prose."));

        // 7. Mixed <tg-button-row> + standalone <tg-button> and control-char / quote callback_data
        let mixed = format!(
            "<tg-button-row>\n<tg-button type=\"callback_data\" data=\"ask:run &amp; verify\nnow\">Run</tg-button>\n</tg-button-row>\n<tg-button type=\"callback_data\" data=\"{persian_long}\">Extra</tg-button>"
        );
        let san_mixed = sanitize_rich_buttons(&mixed, |raw| {
            if raw.contains('&') {
                Some("askr:111111111111".to_string())
            } else {
                Some("askr:222222222222".to_string())
            }
        });
        assert!(san_mixed.contains(r#"data="askr:111111111111""#));
        assert!(san_mixed.contains(r#"data="askr:222222222222""#));
        assert!(!san_mixed.contains('\u{E000}'));
        assert!(!san_mixed.contains(persian_long));
    }
}
