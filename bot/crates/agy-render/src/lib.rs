//! Markdown-to-Telegram HTML rendering, UTF-16 chunking, and Premium UI helpers.

pub mod markdown;
pub mod premium;

pub use markdown::{
    cut_utf16, esc, esc_attr, escape_markdown_v2, extract_tg_button_rows, is_rtl_dominant,
    is_table_sep, latex_to_unicode, md_cell, md_cell_with_fallback, md_text, md_to_html,
    normalize_rich_markdown, rich_to_html_card, sanitize_rich_buttons, split_html,
    split_markdown, strip_md, table_to_pre, truncate_utf8_bytes, utf16_len,
    DEFAULT_HTML_SPLIT_LIMIT, DEFAULT_MD_SPLIT_LIMIT, DEFAULT_MD_SPLIT_LINES, RICH_BLOCK_LIMIT,
    RICH_TEXT_LIMIT, TG_CAPTION_LIMIT, TG_TEXT_LIMIT,
};
pub use premium::{
    default_id, effect_id, fallback_emoji, is_premium_error, load_emoji_overrides,
    looks_premium_error, strip_custom_emoji, strip_icons, strip_md_custom_emoji, PremiumState,
    DEFAULT_IDS, EFFECTS, FALLBACK,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
