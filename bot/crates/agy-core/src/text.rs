//! Shared text truncation, wall-clock timestamp, and serde default helpers.
//!
//! Centralizes small utilities previously duplicated across `agy-core`, `agy-bot`,
//! `agy-ext`, `agy-net`, `agy-widgets`, and `agy-mcp-gateway`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Truncate `s` to at most `max_chars` Unicode scalar values without appending a suffix.
pub fn truncate_chars(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
    }
}

/// Truncate `s` to at most `max_chars` Unicode scalar values, appending `…` when clipped.
pub fn clip_ellipsis(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => format!("{}…", &s[..idx]),
        None => s.to_string(),
    }
}

/// Current UNIX wall-clock timestamp in whole seconds (`i64`).
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Current UNIX wall-clock timestamp in fractional seconds (`f64`).
pub fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Serde default helper returning `true`.
pub fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_and_clip_handle_utf8_and_persian() {
        assert_eq!(truncate_chars("سلام دنیا", 4), "سلام");
        assert_eq!(truncate_chars("abc", 10), "abc");
        assert_eq!(clip_ellipsis("سلام دنیا", 4), "سلام…");
        assert_eq!(clip_ellipsis("ok", 2), "ok");
        assert!(now_unix() > 1_700_000_000);
        assert!(now_secs() > 1_700_000_000.0);
        assert!(default_true());
    }
}
