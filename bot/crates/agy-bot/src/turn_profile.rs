//! Phase 4 dynamic turn profile classifier (`lite` / `standard` / `full`).
//!
//! Never disables or removes MCP servers, skills, or `.md` rules; instead optimizes
//! reasoning effort and print-mode slash expansion on simple short conversational turns
//! so weekly quota stretches further while complex coding/research keeps full capacity.

/// Complexity tier inferred locally in Rust (zero AI tokens) for an incoming user prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnProfile {
    /// Short, pure conversational Q&A / greeting / explanation with no paths, URLs, or tool cues.
    Lite,
    /// Normal technical questions, single-file lookups, or moderate tasks.
    Standard,
    /// Multi-step engineering, architecture, audits, attachments, or explicit MCP/skill/ops work.
    Full,
}

impl TurnProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lite => "lite",
            Self::Standard => "standard",
            Self::Full => "full",
        }
    }
}

const FULL_KEYWORDS: &[&str] = &[
    // English engineering / tool / ops cues (stem-matched for common inflections)
    "refactor", "architect", "architecture", "audit", "debug", "deploy", "migration",
    "benchmark", "clippy", "cargo", "pytest", "systemd", "systemctl", "docker", "nginx",
    "caddy", "webhook", "oauth", "proxy", "proxies", "mcp", "skill", "skillhub",
    "openhands", "venice", "grok", "uncensored", "execute_code", "multi_edit",
    "graphify", "gortex", "subagent", "workflow", "parallel", "failover", "security",
    "ddos", "database", "sql", "kubernetes", "terraform", "pipeline",
    "bug", "error", "crash", "panic", "timeout", "quota", "token", "context", "prompt",
    "config", "build", "test", "fix", "patch", "server", "bot", "script", "cache", "memory",
    // Persian engineering / ops cues (stem-matched for clitics, plurals & ZWNJ)
    "فاز", "معماری", "ریفکتور", "دیباگ", "ممیزی", "سرویس", "پروکسی", "اکانت",
    "دپلوی", "تست", "بیلد", "امنیت", "اسکیل", "فایل", "سورس", "کد", "سرور",
    "دیتابیس", "پچ", "باگ", "لاگ", "گیت", "ربات", "توکن", "کانتکس", "پرامپت",
    "ارور", "خطا", "فیکس", "بهینه", "اپدیت", "آپدیت", "ریستارت", "کانفیگ", "اسکریپت",
];

const NON_LITE_CUES: &[&str] = &[
    "http://", "https://", "```", "/root/", "/etc/", "/var/", "/opt/", "/tmp/",
    ".rs", ".py", ".ts", ".js", ".go", ".sh", ".json", ".toml", ".yaml", ".yml", ".md", ".env",
    "git ", "grep", "curl", "ssh", "journalctl", "tar ", "chmod", "chown",
    "بنویس", "اصلاح", "تغییر", "اجرا", "بساز", "بگرد", "جستجو", "سرچ", "دانلود", "آپلود",
    "بررسی", "چک کن", "نصب", "حذف", "ویرایش", "بکاپ", "گزارش", "تحلیل",
    "write ", "edit ", "fix ", "create ", "run ", "check ", "search ", "install ", "delete ",
    "analyze", "inspect", "explain this code", "read ", "update", "logging",
];

/// Allowed English inflection suffixes after a matched stem.
const EN_SUFFIXES: &[&str] = &[
    "s", "es", "ed", "ing", "ging", "er", "ers", "ion", "ions",
];

/// Allowed Persian clitic / plural / compound suffixes after a matched stem.
const FA_SUFFIXES: &[&str] = &[
    "هاش", "هام", "هات", "های", "هایش", "هایم", "هایت", "ها",
    "مان", "تان", "شان", "نویسی", "ش", "م", "ت", "ی", "و",
];

/// Persian suffixes that require a >=3-char stem (prevents false positives like `کد` matching `کدام`).
const FA_LONG_STEM_SUFFIXES: &[&str] = &["ام", "ات", "اش"];

fn is_word_boundary_char(c: char) -> bool {
    // Treat ZWNJ (`\u{200c}`) as a word boundary so Persian plural/clitic forms (`فایل‌ها`) match cleanly.
    !c.is_alphanumeric() && c != '_' && c != '-'
}

fn suffix_matches_boundary(tail: &str, cue_char_len: usize, is_ascii: bool) -> bool {
    if tail.is_empty() || tail.chars().next().is_some_and(is_word_boundary_char) {
        return true;
    }
    if is_ascii {
        for suf in EN_SUFFIXES {
            if let Some(rest) = tail.strip_prefix(suf) {
                if rest.is_empty() || rest.chars().next().is_some_and(is_word_boundary_char) {
                    return true;
                }
            }
        }
        return false;
    }
    for suf in FA_SUFFIXES {
        if let Some(rest) = tail.strip_prefix(suf) {
            if rest.is_empty() || rest.chars().next().is_some_and(is_word_boundary_char) {
                return true;
            }
        }
    }
    if cue_char_len >= 3 {
        for suf in FA_LONG_STEM_SUFFIXES {
            if let Some(rest) = tail.strip_prefix(suf) {
                if rest.is_empty() || rest.chars().next().is_some_and(is_word_boundary_char) {
                    return true;
                }
            }
        }
    }
    false
}

fn has_cue(low: &str, raw_cue: &str) -> bool {
    let cue = raw_cue.trim();
    if cue.is_empty() {
        return false;
    }
    let needs_boundary = cue
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-');
    if !needs_boundary {
        return low.contains(cue);
    }
    let cue_chars = cue.chars().count();
    let is_ascii = cue.is_ascii();
    let mut start = 0usize;
    while let Some(pos) = low[start..].find(cue) {
        let abs = start + pos;
        let left_ok = abs == 0
            || low[..abs]
                .chars()
                .next_back()
                .is_none_or(is_word_boundary_char);
        let right = abs + cue.len();
        let right_ok = right >= low.len()
            || suffix_matches_boundary(&low[right..], cue_chars, is_ascii);
        if left_ok && right_ok {
            return true;
        }
        start = abs + cue.chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Classify an incoming prompt into [`TurnProfile`] locally in <10µs (zero AI tokens).
pub fn classify_turn_profile(
    text: &str,
    has_attachments: bool,
    is_isolated: bool,
) -> TurnProfile {
    let trimmed = text.trim();
    if has_attachments || trimmed.chars().count() > 600 || trimmed.contains("```") {
        return TurnProfile::Full;
    }
    let low = trimmed.to_ascii_lowercase();
    if FULL_KEYWORDS.iter().any(|kw| has_cue(&low, kw)) {
        return TurnProfile::Full;
    }
    if is_isolated || trimmed.is_empty() {
        return TurnProfile::Standard;
    }
    if trimmed.chars().count() > 220 || trimmed.lines().count() > 3 {
        return TurnProfile::Standard;
    }
    if NON_LITE_CUES.iter().any(|cue| has_cue(&low, cue)) {
        return TurnProfile::Standard;
    }
    TurnProfile::Lite
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_lite_standard_and_full_accurately() {
        assert_eq!(classify_turn_profile("سلام چطوری؟", false, false), TurnProfile::Lite);
        assert_eq!(
            classify_turn_profile("What is the difference between TCP and UDP?", false, false),
            TurnProfile::Lite
        );
        assert_eq!(
            classify_turn_profile("ترجمه کن: Hello world", false, false),
            TurnProfile::Lite
        );

        assert_eq!(
            classify_turn_profile("Check /etc/caddy/Caddyfile please", false, false),
            TurnProfile::Full
        );
        assert_eq!(
            classify_turn_profile("فاز ۴ را با دقت اجرا و تست کن", false, false),
            TurnProfile::Full
        );
        assert_eq!(
            classify_turn_profile("hi", true, false),
            TurnProfile::Full
        );
        assert_eq!(
            classify_turn_profile("edit main.rs to add logging", false, false),
            TurnProfile::Standard
        );
        assert_eq!(
            classify_turn_profile("سلام", false, true),
            TurnProfile::Standard
        );
        assert_eq!(
            classify_turn_profile("کدام مدل بهتر است؟", false, false),
            TurnProfile::Lite
        );
        assert_eq!(
            classify_turn_profile("please read, summarize this", false, false),
            TurnProfile::Standard
        );
    }

    #[test]
    fn classifies_persian_suffixes_and_english_inflections_accurately() {
        for p in [
            "فایل‌ها رو مرتب کن و ارور ربات رو فیکس کن",
            "باگش رو پیدا کن و تستش کن",
            "کدهاش خیلی کند شده، بهینه‌اش کن",
            "ربات چرا توکن زیاد مصرف میکنه؟",
            "سرورم داون شده، سرویسش بالا نمیاد",
            "فیکسش کن، پرامپتش مشکل داره",
            "debugging the broken tests and fixing errors",
            "can you check the configs and scripts?",
            "check out why the bot crashes on timeout",
        ] {
            assert_eq!(
                classify_turn_profile(p, false, false),
                TurnProfile::Full,
                "expected Full for technical prompt: {p}"
            );
        }
        // Control: Persian interrogative `کدام` must NOT falsely match stem `کد`
        assert_eq!(
            classify_turn_profile("کدام کتاب بهتر است؟", false, false),
            TurnProfile::Lite
        );
    }
}
