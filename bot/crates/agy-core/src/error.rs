//! Modern typed error taxonomy for the Antigravity Telegram bridge.

use thiserror::Error;

/// Unified result alias across all bridge crates.
pub type Result<T> = std::result::Result<T, BridgeError>;

/// Domain-specific error type with explicit retryability & HTTP/Telegram status mapping.
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("authentication / ACL error: {0}")]
    Auth(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("payload too large ({actual} bytes > {limit} bytes)")]
    PayloadTooLarge { actual: usize, limit: usize },

    #[error("I/O error at {context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON serialization/parsing error ({context}): {source}")]
    Json {
        context: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("network transport error: {0}")]
    Network(String),

    #[error("Telegram rate limited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64, message: String },

    #[error("Telegram API error ({code}): {message}")]
    BotApi {
        code: u16,
        message: String,
        retryable: bool,
    },

    #[error("process / engine error ({0}): {1}")]
    Process(String, String),

    #[error("MCP tool error ({server}:{tool}): {message}")]
    Mcp {
        server: String,
        tool: String,
        message: String,
    },

    #[error("cron scheduler error: {0}")]
    Cron(String),

    #[error("updater error: {0}")]
    Updater(String),

    #[error("internal lock or channel failure: {0}")]
    Internal(String),
}

impl BridgeError {
    /// Wrap any `std::io::Error` with contextual path/operation description.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Wrap any `serde_json::Error` with contextual payload/file description.
    pub fn json(context: impl Into<String>, source: serde_json::Error) -> Self {
        Self::Json {
            context: context.into(),
            source,
        }
    }

    /// Whether the error is transient and eligible for jittered backoff retry.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network(_) | Self::RateLimited { .. } => true,
            Self::BotApi { retryable, .. } => *retryable,
            _ => false,
        }
    }

    /// Whether Telegram rejected a Premium custom emoji, button icon, or effect.
    pub fn looks_like_premium_rejection(&self) -> bool {
        match self {
            Self::BotApi { message, .. } => {
                let low = message.to_ascii_lowercase();
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
            _ => false,
        }
    }

    /// Whether Telegram indicates chat is unavailable/blocked and should not retry.
    pub fn is_chat_unavailable(&self) -> bool {
        match self {
            Self::BotApi { code, message, .. } => {
                if *code == 403 {
                    return true;
                }
                let low = message.to_ascii_lowercase();
                low.contains("chat not found") || low.contains("bot was blocked")
            }
            _ => false,
        }
    }

    /// Whether Telegram reports message text/markup unchanged on edit.
    pub fn is_not_modified(&self) -> bool {
        matches!(self, Self::BotApi { message, .. } if message.to_ascii_lowercase().contains("not modified"))
    }
}
