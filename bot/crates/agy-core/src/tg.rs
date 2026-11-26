//! Telegram Bot API 10.4 pure wire data types (zero runtime/network dependencies).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Standard Bot API envelope `{"ok": true, "result": ...}`.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiResponse<T> {
    pub ok: bool,
    pub result: Option<T>,
    pub error_code: Option<u16>,
    pub description: Option<String>,
    pub parameters: Option<ResponseParameters>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ResponseParameters {
    pub migrate_to_chat_id: Option<i64>,
    pub retry_after: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct User {
    pub id: i64,
    #[serde(default)]
    pub is_bot: bool,
    #[serde(default)]
    pub first_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language_code: Option<String>,
    #[serde(default)]
    pub is_premium: Option<bool>,
}

impl User {
    /// Human display label matching Python `_user_label`.
    pub fn display_label(&self) -> String {
        let full = match &self.last_name {
            Some(ln) if !ln.trim().is_empty() => format!("{} {}", self.first_name, ln).trim().to_string(),
            _ => self.first_name.trim().to_string(),
        };
        match &self.username {
            Some(un) if !un.is_empty() && !full.is_empty() => format!("{full} (@{un})"),
            Some(un) if !un.is_empty() => format!("@{un}"),
            _ if !full.is_empty() => full,
            _ => self.id.to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Chat {
    pub id: i64,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LinkPreviewOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WebAppInfo {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CopyTextButton {
    pub text: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct InlineKeyboardButton {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_app: Option<WebAppInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copy_text: Option<CopyTextButton>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_custom_emoji_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub switch_inline_query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub switch_inline_query_current_chat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

impl InlineKeyboardButton {
    pub fn callback(text: impl Into<String>, data: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            callback_data: Some(data.into()),
            ..Default::default()
        }
    }

    pub fn web_app_btn(text: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            web_app: Some(WebAppInfo { url: url.into() }),
            ..Default::default()
        }
    }

    pub fn url_btn(text: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            url: Some(url.into()),
            ..Default::default()
        }
    }

    pub fn with_style(mut self, style: impl Into<String>) -> Self {
        self.style = Some(style.into());
        self
    }

    pub fn with_icon(mut self, cid: impl Into<String>) -> Self {
        self.icon_custom_emoji_id = Some(cid.into());
        self
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct InlineKeyboardMarkup {
    pub inline_keyboard: Vec<Vec<InlineKeyboardButton>>,
}

impl InlineKeyboardMarkup {
    pub fn new(rows: Vec<Vec<InlineKeyboardButton>>) -> Self {
        Self {
            inline_keyboard: rows.into_iter().filter(|r| !r.is_empty()).collect(),
        }
    }

    pub fn has_custom_icons(&self) -> bool {
        self.inline_keyboard
            .iter()
            .flatten()
            .any(|b| b.icon_custom_emoji_id.is_some())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct InputRichMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_rtl: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_entity_detection: Option<bool>,
}

impl InputRichMessage {
    pub fn markdown(md: impl Into<String>) -> Self {
        Self {
            markdown: Some(md.into()),
            ..Default::default()
        }
    }

    pub fn markdown_with_rtl(md: impl Into<String>, rtl: bool) -> Self {
        Self {
            markdown: Some(md.into()),
            is_rtl: rtl.then_some(true),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessageEntity {
    #[serde(rename = "type")]
    pub kind: String,
    pub offset: i64,
    pub length: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_emoji_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReplyParameters {
    pub message_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PhotoSize {
    pub file_id: String,
    pub file_unique_id: String,
    #[serde(default)]
    pub file_size: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Document {
    pub file_id: String,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub file_size: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MediaFile {
    pub file_id: String,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub file_size: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Sticker {
    pub file_id: String,
    #[serde(default)]
    pub is_animated: bool,
    #[serde(default)]
    pub is_video: bool,
    #[serde(default)]
    pub file_size: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Widget {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub public_data: Option<String>,
    #[serde(default)]
    pub chat_data: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    pub message_id: i64,
    #[serde(rename = "from", default)]
    pub from_user: Option<User>,
    pub chat: Chat,
    #[serde(default)]
    pub message_thread_id: Option<i64>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub caption: Option<String>,
    #[serde(default)]
    pub entities: Option<Vec<MessageEntity>>,
    #[serde(default)]
    pub effect_id: Option<String>,
    #[serde(default)]
    pub reply_to_message: Option<Box<Message>>,
    #[serde(default)]
    pub photo: Option<Vec<PhotoSize>>,
    #[serde(default)]
    pub document: Option<Document>,
    #[serde(default)]
    pub video: Option<MediaFile>,
    #[serde(default)]
    pub audio: Option<MediaFile>,
    #[serde(default)]
    pub voice: Option<MediaFile>,
    #[serde(default)]
    pub animation: Option<MediaFile>,
    #[serde(default)]
    pub video_note: Option<MediaFile>,
    #[serde(default)]
    pub sticker: Option<Sticker>,
    #[serde(default)]
    pub widget: Option<Widget>,
    /// Bot API 7.2+: set on messages received/sent through a business connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub business_connection_id: Option<String>,
    /// Bot API 7.2+: the business bot that sent this message on behalf of the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_business_bot: Option<User>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CallbackQuery {
    pub id: String,
    #[serde(rename = "from")]
    pub from_user: User,
    #[serde(default)]
    pub message: Option<Message>,
    #[serde(default)]
    pub inline_message_id: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TonWalletCard {
    pub address: String,
    #[serde(default)]
    pub amount: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WidgetQueryWallet {
    pub address: String,
    #[serde(default)]
    pub amount: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WidgetQueryType {
    Data {
        #[serde(default)]
        wallet_card: Option<TonWalletCard>,
    },
    SignData {
        wallet: WidgetQueryWallet,
        sign_data: String,
    },
    SentTransaction {
        wallet: WidgetQueryWallet,
        msg_hash: String,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WidgetQuery {
    pub id: String,
    #[serde(rename = "from")]
    pub from_user: User,
    #[serde(default)]
    pub chat: Option<Chat>,
    #[serde(default)]
    pub chat_type: Option<String>,
    #[serde(default)]
    pub message_id: Option<i64>,
    #[serde(default)]
    pub inline_message_id: Option<String>,
    #[serde(default)]
    pub widget_id: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(rename = "type")]
    pub kind: WidgetQueryType,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SharedWidgetQuery {
    pub id: String,
    #[serde(rename = "from")]
    pub from_user: User,
    pub widget_id: String,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(rename = "type")]
    pub kind: WidgetQueryType,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InlineQuery {
    pub id: String,
    #[serde(rename = "from")]
    pub from_user: User,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub chat_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessageGenerationStopped {
    pub chat: Chat,
    pub draft_id: i64,
    #[serde(default)]
    pub message_thread_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Update {
    pub update_id: i64,
    #[serde(default)]
    pub message: Option<Message>,
    #[serde(default)]
    pub callback_query: Option<CallbackQuery>,
    #[serde(default)]
    pub widget_query: Option<WidgetQuery>,
    #[serde(default)]
    pub shared_widget_query: Option<SharedWidgetQuery>,
    #[serde(default)]
    pub inline_query: Option<InlineQuery>,
    #[serde(default)]
    pub stopped_message_generation: Option<MessageGenerationStopped>,
    /// Business (Secretary Mode) updates, flattened from the top-level Update object.
    #[serde(flatten)]
    pub business: BusinessUpdate,
}

/// Bot API 9.0 `BusinessBotRights` (all optional `True` flags).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct BusinessBotRights {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub can_reply: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub can_read_messages: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub can_delete_sent_messages: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub can_delete_all_messages: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub can_edit_name: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub can_edit_bio: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub can_edit_profile_photo: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub can_edit_username: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub can_view_gifts_and_stars: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub can_manage_stories: bool,
}

/// Bot API `BusinessConnection`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BusinessConnection {
    pub id: String,
    pub user: User,
    pub user_chat_id: i64,
    #[serde(default)]
    pub date: i64,
    #[serde(default)]
    pub rights: Option<BusinessBotRights>,
    #[serde(default)]
    pub is_enabled: bool,
}

/// Bot API `BusinessMessagesDeleted`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BusinessMessagesDeleted {
    pub business_connection_id: String,
    pub chat: Chat,
    #[serde(default)]
    pub message_ids: Vec<i64>,
}

/// The four business update kinds (Update fields `business_connection`, `business_message`,
/// `edited_business_message`, `deleted_business_messages`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BusinessUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub business_connection: Option<BusinessConnection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub business_message: Option<Message>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_business_message: Option<Message>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_business_messages: Option<BusinessMessagesDeleted>,
}

impl BusinessUpdate {
    pub fn is_some(&self) -> bool {
        self.business_connection.is_some()
            || self.business_message.is_some()
            || self.edited_business_message.is_some()
            || self.deleted_business_messages.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotCommand {
    pub command: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BotCommandScope {
    Default,
    Chat { chat_id: i64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MenuButton {
    Commands,
    Default,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookInfo {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub pending_update_count: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelegramFile {
    pub file_id: String,
    #[serde(default)]
    pub file_size: Option<u64>,
    #[serde(default)]
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputWidgetMessageContent {
    pub html: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_queries: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_shared: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSharedWidgetMessageContent {
    pub widget_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineQueryResultArticle {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_message_content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_markup: Option<InlineKeyboardMarkup>,
}
