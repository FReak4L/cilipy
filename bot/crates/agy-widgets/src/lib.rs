//! Bot API 10.4 HTML Widgets engine: validation, Profile-1 lint, parsers, store, built-ins, and WebApp router.

pub mod builtins;
pub mod parser;
pub mod spec;
pub mod store;
pub mod webapp;

pub use builtins::{
    build_inline_widget_article, builtin_widget, preview_summary_text, render_preview_html,
    render_standalone_preview_html,
};
pub use parser::{
    extract_widgets_from_markdown, parse_widget_html_file, parse_widget_json,
    EditMessageDataAction, EditSharedDataAction, ParsedWidgetAction, WidgetJsonInput,
};
pub use spec::{
    count_widget_size, encode_widget_data, lint_widget_profile, minify_widget_html,
    process_js, strip_css_comments, validate_widget_spec, WidgetData, WidgetSizeReport,
    WidgetSpec, BUILTIN_WIDGET_KINDS, LEGACY_WIDGET_HANDLERS, LEGACY_WIDGET_SLUGS,
    WIDGET_ANSWER_DATA_LIMIT, WIDGET_CACHE_TIME_DEFAULT, WIDGET_CACHE_TIME_MAX,
    WIDGET_CACHE_TIME_MIN, WIDGET_CAPTION_LIMIT, WIDGET_DATA_LIMIT, WIDGET_HEIGHT_MAX,
    WIDGET_HEIGHT_MIN, WIDGET_HTML_RAW_LIMIT, WIDGET_HTML_ZLIB_LIMIT, WIDGET_MAX_SIZE,
    WIDGET_MIN_SIZE, WIDGET_QUERY_DATA_LIMIT, WIDGET_QUERY_TIMEOUT_SECS,
    WIDGET_REQUEST_DATA_LIMIT, WIDGET_SHARED_EDIT_MIN_INTERVAL_SECS, WIDGET_SHARED_MAX_CACHE,
    WIDGET_SHARED_MIN_CACHE, WIDGET_WIDTH_MIN,
};
pub use store::{
    DataPatch, MessageRecord, RecentWidgets, RecordSentOpts, RecordSentOutcome,
    SharedWidgetRecord, VoteRecord, VoteResult, WalletEvent, WebAppWidgetRecord, WidgetStore,
    WidgetStoreData,
};
pub use webapp::{
    build_webapp_router, render_in_bubble_widget, render_in_bubble_widget_from_state,
    verify_webapp_init_data, verify_webapp_init_data_at, AllowedUidsProvider, BoxFuture,
    BridgeActionResponse, BridgeQueryResponse, TokenProvider, VerifiedInitData, WebAppState,
    WidgetBridge, DEFAULT_INIT_DATA_MAX_AGE_SECS, WEBAPP_API_MAX_BYTES, WEBAPP_CSP_HEADER,
    WEBAPP_SHELL_HTML,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
