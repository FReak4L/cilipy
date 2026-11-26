//! Network resilience, multi-proxy pooling/racing, typed Telegram Bot API 10.4 client,
//! resilient long-polling, webhook secret verification, `sd_notify`, and `Watchdog`.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod client;
pub mod poller;
pub mod proxy;
pub mod watchdog;

pub use client::{
    full_jitter, full_jitter_with, tg_retry, AnswerCallbackQueryParams, BotApiClient,
    EditMessageTextParams, EditSharedWidgetDataParams, EditWidgetDataParams, MediaInput,
    SendMediaOptions, SendMessageDraftParams, SendMessageParams, SendRichMessageDraftParams,
    SendRichMessageParams, SendSharedWidgetParams, SendWidgetParams, MAX_DOWNLOAD_BYTES,
    MAX_UPLOAD_BYTES,
};
pub use poller::{verify_webhook_secret, Poller, PollerConfig, UpdateFetcher};
pub use proxy::{
    build_client, build_egress_client, parse_retry_after_secs, probe_proxy_route, CircuitState,
    NetConfig, ProxyMode, ProxyPool, ProxyPoolSnapshot, ProxyProbeResult, ProxyRouteConfig,
    ProxyScheme, ProxyStats, DEFAULT_PROXY_PROBE_URL,
};
pub use watchdog::{
    sd_notify, sd_notify_ready, sd_notify_status, sd_notify_stopping, sd_notify_to,
    sd_notify_watchdog, AtomicNetMetrics, NetMetricsSink, ProbeTarget, Watchdog, WatchdogConfig,
    WatchdogSnapshot,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use agy_core::tg::{
        BotCommand, BotCommandScope, Chat, InlineKeyboardButton, InlineKeyboardMarkup,
        InlineQueryResultArticle, InputRichMessage, MenuButton, Message, Update, User,
    };
    use agy_core::BridgeError;
    use axum::body::Body;
    use axum::extract::{Path as AxumPath, Request, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use bytes::Bytes;
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    #[derive(Clone, Default)]
    struct MockState {
        calls: Arc<Mutex<Vec<(String, Value)>>>,
        multipart_hits: Arc<AtomicUsize>,
        getme_hits: Arc<AtomicUsize>,
        getme_mode: Arc<Mutex<GetMeBehavior>>,
        get_updates_hits: Arc<AtomicUsize>,
        edit_returns_bool: Arc<Mutex<bool>>,
        download_payload: Arc<Bytes>,
        send_content_length: Arc<Mutex<bool>>,
    }

    #[derive(Clone, Default)]
    enum GetMeBehavior {
        #[default]
        Ok,
        RateLimitOnceThenOk,
        Server500OnceThenOk,
        BadRequestNotModified,
        ForbiddenBlocked,
    }

    fn sample_user() -> User {
        User {
            id: 42,
            is_bot: true,
            first_name: "AgyBot".into(),
            last_name: None,
            username: Some("agy_test_bot".into()),
            language_code: None,
            is_premium: Some(true),
        }
    }

    fn sample_message(id: i64) -> Message {
        Message {
            message_id: id,
            from_user: Some(sample_user()),
            chat: Chat {
                id: 999,
                kind: "private".into(),
                username: None,
                first_name: Some("Tester".into()),
            },
            message_thread_id: None,
            text: Some("ok".into()),
            caption: None,
            entities: None,
            effect_id: None,
            reply_to_message: None,
            photo: None,
            document: None,
            video: None,
            audio: None,
            voice: None,
            animation: None,
            video_note: None,
            sticker: None,
            widget: None,
            business_connection_id: None,
            sender_business_bot: None,
        }
    }

    async fn handle_bot_method(
        State(st): State<MockState>,
        AxumPath((_token, method)): AxumPath<(String, String)>,
        req: Request,
    ) -> Response {
        let is_multipart = req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("multipart/form-data"));

        if is_multipart {
            let _ = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await;
            st.multipart_hits.fetch_add(1, Ordering::SeqCst);
            return (
                StatusCode::OK,
                Json(json!({ "ok": true, "result": sample_message(77) })),
            )
                .into_response();
        }

        let body_bytes = axum::body::to_bytes(req.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap_or_default();
        let payload: Value = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);
        st.calls.lock().await.push((method.clone(), payload));

        match method.as_str() {
            "getMe" => {
                let hit = st.getme_hits.fetch_add(1, Ordering::SeqCst);
                let behavior = st.getme_mode.lock().await.clone();
                match behavior {
                    GetMeBehavior::Ok => (
                        StatusCode::OK,
                        Json(json!({ "ok": true, "result": sample_user() })),
                    )
                        .into_response(),
                    GetMeBehavior::RateLimitOnceThenOk => {
                        if hit == 0 {
                            (
                                StatusCode::TOO_MANY_REQUESTS,
                                Json(json!({
                                    "ok": false,
                                    "error_code": 429,
                                    "description": "Too Many Requests: retry after 0",
                                    "parameters": { "retry_after": 0 }
                                })),
                            )
                                .into_response()
                        } else {
                            (
                                StatusCode::OK,
                                Json(json!({ "ok": true, "result": sample_user() })),
                            )
                                .into_response()
                        }
                    }
                    GetMeBehavior::Server500OnceThenOk => {
                        if hit == 0 {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({
                                    "ok": false,
                                    "error_code": 500,
                                    "description": "Internal Server Error"
                                })),
                            )
                                .into_response()
                        } else {
                            (
                                StatusCode::OK,
                                Json(json!({ "ok": true, "result": sample_user() })),
                            )
                                .into_response()
                        }
                    }
                    GetMeBehavior::BadRequestNotModified => (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "ok": false,
                            "error_code": 400,
                            "description": "Bad Request: message is not modified"
                        })),
                    )
                        .into_response(),
                    GetMeBehavior::ForbiddenBlocked => (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "ok": false,
                            "error_code": 403,
                            "description": "Forbidden: bot was blocked by the user"
                        })),
                    )
                        .into_response(),
                }
            }
            "getUpdates" => {
                let hit = st.get_updates_hits.fetch_add(1, Ordering::SeqCst);
                if hit == 0 {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    (StatusCode::OK, Json(json!({ "ok": true, "result": [] }))).into_response()
                } else {
                    let u1 = Update {
                        update_id: 100,
                        message: Some(sample_message(10)),
                        callback_query: None,
                        widget_query: None,
                        shared_widget_query: None,
                        inline_query: None,
                        business: Default::default(),
                        stopped_message_generation: None,
                    };
                    let u2 = Update {
                        update_id: 101,
                        message: Some(sample_message(11)),
                        callback_query: None,
                        widget_query: None,
                        shared_widget_query: None,
                        inline_query: None,
                        business: Default::default(),
                        stopped_message_generation: None,
                    };
                    (StatusCode::OK, Json(json!({ "ok": true, "result": [u1, u2] })))
                        .into_response()
                }
            }
            "getWebhookInfo" => (
                StatusCode::OK,
                Json(json!({ "ok": true, "result": { "url": "https://example.com/hook", "pending_update_count": 2 } })),
            )
                .into_response(),
            "getFile" => (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "result": {
                        "file_id": "file123",
                        "file_size": st.download_payload.len(),
                        "file_path": "docs/sample.bin"
                    }
                })),
            )
                .into_response(),
            "sendMessage" | "sendRichMessage" | "sendWidget" | "sendSharedWidget"
            | "sendDocument" | "sendPhoto" | "sendVideo" | "sendAudio" | "sendVoice"
            | "sendAnimation" => (
                StatusCode::OK,
                Json(json!({ "ok": true, "result": sample_message(55) })),
            )
                .into_response(),
            "editMessageText" => {
                if *st.edit_returns_bool.lock().await {
                    (StatusCode::OK, Json(json!({ "ok": true, "result": true }))).into_response()
                } else {
                    (
                        StatusCode::OK,
                        Json(json!({ "ok": true, "result": sample_message(55) })),
                    )
                        .into_response()
                }
            }
            _ => (StatusCode::OK, Json(json!({ "ok": true, "result": true }))).into_response(),
        }
    }

    async fn handle_file_download(
        State(st): State<MockState>,
        AxumPath((_token, _file_path)): AxumPath<(String, String)>,
    ) -> Response {
        let data = (*st.download_payload).clone();
        if *st.send_content_length.lock().await {
            (StatusCode::OK, data).into_response()
        } else {
            // Stream chunked response without Content-Length to exercise streaming byte limit check.
            let half = data.len() / 2;
            let chunks = vec![
                Ok::<Bytes, std::io::Error>(data.slice(..half)),
                Ok::<Bytes, std::io::Error>(data.slice(half..)),
            ];
            let stream = futures_util::stream::iter(chunks);
            Response::new(Body::from_stream(stream))
        }
    }

    async fn start_mock_server(state: MockState) -> SocketAddr {
        let app = Router::new()
            .route("/bot{token}/{method}", post(handle_bot_method))
            .route("/file/bot{token}/{*file_path}", get(handle_file_download))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    async fn start_delayed_tcp_proxy(target: SocketAddr, delay: Duration) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    if let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
        addr
    }

    async fn start_502_proxy() -> SocketAddr {
        let app = Router::new().fallback(|| async {
            (StatusCode::BAD_GATEWAY, "<html>502 Bad Gateway</html>")
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    #[tokio::test]
    async fn axum_bot_api_10_4_methods_and_empty_strings() {
        let st = MockState::default();
        let addr = start_mock_server(st.clone()).await;
        let client = BotApiClient::new(
            "123:TEST_TOKEN",
            NetConfig::default().with_api_base(format!("http://{addr}")),
        )
        .unwrap();

        assert_eq!(client.get_me().await.unwrap().id, 42);
        assert!(client
            .set_webhook("https://h.example/wh", Some("sec"), &["message".into()], true)
            .await
            .unwrap());
        assert_eq!(
            client.get_webhook_info().await.unwrap().url,
            "https://example.com/hook"
        );
        assert!(client.delete_webhook(false).await.unwrap());

        let kb = InlineKeyboardMarkup::new(vec![vec![InlineKeyboardButton::callback("Ok", "ok")]]);
        assert_eq!(
            client
                .send_message(SendMessageParams {
                    chat_id: 999,
                    text: "<b>hi</b>".into(),
                    parse_mode: Some("HTML".into()),
                    reply_markup: Some(kb.clone()),
                    ..Default::default()
                })
                .await
                .unwrap()
                .message_id,
            55
        );
        assert_eq!(
            client
                .send_rich_message(SendRichMessageParams {
                    chat_id: 999,
                    rich_message: InputRichMessage::markdown("# Hello"),
                    reply_markup: Some(kb),
                    ..Default::default()
                })
                .await
                .unwrap()
                .message_id,
            55
        );
        assert!(client
            .send_rich_message_draft(SendRichMessageDraftParams {
                chat_id: 999,
                draft_id: 7,
                rich_message: InputRichMessage::markdown("stream"),
                can_stop: Some(true),
                ..Default::default()
            })
            .await
            .unwrap());
        assert!(client
            .send_message_draft(SendMessageDraftParams {
                chat_id: 999,
                draft_id: 8,
                text: Some("draft".into()),
                parse_mode: Some("HTML".into()),
                can_stop: Some(true),
                ..Default::default()
            })
            .await
            .unwrap());

        // editMessageText returning Message and Bool
        let edited_msg = client
            .edit_message_text(EditMessageTextParams {
                chat_id: Some(999),
                message_id: Some(55),
                text: Some("updated".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(edited_msg.is_object());
        *st.edit_returns_bool.lock().await = true;
        let edited_inline = client
            .edit_message_text(EditMessageTextParams {
                inline_message_id: Some("im1".into()),
                rich_message: Some(InputRichMessage::markdown("edited")),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(edited_inline, json!(true));

        // Widget methods with explicit empty strings preserved
        assert_eq!(
            client
                .send_widget(SendWidgetParams {
                    chat_id: 999,
                    html: "<div>w</div>".into(),
                    public_data: Some(String::new()),
                    chat_data: Some(String::new()),
                    allow_queries: Some(true),
                    is_shared: Some(true),
                    ..Default::default()
                })
                .await
                .unwrap()
                .message_id,
            55
        );
        assert_eq!(
            client
                .send_shared_widget(SendSharedWidgetParams {
                    chat_id: 999,
                    widget_id: "wid_1".into(),
                    chat_data: Some(String::new()),
                    ..Default::default()
                })
                .await
                .unwrap()
                .message_id,
            55
        );
        assert!(client
            .edit_message_widget_data(EditWidgetDataParams {
                chat_id: Some(999),
                message_id: Some(55),
                public_data: Some(String::new()),
                chat_data: Some(String::new()),
                ..Default::default()
            })
            .await
            .unwrap());
        assert!(client
            .edit_shared_widget_data(EditSharedWidgetDataParams {
                widget_id: "wid_1".into(),
                public_data: String::new(),
                cache_time: Some(10),
            })
            .await
            .unwrap());
        assert!(client
            .answer_widget_query("wq_1", Some(""))
            .await
            .unwrap());
        assert!(client
            .answer_callback_query("cq_1", Some("done"))
            .await
            .unwrap());
        assert!(client
            .answer_inline_query(
                "iq_1",
                &[InlineQueryResultArticle {
                    kind: "article".into(),
                    id: "1".into(),
                    title: "Widget".into(),
                    description: None,
                    input_message_content: json!({"message_text": "hi"}),
                    reply_markup: None,
                }],
                Some(5),
                Some(true),
            )
            .await
            .unwrap());
        assert!(client.delete_message(999, 55).await.unwrap());
        assert!(client.send_chat_action(999, "typing").await.unwrap());
        assert!(client
            .set_my_commands(
                &[BotCommand {
                    command: "menu".into(),
                    description: "Dashboard".into(),
                }],
                BotCommandScope::Chat { chat_id: 999 },
            )
            .await
            .unwrap());
        assert!(client
            .set_chat_menu_button(Some(999), MenuButton::Commands)
            .await
            .unwrap());

        let calls = st.calls.lock().await;
        let find_call = |name: &str| -> Value {
            calls
                .iter()
                .find(|(m, _)| m == name)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert_eq!(find_call("sendWidget")["public_data"], json!(""));
        assert_eq!(find_call("sendWidget")["chat_data"], json!(""));
        assert_eq!(find_call("editMessageWidgetData")["public_data"], json!(""));
        assert_eq!(find_call("editMessageWidgetData")["chat_data"], json!(""));
        assert_eq!(find_call("editSharedWidgetData")["public_data"], json!(""));
        assert_eq!(find_call("answerWidgetQuery")["data"], json!(""));
    }

    #[tokio::test]
    async fn axum_retries_429_and_500_without_tripping_circuit_breaker() {
        let st = MockState::default();
        *st.getme_mode.lock().await = GetMeBehavior::RateLimitOnceThenOk;
        let addr = start_mock_server(st.clone()).await;
        let client = BotApiClient::new(
            "123:TOK",
            NetConfig::default().with_api_base(format!("http://{addr}")),
        )
        .unwrap();

        let u = tg_retry(2, 2.0, || client.get_me()).await.unwrap();
        assert_eq!(u.id, 42);
        assert_eq!(st.getme_hits.load(Ordering::SeqCst), 2);
        assert_eq!(client.pool().route_circuit_state(0), Some(CircuitState::Closed));

        // 500 -> retryable BotApi -> succeeds on retry
        st.getme_hits.store(0, Ordering::SeqCst);
        *st.getme_mode.lock().await = GetMeBehavior::Server500OnceThenOk;
        let u2 = tg_retry(2, 0.1, || client.get_me()).await.unwrap();
        assert_eq!(u2.id, 42);
        assert_eq!(st.getme_hits.load(Ordering::SeqCst), 2);

        // 400 "not modified" -> non-retryable, circuit remains Closed
        st.getme_hits.store(0, Ordering::SeqCst);
        *st.getme_mode.lock().await = GetMeBehavior::BadRequestNotModified;
        let err = tg_retry(2, 0.1, || client.get_me()).await.unwrap_err();
        assert!(!err.is_retryable());
        assert!(err.is_not_modified());
        assert_eq!(st.getme_hits.load(Ordering::SeqCst), 1);
        assert_eq!(client.pool().route_circuit_state(0), Some(CircuitState::Closed));

        // 403 -> chat unavailable, non-retryable, circuit remains Closed
        *st.getme_mode.lock().await = GetMeBehavior::ForbiddenBlocked;
        let err403 = client.get_me().await.unwrap_err();
        assert!(err403.is_chat_unavailable());
        assert_eq!(client.pool().route_circuit_state(0), Some(CircuitState::Closed));
    }

    #[tokio::test]
    async fn axum_proxy_failover_and_bad_gateway_proxy() {
        let st = MockState::default();
        let api_addr = start_mock_server(st).await;

        // Dead port (bind & drop immediately)
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);

        let bad_proxy_addr = start_502_proxy().await;

        let routes = ProxyRouteConfig::parse_list(&format!(
            "http://user:s3cret@{dead_addr}, http://{bad_proxy_addr}, direct"
        ))
        .unwrap();

        let cfg = NetConfig {
            api_base: format!("http://{api_addr}"),
            routes,
            proxy_mode: ProxyMode::Failover,
            cb_failure_threshold: 2,
            cb_open_cooldown: Duration::from_secs(30),
            ..Default::default()
        };
        let client = BotApiClient::new("123:TOK", cfg).unwrap();

        // Call 1: route 0 refuses connection, route 1 returns 502 HTML, route 2 (direct) succeeds
        let me = client.get_me().await.unwrap();
        assert_eq!(me.id, 42);

        // Call 2: trips threshold=2 on both route 0 and route 1 -> opens their circuits
        let me2 = client.get_me().await.unwrap();
        assert_eq!(me2.id, 42);
        assert!(matches!(
            client.pool().route_circuit_state(0),
            Some(CircuitState::Open(_))
        ));
        assert!(matches!(
            client.pool().route_circuit_state(1),
            Some(CircuitState::Open(_))
        ));
        assert_eq!(
            client.pool().route_circuit_state(2),
            Some(CircuitState::Closed)
        );

        // Call 3: routes 0 and 1 are skipped while Open!
        let snap_before = client.pool().snapshot();
        assert_eq!(snap_before.active_healthy, 1);
        assert!(!snap_before.routes[0]
            .last_error
            .as_deref()
            .unwrap_or("")
            .contains("s3cret"));

        let me3 = client.get_me().await.unwrap();
        assert_eq!(me3.id, 42);
        let snap_after = client.pool().snapshot();
        assert_eq!(
            snap_after.routes[0].total_requests,
            snap_before.routes[0].total_requests
        );
        assert_eq!(
            snap_after.routes[1].total_requests,
            snap_before.routes[1].total_requests
        );
        assert_eq!(
            snap_after.routes[2].total_requests,
            snap_before.routes[2].total_requests + 1
        );
    }

    #[tokio::test]
    async fn axum_race_mode_hedged_beats_slow_primary() {
        let st = MockState::default();
        let api_addr = start_mock_server(st).await;
        let slow_proxy = start_delayed_tcp_proxy(api_addr, Duration::from_millis(800)).await;
        let fast_proxy = start_delayed_tcp_proxy(api_addr, Duration::ZERO).await;

        let routes =
            ProxyRouteConfig::parse_list(&format!("http://{slow_proxy}, http://{fast_proxy}"))
                .unwrap();
        let cfg = NetConfig {
            api_base: format!("http://{api_addr}"),
            routes,
            proxy_mode: ProxyMode::Race,
            race_hedge_delay: Duration::from_millis(40),
            ..Default::default()
        };
        let client = BotApiClient::new("123:TOK", cfg).unwrap();

        let started = std::time::Instant::now();
        let me = client.get_me().await.unwrap();
        assert_eq!(me.id, 42);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "hedged race should complete via fast backup long before 800ms slow primary"
        );
    }

    #[tokio::test]
    async fn axum_media_upload_and_streaming_download_limits() {
        let payload = vec![b'A'; 128];
        let st = MockState {
            download_payload: Arc::new(Bytes::from(payload.clone())),
            ..Default::default()
        };
        let addr = start_mock_server(st.clone()).await;
        let client = BotApiClient::new(
            "123:TOK",
            NetConfig::default().with_api_base(format!("http://{addr}")),
        )
        .unwrap();

        // Bytes upload
        let msg1 = client
            .send_document(
                999,
                MediaInput::from_bytes(Bytes::from_static(b"hello world"), "hello.txt"),
                SendMediaOptions {
                    caption: Some("doc".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(msg1.message_id, 77);

        // Path upload + other media types + direct call_multipart
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("pic.png");
        std::fs::write(&src, b"\x89PNG\r\n\x1a\n").unwrap();
        let msg2 = client
            .send_photo(999, MediaInput::from_path(&src), None)
            .await
            .unwrap();
        assert_eq!(msg2.message_id, 77);
        assert!(client
            .send_audio(
                999,
                MediaInput::from_bytes(Bytes::from_static(b"mp3"), "a.mp3"),
                None
            )
            .await
            .is_ok());
        assert!(client
            .send_voice(
                999,
                MediaInput::from_bytes(Bytes::from_static(b"ogg"), "v.ogg"),
                None
            )
            .await
            .is_ok());
        assert!(client
            .send_animation(
                999,
                MediaInput::from_bytes(Bytes::from_static(b"gif"), "g.gif"),
                None
            )
            .await
            .is_ok());
        assert!(client
            .send_video(999, MediaInput::from_id_or_url("vid_file_id"), None)
            .await
            .is_ok());
        let direct_form = reqwest::multipart::Form::new()
            .text("chat_id", "999")
            .text("document", "doc_file_id");
        let msg_direct: Message = client
            .call_multipart("sendDocument", direct_form, None)
            .await
            .unwrap();
        assert_eq!(msg_direct.message_id, 77);
        assert_eq!(st.multipart_hits.load(Ordering::SeqCst), 6);

        // Oversized Bytes upload guard
        let big = Bytes::from(vec![0u8; MAX_UPLOAD_BYTES + 1]);
        let err = client
            .send_video(999, MediaInput::from_bytes(big, "big.mp4"), None)
            .await
            .unwrap_err();
        assert!(matches!(err, BridgeError::PayloadTooLarge { .. }));

        // Streaming download under limit
        let f = client.get_file("file123").await.unwrap();
        let fp = f.file_path.unwrap();
        let dest_ok = dir.path().join("sub/ok.bin");
        let n = client.download_file(&fp, &dest_ok, 1024).await.unwrap();
        assert_eq!(n, 128);
        assert_eq!(std::fs::read(&dest_ok).unwrap(), payload);

        // Streaming download over limit (without Content-Length) aborts cleanly with no leftover files
        let dest_bad = dir.path().join("sub/too_big.bin");
        let err_dl = client
            .download_file(&fp, &dest_bad, 32)
            .await
            .unwrap_err();
        assert!(matches!(err_dl, BridgeError::PayloadTooLarge { .. }));
        assert!(!dest_bad.exists());
        let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("sub"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".dl-"))
            .collect();
        assert!(leftovers.is_empty());

        // Download with Content-Length header exceeding limit rejects upfront
        *st.send_content_length.lock().await = true;
        let err_cl = client
            .download_file(&fp, &dest_bad, 64)
            .await
            .unwrap_err();
        assert!(matches!(err_cl, BridgeError::PayloadTooLarge { .. }));
        assert!(!dest_bad.exists());
    }

    #[tokio::test]
    async fn axum_poller_kick_and_offset_end_to_end() {
        let st = MockState::default();
        let addr = start_mock_server(st.clone()).await;
        let client = Arc::new(
            BotApiClient::new(
                "123:TOK",
                NetConfig::default().with_api_base(format!("http://{addr}")),
            )
            .unwrap(),
        );
        let dir = tempfile::tempdir().unwrap();
        let off_file = dir.path().join("offset");
        let metrics = Arc::new(AtomicNetMetrics::new());
        let poller = Arc::new(Poller::new(
            PollerConfig {
                offset_file: off_file.clone(),
                poll_timeout_secs: 30,
                backoff_scale: 0.001,
                ..Default::default()
            },
            metrics.clone(),
        ));

        let received = Arc::new(Mutex::new(Vec::new()));
        let rec_cb = received.clone();
        let poller_for_cb = poller.clone();

        let task = {
            let p = poller.clone();
            let c = client.clone();
            tokio::spawn(async move {
                p.run(&*c, move |u| {
                    let r = rec_cb.clone();
                    let p_stop = poller_for_cb.clone();
                    async move {
                        let mut guard = r.lock().await;
                        guard.push(u.update_id);
                        if guard.len() >= 2 {
                            p_stop.stop();
                        }
                    }
                })
                .await;
            })
        };

        // Wait until first getUpdates request is stuck in flight, then kick it!
        tokio::time::timeout(Duration::from_secs(2), async {
            while st.get_updates_hits.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        poller.kick();

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("poller should recover after kick and handle second batch")
            .unwrap();

        let mut got = received.lock().await.clone();
        got.sort();
        assert_eq!(got, vec![100, 101]);
        assert_eq!(poller.offset(), Some(102));
        assert_eq!(std::fs::read_to_string(&off_file).unwrap(), "102");
        assert_eq!(metrics.updates(), 2);
    }
}
