//! Comprehensive verification test suite for `agy-widgets`:
//! spec/lint/minifier, parsers, persistent WidgetStore, built-in widgets + Node `vm` JS check,
//! In-Bubble card renderer, and Axum WebApp HMAC router.

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use agy_core::error::{BridgeError, Result};
use agy_core::tg::InlineKeyboardMarkup;
use agy_render::PremiumState;
use agy_widgets::builtins::{
    build_inline_widget_article, builtin_widget, preview_summary_text,
    render_standalone_preview_html,
};
use agy_widgets::parser::{
    extract_widgets_from_markdown, parse_widget_html_file, parse_widget_json,
    EditMessageDataAction, EditSharedDataAction, ParsedWidgetAction,
};
use agy_widgets::spec::{
    count_widget_size, encode_widget_data, lint_widget_profile, minify_widget_html,
    validate_widget_spec, WidgetData, WidgetSpec, BUILTIN_WIDGET_KINDS, WIDGET_DATA_LIMIT,
    WIDGET_HTML_RAW_LIMIT, WIDGET_HTML_ZLIB_LIMIT,
};
use agy_widgets::store::{DataPatch, RecordSentOpts, VoteRecord, WidgetStore};
use agy_widgets::webapp::{
    build_webapp_router, render_in_bubble_widget, verify_webapp_init_data_at,
    AllowedUidsProvider, BoxFuture, BridgeActionResponse, BridgeQueryResponse, TokenProvider,
    WebAppState, WidgetBridge,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use tempfile::TempDir;
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

fn sign_init_data(bot_token: &str, user_json: &str, auth_date: i64, query_id: Option<&str>) -> String {
    let mut pairs: BTreeMap<&str, String> = BTreeMap::new();
    pairs.insert("auth_date", auth_date.to_string());
    pairs.insert("chat_type", "private".to_string());
    if let Some(qid) = query_id {
        pairs.insert("query_id", qid.to_string());
    }
    pairs.insert("user", user_json.to_string());

    let data_check = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n");

    let mut secret_mac = HmacSha256::new_from_slice(b"WebAppData").expect("hmac key");
    secret_mac.update(bot_token.as_bytes());
    let secret = secret_mac.finalize().into_bytes();

    let mut sig_mac = HmacSha256::new_from_slice(&secret).expect("hmac secret");
    sig_mac.update(data_check.as_bytes());
    let hash_hex = hex::encode(sig_mac.finalize().into_bytes());

    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in &pairs {
        ser.append_pair(k, v);
    }
    ser.append_pair("hash", &hash_hex);
    ser.finish()
}

fn run_node_vm(script: &str, stdin_json: &Value) -> String {
    let node_bin = if std::path::Path::new("/usr/bin/node").is_file() {
        "/usr/bin/node"
    } else {
        "node"
    };
    let mut child = Command::new(node_bin)
        .args(["-e", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn node for JS verification");

    let payload = serde_json::to_vec(stdin_json).expect("serialize node payload");
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&payload).expect("write node stdin");
    }
    let output = child.wait_with_output().expect("wait for node");
    assert!(
        output.status.success(),
        "node failed (status={}):\nSTDOUT:\n{}\nSTDERR:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn pseudo_random_pool(seed: u64, len: usize, alphabet: &[u8]) -> String {
    let mut x = seed;
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let idx = ((x >> 33) as usize) % alphabet.len();
        out.push(alphabet[idx] as char);
    }
    out
}

// --------------------------------------------------------------------------- 1. SPEC / LINT / MINIFIER

#[test]
fn spec_encode_data_and_multibyte_1024_boundary() {
    assert_eq!(encode_widget_data(None::<&str>, false).unwrap(), None);
    assert_eq!(encode_widget_data(Some(""), false).unwrap(), None);
    assert_eq!(encode_widget_data(Some(""), true).unwrap(), Some(String::new()));
    assert_eq!(
        encode_widget_data(Some(WidgetData::Value(&json!(42))), false).unwrap(),
        Some("42".to_string())
    );
    assert_eq!(
        encode_widget_data(Some(WidgetData::Value(&json!({"ok": true, "n": [1, 2]}))), false).unwrap(),
        Some(r#"{"n":[1,2],"ok":true}"#.to_string())
    );

    // Reject raw NUL bytes
    let nul_err = encode_widget_data(Some("abc\0def"), false).unwrap_err();
    assert!(nul_err.to_string().contains("NUL"));

    // Persian "س" = 2 UTF-8 bytes: 512 chars = 1024 bytes OK, 513 chars = 1026 bytes rejected
    let ok_1024 = "س".repeat(512);
    assert_eq!(ok_1024.len(), WIDGET_DATA_LIMIT);
    assert_eq!(encode_widget_data(Some(ok_1024.as_str()), false).unwrap(), Some(ok_1024));

    let over_1026 = "س".repeat(513);
    assert!(encode_widget_data(Some(over_1026.as_str()), false).is_err());
}

#[test]
fn spec_size_budget_raw_32768_and_zlib9_4096() {
    let empty = count_widget_size("");
    assert_eq!(empty.raw_bytes, 0);
    assert!(!empty.has_nul);
    assert!(!empty.ok);

    let nul = count_widget_size("<div>\0</div>");
    assert!(nul.has_nul);
    assert!(!nul.ok);

    let at_raw = count_widget_size(&"a".repeat(WIDGET_HTML_RAW_LIMIT));
    assert_eq!(at_raw.raw_bytes, 32_768);
    assert!(at_raw.raw_ok && at_raw.zlib_ok && at_raw.ok);

    let over_raw = count_widget_size(&"a".repeat(WIDGET_HTML_RAW_LIMIT + 1));
    assert_eq!(over_raw.raw_bytes, 32_769);
    assert!(!over_raw.raw_ok && !over_raw.ok);

    // Binary search exact 4096 B zlib-9 boundary on incompressible pool
    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`";
    let pool = pseudo_random_pool(42, 9000, alphabet);
    let mut lo = 1000usize;
    let mut hi = pool.len();
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&pool.as_bytes()[..mid]).unwrap();
        let clen = enc.finish().unwrap().len();
        if clen <= WIDGET_HTML_ZLIB_LIMIT {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }

    let fit = count_widget_size(&pool[..lo]);
    assert!(fit.zlib_bytes <= WIDGET_HTML_ZLIB_LIMIT);
    assert!(fit.raw_bytes <= WIDGET_HTML_RAW_LIMIT);
    assert!(fit.ok);

    let over = count_widget_size(&pool[..(lo + 10).min(pool.len())]);
    assert!(over.zlib_bytes > WIDGET_HTML_ZLIB_LIMIT);
    assert!(over.raw_bytes <= WIDGET_HTML_RAW_LIMIT);
    assert!(!over.ok);
}

#[test]
fn spec_minify_preserves_pre_textarea_css_strings_and_js_regex() {
    let raw = r#"
    <!-- tg-widget-dev-start -->
    <div id="dev">DEBUG ONLY</div>
    <script>console.log('dev');</script>
    <!-- tg-widget-dev-end -->
    <!-- normal comment -->
    <style>
      /* drop css comment */
      .box::before { content: "/* keep literal */"; color: red; /* drop */ }
    </style>
    <pre>
      keep   pre
        indent
    </pre>
    <textarea>  keep   spaces  </textarea>
    <script>
      // drop single line comment
      var u = "https://example.com//path/*kept*/";
      var tmpl = `line1
        // keep in template
        ${/* drop expr comment */ 1 + 2}`;
      /* drop multi */
      function ok(s) { return /^https?:\/\/[a-z/]+\/v1$/i.test(s); }
      var ratio = (10 / 2) / 5;
    </script>
    "#;

    let min = minify_widget_html(raw);
    assert!(!min.contains("DEBUG ONLY"));
    assert!(!min.contains("normal comment"));
    assert!(!min.contains("drop css comment"));
    assert!(!min.contains("drop single line"));
    assert!(!min.contains("drop expr comment"));
    assert!(!min.contains("drop multi"));
    assert!(min.contains(r#"content: "/* keep literal */";"#));
    assert!(min.contains("<pre>\n      keep   pre\n        indent\n    </pre>"));
    assert!(min.contains("<textarea>  keep   spaces  </textarea>"));
    assert!(min.contains(r#""https://example.com//path/*kept*/""#));
    assert!(min.contains("// keep in template"));
    assert!(min.contains(r"/^https?:\/\/[a-z/]+\/v1$/i"));
    assert!(min.contains("(10 / 2) / 5"));

    let s_start = min.find("<script>").unwrap() + "<script>".len();
    let s_end = min[s_start..].find("</script>").unwrap() + s_start;
    let js = &min[s_start..s_end];
    run_node_vm(
        "const vm=require('vm'); const d=JSON.parse(require('fs').readFileSync(0,'utf8')); new vm.Script(d.js);",
        &json!({ "js": js }),
    );
}

#[test]
fn spec_lint_widget_profile_rejects_blocked_tags_apis_and_external_urls() {
    let bad = r#"<!DOCTYPE html><html><head>
    <meta name="viewport" content="width=device-width">
    <link rel="stylesheet" href="https://cdn.example.com/a.css">
    <style>
      @font-face { font-family: X; src: url(https://cdn.example.com/f.woff2); }
      @import url("https://cdn.example.com/b.css");
      .a { height: 100vh; width: 50dvh; }
      .b:focus { color: red; }
      .c:has(.x) { border: 1px solid #000; }
    </style>
    </head><body>
    <iframe src="https://evil.example"></iframe>
    <audio src="a.mp3"></audio>
    <input type="text">
    <img src="https://cdn.example.com/a.png">
    <script src="https://cdn.example.com/a.js"></script>
    <button onclick="fetch('/x')">Go</button>
    <script>
      var a = new XMLHttpRequest();
      var b = new WebSocket("wss://x");
      var c = new EventSource("/s");
      navigator.clipboard.writeText("x");
      TelegramWidget.sendMessage("hi");
    </script>
    </body></html>"#;

    let warnings = lint_widget_profile(bad);
    let joined = warnings.join("\n");
    for expected in [
        "<iframe>",
        "<audio>",
        "<meta>",
        "<input>",
        "<script src>",
        "<link>",
        "<img src>",
        "External CSS url",
        "@font-face",
        "@import",
        "viewport unit 'vh'",
        "viewport unit 'dvh'",
        ":focus",
        ":has()",
        "fetch()",
        "XMLHttpRequest",
        "WebSocket",
        "EventSource",
        "navigator.clipboard",
        "TelegramWidget.sendMessage",
    ] {
        assert!(joined.contains(expected), "missing lint warning '{expected}' in:\n{joined}");
    }

    // Comments and CSS strings containing restricted tokens must NOT trigger false positives
    let clean = r#"
    <!-- <iframe src="x"></iframe> <audio></audio> -->
    <style>
      /* :focus :has(.a) 100vh */
      .ok::after { content: ":focus :has(.a) 100vh"; }
    </style>
    <script>
      // fetch('https://x') XMLHttpRequest
      var x = 1;
    </script>
    "#;
    assert!(lint_widget_profile(clean).is_empty());
}

#[test]
fn spec_validate_widget_spec_clamps_auto_minifies_and_errors() {
    let orig = WidgetSpec {
        html: Some("<div>ok</div>".to_string()),
        width: Some(0),
        height: Some(10),
        cache_time: Some(1),
        public_data: Some(r#"{"a":1}"#.to_string()),
        ..Default::default()
    };
    let (norm, warns) = validate_widget_spec(&orig).unwrap();
    assert!(warns.is_empty());
    assert_eq!(norm.width, None);
    assert_eq!(norm.height, Some(50));
    assert_eq!(norm.cache_time, Some(5));

    let (norm2, _) = validate_widget_spec(&WidgetSpec {
        html: Some("<div>ok</div>".to_string()),
        width: Some(100),
        height: Some(900),
        cache_time: Some(9999),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(norm2.width, Some(200));
    assert_eq!(norm2.height, Some(600));
    assert_eq!(norm2.cache_time, Some(3600));

    // Auto-minifies dev block exceeding 32768 B raw
    let dev_raw = format!(
        "<!-- tg-widget-dev-start -->{}<!-- tg-widget-dev-end --><div>ok</div>",
        "x".repeat(34_000)
    );
    assert!(!count_widget_size(&dev_raw).ok);
    let (norm3, _) = validate_widget_spec(&WidgetSpec {
        html: Some(dev_raw),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(norm3.html.as_deref(), Some("<div>ok</div>"));

    // Truly incompressible oversized HTML is rejected
    let pool = pseudo_random_pool(7, 9000, b"abcdefghijklmnopqrstuvwxyz0123456789");
    assert!(validate_widget_spec(&WidgetSpec {
        html: Some(format!("<div>{pool}</div>")),
        ..Default::default()
    })
    .is_err());

    // Empty HTML, NUL, long caption, missing html/widget_id/slug all fail
    assert!(validate_widget_spec(&WidgetSpec {
        html: Some(String::new()),
        ..Default::default()
    })
    .is_err());
    assert!(validate_widget_spec(&WidgetSpec {
        html: Some("<div>\0</div>".to_string()),
        ..Default::default()
    })
    .is_err());
    assert!(validate_widget_spec(&WidgetSpec {
        html: Some("<div>ok</div>".to_string()),
        caption: Some("c".repeat(1025)),
        ..Default::default()
    })
    .is_err());
    assert!(validate_widget_spec(&WidgetSpec::default()).is_err());
}

// --------------------------------------------------------------------------- 2. PARSER

#[test]
fn parser_extract_widgets_from_markdown_code_immunity_and_quotes() {
    let md = r#"
Inline `<tg-widget caption="ignored"><b>x</b></tg-widget>` and ``<tg-shared-widget widget-id="ignored"/>`` stay intact.

```html
<tg-widget caption="fenced-backtick"><div>no</div></tg-widget>
```

~~~
<tg-shared-widget widget-id="fenced-tilde" />
~~~

<tg-widget caption="My &quot;Status&quot;" width="300" height='220' allow-queries="true" public-data='{"k":1}' slug="srv" handler="skills" parse-mode="none" silent>
  <div>Status Body</div>
</tg-widget>

<tg-shared-widget widget-id='w_shared_1' caption='Shared' chat-data='{"c":2}'/>
"#;

    let (cleaned, specs) = extract_widgets_from_markdown(md).unwrap();
    assert_eq!(specs.len(), 2);

    let s0 = &specs[0];
    assert_eq!(s0.html.as_deref(), Some("<div>Status Body</div>"));
    assert_eq!(s0.caption.as_deref(), Some(r#"My "Status""#));
    assert_eq!(s0.width, Some(300));
    assert_eq!(s0.height, Some(220));
    assert_eq!(s0.allow_queries, Some(true));
    assert_eq!(s0.public_data.as_deref(), Some(r#"{"k":1}"#));
    assert_eq!(s0.slug.as_deref(), Some("srv"));
    assert_eq!(s0.handler.as_deref(), Some("skills"));
    assert_eq!(s0.parse_mode, None);
    assert_eq!(s0.disable_notification, Some(true));

    let s1 = &specs[1];
    assert_eq!(s1.widget_id.as_deref(), Some("w_shared_1"));
    assert_eq!(s1.is_shared, Some(true));
    assert_eq!(s1.html, None);
    assert_eq!(s1.caption.as_deref(), Some("Shared"));
    assert_eq!(s1.chat_data.as_deref(), Some(r#"{"c":2}"#));

    assert!(cleaned.contains(r#"`<tg-widget caption="ignored"><b>x</b></tg-widget>`"#));
    assert!(cleaned.contains(r#"``<tg-shared-widget widget-id="ignored"/>``"#));
    assert!(cleaned.contains(r#"caption="fenced-backtick""#));
    assert!(cleaned.contains(r#"widget-id="fenced-tilde""#));
    assert!(!cleaned.contains("<div>Status Body</div>"));
    assert!(!cleaned.contains("w_shared_1"));
}

#[test]
fn parser_widget_html_file_and_json_actions() {
    let dir = TempDir::new().unwrap();

    // Sibling JSON + top <!-- widget: {...} --> comment override
    std::fs::write(
        dir.path().join("dash.json"),
        serde_json::to_string(&json!({"width": 280, "caption": "Sibling", "handler": "skills"})).unwrap(),
    )
    .unwrap();
    let wfile = dir.path().join("dash.widget.html");
    std::fs::write(
        &wfile,
        "<!-- widget: {\"caption\": \"Header\", \"public_data\": {\"r\": 1}, \"cache_time\": 15} -->\n<div>Hello</div><script>TelegramWidget.request('sk:ref');</script>",
    )
    .unwrap();

    let sp = parse_widget_html_file(&wfile).unwrap();
    assert_eq!(sp.width, Some(280));
    assert_eq!(sp.handler.as_deref(), Some("skills"));
    assert_eq!(sp.caption.as_deref(), Some("Header"));
    assert_eq!(sp.public_data.as_deref(), Some(r#"{"r":1}"#));
    assert_eq!(sp.cache_time, Some(15));
    assert_eq!(sp.allow_queries, Some(true));
    assert!(!sp.html.as_deref().unwrap().trim_start().starts_with("<!--"));

    // parse_widget_json: send, send_shared, edit_message_data, edit_shared_data
    std::fs::write(dir.path().join("sample.html"), "<div>From File</div>").unwrap();

    let a_send = parse_widget_json(
        &json!({"action": "send", "html_file": "sample.html", "width": 310}),
        Some(dir.path()),
    )
    .unwrap();
    match a_send {
        ParsedWidgetAction::Send(s) => {
            assert_eq!(s.html.as_deref(), Some("<div>From File</div>"));
            assert_eq!(s.width, Some(310));
        }
        other => panic!("expected Send, got {other:?}"),
    }

    let a_shared = parse_widget_json(
        &json!({
            "action": "send_shared",
            "builtin": "models",
            "initial_state": {"model": "m1", "effort": "high"},
            "caption": "Pick Model"
        }),
        None,
    )
    .unwrap();
    match a_shared {
        ParsedWidgetAction::Send(s) => {
            assert_eq!(s.is_shared, Some(true));
            assert_eq!(s.caption.as_deref(), Some("Pick Model"));
            assert_eq!(s.handler.as_deref(), Some("models"));
            let cd: Value = serde_json::from_str(s.chat_data.as_deref().unwrap()).unwrap();
            assert_eq!(cd, json!({"model": "m1", "effort": "high"}));
        }
        other => panic!("expected Send, got {other:?}"),
    }

    let a_emsg = parse_widget_json(
        &json!({
            "action": "edit_message_data",
            "chat_id": 123,
            "message_id": 45,
            "chat_data": {"step": 2},
            "public_data": ""
        }),
        None,
    )
    .unwrap();
    assert_eq!(
        a_emsg,
        ParsedWidgetAction::EditMessageData(EditMessageDataAction {
            chat_id: Some(123),
            message_id: Some(45),
            inline_message_id: None,
            chat_data: Some(r#"{"step":2}"#.to_string()),
            public_data: Some(String::new()),
        })
    );

    let a_eshared = parse_widget_json(
        &json!({
            "action": "edit_shared_data",
            "slug": "hub_1",
            "public_data": {"v": [1, 2]},
            "cache_time": 1
        }),
        None,
    )
    .unwrap();
    assert_eq!(
        a_eshared,
        ParsedWidgetAction::EditSharedData(EditSharedDataAction {
            widget_id: None,
            slug: Some("hub_1".to_string()),
            public_data: Some(r#"{"v":[1,2]}"#.to_string()),
            cache_time: Some(5),
        })
    );

    assert!(parse_widget_json(r#"{"action":"destroy"}"#, None).is_err());
    assert!(parse_widget_json(r#"{"action":"send"}"#, None).is_err());
}

// --------------------------------------------------------------------------- 3. STORE

#[test]
fn store_record_update_rate_limit_votes_kv_webapp_and_legacy_purge() {
    let dir = TempDir::new().unwrap();
    let store_path = dir.path().join("widgets.json");
    let store = WidgetStore::open(&store_path).unwrap();

    // record_sent + resolve + update_message_state + update_shared_state + shared_edit_delay
    let sp = WidgetSpec {
        html: Some("<div>Poll</div>".to_string()),
        widget_id: Some("wid_poll".to_string()),
        slug: Some("team_poll".to_string()),
        handler: Some("custom".to_string()),
        is_shared: Some(true),
        public_data: Some(r#"{"q":"Lunch?","opts":["Pizza","Sushi","Tacos"],"v":[0,0,0],"r":0}"#.to_string()),
        ..Default::default()
    };
    store.record_sent(Some(10), Some(20), Some(&sp), None).unwrap();
    assert_eq!(store.resolve_widget_id("team_poll").as_deref(), Some("wid_poll"));
    assert_eq!(store.shared_edit_delay("team_poll", None), 0.0);

    let m_upd = store
        .update_message_state(
            Some(10),
            Some(20),
            None,
            DataPatch::Set(WidgetData::Str(r#"{"a":1}"#)),
            DataPatch::Set(WidgetData::Str(r#"{"r":2}"#)),
        )
        .unwrap();
    assert_eq!(m_upd.chat_data.as_deref(), Some(r#"{"a":1}"#));
    assert_eq!(
        store.get_shared("wid_poll").unwrap().public_data.as_deref(),
        Some(r#"{"r":2}"#)
    );

    let sh_rec = store
        .update_shared_state("team_poll", Some(WidgetData::Str(r#"{"r":3}"#)), Some(9999))
        .unwrap();
    assert_eq!(sh_rec.cache_time, 3600);
    let ts = sh_rec.last_edit_ts.unwrap();
    assert!((store.shared_edit_delay("team_poll", Some(ts + 0.25)) - 0.75).abs() < 1e-6);
    assert_eq!(store.shared_edit_delay("wid_poll", Some(ts + 1.0)), 0.0);

    // record_vote deduplication & reload persistence
    let vote_sp = WidgetSpec {
        html: Some("<div>Vote</div>".to_string()),
        widget_id: Some("wid_vote".to_string()),
        slug: Some("lunch_poll".to_string()),
        is_shared: Some(true),
        public_data: Some(r#"{"q":"Lunch?","opts":["Pizza","Sushi","Tacos"],"v":[0,0,0],"r":0}"#.to_string()),
        ..Default::default()
    };
    store.record_sent(Some(10), Some(21), Some(&vote_sp), None).unwrap();
    let v1 = store.record_vote("lunch_poll", 101, 0, 3).unwrap();
    assert_eq!(v1.v, vec![1, 0, 0]);
    assert_eq!(v1.r, 1);
    let v2 = store.record_vote("wid_vote", 101, 2, 3).unwrap();
    assert_eq!(v2.v, vec![0, 0, 1]);
    assert_eq!(v2.r, 2);

    let reloaded = WidgetStore::open(&store_path).unwrap();
    let v3 = reloaded.record_vote("lunch_poll", 202, 1, 3).unwrap();
    assert_eq!(v3.v, vec![0, 1, 1]);
    assert_eq!(v3.r, 3);
    assert!(reloaded.record_vote("lunch_poll", 1, 0, 0).is_err());
    assert!(reloaded.record_vote("lunch_poll", 1, 3, 3).is_err());

    // apply_kv_mutation & bump_rev overflow trimming
    let (s, d) = WidgetStore::apply_kv_mutation(None, "counter:inc").unwrap();
    assert_eq!(d, json!({"count": 1, "r": 1}));
    let (s, d) = WidgetStore::apply_kv_mutation(Some(WidgetData::Str(&s)), "kv:set:env=prod").unwrap();
    assert_eq!(d["kv"], json!({"env": "prod"}));
    assert_eq!(d["r"], json!(2));
    let (_, d) = WidgetStore::apply_kv_mutation(Some(WidgetData::Str(&s)), "kv:del:env").unwrap();
    assert_eq!(d["kv"], json!({}));

    let mut big = Map::new();
    big.insert("r".to_string(), json!(4));
    big.insert("count".to_string(), json!(7));
    let mut kv_big = Map::new();
    for i in 0..12 {
        kv_big.insert(format!("k{i}"), json!("x".repeat(80)));
    }
    big.insert("kv".to_string(), Value::Object(kv_big));
    big.insert("huge".to_string(), json!("z".repeat(400)));
    let (trimmed, rev) = WidgetStore::bump_rev(&big).unwrap();
    assert_eq!(rev, 5);
    assert!(trimmed.len() <= WIDGET_DATA_LIMIT);

    // WebApp widget lifecycle
    let sk_sp = builtin_widget("skills", Some(&json!({"tab": "inst"}))).unwrap();
    let ww_id = reloaded.register_webapp_widget(&sk_sp, Some(10), None, None).unwrap();
    let bound = reloaded.bind_webapp_message(&ww_id, 10, 88, true, Some("sp")).unwrap().unwrap();
    assert_eq!(bound.chat_id, Some(10));
    assert_eq!(bound.message_id, Some(88));
    assert_eq!(bound.tab.as_deref(), Some("sp"));
    let updated_ww = reloaded
        .update_webapp_widget_state(
            &ww_id,
            DataPatch::Set(WidgetData::Str(r#"{"tab":"cat"}"#)),
            DataPatch::Unchanged,
            Some("cat"),
        )
        .unwrap()
        .unwrap();
    assert_eq!(updated_ww.tab.as_deref(), Some("cat"));
    assert_eq!(updated_ww.chat_data.as_deref(), Some(r#"{"tab":"cat"}"#));

    // Seed legacy widgets across all 5 tables + verify purge_legacy_widgets removes only legacy
    reloaded
        .record_sent(
            Some(1),
            Some(10),
            Some(&WidgetSpec {
                html: Some("<div>sys</div>".to_string()),
                widget_id: Some("leg_sys_w".to_string()),
                slug: Some("sys_status".to_string()),
                handler: Some("sys".to_string()),
                is_shared: Some(true),
                ..Default::default()
            }),
            None,
        )
        .unwrap();
    reloaded
        .record_sent(
            Some(1),
            Some(11),
            Some(&WidgetSpec {
                html: Some("<div>poll</div>".to_string()),
                widget_id: Some("leg_poll_w".to_string()),
                slug: Some("shared_poll".to_string()),
                handler: Some("poll".to_string()),
                is_shared: Some(true),
                ..Default::default()
            }),
            None,
        )
        .unwrap();
    reloaded
        .register_webapp_widget(
            &WidgetSpec {
                html: Some("<div>legacy</div>".to_string()),
                handler: Some("status".to_string()),
                slug: Some("sys_status".to_string()),
                ..Default::default()
            },
            Some(1),
            Some(12),
            Some("ww_legacy_1"),
        )
        .unwrap();
    reloaded
        .mutate(|data| {
            data.votes.insert(
                "leg_poll_w".to_string(),
                VoteRecord {
                    q: "Old".to_string(),
                    opts: vec!["A".to_string(), "B".to_string()],
                    r: 1,
                    ..Default::default()
                },
            );
            data.votes.insert(
                "poll:custom".to_string(),
                VoteRecord {
                    q: "Old2".to_string(),
                    opts: vec!["A".to_string(), "B".to_string()],
                    r: 1,
                    ..Default::default()
                },
            );
        })
        .unwrap();

    // Seed official built-ins (must survive)
    for kind in BUILTIN_WIDGET_KINDS {
        let bsp = builtin_widget(kind, Some(&json!({"k": kind}))).unwrap();
        reloaded
            .record_sent_with(RecordSentOpts {
                chat_id: Some(2),
                message_id: Some(200),
                spec: Some(&bsp),
                widget_id: Some(&format!("keep_{kind}")),
                ..Default::default()
            })
            .unwrap();
    }

    let purged = reloaded.purge_legacy_widgets().unwrap();
    assert!(purged >= 5);
    let after = WidgetStore::open(&store_path).unwrap();
    assert!(after.get_shared("sys_status").is_none());
    assert!(after.get_shared("shared_poll").is_none());
    assert!(after.get_webapp_widget("ww_legacy_1").is_none());
    assert!(!after.snapshot().votes.contains_key("leg_poll_w"));
    assert!(!after.snapshot().votes.contains_key("poll:custom"));
    assert!(after.get_webapp_widget(&ww_id).is_some());
    for kind in BUILTIN_WIDGET_KINDS {
        assert!(after.get_shared(&format!("keep_{kind}")).is_some());
    }
    assert_eq!(after.purge_legacy_widgets().unwrap(), 0);
}

// --------------------------------------------------------------------------- 4. BUILTINS & NODE VM SANDBOX

#[test]
fn builtins_all_4_compress_under_4096_and_pass_node_vm_sandbox() {
    assert_eq!(BUILTIN_WIDGET_KINDS, ["skills", "mcp", "models", "memory"]);

    for legacy in ["sys", "panel", "poll", "dash", "status", "control", "wallet"] {
        assert!(builtin_widget(legacy, None).is_err());
    }

    let mut scripts = serde_json::Map::new();
    for kind in BUILTIN_WIDGET_KINDS {
        let sp = builtin_widget(kind, Some(&json!({"init": kind}))).unwrap();
        let html = sp.html.as_deref().expect("builtin html");
        let sz = count_widget_size(html);
        assert!(sz.ok, "{kind} failed size check: {sz:?}");
        assert!(sz.raw_bytes <= WIDGET_HTML_RAW_LIMIT);
        assert!(sz.zlib_bytes < WIDGET_HTML_ZLIB_LIMIT, "{kind} zlib={}", sz.zlib_bytes);
        assert!(lint_widget_profile(html).is_empty(), "{kind} lint warnings");

        let (norm, warns) = validate_widget_spec(&sp).unwrap();
        assert!(warns.is_empty());
        assert_eq!(norm.allow_queries, Some(true));
        assert_eq!(norm.handler.as_deref(), Some(kind));
        assert_eq!(norm.slug.as_deref(), Some(format!("{kind}_hub").as_str()));
        assert!(!html.contains("'dataChanged'") && !html.contains("\"dataChanged\""));
        assert!(html.contains("chatDataChanged"));
        assert!(html.contains("richStateChanged"));
        assert!(html.contains("publicDataChanged"));

        let s_start = html.find("<script>").expect("script open") + "<script>".len();
        let s_end = html[s_start..].find("</script>").expect("script close") + s_start;
        scripts.insert(kind.to_string(), Value::String(html[s_start..s_end].to_string()));
    }

    // Node ES2023 vm syntax & QuickJS TelegramWidget host API DOM execution check
    let node_driver = r#"
    const vm = require('vm');
    const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));

    for (const [k, code] of Object.entries(input.scripts)) {
      new vm.Script(code, { filename: k + '.js' });
    }

    function makeEl(id, extra) {
      return Object.assign({
        id, innerHTML: '', textContent: '', innerText: '', className: '',
        attrs: {}, listeners: {}, _queryAll: [],
        getAttribute(k) { return (k in this.attrs) ? this.attrs[k] : null; },
        setAttribute(k, v) { this.attrs[k] = String(v); },
        querySelectorAll() { return this._queryAll; },
        addEventListener(ev, fn) {
          this.listeners[ev] = this.listeners[ev] || [];
          this.listeners[ev].push(fn);
        },
        emit(ev, evtObj) {
          for (const fn of (this.listeners[ev] || [])) fn(evtObj || { target: this, preventDefault() {} });
        }
      }, extra || {});
    }
    function makeTarget(attrs) {
      return { attrs: attrs || {}, getAttribute(k) { return (k in this.attrs) ? this.attrs[k] : null; } };
    }
    function runWidget(code, els, tgWidget) {
      const ctx = vm.createContext({
        window: { TelegramWidget: tgWidget },
        document: { getElementById(id) { return els[id] || (els[id] = makeEl(id)); } },
        Promise, JSON, Object, Array, String, Number, Boolean, Math,
      });
      ctx.window.window = ctx.window;
      new vm.Script(code).runInContext(ctx);
      return ctx;
    }
    const flush = () => new Promise((r) => setImmediate(r));

    async function main() {
      const out = {};

      // 1. skills
      {
        const calls = [];
        const events = {};
        const tabBtns = [
          makeEl('tb-inst', { attrs: { 'data-t': 'inst' } }),
          makeEl('tb-sp', { attrs: { 'data-t': 'sp' } }),
          makeEl('tb-cat', { attrs: { 'data-t': 'cat' } }),
        ];
        const els = {
          tabs: makeEl('tabs', { _queryAll: tabBtns }),
          q: makeEl('q'), list: makeEl('list'), sub: makeEl('sub'),
          grd: makeEl('grd'), err: makeEl('err'), go: makeEl('go'), ref: makeEl('ref'),
        };
        const tg = {
          richState: { tab: 'inst', q: '', can_manage: true, items: [{ name: 'alpha', desc: 'Alpha', installed: true }] },
          HapticFeedback: { selectionChanged() {}, impactOccurred() {} },
          onEvent(ev, cb) { events[ev] = cb; },
          ready() {},
          callAction(action, payload) {
            calls.push([action, payload]);
            tg.richState = { tab: payload.tab || 'sp', q: payload.q || '', can_manage: true, items: [{ id: 'coding/tdd', slug: 'tdd', name: 'tdd', source: 'skillport', installed: false }] };
            return Promise.resolve({ result: { ok: true }, richState: tg.richState });
          },
        };
        runWidget(input.scripts.skills, els, tg);
        els.tabs.emit('click', { target: makeTarget({ 'data-t': 'sp' }) });
        await flush();
        els.list.emit('click', { target: makeTarget({ 'data-a': 'in', 'data-i': '0' }) });
        await flush();
        tg.richState = { tab: 'inst', can_manage: false, items: [{ name: 'alpha', installed: true }] };
        events.richStateChanged();
        els.list.emit('click', { target: makeTarget({ 'data-a': 'del', 'data-i': '0' }) });
        out.skills = { calls, grd: els.grd.textContent, err: els.err.textContent };
      }

      // 2. mcp
      {
        const calls = [];
        const els = {
          list: makeEl('list'), sub: makeEl('sub'), err: makeEl('err'),
          ais: makeEl('ais'), aib: makeEl('aib'), ed: makeEl('ed'),
          'ed-nm': makeEl('ed-nm'), 'ed-cmd': makeEl('ed-cmd'), 'ed-args': makeEl('ed-args'),
          'ed-env': makeEl('ed-env'), 'ed-x': makeEl('ed-x'), 'ed-sv': makeEl('ed-sv'), ref: makeEl('ref'),
        };
        const tg = {
          richState: {
            can_manage: true,
            servers: [{ name: 'local', type: 'stdio', enabled: true, command: 'node', args: ['s.js'], env: { API_KEY: '••••••••', PLAIN: '1' } }],
          },
          onEvent() {}, ready() {},
          callAction(action, payload) {
            calls.push([action, payload]);
            return Promise.resolve({ result: { ok: true }, richState: tg.richState });
          },
        };
        runWidget(input.scripts.mcp, els, tg);
        els.list.emit('click', { target: makeTarget({ 'data-ed': '0' }) });
        els['ed-env'].innerText = 'API_KEY=••••••••\nPLAIN=2\n-OLD_K';
        els['ed-sv'].emit('click');
        await flush();
        els.list.emit('click', { target: makeTarget({ 'data-tg': '0' }) });
        await flush();
        out.mcp = { sub: els.sub.textContent, calls };
      }

      // 3. models
      {
        const calls = [];
        const els = { sub: makeEl('sub'), ge: makeEl('ge'), gm: makeEl('gm'), gs: makeEl('gs'), ml: makeEl('ml'), ref: makeEl('ref'), err: makeEl('err') };
        const tg = {
          richState: { model: 'm1', model_name: 'Model One', effort: 'high', mode: 'plan', stream_mode: 'live', models: [{ id: 'm1', name: 'Model One' }] },
          onEvent() {}, ready() {},
          callAction(action, payload) { calls.push([action, payload]); return Promise.resolve({ result: { ok: true }, richState: tg.richState }); },
        };
        runWidget(input.scripts.models, els, tg);
        els.ge.emit('click', { target: makeTarget({ 'data-k': 'effort', 'data-v': 'max', 'data-fb': 'mdl:eff:max' }) });
        await flush();
        out.models = { sub: els.sub.textContent, calls };
      }

      // 4. memory
      {
        const calls = [];
        const els = {
          sub: makeEl('sub'), newb: makeEl('newb'), comp: makeEl('comp'),
          ntypes: makeEl('ntypes'), ftypes: makeEl('ftypes'),
          nttl: makeEl('nttl'), nsum: makeEl('nsum'), nsv: makeEl('nsv'),
          q: makeEl('q'), go: makeEl('go'), list: makeEl('list'), ref: makeEl('ref'), err: makeEl('err'),
        };
        const tg = {
          richState: { type: 'all', q: '', total: 5, recent_24h: 2, items: [{ id: '11111111-2222-3333-4444-555555555555', type: 'decision', title: 'Atomic', summary: 'Swap' }] },
          onEvent() {}, ready() {},
          callAction(action, payload) { calls.push([action, payload]); return Promise.resolve({ result: { ok: true }, richState: tg.richState }); },
        };
        runWidget(input.scripts.memory, els, tg);
        els.newb.emit('click');
        els.nttl.innerText = 'New Rule';
        els.nsum.innerText = 'Test always';
        els.nsv.emit('click');
        await flush();
        out.memory = { sub: els.sub.textContent, calls };
      }

      process.stdout.write(JSON.stringify(out));
    }
    main().catch((e) => { console.error(e); process.exit(1); });
    "#;

    let out_raw = run_node_vm(node_driver, &json!({ "scripts": Value::Object(scripts) }));
    let out: Value = serde_json::from_str(&out_raw).unwrap();

    assert_eq!(out["skills"]["grd"], "Read-only");
    assert_eq!(out["skills"]["err"], "Permission denied");
    assert_eq!(out["skills"]["calls"][0][0], "sk_search");
    assert_eq!(out["skills"]["calls"][1][0], "sk_install");

    assert_eq!(out["mcp"]["sub"], "1/1 enabled");
    assert_eq!(out["mcp"]["calls"][0][0], "mcp_update");
    assert_eq!(out["mcp"]["calls"][0][1]["env_set"], json!({"PLAIN": "2"}));
    assert_eq!(out["mcp"]["calls"][0][1]["env_unset"], json!(["OLD_K"]));
    assert_eq!(out["mcp"]["calls"][1][0], "mcp_toggle");

    assert_eq!(out["models"]["sub"], "Model One");
    assert_eq!(out["models"]["calls"][0], json!(["mdl_set", {"effort": "max"}]));

    assert_eq!(out["memory"]["sub"], "Total: 5 · 24h: 2");
    assert_eq!(out["memory"]["calls"][0][0], "mem_add");
}

#[test]
fn builtins_inline_article_preview_and_in_bubble_cards() {
    let sp = builtin_widget("models", Some(&json!({
        "model": "m1",
        "model_name": "Model One",
        "effort": "high",
        "models": [{"id": "m1", "name": "Model One"}]
    })))
    .unwrap();
    let article = build_inline_widget_article("res_1", "Models", &sp, Some("Pick model")).unwrap();
    assert_eq!(article.kind, "article");
    assert_eq!(article.input_message_content["allow_queries"], json!(true));

    let preview = render_standalone_preview_html(&sp).unwrap();
    assert!(preview.contains("Models &amp; Reasoning"));
    assert!(preview_summary_text(&sp).contains("zlib-9"));

    let dir = TempDir::new().unwrap();
    let store = WidgetStore::open(dir.path().join("widgets.json")).unwrap();
    let wid = store.register_webapp_widget(&sp, Some(10), Some(20), None).unwrap();
    let rec = store.get_webapp_widget(&wid).unwrap();
    let prem = PremiumState::new(true);
    let (md, mk): (String, InlineKeyboardMarkup) =
        render_in_bubble_widget(&rec, Some("https://example.org/w/abc"), None, &prem).unwrap();
    assert!(md.contains("Models & Reasoning"));
    assert!(md.contains("Model One"));
    let all_btns: Vec<_> = mk.inline_keyboard.iter().flatten().collect();
    assert!(all_btns.iter().any(|b| b.web_app.is_some()));
    for b in all_btns {
        if let Some(ref cb) = b.callback_data {
            assert!(cb.len() <= 64, "callback_data too long: {cb}");
        }
    }
}

// --------------------------------------------------------------------------- 5. WEBAPP HMAC & AXUM ROUTER

struct MockWebAppBridge {
    state_changed: Mutex<Vec<String>>,
    deny_action: bool,
}

impl MockWebAppBridge {
    fn new(deny_action: bool) -> Arc<Self> {
        Arc::new(Self {
            state_changed: Mutex::new(Vec::new()),
            deny_action,
        })
    }
}

impl WidgetBridge for MockWebAppBridge {
    fn query_widget<'a>(
        &'a self,
        _wid: &'a str,
        _kind: &'a str,
        data: &'a str,
        uid: i64,
        _chat_id: Option<i64>,
    ) -> BoxFuture<'a, Result<BridgeQueryResponse>> {
        Box::pin(async move {
            Ok(BridgeQueryResponse {
                result: json!({ "ok": true, "echo": data, "uid": uid }),
                chat_data: Some(json!({ "last_q": data })),
                public_data: None,
            })
        })
    }

    fn call_action<'a>(
        &'a self,
        _wid: &'a str,
        _kind: &'a str,
        action: &'a str,
        payload: &'a Value,
        _uid: i64,
        _chat_id: Option<i64>,
    ) -> BoxFuture<'a, Result<BridgeActionResponse>> {
        let deny = self.deny_action;
        Box::pin(async move {
            if deny {
                return Ok(BridgeActionResponse::rejected(403, "Permission denied"));
            }
            Ok(BridgeActionResponse {
                ok: true,
                status: 200,
                error: None,
                result: json!({ "ok": true, "action": action, "payload": payload }),
                chat_data: Some(json!({ "tab": "sp" })),
                public_data: None,
                rich_state: Some(json!({ "tab": "sp", "items": [] })),
            })
        })
    }

    fn get_rich_state<'a>(
        &'a self,
        _wid: &'a str,
        kind: &'a str,
        uid: i64,
        _chat_id: Option<i64>,
    ) -> BoxFuture<'a, Result<Option<Value>>> {
        Box::pin(async move { Ok(Some(json!({ "kind": kind, "uid": uid, "ready": true }))) })
    }

    fn on_state_changed<'a>(&'a self, wid: &'a str) -> BoxFuture<'a, ()> {
        let wid_s = wid.to_string();
        Box::pin(async move {
            self.state_changed.lock().unwrap().push(wid_s);
        })
    }
}

#[test]
fn webapp_hmac_init_data_verification_valid_expired_bad_sig_and_unapproved() {
    let token = "123456:TEST_TOKEN_XYZ";
    let mut allowed = HashSet::new();
    allowed.insert(1000000001_i64);
    let user_ok = r#"{"id":1000000001,"first_name":"Owner"}"#;
    let now = 1_700_000_000_i64;

    let valid = sign_init_data(token, user_ok, now - 10, Some("q1"));
    let v = verify_webapp_init_data_at(&valid, token, &allowed, 3600, now).unwrap();
    assert_eq!(v.uid, 1000000001);
    assert_eq!(v.query_id.as_deref(), Some("q1"));

    // Expired auth_date
    let expired = sign_init_data(token, user_ok, now - 5000, None);
    let err_exp = verify_webapp_init_data_at(&expired, token, &allowed, 3600, now).unwrap_err();
    assert!(matches!(err_exp, BridgeError::Auth(_)));

    // Wrong signature
    let bad_sig = valid.replacen("hash=", "hash=0000", 1);
    let err_sig = verify_webapp_init_data_at(&bad_sig[..valid.len()], token, &allowed, 3600, now);
    assert!(matches!(err_sig, Err(BridgeError::Auth(_))));

    // Signed by valid Telegram token, but uid not in allowed_uids -> PermissionDenied
    let stranger_init = sign_init_data(token, r#"{"id":999999,"first_name":"Stranger"}"#, now - 5, None);
    let err_uid = verify_webapp_init_data_at(&stranger_init, token, &allowed, 3600, now).unwrap_err();
    assert!(matches!(err_uid, BridgeError::PermissionDenied(_)));
}

#[tokio::test]
async fn webapp_router_endpoints_health_shell_init_query_action_state_and_auth_rejections() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(WidgetStore::open(dir.path().join("widgets.json")).unwrap());
    let sp = builtin_widget("skills", Some(&json!({"tab": "inst"}))).unwrap();
    let wid = store.register_webapp_widget(&sp, Some(100), Some(200), Some("wid-test-1")).unwrap();

    let token = "123456:ROUTER_TEST_TOKEN";
    let mut allowed = HashSet::new();
    allowed.insert(1000000001_i64);
    let bridge = MockWebAppBridge::new(false);

    let token_prov: TokenProvider = Arc::new(move || token.to_string());
    let uids_prov: AllowedUidsProvider = Arc::new(move || allowed.clone());
    let state = WebAppState::with_providers(token_prov, uids_prov, Arc::clone(&store), bridge.clone());
    let app = build_webapp_router(state);

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let valid_init = sign_init_data(token, r#"{"id":1000000001,"first_name":"F"}"#, now_unix - 10, None);
    let expired_init = sign_init_data(token, r#"{"id":1000000001,"first_name":"F"}"#, now_unix - 200_000, None);
    let wrong_sig_init = sign_init_data("wrong:token", r#"{"id":1000000001,"first_name":"F"}"#, now_unix - 10, None);
    let unapproved_init = sign_init_data(token, r#"{"id":9001,"first_name":"S"}"#, now_unix - 10, None);

    // 1. /healthz -> 200
    let r_health = app
        .clone()
        .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r_health.status(), StatusCode::OK);

    // 2. /w/{wid} -> 200 with security headers, unknown -> 404
    let r_shell = app
        .clone()
        .oneshot(Request::builder().uri(format!("/w/{wid}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r_shell.status(), StatusCode::OK);
    let csp = r_shell.headers().get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.contains("frame-ancestors 'self' https://web.telegram.org"));
    assert_eq!(r_shell.headers().get("referrer-policy").unwrap(), "no-referrer");
    assert!(r_shell.headers().contains_key("permissions-policy"));
    assert_eq!(r_shell.headers().get("cache-control").unwrap(), "no-store");

    let r_404 = app
        .clone()
        .oneshot(Request::builder().uri("/w/missing-wid").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r_404.status(), StatusCode::NOT_FOUND);

    // 3. Auth rejection cases on /api/w/{wid}/init (expired, wrong sig, unapproved uid)
    for bad_init in [expired_init, wrong_sig_init, unapproved_init] {
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/w/{wid}/init"))
            .header("content-type", "application/json")
            .body(Body::from(json!({ "initData": bad_init }).to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // 4. Valid /init -> 200 with html & richState
    let r_init = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/w/{wid}/init"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "initData": valid_init }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_init.status(), StatusCode::OK);
    let init_bytes = r_init.into_body().collect().await.unwrap().to_bytes();
    let init_json: Value = serde_json::from_slice(&init_bytes).unwrap();
    assert_eq!(init_json["ok"], json!(true));
    assert_eq!(init_json["richState"]["kind"], json!("skills"));

    // 5. /query -> 200 + updates store + calls on_state_changed
    let r_query = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/w/{wid}/query"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "initData": valid_init, "data": "ping" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_query.status(), StatusCode::OK);
    let q_bytes = r_query.into_body().collect().await.unwrap().to_bytes();
    let q_json: Value = serde_json::from_slice(&q_bytes).unwrap();
    assert_eq!(q_json["result"]["echo"], json!("ping"));
    assert_eq!(q_json["chatData"]["last_q"], json!("ping"));

    // 6. /action -> 200 + updates store
    let r_act = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/w/{wid}/action"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "initData": valid_init, "action": "sk_search", "payload": { "tab": "sp" } }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_act.status(), StatusCode::OK);
    let a_bytes = r_act.into_body().collect().await.unwrap().to_bytes();
    let a_json: Value = serde_json::from_slice(&a_bytes).unwrap();
    assert_eq!(a_json["richState"]["tab"], json!("sp"));

    // 7. /state -> 200 reflecting persisted state
    let r_state = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/w/{wid}/state"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "initData": valid_init }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_state.status(), StatusCode::OK);
    let s_bytes = r_state.into_body().collect().await.unwrap().to_bytes();
    let s_json: Value = serde_json::from_slice(&s_bytes).unwrap();
    assert_eq!(s_json["ok"], json!(true));
    assert!(s_json["chatData"].as_str().unwrap().contains("\"tab\":\"sp\""));
    assert_eq!(bridge.state_changed.lock().unwrap().len(), 2);

    // 8. Denied action bridge -> 403
    let deny_app = build_webapp_router(WebAppState::new(
        token,
        HashSet::from([1000000001_i64]),
        Arc::clone(&store),
        MockWebAppBridge::new(true),
    ));
    let r_deny = deny_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/w/{wid}/action"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "initData": valid_init, "action": "sk_install", "payload": {} }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_deny.status(), StatusCode::FORBIDDEN);

    // 9. Per-UID /api/w/* rate limiter returns 429 on flood
    let rl_app = build_webapp_router(
        WebAppState::new(
            token,
            HashSet::from([1000000001_i64]),
            store,
            MockWebAppBridge::new(false),
        )
        .with_api_uid_rate_limit(10), // burst clamps to 15
    );
    let mut hit_429 = false;
    for _ in 0..20 {
        let resp = rl_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/w/{wid}/state"))
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "initData": valid_init }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            hit_429 = true;
            assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
            break;
        }
        assert_eq!(resp.status(), StatusCode::OK);
    }
    assert!(hit_429, "per-UID /api/w/* rate limiter must return 429 on burst flood");
}
