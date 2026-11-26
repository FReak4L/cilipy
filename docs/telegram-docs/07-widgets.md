# 07 · HTML Widgets (Bot API 10.4)

Interactive HTML widgets introduced in **Bot API 10.4 (November 9, 2026)** render live,
self-contained HTML/CSS/JS inside a chat message bubble. Code executes in an isolated
**QuickJS ES2023** thread with **zero network access** and a strict **Profile-1** DOM/CSS
allowlist. Widget markup is immutable once sent; dynamic updates happen through bot-written
`public_data` and `chat_data` plus lightweight widget queries (`TelegramWidget.request()`).

## 1. Production vs. test server
| Capability | Production | Telegram Test Server |
|---|---|---|
| Where widgets can be sent | **Private chats only** | Private chats, groups, supergroups |
| Content protection | Forced (`protect_content=True`, no forwarding) | Forwarding allowed (for shared widgets) |
| Inline queries (`InputWidgetMessageContent`, `InputSharedWidgetMessageContent`) | Rejected | Supported |
| `SharedWidgetQuery` (forwarded shared widgets) | Not reachable (forwarding blocked) | Supported |

In `agy-telegram`, `/opt/agy-telegram/app/auth.py` accepts `widget_query` from allow-listed
users in private chats (`chat.type == "private"` or `chat_type in ("private", "sender")`),
accepts `shared_widget_query` from allow-listed users, and drops `inline_query` unless
`ALLOW_INLINE_WIDGETS=1` is set in the environment.

### Dual In-Telegram Execution (Production Compatibility)
When Telegram's cloud Bot API temporarily gates general bots with `INPUT_MEDIA_WIDGET_NOT_ALLOWED`, `agy-telegram` automatically renders the widget **directly inside Telegram** via its dual engine (`/opt/agy-telegram/app/webapp.py`):
1. **In-Bubble Rich Card:** live Rich Markdown table/status + `wact:<wid>:...` inline buttons that update the bubble in-place.
2. **Native Telegram `WebApp` Sheet:** a `WebAppInfo` button (`https://example.sslip.io/w/<wid>`) opening the exact HTML widget inside Telegram's native sheet with HMAC-SHA256 `initData` auth, `richState`, and a full `window.TelegramWidget` (`request`, `callAction`) -> `Telegram.WebApp` live bridge.

Built-in interactive hub widgets: `skills` (Skills Manager), `mcp` (MCP Servers & config editor), `models` (Models & reasoning config), `memory` (AI Memory browser/editor).

---

## 2. Sending widgets via `agy-telegram`

### Inline tags in your final answer
Place widget tags **outside** Markdown code fences (tags inside ```` ```...``` ```` are shown as
code, never rendered as widgets).

**New widget:**
```html
<tg-widget
  caption="Service status"
  width="340"
  height="160"
  allow-queries="true"
  is-shared="true"
  cache-time="10"
  slug="svc-status"
  handler="status"
  public-data='{"state":"ok"}'
  chat-data='{"clicks":0}'>
<!doctype html>
<html>...</html>
</tg-widget>
```

**Re-send a shared widget by ID:**
```html
<tg-shared-widget widget-id="WGT_ID" caption="Shared live card"/>
```
Optional `chat-data='...'` sets per-chat initial state when re-sending.

Key attributes on `<tg-widget>`:
- `caption` — text below/above widget (≤ 1,024 chars).
- `width` / `height` — logical px hints (`200..600` width, `50..600` height; `0` or omitted = auto).
- `allow-queries` — `"true"` enables `TelegramWidget.request(...)` and `wallet` APIs.
- `is-shared` — `"true"` creates a server-side shared widget with a reusable `widget_id`.
- `cache-time` — shared polling cache hint (`5..3600` s).
- `slug` — bridge alias for `/widget list`, `/widget resend`, `/widget edit`.
- `handler` — bridge query handler (`sys`/`status`, `poll`, `ctl`/`control`, `wallet`, `kv`, `counter`, `agy`, or custom).
- `public-data` / `chat-data` — initial state strings (≤ 1,024 UTF-8 bytes each).

### Outbox files
Save widget files in the turn's outbox (`/root/agy-workspace/outbox/<user_id>/<job_id>/`):
- **`*.widget.html`** — standalone widget HTML document. May begin with a JSON metadata header:
  ```html
  <!-- widget: {"caption": "Quick check", "width": 340, "height": 150, "allow_queries": true, "is_shared": false, "cache_time": 10, "slug": "quick-check", "handler": "control", "public_data": "", "chat_data": "{}"} -->
  <!doctype html>
  ```
- **`*.widget.json`** — declarative widget action object supporting four actions:
  - `send` — send HTML widget (`html` or `html_file`, `caption`, `width`, `height`, `allow_queries`, `is_shared`, `cache_time`, `slug`, `handler`, `public_data`, `chat_data`).
  - `send_shared` — re-send shared widget (`widget_id`, optional `chat_data`, `caption`).
  - `edit_message_data` — update `public_data` / `chat_data` on an existing message (`chat_id`, `message_id` or `inline_message_id`, `public_data`, `chat_data`).
  - `edit_shared_data` — update shared widget global state (`widget_id`, `public_data`, optional `cache_time`).

### Bot commands
- `/widget` — usage overview and quick actions.
- `/widget skills|mcp|models|memory` — send one of the 4 built-in interactive widgets (`skills`, `mcp`, `models`, `memory`).
- `/widget list` — list tracked widgets sent in the session.
- `/widget resend` — re-send a tracked or shared widget.
- `/widget edit` — update `public_data` or `chat_data` on a widget.
- `/widget shared` — inspect shared widget IDs and state.
- `/widget check` — validate raw UTF-8 size, `zlib-9` compressed size, and Profile-1 compliance.

---

## 3. Bot API 10.4 methods and types (`aiogram==3.32.0`)

### Methods
| Method | Key parameters | Returns / notes |
|---|---|---|
| `sendWidget` | `chat_id`, `html`, `width?`, `height?`, `public_data?`, `chat_data?`, `caption?`, `parse_mode?`, `caption_entities?`, `show_caption_above_media?`, `allow_queries?`, `is_shared?`, `message_thread_id?`, `disable_notification?`, `protect_content?`, `allow_paid_broadcast?`, `message_effect_id?`, `reply_parameters?`, `reply_markup?` | `Message` (contains `message.widget`) |
| `sendSharedWidget` | `chat_id`, `widget_id`, `chat_data?`, `caption?`, `parse_mode?`, `caption_entities?`, `show_caption_above_media?`, `message_thread_id?`, `disable_notification?`, `protect_content?`, `allow_paid_broadcast?`, `message_effect_id?`, `reply_parameters?`, `reply_markup?` | `Message` |
| `answerWidgetQuery` | `widget_query_id`, `data?` | `True`. Must answer within **15 s**. Delivered only to querying widget; does **not** edit widget data |
| `editMessageWidgetData` | `chat_id?`, `message_id?`, `inline_message_id?`, `public_data?`, `chat_data?` | `True`. Shared `public_data` edits capped at **1/s** |
| `editSharedWidgetData` | `widget_id`, `public_data`, `cache_time?` | `True`. Rate-limited to **1 edit/s** |

### Types
- **`Widget`** — `html`, `id?`, `width?`, `height?`, `public_data?`, `chat_data?`.
- **`WidgetQuery`** — `id`, `from_user` (`from`), `chat_instance`, `type`, `data`, `chat?`, `message_id?`, `inline_message_id?`, `chat_type?`, `widget_id?`.
- **`SharedWidgetQuery`** — `id`, `from_user` (`from`), `type`, `data`, `widget_id`.
- **`WidgetQueryType*` union** (discriminated on `type`):
  - `WidgetQueryTypeData` — `type="data"`, `wallet_card?: TonWalletCard` (`address`, `amount`, `stickers`, `background_nft_address?`).
  - `WidgetQueryTypeSignData` — `type="sign_data"`, `wallet: WidgetQueryWallet`, `sign_data` (signed for domain `bot<bot_id>`).
  - `WidgetQueryTypeSentTransaction` — `type="sent_transaction"`, `wallet: WidgetQueryWallet`, `msg_hash`.
  - `WidgetQueryWallet` — `address`, `amount`, `public_key?`, `state_init?`.
- **`InputWidgetMessageContent`** — `html`, `width?`, `height?`, `public_data?`, `chat_data?`, `caption?`, `parse_mode?`, `caption_entities?`, `show_caption_above_media?`, `allow_queries?`, `is_shared?` (inline queries; test server only).
- **`InputSharedWidgetMessageContent`** — `widget_id`, `chat_data?`, `caption?`, `parse_mode?`, `caption_entities?`, `show_caption_above_media?` (inline queries; test server only).

---

## 4. Hard limits
| Resource / parameter | Hard limit | Notes |
|---|---|---|
| Raw HTML size | **32,768 bytes** | UTF-8 encoded string |
| Compressed HTML size | **4,096 bytes** | `zlib.compress(html.encode(), 9)` |
| `chat_data` / `public_data` | **1,024 UTF-8 bytes** | Each field independently (`""` clears on edit) |
| `answerWidgetQuery.data` | **1,024 UTF-8 bytes** | Returned to querying widget (`{ result }`) |
| `caption` | **1,024 chars** | Standard media caption limit |
| `TelegramWidget.request(data)` | **64 bytes** | Payload sent in query |
| `answerWidgetQuery` deadline | **15 s** | Query expires after 15 s |
| User query rate | **5 req / 5 s** | Per user across all their widgets |
| Shared widget edit rate | **1 edit / s** | `editSharedWidgetData` & shared `public_data` |
| Shared `cache_time` | **5..3600 s** | Client refresh interval when `watchPublicData()` active |
| Bubble width | **200..600 px** | `0` / omitted = auto (mobile ~320–430 px) |
| Bubble height | **50..600 px** | `0` / omitted = auto; overflow is clipped |
| DOM nodes | **2,000 nodes** | Elements + text + comment nodes |
| JS heap / memory | **8 MB** | QuickJS runtime cap |
| CPU budget | **300 ms / s** | Sustained per second |
| Single JS task | **500 ms max** | Exceeding stops widget ("Widget stopped") |
| Heavy visual effects | **16 elements max** | Blurred shadow, `filter`, `backdrop-filter`, or `opacity < 1` |
| `backdrop-filter` | **2 elements max** | Prefer solid/RGBA theme colors where possible |

---

## 5. Profile-1 sandbox rules (HTML, SVG, CSS, QuickJS)

### HTML
- **Allowed:** Layout/semantic tags (`div`, `p`, `span`, `header`, `footer`, `main`, `nav`, `section`, `article`, `aside`, `pre`, `blockquote`, `figure`, `figcaption`), headings (`h1`–`h6`), inline formatting (`b`, `i`, `u`, `s`, `em`, `strong`, `small`, `mark`, `code`, `kbd`, `sub`, `sup`, `abbr`, `cite`, `q`, `del`, `ins`, `time`, `br`, `hr`), lists & tables (`ul`, `ol`, `li`, `dl`, `dt`, `dd`, `menu`, `table`, `thead`, `tbody`, `tfoot`, `tr`, `th`, `td`, `caption`, `colgroup`, `col` with `colspan`/`rowspan`, `details`, `summary`), `<button>`, `<canvas>`, `<img src="data:image/(png|jpeg|gif|webp);...">`, `<a href="#id">`, `<a href="https://...">` (opens via `openLink` on tap). Attributes: `class`, `id`, `style`, `title`, `hidden`, `lang`, `dir`, `data-*`, `aria-*`, inline `on*`.
- **Forbidden:** Form inputs (`input`, `select`, `textarea`, `option`, `fieldset`, `form`), `progress`, `meter`, `dialog`, popovers, `audio`, `video`, `iframe`, `object`, `embed`, `<script src="...">`, `<link>`, `<meta>`, `<template>`, `<math>`, `<ruby>`, legacy `center`/`font`, external image URLs, `data:image/svg+xml`, `avif`, `bmp`, `ico`.

### Inline SVG
- **Allowed:** `<svg viewBox="...">`, shapes & paths (`path`, `rect`, `circle`, `ellipse`, `line`, `polyline`, `polygon`), `<g>`, `<defs>`, `<symbol>`, `<use href="#...">`, `transform`, `<text>`, `<tspan>`, `<linearGradient>`, `<radialGradient>`, `<stop>`, CSS fills/strokes and CSS animations on SVG properties.
- **Forbidden:** `clipPath`, `mask`, `pattern`, `marker`, SVG filter primitives (`<filter>`, `fe*`), SMIL animations (`animate`, `animateTransform`, `animateMotion`).

### CSS
- **Allowed:** Flexbox, CSS Grid, `%`, `vw` (bubble width), `vmin`, `calc()`, CSS custom properties, transitions, transforms, `@keyframes`, `prefers-reduced-motion`, `position: fixed` (scoped to bubble), `touch-action`.
- **Forbidden / rewritten:** `vh` (removed), `position: sticky` (becomes `relative`), `overflow: auto/scroll` (becomes `hidden`), external `@import` / `url(https://...)`, and > 400 CSS rules. Use `--tg-theme-*` or `rgba()` instead of `opacity < 1` to avoid the 16-element heavy-effect limit.

### QuickJS ES2023 runtime
- Runs ES2023 on an isolated thread (no JIT — keep frame callbacks fast).
- Supports `Promise`, `async/await`, `setTimeout`/`setInterval`, `requestAnimationFrame`, `eval`, `new Function`, and per-message `localStorage` (persisted per message on device).
- **Zero network access:** `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `RTCPeerConnection`, and `Worker` throw `NetworkDisabledError`. No `location`/`history` navigation or cookies.

---

## 6. `touch-action` gesture matrix & safe areas

Widgets share the bubble with chat scrolling, swipe-to-reply, and long-press menus. Vertical
dragging inside a widget is **never** allowed (use horizontal sliders or buttons instead); a
double-tap is two taps within 300 ms and 40 px.

| `touch-action` | Widget receives | Chat retains | Use for |
|---|---|---|---|
| `auto` (default) | Tap, double-tap | Vertical scroll, swipe-to-reply, long-press menu | Static text, cards, standard buttons |
| `pan-y` | Tap, double-tap, **horizontal drag** | Vertical scroll | Horizontal sliders, carousels, tabs |
| `none` | Tap, double-tap, **hold & free drag** | Vertical scroll outside the element | Hold buttons, canvases, game pads |

### Safe-area padding (timestamp & corner clearance)
When a widget has no caption, Telegram overlays the message timestamp/ticks in a bottom corner.
Reset `body { padding: 0; }` if managing safe-area yourself, and pad bottom controls using:
```css
.footer {
  padding-bottom: max(8px, env(safe-area-inset-bottom));
  padding-right: max(12px, var(--tg-content-safe-area-corner-right));
  padding-left: max(12px, var(--tg-content-safe-area-corner-left));
}
```
Variables exposed: `env(safe-area-inset-bottom)`, `--tg-content-safe-area-inset-bottom`,
`--tg-content-safe-area-corner-left`, `--tg-content-safe-area-corner-right` (the non-covered
side is `0`), mirrored in JS as `TelegramWidget.contentSafeAreaInset`.

---

## 7. `window.TelegramWidget` & `wallet` API reference

### Properties
- `publicData` / `chatData` — current state strings pushed by the bot.
- `isShared` / `allowQueries` — booleans reflecting send flags.
- `isActive` — `true` while widget is visible on screen.
- `viewer` — current viewer info (`id`, `name`/`first_name`, `username`, `is_premium`).
- `colorScheme` — `'light'` or `'dark'`.
- `themeParams` — chat palette (`bg_color`, `text_color`, `hint_color`, `link_color`, `button_color`, `button_text_color`, `secondary_bg_color`, etc.), also exposed as `--tg-theme-*` CSS variables.
- `contentSafeAreaInset` — current safe-area inset metrics.

### Methods & events
- `request(data, options?)` → `Promise` — send `data` (≤ 64 bytes) to bot (`widget_query` / `shared_widget_query`). Pass `{ wallet: true }` to include `TonWalletCard`.
- `watchPublicData()` / `unwatchPublicData()` — subscribe/unsubscribe to shared `publicData` updates while visible.
- `onEvent(event, cb)` / `offEvent(event, cb)` — events: `chatDataChanged`, `publicDataChanged`, `themeChanged`, `activated`, `deactivated`, `contentSafeAreaChanged`.
- `openLink(url)` / `openTelegramLink(url)` — open external `https://` or `tg://` links.
- `HapticFeedback`: `impactOccurred('light'|'medium'|'heavy'|'rigid'|'soft')`, `notificationOccurred('error'|'success'|'warning')`, `selectionChanged()`.

### `window.TelegramWidget.wallet`
`null` if no wallet is available, `allow_queries` is false, or in preview; check `if (TelegramWidget.wallet)` before rendering wallet controls. Limited to **1 wallet call per user tap or bot answer** (`'REJECTED'` / `'BAD_REQUEST'` on failure):
- `wallet.sendTransaction(tx, data)` — `tx = { valid_until, messages: [{ address, amount, payload?, stateInit? }] }` (1–255 messages, `amount` in nanotons string). After a tap-triggered `request(..., { wallet: true })`, stays authorized for **10 s** without a second tap; triggers `sent_transaction` query with `msg_hash`.
- `wallet.signData(payload, data)` — sign `{ type: 'text' | 'binary' | 'cell', ... }` for domain `bot<bot_id>`; triggers `sign_data` query.

---

## 8. Apple-HIG minimal widget example

Clean surface, low element density, theme-adaptive CSS variables, soft-raised tactile button,
safe-area corner padding, haptic tap feedback, and live state sync (well under 4,096 bytes `zlib-9`):

```html
<!doctype html>
<html>
<head>
<style>
  * { box-sizing: border-box; margin: 0; }
  body {
    padding: 14px 16px max(12px, env(safe-area-inset-bottom));
    font: 14px/1.35 -apple-system, system-ui, sans-serif;
    color: var(--tg-theme-text-color, #111);
    background: var(--tg-theme-bg-color, #fff);
  }
  .card { display: flex; flex-direction: column; gap: 10px; }
  .row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .title { font-weight: 600; font-size: 15px; letter-spacing: -0.01em; }
  .sub { font-size: 12px; color: var(--tg-theme-hint-color, #6b7280); }
  .pill {
    padding: 3px 9px; border-radius: 999px; font-size: 12px; font-weight: 600;
    background: var(--tg-theme-secondary-bg-color, #f2f3f5);
  }
  .foot {
    display: flex; align-items: center; justify-content: space-between; gap: 10px;
    padding-right: max(0px, var(--tg-content-safe-area-corner-right, 0px));
    padding-left: max(0px, var(--tg-content-safe-area-corner-left, 0px));
  }
  button {
    touch-action: none; border: 0; border-radius: 10px; padding: 8px 14px;
    font: 600 13px/1 -apple-system, system-ui, sans-serif; cursor: pointer;
    color: var(--tg-theme-button-text-color, #fff);
    background: var(--tg-theme-button-color, #2481cc);
    box-shadow: 0 1px 2px rgba(0,0,0,.14), inset 0 1px 0 rgba(255,255,255,.18);
  }
  button:active { transform: scale(0.97); }
  button:disabled { opacity: 0.5; }
</style>
</head>
<body>
<div class="card">
  <div class="row">
    <div>
      <div class="title" id="t">Staging Deploy</div>
      <div class="sub" id="s">Ready</div>
    </div>
    <span class="pill" id="b">idle</span>
  </div>
  <div class="foot">
    <span class="sub" id="m">Tap to check</span>
    <button id="btn" type="button">Ping</button>
  </div>
</div>
<script>
  const w = window.TelegramWidget;
  const $ = (id) => document.getElementById(id);
  function render() {
    let d = {};
    try { d = JSON.parse(w.chatData || w.publicData || "{}"); } catch {}
    $("b").textContent = d.status || "idle";
    $("s").textContent = d.note || "Ready";
    $("m").textContent = d.updated || "Tap to check";
  }
  $("btn").onclick = () => {
    w.HapticFeedback && w.HapticFeedback.selectionChanged();
    $("btn").disabled = true;
    w.request("ping").then(
      (r) => { $("m").textContent = (r && r.result) || (typeof r === "string" ? r : "ok"); },
      () => { $("m").textContent = "Query failed"; }
    ).finally(() => { $("btn").disabled = false; });
  };
  w.onEvent("chatDataChanged", render);
  w.onEvent("publicDataChanged", render);
  render();
</script>
</body>
</html>
```
