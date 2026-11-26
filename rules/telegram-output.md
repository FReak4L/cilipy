---
trigger: always_on
description: Answer formatting for prompts starting with [telegram-bridge]
---

# Telegram output (only for prompts starting with `[telegram-bridge]`)

Read on a phone. The final text is sent as a Telegram Rich Message (GFM) with automatic HTML fallback. Full docs: `/root/agy-workspace/telegram-docs/`.

## Write
- GFM: `##` headings, lists, task lists, tables (≤5 columns on mobile, inline formatting only), fenced code with a language, quotes, `---`, footnotes, `$math$`, `==mark==`, `||spoiler||`.
- Extra HTML: `<u> <sub> <sup> <tg-spoiler>`, `<details><summary>…</summary>…</details>` for long or secondary content, `<aside>`.
- Literal `<` or `&` outside code: write `&lt;` / `&amp;` or use backticks. Inline media: http(s) URLs only.

## Style
Answer first, short paragraphs, minimal emoji, no sign-offs, don't repeat the question. Reply in the user's language (Persian or English); code, paths and commands in code formatting. Never print secrets.

## Files
User attachments: local paths listed in the prompt (≤20 MB). To send files, save them in the outbox folder named in the prompt (image→photo, mp4→video, mp3→audio, ogg→voice, else document; ≤50 MB each, ≤10 per turn). Code over ~80 lines, whole configs, logs, wide tables → put in a file and summarize.

## Limits
Rich message 32,768 chars and 500 blocks (split on blank lines outside fences). Classic 4,096. Caption 1,024. Callback data 64 bytes.

## Buttons (only for real choices)
```html
<tg-button-row>
 <tg-button type="callback_data" style="primary" data="ask:run the tests">Run tests</tg-button>
 <tg-button type="copy_text" text="systemctl status nginx">Copy cmd</tg-button>
 <tg-button type="url" url="https://example.com">Open</tg-button>
</tg-button-row>
```
`callback_data` must start with `ask:`; the rest arrives as the next user message.

## Premium and widgets
- Custom emoji, at most 1–3 per answer, alt text = the matching emoji: `![✅](tg://emoji?id=5427009714745517609)`. More IDs: `telegram-docs/06-premium-features.md`.
- Widgets (`<tg-widget …>` outside code fences, or outbox `*.widget.html` / `*.widget.json`): read `telegram-docs/07-widgets.md` first (size, data and sandbox limits).

Session continuity: follow `session-handoff.md`.
