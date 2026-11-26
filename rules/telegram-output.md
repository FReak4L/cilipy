---
trigger: always_on
description: User-facing Telegram Rich Message output contract (only for [telegram-bridge] prompts)
---

<output_contract scope="[telegram-bridge]">
# Internal reasoning/rules are AI-native; ONLY final Telegram replies use natural user language (Persian/English).
FORMAT: GFM Rich Message (auto HTML fallback; docs: /root/agy-workspace/telegram-docs/).
  ALLOWED_GFM: ## headings, lists, tasks, tables(<=5 cols, inline only), fenced code+lang, quotes, ---, footnotes, $math$, ==mark==, ||spoiler||.
  ALLOWED_HTML: <u> <sub> <sup> <tg-spoiler> <details><summary>...</summary>...</details> <aside>.
  ESCAPE: literal < or & outside code -> &lt; / &amp; or backticks. Inline media: http(s) only.
STYLE: answer-first, short mobile paragraphs, minimal emoji, no sign-offs, never repeat question, match user language (Persian/English), code-format paths/cmds, NEVER print secrets.
FILES: user attachments <=20MB; send deliverables via prompt outbox dir (img->photo, mp4->video, mp3->audio, ogg->voice, else doc; <=50MB, <=10/turn). Code >80L, full configs, logs, wide tables -> outbox file + summary.
LIMITS: rich 32768c/500 blocks (split blank lines outside fences); classic 4096c; caption 1024c; callback_data 64B.
BUTTONS (real choices only; callback_data MUST start with `ask:`):
  <tg-button-row><tg-button type="callback_data" style="primary" data="ask:...">Label</tg-button><tg-button type="copy_text" text="...">Copy</tg-button><tg-button type="url" url="https://...">Open</tg-button></tg-button-row>
PREMIUM: <=1-3 custom emoji (`![✅](tg://emoji?id=5427009714745517609)`); widgets (`<tg-widget>` or outbox `*.widget.html|json`) -> read telegram-docs/07-widgets.md first.
CONTINUITY: follow session-handoff.md.
</output_contract>
