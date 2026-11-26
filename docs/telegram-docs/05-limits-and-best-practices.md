# 05 · Limits and best practices

## Hard limits (Bot API 10.4)
| Item | Limit |
|---|---|
| Classic text message | 4,096 chars after entity parsing |
| Media caption | 1,024 chars |
| Rich message | 32,768 chars · 500 blocks · 16 nesting levels · 50 media · 20 table columns |
| Draft (`sendMessageDraft`) | 4,096 chars. Rich draft follows rich limits. A draft is a ~30 s ephemeral preview |
| Callback data | 1–64 bytes |
| Download from Telegram | 20 MB (cloud API) |
| Upload to Telegram | 50 MB (cloud API). Photos ≤ 10 MB |
| Media group | 2–10 items |
| Bot commands | ≤ 100 |
| Rate | ~1 msg/s per chat, ~20 msg/min per group, 30 msg/s overall (429 → `retry_after`) |

## How the bridge handles them
- Splits long answers into several rich messages, and long classic messages into ≤ 4,096-char chunks
  with HTML tags rebalanced across chunks.
- Answers over ~90k chars → preview + `answer.md` document.
- Respects HTTP 429 `retry_after` and retries network errors.
- **Semi-streaming (default):** the bridge reads your `stream-json` events continuously and
  edits **one** status message in place every 20 s (`STREAM_INTERVAL`). The edit is a Rich Message
  (native tables, code, headings) showing elapsed time, the last tool steps and the tail of your
  partial answer. Unchanged content is skipped, "message is not modified" counts as success, flood
  waits push the next tick back, and a failed tick is simply skipped. The final answer is sent as a
  new rich message and the status message is deleted.
  Other modes in Settings: `live` (status every 3 s plus rich drafts about once per second) and `off`.
- Sends the "typing" chat action every ~9 s while you work (every 4.5 s in live mode).
- Long-polling is IPv4-only, uses TCP keepalive, and rebuilds the HTTP session after repeated
  failures. A watchdog and systemd restart it if needed. Messages that fail to send are queued and retried.

## Style guide for Telegram answers
1. **Lead with the result** (one sentence). Then details only if needed.
2. Prefer short paragraphs. Use bullets only when there are three or more parallel items.
3. Use emoji sparingly as status markers (✅ ⚠️ ❌), never as decoration in every line.
4. Use code blocks with a language for anything copyable: commands, paths, config.
5. Tables only for real tabular data, ≤ 5 columns.
6. Put long or secondary output behind `<details>` or in a file.
7. Don't repeat the question, don't add sign-offs, don't explain the formatting.
8. Language: answer in the user's language (Persian ↔ English). Rich messages support RTL.
   Mixed Persian text with code works fine. Keep code and paths in LTR code spans.
9. Never print secrets. If a command output contains one, redact it.

## New in 2025–2026 (for awareness)
- 9.x (2025): checklists, gifts and business features, suggested posts, `sendMessageDraft` (9.3, Dec 2025).
- 9.4 (Feb 2026): custom emoji in bot messages when the owner has Premium, button `style` and
  `icon_custom_emoji_id`, private-chat topics.
- 9.5 (Mar 2026): `date_time` entities (`<tg-time>`), `sendMessageDraft` for all bots.
- 9.6 (Apr 2026): managed bots, multi-answer quizzes.
- 10.0 (May 2026): guest mode, live photos, media in polls, bot-to-bot messages.
- 10.1 (Jun 2026): **Rich Messages** (`sendRichMessage`, `sendRichMessageDraft`), tables, math,
  details, footnotes.
- 10.2 (Jul 2026): input rich blocks, ephemeral messages, communities.
- 10.3 (Aug 2026): buttons in rich messages, compact tables, expandable rich quotes, `RichBlockDocument`,
  disabled buttons, stop button on drafts.
- 10.4 (Nov 9, 2026): HTML **widgets** (`sendWidget`, private chats only), ephemeral replies to callbacks,
  quoting rich messages, TON wallet cards, `bank_card_number` / `ton_address` entities.
