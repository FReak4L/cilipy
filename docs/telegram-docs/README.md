# Telegram output docs for Antigravity (agy)

You are reachable from Telegram through the **agy-telegram** bridge (`@your_agy_bot`,
service `agy-telegram.service`, Rust source in `/opt/agy-telegram-rs`). Prompts that come from
Telegram start with `[telegram-bridge]`. For those prompts, write your answer for a phone
screen, following these docs.

Sources: official Telegram Bot API, **Bot API 10.4 (November 9, 2026)**:
<https://core.telegram.org/bots/api>, changelog <https://core.telegram.org/bots/api-changelog>,
features <https://core.telegram.org/bots/features>. Read for this pack on 2026-11-17.

| File | What it covers |
|---|---|
| [01-formatting.md](01-formatting.md) | Rich Markdown (what the bridge sends), classic HTML and MarkdownV2, escaping |
| [02-tables-and-layout.md](02-tables-and-layout.md) | Native rich tables, `<pre>` fallback tables, headings, lists, quotes, details, math |
| [03-media-and-files.md](03-media-and-files.md) | Incoming attachments, the outbox, photos/video/audio/documents, size limits |
| [04-keyboards-and-ui.md](04-keyboards-and-ui.md) | Inline keyboards, buttons inside rich messages, callback choices, reply keyboards |
| [05-limits-and-best-practices.md](05-limits-and-best-practices.md) | Length limits, splitting, rate limits, streaming drafts, style guide |
| [06-premium-features.md](06-premium-features.md) | Custom emoji, button icons, message effects (bot owner has Premium) |
| [07-widgets.md](07-widgets.md) | Bot API 10.4 HTML widgets (`skills`/`mcp`/`models`/`memory`), Dual WebApp engine, `<tg-widget>`, Profile-1 & JS API |
| [08-accounts-and-handoff.md](08-accounts-and-handoff.md) | Multi-account pool, per-account models and the model picker, automatic failover, flood control, session continuity (Resume → Replay → Recall), your handoff duties |
| [09-parallel.md](09-parallel.md) | Parallel mode: plan → `tg-mother` agents on distinct accounts → merge; git worktrees for overlapping writers; ownership conflict report |


## MCP and built-in tools (search and docs)
These MCP servers are wired globally for every agy session, including Telegram. agy's built-in search is primary; the search MCPs only help accelerate and verify it. Full policy: `~/.gemini/config/rules/search-tools.md`.

| Server / tool | When to use it |
|---|---|
| Built-in `search_web` / `read_url_content` | **Primary** public-web search and URL reading. Always use this. |
| **searxng** (`searxng_web_search`, `web_url_read`) | Auxiliary accelerator. Call in parallel with `search_web` to broaden or verify results; fallback if built-in search fails, is empty, or is slow. Local SearXNG at 127.0.0.1:8888. |
| **open-websearch** (`search`, `fetchWebContent`, `fetchGithubReadme`) | Auxiliary accelerator, same parallel / fallback role; also fetch a known URL or GitHub README. |
| **context7** (`resolve-library-id`, `query-docs`) | Current library docs and examples, before writing code against a third-party API. |
| **gortex** / **graphify** / **ai-memory** | This codebase and durable project memory (see `mcp-trio.md`), not the public web. |
| **skillport** / **skills-catalog** | Procedures and skills (`skills-and-reasoning.md`). |

## The contract in one screen
1. **Write GitHub-flavored Markdown.** The bridge sends it as a Telegram **Rich Message**
   (`sendRichMessage`, `InputRichMessage.markdown`), so headings, lists, task lists, real
   tables, code blocks with language, quotes, `<details>`, footnotes and LaTeX render natively.
   If Telegram rejects it, the bridge converts it to classic HTML automatically.
2. **Short and clean.** Lead with the answer. Use a heading only when the answer has 2+ sections.
3. **Files:** save anything the user should receive (code files, reports, images, archives)
   in the outbox folder named in the prompt. The bridge uploads it after your turn.
4. **Attachments** from the user arrive as local paths under `/root/agy-workspace/inbox/<user_id>/`.
5. **Never** print secrets (tokens, passwords, keys). The bridge never shows its token to you.
6. **Session handoff.** A chat can move to another Antigravity account mid-task. At session start,
   `memory_search` for `handoff tg-<user_id>` and resume from the note. For non-trivial work, keep
   `/root/agy-workspace/.handoff/tg-<user_id>.md` current in the session-handoff / handoff skill's
   five-section format, and store one ai-memory record (`title` + `summary`, tags `handoff`,
   `tg-<user_id>`). Official prompt marker: `[session-handoff]` (alias `[handoff-resume]`); mid-turn
   switch: `[failover]`. See `~/.gemini/config/rules/session-handoff.md`.
7. **Accounts and models.** Each account has its own model list. The bridge always passes an
   explicit `--model` and never swaps models silently: if a model is missing on an account, the
   user picks one and the same conversation continues. Details:
   [08-accounts-and-handoff.md](08-accounts-and-handoff.md).
8. **Parallel mode.** Prompts tagged `[parallel-plan]`, `[parallel-worker]` or `[parallel-merge]`
   follow [09-parallel.md](09-parallel.md) and `~/.gemini/config/rules/parallel-agents.md`.
   Edit only paths you own, and in a worktree commit on your branch.
9. **Web search and library docs.** Built-in `search_web` / `read_url_content` is primary. Use searxng and open-websearch in parallel with it as accelerators, or as fallback if it fails, is empty, or is slow — never as a replacement. Use context7 for third-party library docs before coding. See `~/.gemini/config/rules/search-tools.md`.
