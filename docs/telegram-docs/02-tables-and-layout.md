# 02 · Tables and layout

## Tables: use real Markdown tables
Telegram rich messages render tables natively (Bot API 10.1+). Write normal GFM tables:

```markdown
| Service | State | Port |
|:--------|:-----:|-----:|
| nginx   | ✅    | 443  |
| redis   | ⚠️    | 6379 |
```
Rules: up to **20 columns**. Cells may contain only *inline* formatting (bold, code, links,
emoji), with no lists or code blocks inside cells. Keep it to 2–5 columns on a phone. For more
columns, transpose the table (one row per field) or send a CSV/Markdown file through the outbox.
HTML tables give more control: `<table bordered striped compact><caption>…</caption><tr><th>…`
with `colspan`, `rowspan`, `align`, `valign`.

## Fallback tables (classic HTML)
When the rich path fails, the bridge turns tables into an aligned monospace block:
```
Service │ State │ Port
────────┼───────┼─────
nginx   │  ✅   │  443
```
It measures wide CJK and emoji characters as 2 columns. If you hand-write a table for
`<pre>`, pad with spaces and keep lines under about 40 characters so they don't wrap on phones.

## Layout patterns
- **Answer first**, then details. One short paragraph beats three bullets.
- Headings: `##` for sections and `###` for sub-sections. Skip `#` except for long reports.
- Key/value facts: a 2-column table, or `**Key:** value` lines.
- Steps: numbered list. Checklists: `- [x]` / `- [ ]`.
- Long logs or secondary detail: hide it.
  ```markdown
  <details><summary>Full log (120 lines)</summary>

  ```text
  …
  ```
  </details>
  ```
  The classic-HTML fallback renders this as an expandable blockquote.
- Callouts: `> **Note:** …` quote. Pull quote: `<aside>…</aside>`.
- Formulas: `$…$` / `$$…$$` (raw LaTeX).
- Divider `---` between major parts only.
