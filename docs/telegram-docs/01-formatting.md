# 01 · Formatting

## 1. What the bridge does with your answer
Your final text is treated as **Rich Markdown** (Bot API 10.1+, `sendRichMessage`).
Rich Markdown is GitHub-flavored Markdown plus a few Telegram extensions, and it may contain
the supported HTML tags below. Limits: 32,768 characters, 500 blocks, 16 nesting levels,
50 media, 20 table columns. The bridge splits longer answers on blank lines outside code fences.
If Telegram rejects the rich message, the bridge converts it to classic HTML (`parse_mode=HTML`).

## 2. Rich Markdown syntax (use this)
| Effect | Syntax |
|---|---|
| bold | `**bold**` or `__bold__` |
| italic | `*italic*` or `_italic_` |
| strikethrough | `~~text~~` |
| marked (highlight) | `==text==` |
| spoiler | `\|\|hidden\|\|` |
| inline code | `` `code` `` |
| link | `[label](https://…)`, `mailto:`, `tel:`, `tg://user?id=…` |
| headings | `#` … `######` |
| code block | ```` ```python ```` … ```` ``` ```` (language gets syntax highlighting) |
| rule | `---` |
| lists | `-`, `*`, `+`, `1.` |
| task list | `- [ ] todo`, `- [x] done` |
| quote | `> text` |
| table | GFM pipes, `:--` / `:-:` / `--:` alignment |
| footnote | `text[^1]` … `[^1]: note` |
| math | `$x^2$` inline, `$$E=mc^2$$` or ```` ```math ```` block |
| date/time | `![22:45](tg://time?unix=1647531900&format=wDT)` (shown in the reader's timezone) |
| custom emoji | `![⭐](tg://emoji?id=<custom_emoji_id>)` (see 06-premium-features.md) |

HTML that has no Markdown syntax can be mixed in: `<u>`, `<sub>`, `<sup>`, `<tg-spoiler>`,
`<details open><summary>Title</summary>…</details>` (Markdown is parsed inside `<details>`),
`<aside>pull quote<cite>Author</cite></aside>`, `<tg-math-block>`, `<tg-map lat=… long=… zoom=…/>`,
`<table bordered striped compact>`, `<tg-button …>` (see 04). Markdown is **not** parsed inside
other block HTML tags. Inline HTML tags do parse nested Markdown.

Media inside a rich message must be an **http(s) URL** in its own block:
`![](https://example.com/chart.png "caption")`. For local files, use the outbox instead (03).

**Escaping in Rich Markdown:** write literal `<` and `&` as `&lt;` / `&amp;` when they could
look like a tag (`List&lt;String&gt;`), or put them in backticks. Inside code spans and fences,
nothing needs escaping. Prefix a literal `#hashtag` at the start of a line with `\`.

## 3. Classic HTML (`parse_mode=HTML`), the fallback
Supported tags only: `<b>/<strong>`, `<i>/<em>`, `<u>/<ins>`, `<s>/<strike>/<del>`,
`<tg-spoiler>` or `<span class="tg-spoiler">`, `<a href>`, `<code>`, `<pre>`,
`<pre><code class="language-xx">`, `<blockquote>`, `<blockquote expandable>`,
`<tg-emoji emoji-id>`, `<tg-time unix format>`.
- Escape every `<`, `>`, `&` that is not markup: `&lt; &gt; &amp;` (also `&quot;`).
- No headings, lists or tables: headings become **bold** lines, lists become `•` lines,
  and tables become monospace `<pre>` (02).
- Nesting: bold/italic/underline/strike/spoiler can nest freely, but not inside `pre`/`code`.
  Blockquotes can't nest.
- Programming language works only on `<pre><code class="language-…">`, not on a standalone `<code>`.

## 4. MarkdownV2 (reference only, the bridge does not use it)
Escape `_ * [ ] ( ) ~ \` > # + - = | { } . !` with `\` everywhere outside code.
Inside `pre`/`code`, escape `` ` `` and `\`. Inside `(...)` of links, escape `)` and `\`.
Underline is `__x__`, spoiler `||x||`, expandable quote `**>line … >last||`.

## 5. Date-time entity formats
`format` matches `r|w?[dD]?[tT]?`: `r` relative, `w` weekday, `d` short date, `D` long date,
`t` short time, `T` long time. Example: `wDT` gives "Tuesday, November 17, 2026 21:05".
