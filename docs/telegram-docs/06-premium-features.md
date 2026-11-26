# 06 · Premium features (the bot owner has Telegram Premium)

The Bot API (9.4+) lets a bot use **custom emoji** in messages it sends directly to private,
group and supergroup chats, and on inline buttons (`icon_custom_emoji_id`), **if the bot's owner
has Telegram Premium** (or the bot has a username bought on Fragment). Message effects work in
private chats for any bot.

## Custom emoji in your answers
Rich Markdown: `![✅](tg://emoji?id=5427009714745517609)` · HTML: `<tg-emoji emoji-id="5427009714745517609">✅</tg-emoji>`.
The alt text must be a single matching normal emoji. It shows wherever custom emoji can't render.
Use **at most 1–3 per answer**, as status markers. Don't decorate every line.

Vetted IDs from Telegram's official animated set `RestrictedEmoji` (fetched via `getStickerSet`):
| Emoji | custom_emoji_id | Use for |
|---|---|---|
| ✅ | 5427009714745517609 | success / done |
| ❌ | 5465665476971471368 | failure |
| ❗ | 5467928559664242360 | warning / attention |
| ⏳ | 5451732530048802485 | in progress |
| 🚀 | 5445284980978621387 | deployed / shipped |
| 🎉 | 5436040291507247633 | celebration |
| 💡 | 5472146462362048818 | tip / idea |
| 🔥 | 5420315771991497307 | hot / important |
| 📎 | 5377844313575150051 | attachment |
| 📝 | 5334882760735598374 | notes / document |
| 🧠 | 5237799019329105246 | reasoning / model |
| 📊 | 5431577498364158238 | stats |
| 🔗 | 5375129357373165375 | link / MCP |
| ✨ | 5472164874886846699 | skills / new |
The full map the bridge uses is in `/var/lib/agy-telegram/emoji.json`. If a custom emoji is
rejected, the bridge switches to plain emoji automatically.

Extended UI & commerce icon pack (21 custom emoji IDs registered in `emoji.json` & `DEFAULT_IDS`):
| Key | Alt | custom_emoji_id |
|---|---|---|
| `products` | 🛍️ | 5294385600000956892 |
| `search` | 🔍 | 5433651413517360422 |
| `cart` | 🛒 | 5192844064793327232 |
| `orders` | 📦 | 6334602442591700514 |
| `wallet` | 👛 | 5215275686842869661 |
| `back` | 🔙 | 5215675024312117374 |
| `exit` | ✖️ | 5017058788604117831 |
| `support` | 💬 | 5438246259724925761 |
| `add` | ➕ | 5235472087652510235 |
| `remove` | 🗑️ | 5904542823167824187 |
| `refresh` | 🔄 | 5017470156276761427 |
| `checkout` | 🧾 | 5444856076954520455 |
| `check` | ✅ | 5294336053258233678 |
| `pay` | 💳 | 5195410990652474023 |
| `cancel` | ❌ | 5828156683779576757 |
| `admin` | 🛠️ | 5852967837970206643 |
| `watch` | 🔔 | 5339051047971203310 |
| `phone` | 📱 | 5219748160842247251 |
| `account` | 👤 | 6032693626394382504 |
| `web` | 🌐 | 4940645878684713890 |
| `share` | 📤 | 5884343982816759327 |

Extended Gateway, Browser & Bot UI pack (`sfsymbols`, 18 verified IDs in `emoji.json`):
| Key | Alt | custom_emoji_id |
|---|---|---|
| `browser` | 🌐 | 6019205852831947754 |
| `mcpgw` | ☁️ | 6019252221298874807 |
| `codeintel` | 🖥 | 6021607757457660145 |
| `optimizer` | 🎛 | 6026248173268243634 |
| `memory` | 🧠 | 6021733363776231718 |
| `shield` | 🛡 | 6019258242843023335 |
| `key` | 🔑 | 6019290828759898301 |
| `lock` | 🔐 | 6019568309417023812 |
| `settings` | ⚙ | 6021582331251268218 |
| `cfg` | 🎛 | 6025946567779818123 |
| `edit` | ✏️ | 6024110353296660793 |
| `info` | ℹ️ | 6021620268697393273 |
| `stop` | ⏹ | 5807622114424924272 |
| `plus` | ➕ | 5807642902066634351 |
| `net` | 🛜 | 6019289243916968110 |
| `accounts` | 👤 | 6021386648246294190 |
| `fire` | 🔥 | 6021384767050618542 |
| `grok` | ⚡ | 6023761060786346622 |

> **Full catalog skill:** `telegram-premium-emoji` (7,092 verified IDs across 58 packs) is installed in `/root/agy-stack/config/gemini/skills/telegram-premium-emoji/`.

## What the bridge uses
- Custom emoji in its own UI (dashboard, status, errors) and as **button icons**
  (`icon_custom_emoji_id`) on the main keyboard.
- A **message effect** (`message_effect_id`, 🎉 `5046509860389126442`) on the startup notice.
  Other public effect IDs: 🔥 `5104841245755180586`, 👍 `5107584321108051014`, ❤️ `5159385139981059251`.
- Fallback order for every send: premium → plain emoji → plain text.

## What Premium does NOT change for bots
- File limits stay 20 MB download / 50 MB upload on the cloud Bot API. Only a self-hosted
  Local Bot API server raises them (2000 MB).
- Message length limits stay as listed in 05.
