# 04 · Keyboards and UI

## What the bridge already provides
Every answer ends with **New chat · Menu** buttons. The dashboard (`/start`, `/menu`) has
New chat, Model, Status, MCPs, Skills, Settings, Sessions/Stop, Help, Widgets (plus **Users** for the Owner).
It's an inline keyboard that edits in place (`editMessageText`) so the chat stays tidy.
- Unapproved `/start` users receive no response until approved by the Owner via inline notification cards.
- `/users` manages single and batch user approvals plus permissions (`skills_manage`, `mcp_manage`, `root_access`).
- `/skills` offers 1-tap SkillPort / catalog / AI skill installation and removal.
- `/mcp` offers per-server toggle, config/env/JSON editing, removal, and AI-assisted installation with Owner approval.
A Stop button shows on the status message that updates in place every 20 s while you work. Don't re-describe these buttons in your answers.

## Buttons you may add inside your answer (rich messages)
Rich messages support inline buttons in the text. Use them sparingly, for real choices:
```html
<tg-button-row>
 <tg-button type="callback_data" style="primary" data="ask:deploy to staging">Deploy staging</tg-button>
 <tg-button type="callback_data" data="ask:show the diff first">Show diff</tg-button>
</tg-button-row>
<tg-button-row>
 <tg-button type="url" url="https://github.com/org/repo/pull/12">Open PR</tg-button>
 <tg-button type="copy_text" text="systemctl restart nginx">Copy command</tg-button>
</tg-button-row>
```
- `callback_data` buttons must use the prefix **`ask:`**. When tapped, the bridge sends the
  text after `ask:` to you as the user's next message (`[button] deploy to staging`).
  Max 64 bytes of data.
- `url`: http(s) or tg:// links. `copy_text`: copies text to the clipboard. `disabled`: greyed out.
- `style`: `primary` (blue), `success` (green), `danger` (red), `link` (callback buttons only).
- Rows: `<tg-button-row align="left|center|right">`.

## Telegram UI building blocks (reference)
- **InlineKeyboardMarkup**: buttons under a message. Types: callback_data, url, web_app,
  login_url, switch_inline_query*, copy_text, pay, disabled (10.3).
  Since 9.4, buttons have `style` and `icon_custom_emoji_id`.
- **ReplyKeyboardMarkup**: buttons that replace the keyboard (request contact/location/users/chats/managed bots).
  This bridge doesn't use them, to keep the chat clean.
- **ForceReply**, **ReplyKeyboardRemove**.
- **Callback queries** must be answered (`answerCallbackQuery`) to stop the spinner. A toast
  (≤ 200 chars) or an alert can be shown.
- **Menu button** (`setChatMenuButton`) opens the command list. Commands are set per user with
  `setMyCommands` scope `chat`.
- **Ephemeral messages** (10.2+): visible only to one user in a group.
- **Edit-in-place:** `editMessageText` (also `rich_message`), `editMessageCaption`, `editMessageMedia`,
  `editMessageReplyMarkup`.
