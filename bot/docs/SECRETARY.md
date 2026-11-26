# Secretary Mode (Telegram Business) and Automations

## Secretary (owner only, /secretary)
- Telegram requirement: @BotFather → /mybots → @your_agy_bot → Bot Settings → Secretary Mode → Turn on (getMe.can_connect_to_business must be true). Then Telegram Settings → Telegram Business → Chatbots (Chat Automation) → @your_agy_bot, choose chats + rights (Reply to messages, Mark as read).
- Updates: business_connection, business_message, edited_business_message, deleted_business_messages (in DEFAULT_ALLOWED_UPDATES).
- Default OFF + Draft mode. Modes: draft | auto | autoquiet. Allow-list / ignore list, quiet hours (UTC), persona, mark_read, max/hour.
- Only connections whose user.id == OWNER_ID are used. Auto-send requires rights.can_reply; readBusinessMessage requires can_read_messages + mark_read.
- agy run is tool-less: --sandbox, --disable-slash-commands, --settings deny command/mcp/url/read_file/write_file, empty cwd $STATE_DIR/secretary-ws.
- Deep link from "Manage Bot": /start bizChat<chat_id> → per-chat panel.

## Automations (/auto)
- /auto add SCHEDULE | PROMPT ; schedules: every Nm|Nh|Nd, daily HH:MM, weekdays HH:MM, weekly mon HH:MM, cron (5/6 fields). UTC. Min interval 15 min (owner 5). Max 10 per user (owner 30).
- Each run = isolated JobRequest (fresh conversation) with prefix "[automation #id …]". Permission: owner or ACL perm "automations".
