# 03 · Media and files

## Incoming (user → you)
The bridge downloads every attachment (photo, document, video, audio, voice, animation,
video note, sticker) to `/root/agy-workspace/inbox/<user_id>/<timestamp>_<name>` and lists
the paths in your prompt under "User attachments". Open them with your normal file tools.
Photos arrive as the largest available JPEG. Voice notes are `.ogg` (Opus).
**Limit:** the cloud Bot API lets bots download at most **20 MB** per file (`getFile`).
Bigger files need a self-hosted Local Bot API server (up to 2000 MB) or `scp`.

## Outgoing (you → user)
Save files in the **outbox folder given in the prompt**
(`/root/agy-workspace/outbox/<user_id>/<job_id>/`). After your turn, the bridge sends:
| Extension | Sent as |
|---|---|
| .png .jpg .jpeg .webp (≤ 10 MB) | photo (`sendPhoto`) |
| .gif | animation |
| .mp4 .mov .webm .mkv | video (streaming) |
| .mp3 .m4a .flac .wav .aac | audio |
| .ogg .oga .opus | voice message |
| anything else | document |
Upload limit: **50 MB** per file (cloud Bot API). At most 10 files per turn are sent
automatically. Files you mention by absolute path under `/root/agy-workspace/` that you created
or changed during the turn are sent too.

## When to send a file instead of text
- Code longer than ~80 lines, whole config files, diffs, logs → write a file
  (`.py`, `.md`, `.txt`, `.log`, `.patch`) and summarize in chat.
- Answers longer than about 90k characters are sent automatically as `answer.md` with a preview.
- Data tables with >20 columns or >150 rows → CSV/XLSX in the outbox.
- Generated images and charts → PNG in the outbox.

## Captions and media in text
Captions are limited to 1,024 characters. Inside a rich message, media blocks accept only
http(s) URLs: `![](https://…/img.png "caption")`, plus `<tg-collage>` / `<tg-slideshow>` for galleries.
Bot API methods for reference: `sendPhoto`, `sendDocument`, `sendVideo`, `sendAudio`, `sendVoice`,
`sendAnimation`, `sendVideoNote`, `sendLivePhoto` (10.0), `sendMediaGroup` (2–10 items),
`editMessageMedia`.
