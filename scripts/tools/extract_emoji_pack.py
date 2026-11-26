#!/usr/bin/env python3
"""Extract custom_emoji_ids & thumbnails from any Telegram custom emoji pack (`t.me/addemoji/<name>`)
and render numbered contact-sheet PNGs for accurate visual labeling.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import urllib.request
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

BOT_ENV_PATH = Path(os.environ.get("BOT_ENV_PATH", "/etc/agy-telegram/bot.env"))


def load_bot_token() -> str:
    env_tok = os.environ.get("BOT_TOKEN", "").strip()
    if env_tok:
        return env_tok
    if BOT_ENV_PATH.exists():
        for line in BOT_ENV_PATH.read_text(encoding="utf-8").splitlines():
            if line.startswith("BOT_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise RuntimeError(f"BOT_TOKEN not found in env or {BOT_ENV_PATH}")


def parse_pack_name(raw: str) -> str:
    s = raw.strip()
    m = re.search(r"t\.me/(?:addemoji|addstickers)/([A-Za-z0-9_]+)", s)
    if m:
        return m.group(1)
    return s.strip("/").split("?")[0]


def tg_api(token: str, method: str, payload: dict) -> dict:
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not data.get("ok"):
        raise RuntimeError(f"Telegram API {method} failed: {data}")
    return data["result"]


def download_file(token: str, file_id: str, dest: Path) -> bool:
    if dest.exists() and dest.stat().st_size > 0:
        return True
    try:
        finfo = tg_api(token, "getFile", {"file_id": file_id})
        fpath = finfo["file_path"]
        url = f"https://api.telegram.org/file/bot{token}/{fpath}"
        with urllib.request.urlopen(url, timeout=20) as r:
            dest.write_bytes(r.read())
        return True
    except Exception:
        if dest.exists():
            dest.unlink()
        return False


def pick_font(size: int) -> ImageFont.ImageFont:
    for p in [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    ]:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def render_sheets(pack_name: str, title: str, items: list[dict], icons_dir: Path, out_dir: Path, per_sheet: int = 50) -> list[Path]:
    cols = 10
    cell_w, cell_h = 132, 148
    pad_top = 56
    font = pick_font(18)
    head_font = pick_font(22)
    sheets: list[Path] = []

    for start in range(0, len(items), per_sheet):
        chunk = items[start : start + per_sheet]
        rows = (len(chunk) + cols - 1) // cols
        w = cols * cell_w + 16
        h = pad_top + rows * cell_h + 16
        img = Image.new("RGB", (w, h), "#1e293b")
        draw = ImageDraw.Draw(img)
        draw.text(
            (14, 14),
            f"{pack_name} ({title}) — #{start + 1}..#{start + len(chunk)} / {len(items)}",
            font=head_font,
            fill="#f8fafc",
        )
        for pos, item in enumerate(chunk):
            idx = item["index"]
            r, c = divmod(pos, cols)
            x0 = 8 + c * cell_w
            y0 = pad_top + r * cell_h
            draw.rounded_rectangle((x0 + 4, y0 + 4, x0 + cell_w - 4, y0 + cell_h - 4), radius=10, fill="#475569")
            icon_path = icons_dir / f"{idx:04d}.webp"
            if icon_path.exists():
                try:
                    ic = Image.open(icon_path).convert("RGBA")
                    ic.thumbnail((96, 96), Image.Resampling.LANCZOS)
                    ix = x0 + (cell_w - ic.width) // 2
                    iy = y0 + 10 + (96 - ic.height) // 2
                    img.paste(ic, (ix, iy), ic)
                except Exception:
                    pass
            lbl = f"#{idx}"
            bbox = draw.textbbox((0, 0), lbl, font=font)
            tw = bbox[2] - bbox[0]
            draw.text((x0 + (cell_w - tw) // 2, y0 + 114), lbl, font=font, fill="#f1f5f9")

        sheet_idx = start // per_sheet + 1
        out_path = out_dir / f"{pack_name}_sheet_{sheet_idx:02d}.png"
        img.save(out_path, optimize=True)
        sheets.append(out_path)
    return sheets


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pack", help="t.me/addemoji/<name> or pack short name")
    ap.add_argument("--out-dir", default="/tmp/emoji_extract", help="Output directory")
    ap.add_argument("--per-sheet", type=int, default=50)
    args = ap.parse_args()

    token = load_bot_token()
    pack_name = parse_pack_name(args.pack)
    out_dir = Path(args.out_dir)
    icons_dir = out_dir / "icons" / pack_name
    out_dir.mkdir(parents=True, exist_ok=True)
    icons_dir.mkdir(parents=True, exist_ok=True)

    ss = tg_api(token, "getStickerSet", {"name": pack_name})
    title = ss.get("title", pack_name)
    stickers = ss.get("stickers", [])

    items = []
    tasks = []
    for i, st in enumerate(stickers, 1):
        thumb = st.get("thumbnail") or st.get("thumb")
        fid = thumb["file_id"] if thumb else (st["file_id"] if not st.get("is_animated") and not st.get("is_video") else None)
        dest = icons_dir / f"{i:04d}.webp"
        if fid:
            tasks.append((fid, dest))
        items.append({
            "index": i,
            "custom_emoji_id": st.get("custom_emoji_id"),
            "fallback": st.get("emoji", ""),
            "is_animated": bool(st.get("is_animated")),
            "is_video": bool(st.get("is_video")),
            "keywords": st.get("keywords", []),
        })

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        list(ex.map(lambda p: download_file(token, p[0], p[1]), tasks))

    raw_json = out_dir / f"{pack_name}_raw.json"
    raw_json.write_text(
        json.dumps({"pack": pack_name, "title": title, "count": len(items), "items": items}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    sheets = render_sheets(pack_name, title, items, icons_dir, out_dir, per_sheet=args.per_sheet)
    print(json.dumps({
        "pack": pack_name,
        "title": title,
        "count": len(items),
        "raw_json": str(raw_json),
        "sheets": [str(s) for s in sheets],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
