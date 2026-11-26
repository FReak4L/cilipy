"""Zero-dependency Pure-ANSI terminal styling and responsive layout primitives."""

from __future__ import annotations

import os
import re
import shutil
import sys
from typing import Literal

Breakpoint = Literal["compact", "standard", "wide"]

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def supports_color(*, force_color: bool | None = None) -> bool:
    """Honor NO_COLOR, TERM=dumb, and TTY detection unless explicitly overridden."""
    if force_color is not None:
        return force_color
    if os.environ.get("NO_COLOR") is not None:
        return False
    term = os.environ.get("TERM", "")
    if term.lower() == "dumb":
        return False
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def supports_utf8() -> bool:
    encoding = (getattr(sys.stdout, "encoding", None) or "utf-8").lower()
    return "utf" in encoding


class Ansi:
    """Minimalist 5-tone Pure-ANSI palette (zero external libraries)."""

    def __init__(self, *, enabled: bool | None = None) -> None:
        self.enabled = supports_color(force_color=enabled)

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled or not text:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def bold_cyan(self, text: str) -> str:
        return self._wrap("1;36", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def bold_green(self, text: str) -> str:
        return self._wrap("1;32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def bold_yellow(self, text: str) -> str:
        return self._wrap("1;33", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def bold_red(self, text: str) -> str:
        return self._wrap("1;31", text)

    def white(self, text: str) -> str:
        return self._wrap("97", text)

    def badge(self, text: str, tone: Literal["ok", "warn", "err", "info", "muted"] = "info") -> str:
        if tone == "ok":
            return self.bold_green(text)
        if tone == "warn":
            return self.bold_yellow(text)
        if tone == "err":
            return self.bold_red(text)
        if tone == "muted":
            return self.dim(text)
        return self.bold_cyan(text)

    def toggle(self, value: bool) -> str:
        return self.bold_green("ON ") if value else self.dim("OFF")


def strip_ansi(text: str) -> str:
    """Remove ANSI CSI escape sequences for accurate visible width calculation."""
    return _ANSI_ESCAPE_RE.sub("", text)


def visible_len(text: str) -> int:
    return len(strip_ansi(text))


def truncate_visible(text: str, max_width: int) -> str:
    """Truncate plain or ANSI-free text cleanly to `max_width` visible characters."""
    if max_width <= 0:
        return ""
    plain = strip_ansi(text)
    if len(plain) <= max_width:
        return plain
    if max_width == 1:
        return plain[:1]
    ell = "…" if supports_utf8() else "."
    return plain[: max_width - 1] + ell


def pad_visible(text: str, width: int, align: Literal["left", "right"] = "left") -> str:
    """Pad ANSI-styled string to exact visible `width` without corrupting escape codes."""
    vis = visible_len(text)
    if vis >= width:
        return text
    pad = " " * (width - vis)
    return f"{pad}{text}" if align == "right" else f"{text}{pad}"


def get_screen_size(default: tuple[int, int] = (80, 24)) -> tuple[int, int]:
    """Read live terminal `(columns, lines)` safely across SSH, tmux, mobile, and non-TTY."""
    size = shutil.get_terminal_size(fallback=default)
    return max(32, size.columns), max(12, size.lines)


def layout_breakpoint(cols: int) -> Breakpoint:
    if cols < 72:
        return "compact"
    if cols < 110:
        return "standard"
    return "wide"


def clear_screen() -> str:
    return "\x1b[2J\x1b[H"


def cursor_home() -> str:
    return "\x1b[H\x1b[J"


def horizontal_rule(width: int, ansi: Ansi) -> str:
    ch = "─" if supports_utf8() else "-"
    return ansi.dim(ch * max(10, width))


def render_header(
    title: str,
    meta_items: list[str],
    *,
    cols: int,
    ansi: Ansi,
) -> str:
    """Render a minimalist responsive header fitting any terminal width (32..300 cols)."""
    bp = layout_breakpoint(cols)
    utf8 = supports_utf8()
    sep = " │ " if utf8 else " | "
    inner_w = max(28, min(cols, 120))

    if bp == "compact":
        line1 = ansi.bold_cyan(truncate_visible(title, inner_w))
        line2 = ansi.dim(truncate_visible(" · ".join(meta_items), inner_w))
        return f"{line1}\n{line2}\n{horizontal_rule(inner_w, ansi)}"

    box_w = inner_w - 2
    top = ("┌" + "─" * box_w + "┐") if utf8 else ("+" + "-" * box_w + "+")
    bot = ("└" + "─" * box_w + "┘") if utf8 else ("+" + "-" * box_w + "+")
    vbar = "│" if utf8 else "|"

    joined = f"  {title}{sep}{sep.join(meta_items)}"
    clipped = truncate_visible(joined, box_w)
    styled = clipped.replace(title, ansi.bold_cyan(title), 1)
    padded = pad_visible(styled, box_w, "left")
    return "\n".join(
        [
            ansi.dim(top),
            f"{ansi.dim(vbar)}{padded}{ansi.dim(vbar)}",
            ansi.dim(bot),
        ]
    )


def render_progress_bar(done: int, total: int, width: int, ansi: Ansi) -> str:
    """Minimalist progress bar sized safely for compact/standard/wide screens."""
    bar_w = max(8, min(width, 32))
    safe_total = max(1, total)
    ratio = min(1.0, max(0.0, done / safe_total))
    filled = int(round(ratio * bar_w))
    utf8 = supports_utf8()
    fill_ch = "█" if utf8 else "#"
    empty_ch = "░" if utf8 else "-"
    pct = int(round(ratio * 100))
    bar = ansi.green(fill_ch * filled) + ansi.dim(empty_ch * (bar_w - filled))
    return f"[{bar}] {done}/{total} ({pct}%)"
