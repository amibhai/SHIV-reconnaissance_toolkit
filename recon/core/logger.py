"""
recon.core.logger — Rich-based structured logger with console + JSONL file output.

Provides per-module loggers with color-coded severity levels, timestamps,
and structured JSON Lines output for post-processing.
"""

from __future__ import annotations

import json
import logging
import os
import random
import sys
import textwrap
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

__all__ = [
    "get_logger",
    "console",
    "err_console",
    "make_progress",
    "print_banner",
    "print_compact_header",
    "print_findings_table",
]

_RECON_THEME = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "critical": "bold red on white",
        "success": "bold green",
        "debug": "dim",
        "host": "bold blue",
        "port": "bold magenta",
        "vuln.critical": "bold red",
        "vuln.high": "red",
        "vuln.medium": "yellow",
        "vuln.low": "green",
        "vuln.info": "cyan",
    }
)

console = Console(theme=_RECON_THEME, stderr=False, emoji=True, highlight=False)
err_console = Console(theme=_RECON_THEME, stderr=True)

_file_handler_lock = threading.Lock()
_log_file_path: Path | None = None
_log_file_handle = None


def _set_log_file(path: Path) -> None:
    global _log_file_path, _log_file_handle
    with _file_handler_lock:
        if _log_file_handle:
            _log_file_handle.close()
        path.parent.mkdir(parents=True, exist_ok=True)
        _log_file_handle = open(path, "a", encoding="utf-8")
        _log_file_path = path


def _write_jsonl(record: dict[str, Any]) -> None:
    """Append a log record to the JSONL log file (thread-safe)."""
    if _log_file_handle is None:
        return
    with _file_handler_lock:
        try:
            _log_file_handle.write(json.dumps(record, default=str) + "\n")
            _log_file_handle.flush()
        except Exception:
            pass


class _JsonlHandler(logging.Handler):
    """Logging handler that writes structured JSON Lines to disk."""

    def emit(self, record: logging.LogRecord) -> None:
        entry = {
            "ts": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "module": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        _write_jsonl(entry)


def _make_rich_handler(level: int) -> RichHandler:
    return RichHandler(
        console=console,
        show_time=True,
        show_level=True,
        show_path=False,
        rich_tracebacks=True,
        log_time_format="[%H:%M:%S]",
        level=level,
        markup=True,
    )


def configure_logging(verbosity: int = 1, log_file: Path | None = None) -> None:
    """
    Configure root logging for the toolkit.

    Args:
        verbosity: 0=WARNING, 1=INFO, 2=DEBUG, 3=DEBUG+JSONL
        log_file: Optional path to write JSON Lines log.
    """
    level_map = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG, 3: logging.DEBUG}
    level = level_map.get(verbosity, logging.INFO)

    root = logging.getLogger("recon")
    root.setLevel(level)
    root.handlers.clear()

    root.addHandler(_make_rich_handler(level))

    if log_file or verbosity >= 3:
        path = log_file or Path("./output/recon.log.jsonl")
        _set_log_file(path)
        jsonl = _JsonlHandler(level=logging.DEBUG)
        root.addHandler(jsonl)

    for noisy in ("scapy.runtime", "scapy.loading", "paramiko", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.ERROR)


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger under the recon hierarchy.

    Args:
        name: Sub-module name (e.g. 'dns_enum', 'port_scan').

    Returns:
        Configured Logger instance.
    """
    return logging.getLogger(f"recon.{name}")


def make_progress(description: str = "Scanning") -> Progress:
    """
    Build a Rich Progress bar suitable for scanning operations.

    Args:
        description: Default task description label.

    Returns:
        Configured Progress instance (use as context manager).
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    )


# ─── Banner system (wifi_down-style) ─────────────────────────────────────────

MAHADEV_ART = """\
                                          ☽  )
                                       ☽       )
    ≋  ≋  ≋  ≋  ≋  ≋  ≋  ≋  ≋  ≋  ≋≋≋   ≋  )
   ≋≋  ≋≋  ≋≋  ≋≋  ≋≋  ≋≋  ≋≋  ≋≋  ≋≋  ≋≋  ≋≋
  ≋≋  ≋≋  ≋≋  ≋ .──────────────────. ≋≋  ≋≋  ≋≋
  ≋≋  ≋≋  ≋≋  ≋/        ▽           \≋≋  ≋≋  ≋≋
  ≋≋  ≋≋  ≋≋  ≋|  ╱────╲   ╱────╲   |≋≋  ≋≋  ≋≋
  ≋≋  ≋≋  ≋≋  ≋|  ╰════╯   ╰════╯   |≋≋  ≋≋  ≋≋
  ≋≋  ≋≋  ≋≋  ≋|                    |≋≋  ≋≋  ≋≋
  ≋≋  ≋≋  ≋≋  ≋|      ╭──╮          |≋≋  ≋≋  ≋≋
  ≋≋  ≋≋  ≋≋  ≋|      │  │          |≋≋  ≋≋  ≋≋
  ≋≋  ≋≋  ≋≋  ≋|      ╰──╯          |≋≋  ≋≋  ≋≋
  ≋≋  ≋≋  ≋≋  ≋|      ─────         |≋≋  ≋≋  ≋≋
 ◉≋≋  ≋≋  ≋≋  ≋|    ─────────       |≋≋  ≋≋  ≋≋◉
  ≋≋  ≋≋  ≋≋  ≋|                    |≋≋  ≋≋  ≋≋
  ≋≋  ≋≋  ≋≋  ≋ \──────────────────/≋≋  ≋≋  ≋≋
  ≋≋  ≋≋  ≋≋  ≋  ──────────────────  ≋≋  ≋≋  ≋≋
   ≋≋  ≋≋  ≋≋  ≋≋  ≋≋  ≋≋  ≋≋  ≋≋  ≋≋  ≋≋  ≋≋
  ○●○●○●○●○●○●○●○●○●○●○●○●○●○●○"""

SHIV_ART = """\
███████╗██╗  ██╗██╗██╗   ██╗
██╔════╝██║  ██║██║██║   ██║
███████╗███████║██║╚██╗ ██╔╝
╚════██║██╔══██║██║ ╚████╔╝
███████║██║  ██║██║  ╚██╔╝
╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝  """

QUOTES = [
    (
        "Kevin Mitnick",
        "The human side of computer security is easily exploited "
        "and we still don't take it seriously enough.",
    ),
    ("Bruce Schneier", "Security is not a product, but a process."),
    ("Bruce Schneier", "Amateurs hack systems, professionals hack people."),
    (
        "Dan Kaminsky",
        "We keep saying the internet isn't a safe place. "
        "But we built it as if it was.",
    ),
    ("Mikko Hyppönen", "If it's smart, it's vulnerable."),
    (
        "Edward Snowden",
        "Arguing that you don't care about privacy because you have "
        "nothing to hide is no different from saying you don't care "
        "about free speech because you have nothing to say.",
    ),
    ("Richard Stallman", "Free software is a matter of liberty, not price."),
    (
        "Gene Spafford",
        "The only truly secure system is one that is powered off, "
        "cast in a block of concrete and sealed in a lead-lined room "
        "with armed guards.",
    ),
    (
        "Parisa Tabriz",
        "I think of hacking as an intellectual challenge — "
        "a puzzle waiting to be solved.",
    ),
]

_CORNER_CHARS = frozenset("╗╔╝╚╣╠╦╩╬")

_S_LEFT   = Style(color="color(51)")
_S_MID    = Style(color="color(87)", bold=True)
_S_RIGHT  = Style(color="color(50)")
_S_CORNER = Style(color="color(45)", bold=True)

# Mahadev portrait — purple-left / cyan-right neon split
_S_PURPLE = Style(color="color(93)",  bold=True)   # purple left hair
_S_VIOLET = Style(color="color(135)")              # violet mid-transition
_S_CYAN_H = Style(color="color(51)",  bold=True)   # bright cyan right hair + face
_S_CYAN2  = Style(color="color(87)")               # softer cyan left face features
_S_WHITE  = Style(color="color(255)", bold=True)   # moon, tilak
_S_ORANGE = Style(color="color(208)", bold=True)   # orange earrings (kundal)
_FACE_CENTER = 25                                   # column split for purple/cyan hair

_RESET_ESC = "\033[0m"


def _make_banner_console() -> Console:
    """Create a console pointing at the (possibly reconfigured) stdout."""
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    return Console(file=sys.stdout, force_terminal=True, legacy_windows=False)


def _ansi(style_str: str) -> str:
    """Convert space-separated style tokens to an ANSI escape sequence."""
    codes: list[str] = []
    for token in style_str.split():
        if token == "bold":
            codes.append("1")
        elif token == "dim":
            codes.append("2")
        elif token == "italic":
            codes.append("3")
        elif token.startswith("color(") and token.endswith(")"):
            n = token[6:-1]
            codes.append(f"38;5;{n}")
    return f"\033[{';'.join(codes)}m" if codes else ""


def _raw_write(text: str) -> None:
    """Write to stdout and flush immediately (single-stream, no buffer conflict)."""
    sys.stdout.write(text)
    sys.stdout.flush()


def _typewrite(text: str, style: str = "", delay: float = 0.018, newline: bool = True) -> None:
    """Print text character-by-character with optional ANSI style and delay."""
    esc = _ansi(style) if style else ""
    for char in text:
        _raw_write(f"{esc}{char}{_RESET_ESC}" if esc else char)
        time.sleep(delay)
    if newline:
        _raw_write("\n")


def _color_mahadev_row(row: str, row_idx: int, total_rows: int) -> Text:
    """Color one row of the Mahadev portrait.

    ≋ left of _FACE_CENTER → purple hair
    ≋ right of _FACE_CENTER → cyan hair
    face outline / features  → cyan (dual-tone across center)
    ☽ / ) in first 2 rows   → white moon
    ▽                        → white tilak
    ◉                        → orange earring
    bead row ●○              → purple→cyan gradient
    """
    is_bead_row = (row_idx >= total_rows - 1)
    t = Text()
    n = len(row)
    for col, ch in enumerate(row):
        if ch == ' ':
            t.append(ch)
        elif ch == '☽' or (ch == ')' and row_idx <= 1):
            t.append(ch, _S_WHITE)
        elif ch in ('▽', '▼'):
            t.append(ch, _S_WHITE)
        elif ch == '◉':
            t.append(ch, _S_ORANGE)
        elif is_bead_row and ch in ('●', '○'):
            ratio = col / max(n - 1, 1)
            if ratio < 0.30:
                t.append(ch, _S_PURPLE)
            elif ratio < 0.55:
                t.append(ch, _S_VIOLET)
            else:
                t.append(ch, _S_CYAN_H)
        elif ch == '≋':
            t.append(ch, _S_PURPLE if col < _FACE_CENTER else _S_CYAN_H)
        else:
            t.append(ch, _S_CYAN2 if col < _FACE_CENTER else _S_CYAN_H)
    return t


def _render_image_blocks(image_path: str, term_width: int = 54) -> list[str]:
    """
    Render an image as ANSI true-color half-block (▀/▄) rows.

    Each character cell covers 2 vertical image pixels.
    Near-black pixels (<30 total RGB) become spaces so the terminal
    background bleeds through — creating the 'blended' effect.
    """
    from PIL import Image as _PILImage

    img = _PILImage.open(image_path).convert("RGBA")
    iw, ih = img.size
    # Characters are ~2× taller than wide; each row = 2 pixel rows.
    px_w = term_width
    px_h = int(px_w * ih / iw)          # raw pixel height at this width
    px_h = px_h + (px_h % 2)            # ensure even
    img  = img.resize((px_w, px_h), _PILImage.LANCZOS)
    pxs  = img.load()

    lines: list[str] = []
    for r in range(0, px_h, 2):
        parts: list[str] = []
        for c in range(px_w):
            r1, g1, b1, a1 = pxs[c, r]
            r2, g2, b2, a2 = pxs[c, r + 1] if r + 1 < px_h else (0, 0, 0, 255)
            if a1 < 128: r1 = g1 = b1 = 0
            if a2 < 128: r2 = g2 = b2 = 0
            dark1 = (r1 + g1 + b1) < 30
            dark2 = (r2 + g2 + b2) < 30
            if dark1 and dark2:
                parts.append(" ")
            elif dark1:
                parts.append(f"\033[38;2;{r2};{g2};{b2}m▄\033[0m")
            elif dark2:
                parts.append(f"\033[38;2;{r1};{g1};{b1}m▀\033[0m")
            else:
                parts.append(
                    f"\033[38;2;{r1};{g1};{b1}m"
                    f"\033[48;2;{r2};{g2};{b2}m▀\033[0m"
                )
        lines.append("".join(parts))
    return lines


def _print_mahadev(bc: Console) -> None:
    """Print Mahadev — true-color half-block image if found, else ASCII fallback."""
    _data = Path(__file__).parent.parent / "data" / "mahadev.png"
    try:
        if _data.exists():
            for line in _render_image_blocks(str(_data)):
                _raw_write(line + "\n")
                time.sleep(0.012)
            return
    except Exception:
        pass
    # Fallback: ASCII art with neon split-color
    rows = MAHADEV_ART.splitlines()
    total = len(rows)
    for i, row in enumerate(rows):
        bc.print(_color_mahadev_row(row, i, total))
        time.sleep(0.038)


def _color_row(row: str) -> Text:
    """Apply tri-zone cyan gradient to a single art row."""
    n  = len(row)
    t1 = row[: n // 3]
    t2 = row[n // 3 : 2 * n // 3]
    t3 = row[2 * n // 3 :]

    def _section(s: str, base: Style) -> list:
        return [(ch, _S_CORNER if ch in _CORNER_CHARS else base) for ch in s]

    return Text.assemble(
        *_section(t1, _S_LEFT),
        *_section(t2, _S_MID),
        *_section(t3, _S_RIGHT),
    )


def _print_art(bc: Console) -> None:
    """Scan-line reveal of the SHIV text logo with a 0.04 s delay per row."""
    for row in SHIV_ART.splitlines():
        if not row.strip():
            continue
        bc.print(_color_row(row))
        time.sleep(0.04)


def _print_tagline() -> None:
    """Typewriter print of the SHIV acronym expansion + recon_toolkit subtitle."""
    _raw_write("\n")
    parts = [
        ("  ",                  ""),
        ("S",                   "color(51) bold"),
        ("ecurity  ",           "color(240)"),
        ("H",                   "color(51) bold"),
        ("unting  ",            "color(240)"),
        ("I",                   "color(51) bold"),
        ("ntelligence  &  ",    "color(240)"),
        ("V",                   "color(51) bold"),
        ("ulnerability Assessment", "color(240)"),
    ]
    for text, style_str in parts:
        esc = _ansi(style_str) if style_str else ""
        for char in text:
            _raw_write(f"{esc}{char}{_RESET_ESC}" if esc else char)
            time.sleep(0.012)
    _raw_write("\n")
    _typewrite("          ─────── recon_toolkit ───────", style="color(238) dim", delay=0.008)


def _print_made_by() -> None:
    """Left-aligned 'made by Swastik' printed char-by-char at 0.04 s/char."""
    parts = [
        ("── made by ", "color(240) italic"),
        ("Swastik",     "color(213) bold"),
        (" ──",         "color(240) italic"),
    ]
    for text, style_str in parts:
        esc = _ansi(style_str)
        for char in text:
            _raw_write(f"{esc}{char}{_RESET_ESC}")
            time.sleep(0.04)
    _raw_write("\n")


def _print_quote(bc: Console, author: str, quote: str) -> None:
    """Single quote with separator/❝❞ formatting, typewriter output."""
    sep = "  ─────────────────────────────────────────────────"
    _typewrite(sep, style="color(238) dim", delay=0.005)
    bc.print()

    wrapped_lines = textwrap.fill(quote, width=65).splitlines()
    for i, ln in enumerate(wrapped_lines):
        prefix = "   ❝  " if i == 0 else "      "
        suffix = "  ❞" if i == len(wrapped_lines) - 1 else ""
        _typewrite(prefix + ln + suffix, style="color(252) italic", delay=0.022)

    bc.print()
    _typewrite(f"        — {author}", style="color(87) bold", delay=0.035)
    bc.print()
    _typewrite(sep, style="color(238) dim", delay=0.005)


def _print_disclaimer(bc: Console) -> None:
    """Plain typewriter legal notice — no Rich Panel."""
    sep = "  ─────────────────────────────────────────────────"
    bc.print()
    _typewrite(sep, style="color(238) dim", delay=0.005)
    bc.print()
    _typewrite("  ⚠  LEGAL NOTICE", style="color(196) bold", delay=0.03)
    bc.print()
    _typewrite("  Use only on systems you own or have written",      style="color(252)", delay=0.015)
    _typewrite("  permission to test. Unauthorized access is a",     style="color(252)", delay=0.015)
    _typewrite("  criminal offence under CFAA, IT Act 2000 and",     style="color(252)", delay=0.015)
    _typewrite("  equivalent laws worldwide. No liability accepted.", style="color(252)", delay=0.015)
    bc.print()
    _typewrite(sep, style="color(238) dim", delay=0.005)


def _print_status(bc: Console) -> None:
    """Segment-by-segment ANSI typewriter status line."""
    ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    bc.print()
    segments = [
        ("  ◈ ",        "color(51)"),
        ("toolkit: ",     "color(240) dim"),
        ("SHIV v3.0",     "color(87) bold"),
        ("   ◈ ",       "color(51)"),
        ("status: ",      "color(240) dim"),
        ("ready",         "color(87) bold"),
        ("   ◈ ",       "color(51)"),
        (ts,              "color(87) bold"),
    ]
    for text, style_str in segments:
        esc = _ansi(style_str)
        for char in text:
            _raw_write(f"{esc}{char}{_RESET_ESC}")
            time.sleep(0.012)
    _raw_write("\n")


def _print_enter_prompt(bc: Console) -> None:
    """Typewriter prompt → 3-color pulse → wait for ENTER → clear screen."""
    prompt = "           [ Press ENTER  to  launch  S·H·I·V ]"
    bc.print()
    _typewrite(prompt, style="color(51) bold", delay=0.045)

    pulse_colors = ["color(51)", "color(87)", "color(123)", "color(87)", "color(51)"]
    for _ in range(3):
        for c in pulse_colors:
            esc = _ansi(c + " bold")
            _raw_write(f"\r{esc}{prompt}{_RESET_ESC}   ")
            time.sleep(0.15)

    _raw_write("\r" + " " * (len(prompt) + 3) + "\r")

    try:
        input("")
    except (EOFError, KeyboardInterrupt):
        pass

    bc.clear()


def _ansi_str(text: str, style_str: str) -> str:
    """Wrap text in ANSI escape codes derived from a style string."""
    esc = _ansi(style_str)
    return f"{esc}{text}{_RESET_ESC}" if esc else text


def _rich_line(obj) -> str:
    """Render a Rich Text object to a plain ANSI string (no trailing newline)."""
    from io import StringIO as _StringIO
    sio = _StringIO()
    cap = Console(file=sio, force_terminal=True, legacy_windows=False,
                  highlight=False, width=80)
    cap.print(obj, end="")
    return sio.getvalue()


def _build_right_column(author: str, quote: str) -> list[str]:
    """Build the right-hand text panel as a list of ANSI-colored strings."""
    sep = _ansi_str("  ─────────────────────────────────────────", "color(238) dim")
    L: list[str] = []

    L += ["", ""]

    # SHIV logo
    for row in SHIV_ART.splitlines():
        if row.strip():
            L.append(_rich_line(_color_row(row)))
    L.append("")

    # Tagline
    L.append(
        "  "
        + _ansi_str("S", "color(51) bold") + _ansi_str("ecurity  ",         "color(240)")
        + _ansi_str("H", "color(51) bold") + _ansi_str("unting  ",           "color(240)")
        + _ansi_str("I", "color(51) bold") + _ansi_str("ntelligence  &  ",   "color(240)")
        + _ansi_str("V", "color(51) bold") + _ansi_str("ulnerability Assessment", "color(240)")
    )
    L.append(_ansi_str("          ─────── recon_toolkit ───────", "color(238) dim"))
    L.append("")

    # Made by
    L.append(
        _ansi_str("  ── made by ", "color(240) italic")
        + _ansi_str("Swastik",     "color(213) bold")
        + _ansi_str(" ──",         "color(240) italic")
    )
    L.append("")

    # Quote
    L.append(sep)
    L.append("")
    wrapped = textwrap.fill(quote, width=50).splitlines()
    for i, ln in enumerate(wrapped):
        prefix = "   ❝  " if i == 0 else "      "
        suffix = "  ❞"    if i == len(wrapped) - 1 else ""
        L.append(_ansi_str(prefix + ln + suffix, "color(252) italic"))
    L.append("")
    L.append(_ansi_str(f"        — {author}", "color(87) bold"))
    L.append("")
    L.append(sep)

    # Disclaimer
    L.append("")
    L.append(_ansi_str("  ⚠  LEGAL NOTICE", "color(196) bold"))
    L.append("")
    for ln in (
        "  Use only on systems you own or have written",
        "  permission to test. Unauthorized access is a",
        "  criminal offence under CFAA, IT Act 2000 and",
        "  equivalent laws worldwide. No liability accepted.",
    ):
        L.append(_ansi_str(ln, "color(252)"))
    L.append("")
    L.append(sep)

    # Status
    ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    L.append("")
    L.append(
        _ansi_str("  ◈ ", "color(51)")
        + _ansi_str("toolkit: ",  "color(240) dim") + _ansi_str("SHIV v3.0", "color(87) bold")
        + _ansi_str("   ◈ ",      "color(51)")
        + _ansi_str("status: ",   "color(240) dim") + _ansi_str("ready",     "color(87) bold")
        + _ansi_str("   ◈ ",      "color(51)")
        + _ansi_str(ts,            "color(87) bold")
    )
    return L


def print_banner() -> None:
    """Full launch banner — SHIV edition, called once at startup."""
    os.system("cls" if os.name == "nt" else "clear")
    bc = _make_banner_console()

    _data = Path(__file__).parent.parent / "data" / "mahadev.png"

    if _data.exists():
        try:
            img_lines = _render_image_blocks(str(_data))
        except Exception:
            img_lines = []

        if img_lines:
            author, quote = random.choice(QUOTES)
            txt_lines     = _build_right_column(author, quote)
            n = max(len(img_lines), len(txt_lines))
            for i in range(n):
                left  = img_lines[i] if i < len(img_lines) else " " * 54
                right = txt_lines[i] if i < len(txt_lines) else ""
                _raw_write(left + "  " + right + "\n")
                time.sleep(0.012)
            _print_enter_prompt(bc)
            return

    # No image — text-only layout (no ASCII art fallback)
    _print_art(bc)
    _print_tagline()
    _print_made_by()
    author, quote = random.choice(QUOTES)
    bc.print()
    _print_quote(bc, author, quote)
    _print_disclaimer(bc)
    _print_status(bc)
    _print_enter_prompt(bc)


def print_compact_header(target: str | None = None) -> None:
    """One-line header shown at the top of each command run."""
    ts    = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    label = target or "no target"
    t = Text.assemble(
        ("  SHIV-recon_toolkit", Style(color="color(51)", bold=True)),
        ("  ◈  ",       Style(color="color(238)")),
        (ts,                Style(color="color(240)", dim=True)),
        ("  ◈  ",       Style(color="color(238)")),
        (label,             Style(color="color(87)")),
    )
    console.print(t)
    console.print()


def print_findings_table(findings: list[dict[str, Any]], title: str = "Findings") -> None:
    """
    Render a Rich table of scan findings with severity coloring.

    Args:
        findings: List of finding dicts with keys: severity, cve, service, port, description.
        title: Table title.
    """
    table = Table(
        title=title,
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("CVE/Finding", width=20)
    table.add_column("Service", width=12)
    table.add_column("Port", width=6)
    table.add_column("Description", ratio=1)

    sev_styles = {
        "critical": "bold red",
        "high":     "red",
        "medium":   "yellow",
        "low":      "green",
        "info":     "cyan",
    }

    for f in findings:
        sev   = f.get("severity", "info").lower()
        style = sev_styles.get(sev, "white")
        table.add_row(
            f"[{style}]{sev.upper()}[/{style}]",
            f.get("cve", f.get("finding", "N/A")),
            f.get("service", ""),
            str(f.get("port", "")),
            f.get("description", ""),
        )

    console.print(table)
