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

ADIYOGI_ART = """\
                              ☽
     ~~   ~~   ~~   ~~   ~~   ~~   ~~   ~~
   ~~  ~~   ~~   ~~   ~~   ~~   ~~   ~~  ~~
  ~~  ~~  ~~  ~~  .─────────────────.  ~~  ~~
  ~~  ~~  ~~  ~~ /  ─ ─ ─ • ─ ─ ─   \ ~~  ~~
  ~~  ~~  ~~  ~~|   ╭──╮     ╭──╮    |~~  ~~
  ~~  ~~  ~~  ~~|   ╰──╯     ╰──╯    |~~  ~~
  ~~  ~~  ~~  ~~|        ∩            |~~  ~~
  ~~  ~~  ~~  ~~|     ─────────       |~~  ~~
  ~~  ~~  ~~  ~~ \   ─ ─ ─ ─ ─ ─    / ~~  ~~
  ~~  ~~  ~~  ~~   ─────────────────  ~~  ~~
    ~~   ~~   ~~   ~~   ~~   ~~   ~~   ~~"""

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

_S_JATA  = Style(color="color(87)")              # cyan for matted hair (jata)
_S_MOON  = Style(color="color(226)", bold=True)   # gold for crescent moon
_S_TEYE  = Style(color="color(196)", bold=True)   # red for third eye (Ajna)
_S_EYES  = Style(color="color(123)", bold=True)   # bright cyan for eye brackets
_S_FACE  = Style(color="color(255)")              # bright white for face

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


def _color_adiyogi_row(row: str) -> Text:
    """Color a single Adiyogi art row — gold moon, cyan jata, red third eye, white face."""
    t = Text()
    for ch in row:
        if ch == '☽':       # ☽ crescent
            t.append(ch, _S_MOON)
        elif ch == '~':
            t.append(ch, _S_JATA)
        elif ch == '•':     # • third eye
            t.append(ch, _S_TEYE)
        elif ch in ('╭', '╮', '╰', '╯'):  # ╭ ╮ ╰ ╯
            t.append(ch, _S_EYES)
        else:
            t.append(ch, _S_FACE)
    return t


def _print_adiyogi(bc: Console) -> None:
    """Scan-line reveal of the Adiyogi Shiva ASCII art."""
    for row in ADIYOGI_ART.splitlines():
        bc.print(_color_adiyogi_row(row))
        time.sleep(0.04)


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
    """Scan-line reveal — print each art row with a 0.04 s delay."""
    for row in RECON_ART.splitlines():
        if not row.strip():
            continue
        bc.print(_color_row(row))
        time.sleep(0.04)


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
        ("recon v2.0",    "color(87) bold"),
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
    prompt = "         [ Press ENTER to launch recon-toolkit ]"
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


def print_banner() -> None:
    """Full launch banner — wifi_down-style, called once at startup."""
    os.system("cls" if os.name == "nt" else "clear")
    bc = _make_banner_console()

    _print_art(bc)
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
        ("  recon-toolkit", Style(color="color(51)", bold=True)),
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
