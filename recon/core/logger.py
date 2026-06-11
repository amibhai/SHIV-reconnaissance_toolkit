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
from rich.panel import Panel
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

_RESET_ESC = "\033[0m"


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


def print_banner() -> None:
    """Print the toolkit banner with legal disclaimer."""
    banner = r"""
[bold red]
 ____  _____ ____ ___  _   _
|  _ \| ____/ ___/ _ \| \ | |
| |_) |  _|| |  | | | |  \| |
|  _ <| |__| |__| |_| | |\  |
|_| \_\_____\____\___/|_| \_|[/bold red]
[bold yellow]     Network Reconnaissance Suite v2.0[/bold yellow]
    """
    console.print(banner)
    console.print(
        Panel(
            "[bold yellow]⚠  LEGAL NOTICE[/bold yellow]\n\n"
            "This toolkit is designed for [bold]authorized security testing[/bold] "
            "and [bold]educational purposes only[/bold].\n\n"
            "Unauthorized use against systems you do not own or lack explicit "
            "written permission to test is [bold red]illegal[/bold red] and may "
            "violate the Computer Fraud and Abuse Act (CFAA), the UK Computer "
            "Misuse Act, and equivalent laws worldwide.\n\n"
            "By using this tool you confirm you have [bold green]written authorization[/bold green] "
            "from the target system owner.",
            style="yellow",
            title="[bold red]WARNING[/bold red]",
            expand=False,
        )
    )


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
