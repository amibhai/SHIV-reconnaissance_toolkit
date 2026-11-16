"""
recon.tui — interactive menu front-end.

A thin layer over the same engine + registry + OutputManager the CLI uses: it
enumerates capabilities from the registry (no hand-maintained menu list), runs
the chosen one through recon.engine, and writes a real report in every
configured format. This replaces the old ~1400-line menu that drove a separate
legacy `tools/*` engine and produced no report at all.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

from recon.core.config import ReconConfig
from recon.core.logger import (
    configure_logging,
    console,
    print_banner,
    print_compact_header,
    print_findings_table,
)
from recon.core.output import OutputManager
from recon.core.privilege import PrivilegeChecker
from recon.core.registry import all_specs
from recon import engine  # noqa: F401 — importing populates the registry

__all__ = ["main"]


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return value or default


def _collect_options(spec) -> dict:
    """Prompt for the few options a given capability supports."""
    opts: dict = {}
    if spec.name in ("portscan", "asyncscan"):
        opts["ports"] = _ask("Ports (top100/top1000/all/80,443)", "top1000")
    if spec.name == "portscan":
        opts["scan_type"] = _ask("Scan type (connect/syn/udp)", "connect")
    if spec.name == "tlsprobe":
        opts["port"] = int(_ask("Port", "443") or 443)
    if spec.name == "tlsprobe":
        opts["ct"] = _ask("Query CT logs? (y/N)", "n").lower().startswith("y")
    if spec.name == "snmpenum":
        community = _ask("Community (blank = brute-force)", "")
        if community:
            opts["community"] = community
    return opts


def _run_spec(spec, cfg: ReconConfig) -> None:
    if spec.runner is None:
        console.print(
            f"[yellow]{spec.name} is not available from the menu "
            f"(needs an interface / elevated privileges). Use the CLI.[/yellow]"
        )
        return

    target = _ask("Target (IP / hostname / CIDR)")
    if not target:
        console.print("[red]No target provided.[/red]")
        return

    opts = _collect_options(spec)
    console.print(f"\n[cyan]Running {spec.name} on {target} …[/cyan]")
    try:
        report = spec.runner(target, cfg, **opts)
    except Exception as exc:  # a scan failure must not kill the menu
        console.print(f"[red]{spec.name} failed: {exc}[/red]")
        return

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = f"{spec.name}_{target.replace('/', '_').replace(':', '_')}_{ts}"
    paths = OutputManager(cfg.output_dir, base).write_all(
        report, cfg.report_formats or ["json", "html"]
    )
    if report.raw_findings:
        print_findings_table(report.raw_findings, title=f"Findings: {target}")
    else:
        console.print(f"[dim]No findings for {target}.[/dim]")
    for fmt, path in paths.items():
        console.print(f"[green]{fmt.upper()}:[/green] {path}")


def main() -> None:
    configure_logging(verbosity=1)
    cfg = ReconConfig()
    cfg.ensure_output_dir()

    if sys.stdin.isatty() and os.environ.get("RECON_NO_BANNER") != "1":
        print_banner(interactive=True)

    priv = PrivilegeChecker()
    priv.check()

    while True:
        print_compact_header()
        specs = all_specs()
        console.print("[bold]Select a scan:[/bold]\n")
        for i, spec in enumerate(specs, 1):
            ok = spec.required_feature is None or priv.can(spec.required_feature)
            mark = "" if ok else " [red](unavailable)[/red]"
            console.print(f"  [cyan]{i:>2}[/cyan]. [bold]{spec.name}[/bold]{mark} — {spec.summary}")
        console.print("   [cyan]0[/cyan]. exit")

        choice = _ask("\nChoice")
        if choice.lower() in ("0", "q", "exit", ""):
            break
        try:
            spec = specs[int(choice) - 1]
        except (ValueError, IndexError):
            console.print("[red]Invalid choice.[/red]")
            continue

        _run_spec(spec, cfg)
        _ask("\nPress ENTER to continue")

    console.print("[dim]Done.[/dim]")


if __name__ == "__main__":
    main()
