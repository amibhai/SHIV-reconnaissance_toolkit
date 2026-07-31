"""
recon.py -- Main CLI entrypoint for the Recon Toolkit v2.0.

LEGAL NOTICE: This tool is for authorized security testing and educational
purposes only. Using it against systems without explicit written permission
is illegal under the CFAA, UK Computer Misuse Act, and equivalent laws.

Usage:
  python recon.py dns -d example.com [--full]
  python recon.py discover -t 192.168.1.0/24 --all
  python recon.py os -t 192.168.1.100 --full
  python recon.py portscan -t 192.168.1.100 -s syn -p top1000
  python recon.py vulnscan -t 192.168.1.100 --ssl --cve --creds
  python recon.py wireless --list
  python recon.py full -t 192.168.1.100 --out ./report
"""

from __future__ import annotations

import json
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# -- Bootstrap logging before any module import ------------------------------
from recon.core.logger import configure_logging, console, get_logger, print_banner
from recon.core.config import ReconConfig
from recon.core.output import OutputManager, ScanReport
from recon.core.privilege import PrivilegeChecker

_log = get_logger("cli")

app = typer.Typer(
    name="recon",
    help="Production-grade network reconnaissance suite. AUTHORIZED USE ONLY.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# -- Shared CLI options ------------------------------------------------------

def _common_config(
    threads:    int   = 50,
    timeout:    float = 3.0,
    output_dir: Path  = Path("./output"),
    evasion:    int   = 0,
    pcap:       bool  = False,
    verbose:    int   = 1,
) -> ReconConfig:
    """Build a ReconConfig from common CLI parameters."""
    cfg = ReconConfig(
        threads=threads,
        timeout=timeout,
        output_dir=output_dir,
        evasion_level=evasion,
        pcap_enabled=pcap,
        verbosity=verbose,
    )
    configure_logging(verbosity=verbose)
    cfg.ensure_output_dir()
    return cfg


# -- dns subcommand ----------------------------------------------------------

@app.command()
def dns(
    domain:       str           = typer.Option(..., "-d", "--domain", help="Target domain"),
    full:         bool          = typer.Option(False, "--full",    help="Run all DNS checks"),
    zone:         bool          = typer.Option(False, "--zone",    help="Zone transfer only"),
    brute:        bool          = typer.Option(False, "--brute",   help="Subdomain brute-force only"),
    reverse:      Optional[str] = typer.Option(None,  "--reverse", help="Reverse DNS CIDR (e.g. 192.168.1.0/24)"),
    wordlist:     Optional[Path]= typer.Option(None,  "-w", "--wordlist", help="Custom subdomain wordlist"),
    threads:      int           = typer.Option(50,    "-t", "--threads"),
    timeout:      float         = typer.Option(3.0,   "--timeout"),
    output_dir:   Path          = typer.Option(Path("./output"), "-o", "--output-dir"),
    evasion:      int           = typer.Option(0,     "--evasion", min=0, max=3),
    verbose:      int           = typer.Option(1,     "-v", "--verbose", count=True),
    pcap:         bool          = typer.Option(False, "--pcap"),
) -> None:
    """[cyan]DNS enumeration[/cyan]: zone transfer, brute-force, record types, DNSSEC."""
    print_banner()
    cfg = _common_config(threads, timeout, output_dir, evasion, pcap, verbose)

    from recon.modules.dns_enum import DNSEnumerator

    enumerator = DNSEnumerator(domain, cfg, wordlist_path=wordlist)

    do_zone = zone or full or not (brute or reverse)
    do_brute = brute or full
    do_records = full or not (zone or brute or reverse)
    do_dnssec = full or do_records

    results = enumerator.run_full(
        do_zone=do_zone,
        do_brute=do_brute,
        do_records=do_records,
        do_dnssec=do_dnssec,
        reverse_cidr=reverse,
    )

    # Save outputs
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = OutputManager(cfg.output_dir, f"dns_{domain}_{ts}")

    report = ScanReport(target=domain, scan_type="dns")
    for r in results.get("records", []):
        report.add_dns(r)
    for s in results.get("subdomains", []):
        report.add_subdomain(s)
    report.finalize()

    json_path = out.write_json(report)
    html_path = out.write_html(report)
    console.print(f"\n[green]JSON:[/green] {json_path}")
    console.print(f"[green]HTML:[/green] {html_path}")


# -- discover subcommand -----------------------------------------------------

@app.command()
def discover(
    target:     str   = typer.Option(..., "-t", "--target", help="CIDR / IP range / hostname"),
    all_methods:bool  = typer.Option(False, "--all",  help="Use all discovery methods"),
    arp:        bool  = typer.Option(False, "--arp",  help="ARP sweep (root required)"),
    icmp:       bool  = typer.Option(False, "--icmp", help="ICMP sweep"),
    tcp:        bool  = typer.Option(False, "--tcp",  help="TCP connect sweep"),
    udp:        bool  = typer.Option(False, "--udp",  help="UDP probe sweep"),
    threads:    int   = typer.Option(100,  "--threads"),
    timeout:    float = typer.Option(2.0,  "--timeout"),
    output_dir: Path  = typer.Option(Path("./output"), "-o"),
    evasion:    int   = typer.Option(0,    "--evasion", min=0, max=3),
    verbose:    int   = typer.Option(1,    "-v", count=True),
    pcap:       bool  = typer.Option(False, "--pcap"),
) -> None:
    """[cyan]Host discovery[/cyan]: ARP / ICMP / TCP / UDP multi-method sweep."""
    print_banner()
    cfg = _common_config(threads, timeout, output_dir, evasion, pcap, verbose)

    from recon.modules.host_discovery import HostDiscovery

    use_arp  = arp  or all_methods or not any([arp, icmp, tcp, udp])
    use_icmp = icmp or all_methods or not any([arp, icmp, tcp, udp])
    use_tcp  = tcp  or all_methods or not any([arp, icmp, tcp, udp])
    use_udp  = udp  or all_methods

    disc = HostDiscovery(target, cfg)
    hosts = disc.run_full(use_arp=use_arp, use_icmp=use_icmp, use_tcp=use_tcp, use_udp=use_udp)

    # Print results table
    table = Table(title=f"Hosts: {target}", border_style="dim")
    table.add_column("IP", style="bold cyan")
    table.add_column("Hostname")
    table.add_column("MAC")
    table.add_column("Vendor")
    table.add_column("OS Hint")
    table.add_column("Methods")
    table.add_column("Open Ports")
    for h in hosts:
        table.add_row(
            h.ip, h.hostname, h.mac, h.vendor, h.ttl_os_hint,
            ",".join(h.methods),
            ",".join(str(p) for p in h.open_ports[:6]),
        )
    console.print(table)

    # Save
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = cfg.output_dir / f"discover_{ts}.json"
    with open(out_path, "w") as f:
        json.dump([h.to_dict() for h in hosts], f, indent=2)
    console.print(f"\n[green]Saved:[/green] {out_path}")


# -- os subcommand -----------------------------------------------------------

@app.command(name="os")
def os_scan(
    target:     str   = typer.Option(..., "-t", "--target", help="Target IP/hostname"),
    full:       bool  = typer.Option(False, "--full",      help="All fingerprint methods"),
    ttl:        bool  = typer.Option(False, "--ttl",       help="TTL analysis only"),
    banner:     bool  = typer.Option(False, "--banner",    help="Banner analysis only"),
    tcp_stack:  bool  = typer.Option(False, "--tcp-stack", help="TCP stack fingerprint only"),
    timeout:    float = typer.Option(3.0,   "--timeout"),
    output_dir: Path  = typer.Option(Path("./output"), "-o"),
    verbose:    int   = typer.Option(1,     "-v", count=True),
) -> None:
    """[cyan]OS fingerprinting[/cyan]: TTL, TCP stack, banner, ICMP quirks."""
    print_banner()
    cfg = _common_config(timeout=timeout, output_dir=output_dir, verbose=verbose)

    from recon.modules.os_fingerprint import OSFingerprinter

    fp = OSFingerprinter(target, cfg)
    guess = fp.run_full()

    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]OS Guess:[/bold] [cyan]{guess.os_guess}[/cyan]\n"
        f"[bold]Confidence:[/bold] {guess.confidence}%\n"
        f"[bold]Methods:[/bold] {', '.join(f'{k}: {v}' for k, v in guess.methods.items())}",
        title="OS Fingerprint Result",
        border_style="cyan",
    ))


# -- portscan subcommand -----------------------------------------------------

@app.command()
def portscan(
    target:     str   = typer.Option(..., "-t", "--target",  help="Target IP/hostname"),
    scan_type:  str   = typer.Option("syn", "-s", "--scan",
                        help="Scan type: syn|connect|fin|xmas|null|ack|maimon|udp"),
    ports:      str   = typer.Option("top1000", "-p", "--ports",
                        help="Port spec: top100|top1000|all|1-1024|80,443"),
    no_service: bool  = typer.Option(False, "--no-service", help="Skip service detection"),
    threads:    int   = typer.Option(50,   "--threads"),
    timeout:    float = typer.Option(3.0,  "--timeout"),
    output_dir: Path  = typer.Option(Path("./output"), "-o"),
    evasion:    int   = typer.Option(0,    "--evasion", min=0, max=3),
    verbose:    int   = typer.Option(1,    "-v", count=True),
    pcap:       bool  = typer.Option(False, "--pcap"),
) -> None:
    """[cyan]Port scanner[/cyan]: SYN / Connect / FIN / XMAS / NULL / ACK / UDP."""
    print_banner()
    cfg = _common_config(threads, timeout, output_dir, evasion, pcap, verbose)

    from recon.modules.port_scan import PortScanner

    scanner = PortScanner(target, cfg)
    results = scanner.scan_ports(
        ports=ports,
        scan_type=scan_type.lower(),
        detect_services=not no_service,
    )

    # Display results
    table = Table(title=f"Port Scan: {target} [{scan_type.upper()}]", border_style="dim")
    table.add_column("Port", style="bold magenta")
    table.add_column("Proto")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("Banner")
    for r in results:
        state_style = {
            "open": "bold green", "closed": "dim", "filtered": "yellow",
            "open|filtered": "yellow", "unfiltered": "cyan",
        }.get(r.state, "white")
        table.add_row(
            str(r.port),
            r.protocol,
            f"[{state_style}]{r.state}[/{state_style}]",
            r.service,
            r.version,
            r.banner[:60] if r.banner else "",
        )
    console.print(table)

    # Save
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = cfg.output_dir / f"portscan_{target}_{ts}.json"
    with open(out_path, "w") as f:
        json.dump([r.to_dict() for r in results], f, indent=2)
    console.print(f"\n[green]Saved:[/green] {out_path}")


# -- vulnscan subcommand -----------------------------------------------------

@app.command()
def vulnscan(
    target:     str        = typer.Option(...,  "-t", "--target", help="Target IP/hostname"),
    ports:      Optional[str] = typer.Option(None, "-p", "--ports",
                              help="Ports to scan (default: auto-detect from portscan)"),
    ssl_check:  bool       = typer.Option(False, "--ssl",     help="SSL/TLS audit"),
    cve_check:  bool       = typer.Option(False, "--cve",     help="CVE banner matching"),
    creds_check:bool       = typer.Option(False, "--creds",   help="Default credential tests"),
    misconfig:  bool       = typer.Option(False, "--misconfig", help="Misconfiguration checks"),
    all_checks: bool       = typer.Option(False, "--all",     help="Run all checks"),
    threads:    int        = typer.Option(20,    "--threads"),
    timeout:    float      = typer.Option(5.0,   "--timeout"),
    output_dir: Path       = typer.Option(Path("./output"), "-o"),
    verbose:    int        = typer.Option(1,     "-v", count=True),
    pcap:       bool       = typer.Option(False, "--pcap"),
) -> None:
    """[cyan]Vulnerability scanner[/cyan]: CVE matching, SSL audit, default creds, misconfigs."""
    print_banner()
    cfg = _common_config(threads, timeout, output_dir, verbose=verbose, pcap=pcap)

    from recon.modules.port_scan import PortScanner, _parse_port_spec
    from recon.modules.vuln_scan import VulnScanner
    from recon.core.logger import print_findings_table

    # First run a quick port scan if no ports given
    port_results: list[dict] = []
    if ports:
        scanner = PortScanner(target, cfg)
        open_ports = scanner.scan_ports(ports=ports, scan_type="connect", detect_services=True)
        port_results = [r.to_dict() for r in open_ports]
    else:
        _log.info("Running quick top-100 connect scan first...")
        scanner = PortScanner(target, cfg)
        open_ports = scanner.scan_ports(ports="top100", scan_type="connect", detect_services=True)
        port_results = [r.to_dict() for r in open_ports]

    do_ssl     = ssl_check or all_checks
    do_cve     = cve_check or all_checks
    do_creds   = creds_check or all_checks
    do_misc    = misconfig or all_checks
    if not any([ssl_check, cve_check, creds_check, misconfig, all_checks]):
        do_cve = do_misc = True  # default

    vscan = VulnScanner(target, cfg)
    findings = vscan.run_full(
        port_results=port_results,
        check_creds=do_creds,
        check_misconfig=do_misc,
        check_cve=do_cve,
    )

    print_findings_table(
        [f.to_dict() for f in findings],
        title=f"Vulnerability Findings: {target}",
    )

    # Save
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = cfg.output_dir / f"vulnscan_{target}_{ts}.json"
    with open(out_path, "w") as f:
        json.dump([f.to_dict() for f in findings], f, indent=2)
    console.print(f"\n[green]Saved:[/green] {out_path}")


# -- wireless subcommand -----------------------------------------------------

@app.command()
def wireless(
    list_ifaces: bool         = typer.Option(False, "--list",    help="List wireless interfaces"),
    monitor:     Optional[str]= typer.Option(None,  "--monitor", help="Enable monitor mode on interface"),
    restore:     Optional[str]= typer.Option(None,  "--restore", help="Restore interface to managed mode"),
    scan:        bool         = typer.Option(False, "--scan",    help="Capture and display networks"),
    iface:       Optional[str]= typer.Option(None,  "-i",        help="Interface for scan"),
    duration:    int          = typer.Option(30,    "--duration", help="Capture duration (seconds)"),
    bands:       str          = typer.Option("2.4ghz,5ghz", "--bands"),
    output_dir:  Path         = typer.Option(Path("./output"), "-o"),
    verbose:     int          = typer.Option(1,     "-v", count=True),
) -> None:
    """[cyan]Wireless reconnaissance[/cyan]: monitor mode, channel hopping, network discovery."""
    print_banner()
    cfg = _common_config(output_dir=output_dir, verbose=verbose)

    from recon.modules.wireless import WirelessManager

    wm = WirelessManager(cfg)

    if list_ifaces:
        ifaces = wm.discover_interfaces()
        if not ifaces:
            console.print("[yellow]No wireless interfaces found[/yellow]")
            return
        table = Table(title="Wireless Interfaces", border_style="dim")
        table.add_column("Name", style="bold cyan")
        table.add_column("MAC")
        table.add_column("Mode")
        table.add_column("PHY")
        for i in ifaces:
            table.add_row(i.get("name",""), i.get("mac",""), i.get("mode",""), i.get("phy",""))
        console.print(table)
        return

    if restore:
        wm.disable_monitor_mode(restore)
        return

    if monitor:
        mon_iface = wm.enable_monitor_mode(monitor)
        if not mon_iface:
            console.print("[red]Failed to enable monitor mode[/red]")
            raise typer.Exit(1)
        console.print(f"[green]Monitor mode enabled:[/green] {mon_iface}")
        return

    if scan:
        target_iface = iface
        if not target_iface:
            wm.discover_interfaces()
            if not wm._interfaces:
                console.print("[red]No wireless interfaces found[/red]")
                raise typer.Exit(1)
            target_iface = wm._interfaces[0]["name"]
        mon_iface = wm.enable_monitor_mode(target_iface)
        if not mon_iface:
            console.print("[red]Could not enable monitor mode[/red]")
            raise typer.Exit(1)
        band_list = [b.strip() for b in bands.split(",")]
        wm.hop_channels(mon_iface, bands=band_list)
        networks = wm.start_capture(mon_iface, duration=duration)
        wm.stop_hopping()
        wm.disable_monitor_mode(mon_iface)

        table = Table(title="Wireless Networks", border_style="dim")
        table.add_column("BSSID", style="bold cyan")
        table.add_column("SSID")
        table.add_column("Ch")
        table.add_column("Signal")
        table.add_column("Encryption")
        table.add_column("Beacons")
        table.add_column("Flags")
        for n in networks:
            table.add_row(
                n.bssid, n.ssid, str(n.channel), f"{n.signal_dbm} dBm",
                n.encryption, str(n.beacons),
                " ".join(filter(None, ["PMKID" if n.pmkid_seen else "", "EAPOL" if n.eapol_seen else ""])),
            )
        console.print(table)


# -- full subcommand ---------------------------------------------------------

@app.command()
def full(
    target:     str   = typer.Option(..., "-t", "--target", help="Target IP/hostname/CIDR"),
    out:        Path  = typer.Option(Path("./output"), "--out", "-o"),
    threads:    int   = typer.Option(50,   "--threads"),
    timeout:    float = typer.Option(3.0,  "--timeout"),
    evasion:    int   = typer.Option(0,    "--evasion", min=0, max=3),
    verbose:    int   = typer.Option(1,    "-v", count=True),
    pcap:       bool  = typer.Option(False, "--pcap"),
    open_report:bool  = typer.Option(True,  "--open/--no-open", help="Open HTML report in browser"),
) -> None:
    """
    [bold cyan]Full pipeline[/bold cyan]: discover -> OS fingerprint -> port scan -> vuln scan -> HTML report.

    Feeds results from each stage into the next for maximum accuracy.
    """
    print_banner()

    # Privilege check
    priv = PrivilegeChecker()
    status = priv.check()
    if not status.is_root:
        console.print(
            "[yellow]Warning: Running without root. SYN scan, ARP, and ICMP "
            "will fall back to connect/system-ping.[/yellow]"
        )

    cfg = _common_config(threads, timeout, out, evasion, pcap, verbose)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report = ScanReport(target=target, scan_type="full")

    findings_live: list[dict] = []
    live_table = Table(title="Live Findings", border_style="dim", expand=True)
    live_table.add_column("Sev", width=10)
    live_table.add_column("Finding")
    live_table.add_column("Service")
    live_table.add_column("Port")
    live_table.add_column("Description", ratio=1)

    # -- Stage 1: Host discovery ------------------------------------------
    console.rule("[bold cyan]Stage 1: Host Discovery[/bold cyan]")
    from recon.modules.host_discovery import HostDiscovery, HostResult as HDiscResult

    disc = HostDiscovery(target, cfg)
    hosts = disc.run_full(use_arp=status.is_root, use_icmp=True, use_tcp=True, use_udp=False)

    if not hosts:
        console.print(f"[yellow]No hosts found for {target}. Check the target and try again.[/yellow]")
        raise typer.Exit(0)

    # -- Stage 2: OS fingerprint each host -------------------------------
    console.rule("[bold cyan]Stage 2: OS Fingerprinting[/bold cyan]")
    from recon.modules.os_fingerprint import OSFingerprinter
    from recon.core.output import HostResult as ReportHost

    report_hosts: list[ReportHost] = []
    for h in hosts[:20]:  # Limit to 20 hosts for full pipeline
        fp = OSFingerprinter(h.ip, cfg)
        guess = fp.run_full()
        rh = ReportHost(
            ip=h.ip,
            hostname=h.hostname,
            mac=h.mac,
            vendor=h.vendor,
            os_guess=guess.os_guess,
            os_confidence=guess.confidence,
            methods=h.methods,
            ttl=h.ttl,
        )
        report_hosts.append(rh)
        report.add_host(rh)

    # -- Stage 3: Port scan each host -------------------------------------
    console.rule("[bold cyan]Stage 3: Port Scanning[/bold cyan]")
    from recon.modules.port_scan import PortScanner

    host_ports: dict[str, list[dict]] = {}
    scan_type = "syn" if status.is_root else "connect"

    for rh in report_hosts:
        scanner = PortScanner(rh.ip, cfg)
        open_ports = scanner.scan_ports(
            ports="top1000", scan_type=scan_type, detect_services=True
        )
        rh.ports = [r.to_dict() for r in open_ports]
        host_ports[rh.ip] = rh.ports
        console.print(
            f"  [cyan]{rh.ip}[/cyan]: {len(open_ports)} open ports"
        )

    # -- Stage 4: Vulnerability scan each host ---------------------------
    console.rule("[bold cyan]Stage 4: Vulnerability Scanning[/bold cyan]")
    from recon.modules.vuln_scan import VulnScanner

    for rh in report_hosts:
        ports = host_ports.get(rh.ip, [])
        if not ports:
            continue
        vscan = VulnScanner(rh.ip, cfg)
        findings = vscan.run_full(
            port_results=ports,
            check_creds=True,
            check_misconfig=True,
            check_cve=True,
        )
        rh.findings = [f.to_dict() for f in findings]
        for f in findings:
            report.add_finding(f.to_dict())
            findings_live.append(f.to_dict())

    # -- Stage 5: Generate reports ----------------------------------------
    console.rule("[bold cyan]Stage 5: Report Generation[/bold cyan]")
    report.finalize()

    base_name = f"full_{target.replace('/', '_')}_{ts}"
    output_mgr = OutputManager(cfg.output_dir, base_name)

    json_path = output_mgr.write_json(report)
    html_path = output_mgr.write_html(report)

    # Summary panel
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Hosts found:[/bold] {len(report_hosts)}\n"
        f"[bold]Total findings:[/bold] {len(report.raw_findings)}\n"
        f"[bold]Critical:[/bold] [red]{report.critical_count()}[/red]  "
        f"[bold]High:[/bold] [orange1]{report.high_count()}[/orange1]\n"
        f"[bold]Duration:[/bold] {report.duration_seconds():.1f}s\n\n"
        f"[bold]JSON:[/bold] {json_path}\n"
        f"[bold]HTML:[/bold] {html_path}",
        title="[bold green]Scan Complete[/bold green]",
        border_style="green",
    ))

    if open_report and html_path.exists():
        webbrowser.open(f"file://{html_path.resolve()}")


# -- privilege check subcommand ----------------------------------------------

@app.command()
def privcheck() -> None:
    """Show current privilege status and available features."""
    print_banner()
    priv = PrivilegeChecker()
    priv.check()
    priv.print_status()


# -- Entry point -------------------------------------------------------------

if __name__ == "__main__":
    app()
