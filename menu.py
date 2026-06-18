#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║        S·H·I·V  —  recon_toolkit  —  INTERACTIVE MENU              ║
║   Security Hunting · Intelligence · Vulnerability Assessment         ║
║  1. DNS Enumeration      — zone transfer, records, subdomain brute   ║
║  2. Host Discovery       — ARP, ICMP, TCP, UDP multi-method          ║
║  3. OS Scan              — TTL, TCP stack, banners, ICMP quirks      ║
║  4. Ping Sweep           — threaded ICMP/TCP with evasion options    ║
║  5. Port Scan            — SYN/Connect/FIN/XMAS/ACK/UDP + services  ║
║  6. Vulnerability Scan   — CVE DB, SSL audit, default creds          ║
║  7. Wireless Adapter     — auto-detect, monitor mode, hop channels   ║
║  P. PCAP Settings        — toggle capture, set output directory      ║
║  0. Exit                                                             ║
╚══════════════════════════════════════════════════════════════════════╝

Usage:
    sudo python3 menu.py        (root recommended)
    python3 menu.py             (non-root, reduced feature set)
"""

import sys
import os
import re
import time
import threading
import socket
from datetime import datetime

# ── Path setup: SCRIPT_DIR is the project root (recon-toolkit/) ──────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)                              # makes recon pkg importable
sys.path.insert(0, os.path.join(SCRIPT_DIR, "tools"))      # makes standalone tools importable

try:
    from recon.core.logger import print_banner as _full_banner, print_compact_header
    _HAS_LOGGER = True
except Exception:
    _HAS_LOGGER = False

# ── Optional Scapy (needed for PCAP) ─────────────────────────────────────────
try:
    from scapy.all import wrpcap, sniff, conf as _scapy_conf
    _scapy_conf.verb = 0
    SCAPY = True
except ImportError:
    SCAPY = False


# ═════════════════════════════════════════════════════════════════════════════
# COLOURS & UI HELPERS
# ═════════════════════════════════════════════════════════════════════════════

class C:
    RED  = "\033[91m"; GRN  = "\033[92m"; YLW  = "\033[93m"
    CYN  = "\033[96m"; MAG  = "\033[95m"; BLU  = "\033[94m"
    BOLD = "\033[1m";  DIM  = "\033[2m";  R    = "\033[0m"
    LINE = "\033[90m" + "─" * 70 + "\033[0m"


def banner():
    """Compact header shown at the top of every menu screen (not the full launch banner)."""
    os.system('cls' if os.name == 'nt' else 'clear')
    if _HAS_LOGGER:
        try:
            print_compact_header()
            return
        except Exception:
            pass
    # Fallback: plain header
    ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    print(f"\033[1;38;5;51m  SHIV-recon_toolkit\033[0m"
          f"\033[38;5;238m  ◈  \033[0m"
          f"\033[2;38;5;240m{ts}\033[0m\n")


def hdr(title, description=""):
    print(f"\n{C.LINE}")
    print(f"  {C.BOLD}{C.CYN}{title}{C.R}")
    if description:
        print(f"  {C.DIM}{description}{C.R}")
    print(f"{C.LINE}\n")


def info(m):  print(f"{C.CYN}  [*]{C.R} {m}")
def ok(m):    print(f"{C.GRN}  [+]{C.R} {m}")
def warn(m):  print(f"{C.YLW}  [!]{C.R} {m}")
def err(m):   print(f"{C.RED}  [✗]{C.R} {m}")
def sep():    print(f"  {C.DIM}{'─' * 50}{C.R}")


def ask(prompt, default=""):
    try:
        v = input(f"  {C.YLW}→{C.R} {prompt} [{C.BOLD}{default}{C.R}]: ").strip()
        return v if v else default
    except (KeyboardInterrupt, EOFError):
        print()
        return default


def ask_int(prompt, default, lo=1, hi=65535):
    while True:
        raw = ask(prompt, str(default))
        try:
            v = int(raw)
            if lo <= v <= hi:
                return v
            warn(f"Must be between {lo} and {hi}")
        except ValueError:
            warn("Please enter a whole number")


def ask_float(prompt, default):
    while True:
        raw = ask(prompt, str(default))
        try:
            return float(raw)
        except ValueError:
            warn("Please enter a number (e.g. 1.0)")


def pause():
    input(f"\n  {C.DIM}Press Enter to return to menu…{C.R}")


# ═════════════════════════════════════════════════════════════════════════════
# PCAP CAPTURE ENGINE
# Passive background sniffer — captures ALL traffic while a scan runs.
# ═════════════════════════════════════════════════════════════════════════════

_pcap_enabled  = False      # globally toggled from PCAP Settings menu
_pcap_dir      = "./pcaps"  # output directory
_pcap_active   = False      # True only during an active scan
_pcap_packets  = []         # accumulated packet buffer
_pcap_lock     = threading.Lock()
_pcap_stop_evt = None       # threading.Event to stop the sniffer thread
_pcap_thread   = None       # background sniff thread


class PCAPCapture:
    """
    Inline passive PCAP capture.

    Sniffs all traffic on the default interface in a background thread
    while a scan runs, then flushes to a named file on stop().

    Filename format:
        <ScanName>_<YYYYMMDD>_<HHMMSS>.pcap
        e.g.  DNS_Enumeration_20240427_143022.pcap
    """

    path   = None   # path of the current output file
    _label = ""     # scan name used for logging

    # ── start ──────────────────────────────────────────────────────────
    @classmethod
    def start(cls, scan_name: str):
        """Begin capture. No-op if PCAP is disabled or Scapy unavailable."""
        global _pcap_active, _pcap_packets, _pcap_stop_evt, _pcap_thread

        if not _pcap_enabled:
            return
        if not SCAPY:
            warn("Scapy not installed — PCAP unavailable.  pip3 install scapy")
            return

        # Build filename
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", scan_name.strip())
        safe = re.sub(r"_+", "_", safe).strip("_")
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{safe}_{ts}.pcap"

        os.makedirs(_pcap_dir, exist_ok=True)
        cls.path   = os.path.join(_pcap_dir, filename)
        cls._label = scan_name

        with _pcap_lock:
            _pcap_packets = []
            _pcap_active  = True

        _pcap_stop_evt = threading.Event()

        def _sniffer():
            try:
                sniff(
                    prn         = _pcap_record,
                    store       = False,
                    stop_filter = lambda _: _pcap_stop_evt.is_set(),
                )
            except Exception:
                pass

        _pcap_thread = threading.Thread(target=_sniffer, daemon=True)
        _pcap_thread.start()
        info(f"PCAP capture started  →  {C.BOLD}{cls.path}{C.R}")

    # ── stop ───────────────────────────────────────────────────────────
    @classmethod
    def stop(cls):
        """Stop capture and flush packets to disk."""
        global _pcap_active, _pcap_packets, _pcap_stop_evt, _pcap_thread

        if not _pcap_active:
            return

        # Signal sniffer to stop and wait briefly for it to drain
        if _pcap_stop_evt:
            _pcap_stop_evt.set()
        if _pcap_thread:
            _pcap_thread.join(timeout=3)

        with _pcap_lock:
            _pcap_active = False
            pkts = list(_pcap_packets)
            _pcap_packets = []

        if not pkts:
            if cls.path:
                warn(f"No packets captured for '{cls._label}'")
            return

        try:
            wrpcap(cls.path, pkts)
            size = os.path.getsize(cls.path)
            ok(f"PCAP saved  →  {C.BOLD}{cls.path}{C.R}  "
               f"({len(pkts):,} packets · {size:,} bytes)")
        except Exception as e:
            warn(f"wrpcap failed: {e}")


def _pcap_record(pkt):
    """Callback for every packet sniffed during a scan."""
    global _pcap_active, _pcap_packets
    if _pcap_active:
        with _pcap_lock:
            _pcap_packets.append(pkt)


def _pcap_status():
    """One-line status string shown on every menu screen."""
    if _pcap_enabled:
        return (f"  {C.GRN}{C.BOLD}PCAP  ON{C.R}  "
                f"{C.DIM}→ {_pcap_dir}  "
                f"(ScanName_YYYYMMDD_HHMMSS.pcap){C.R}")
    else:
        return (f"  {C.YLW}PCAP  OFF{C.R}  "
                f"{C.DIM}— press P to configure / "
                f"each scan will prompt you{C.R}")


def _maybe_start_pcap(label: str) -> bool:
    """
    Start capture if PCAP is globally ON.
    If PCAP is globally OFF, ask the user for a one-off capture.
    Returns True if a capture session was started.
    """
    global _pcap_enabled

    if _pcap_enabled:
        PCAPCapture.start(label)
        return True

    # One-off prompt
    sep()
    ans = ask("Save this scan to a PCAP file? (y/n)", "n").lower()
    if ans == "y":
        # Temporarily enable for this run only
        _pcap_enabled = True
        PCAPCapture.start(label)
        return True          # caller restores _pcap_enabled via _stop_pcap(True)
    return False


def _stop_pcap(was_temp: bool):
    """Stop capture; restore OFF state if PCAP was only temporarily enabled."""
    global _pcap_enabled
    PCAPCapture.stop()
    if was_temp:
        _pcap_enabled = False


# ═════════════════════════════════════════════════════════════════════════════
# PCAP SETTINGS SUBMENU
# ═════════════════════════════════════════════════════════════════════════════

def menu_pcap_settings():
    global _pcap_enabled, _pcap_dir

    while True:
        banner()
        hdr("PCAP Settings", "Configure inline packet capture for scan sessions")
        print(_pcap_status())
        print()
        print(f"  {C.CYN}1.{C.R}  Toggle PCAP  "
              f"({'currently ' + C.GRN + 'ON' + C.R if _pcap_enabled else 'currently ' + C.YLW + 'OFF' + C.R})")
        print(f"  {C.CYN}2.{C.R}  Set output directory   "
              f"{C.DIM}(current: {_pcap_dir}){C.R}")
        print(f"  {C.CYN}0.{C.R}  Back to main menu")
        print()

        choice = ask("Select", "0")

        if choice == "1":
            _pcap_enabled = not _pcap_enabled
            state = f"{C.GRN}ENABLED{C.R}" if _pcap_enabled else f"{C.YLW}DISABLED{C.R}"
            print(f"\n  PCAP capture {state}")
            if _pcap_enabled:
                info(f"Files will be saved to: {C.BOLD}{_pcap_dir}{C.R}")
                info("Format: ScanName_YYYYMMDD_HHMMSS.pcap")
            time.sleep(1)

        elif choice == "2":
            new_dir = ask("Output directory", _pcap_dir).strip()
            if new_dir:
                _pcap_dir = new_dir
                try:
                    os.makedirs(_pcap_dir, exist_ok=True)
                    ok(f"PCAP directory set  →  {C.BOLD}{_pcap_dir}{C.R}")
                except Exception as e:
                    warn(f"Could not create directory: {e}")
            time.sleep(1)

        elif choice == "0":
            break
        else:
            warn("Enter 1, 2 or 0")


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 1 — DNS ENUMERATION
# ═════════════════════════════════════════════════════════════════════════════

def menu_dns_enum():
    while True:
        banner()
        hdr("DNS Enumeration",
            "Zone transfers · Subdomain brute-force · Record enumeration · Cache snooping")
        print(_pcap_status())
        print()
        print(f"  {C.CYN}1.{C.R}  Full enumeration    — all methods combined")
        print(f"  {C.CYN}2.{C.R}  Zone transfer only  — AXFR attempt against all NS")
        print(f"  {C.CYN}3.{C.R}  DNS records only    — A/AAAA/MX/NS/TXT/SOA/SRV/CAA")
        print(f"  {C.CYN}4.{C.R}  Subdomain brute-force")
        print(f"  {C.CYN}5.{C.R}  Reverse DNS sweep   — PTR lookups over CIDR")
        print(f"  {C.CYN}0.{C.R}  Back")
        print()
        choice = ask("Select attack", "0")

        if choice == "0":
            break

        elif choice in ("1","2","3","4","5"):
            domain   = ask("Target domain", "example.com")
            threads  = ask_int("Threads", 10, 1, 200)
            timeout  = ask_int("Timeout (s)", 3, 1, 30)

            wordlist = None
            if choice in ("1","4"):
                wl_default = os.path.join(SCRIPT_DIR, "wordlists", "subdomains.txt")
                wl = ask("Subdomain wordlist (Enter = built-in)", wl_default)
                wordlist = wl if wl and os.path.exists(wl) else None

            cidr = None
            if choice == "5":
                cidr = ask("CIDR range for reverse sweep", "192.168.1.0/24")

            was_temp = _maybe_start_pcap("DNS_Enumeration")
            try:
                from dns_enum import DNSEnumerator
                e = DNSEnumerator(domain, threads, timeout, wordlist)

                if choice == "1":
                    e.run_full(wordlist)
                elif choice == "2":
                    e.zone_transfer()
                elif choice == "3":
                    e.enumerate_records()
                elif choice == "4":
                    e.wildcard_check()
                    e.subdomain_bruteforce(wordlist)
                elif choice == "5":
                    e.reverse_lookup_range(cidr)

            except ImportError as ex:
                err(f"Could not import dns_enum: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            finally:
                _stop_pcap(was_temp)
            pause()
        else:
            warn("Enter 1–5 or 0")


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 2 — HOST DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def menu_host_discovery():
    while True:
        banner()
        hdr("Host Discovery",
            "ARP sweep · ICMP echo · TCP port probing · UDP service probing")
        print(_pcap_status())
        print()
        print(f"  {C.CYN}1.{C.R}  Full discovery      — ARP + ICMP + TCP fallback")
        print(f"  {C.CYN}2.{C.R}  ARP sweep only      — Layer 2, local network only")
        print(f"  {C.CYN}3.{C.R}  ICMP sweep only     — ping sweep")
        print(f"  {C.CYN}4.{C.R}  TCP sweep only      — no root needed")
        print(f"  {C.CYN}5.{C.R}  UDP probe sweep     — DNS/NTP/SNMP probes")
        print(f"  {C.CYN}0.{C.R}  Back")
        print()
        choice = ask("Select attack", "0")

        if choice == "0":
            break

        elif choice in ("1","2","3","4","5"):
            target  = ask("Target (IP / CIDR / range e.g. 192.168.1.0/24)",
                          "192.168.1.0/24")
            threads = ask_int("Threads", 50, 1, 500)
            timeout = ask_float("Timeout (s)", 1.0)

            was_temp = _maybe_start_pcap("Host_Discovery")
            try:
                from host_discovery import HostDiscovery
                from recon_utils import expand_cidr

                disc = HostDiscovery(target, threads, timeout)

                if choice == "1":
                    disc.run_full()
                elif choice == "2":
                    disc.arp_sweep(target)
                elif choice == "3":
                    hosts = expand_cidr(target) if "/" in target else [target]
                    disc.icmp_sweep(hosts)
                elif choice == "4":
                    hosts = expand_cidr(target) if "/" in target else [target]
                    disc.tcp_sweep(hosts)
                elif choice == "5":
                    hosts = expand_cidr(target) if "/" in target else [target]
                    disc.udp_sweep(hosts)

            except ImportError as ex:
                err(f"Could not import host_discovery: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            finally:
                _stop_pcap(was_temp)
            pause()
        else:
            warn("Enter 1–5 or 0")


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 3 — OS SCAN
# ═════════════════════════════════════════════════════════════════════════════

def menu_os_scan():
    while True:
        banner()
        hdr("OS Scan",
            "TTL fingerprinting · TCP stack analysis · Banner grabbing · ICMP quirks")
        print(_pcap_status())
        print()
        print(f"  {C.CYN}1.{C.R}  Full OS scan        — all methods, best confidence")
        print(f"  {C.CYN}2.{C.R}  TTL fingerprint     — fast, no root needed")
        print(f"  {C.CYN}3.{C.R}  TCP stack analysis  — window/options/DF (root needed)")
        print(f"  {C.CYN}4.{C.R}  Banner grabbing     — service version extraction")
        print(f"  {C.CYN}5.{C.R}  ICMP quirk probes   — type 13/17 responses")
        print(f"  {C.CYN}0.{C.R}  Back")
        print()
        choice = ask("Select attack", "0")

        if choice == "0":
            break

        elif choice in ("1","2","3","4","5"):
            target  = ask("Target IP / hostname", "192.168.1.100")
            timeout = ask_int("Timeout (s)", 3, 1, 30)

            ports = None
            if choice in ("1","4"):
                raw = ask("Ports for banner scan (comma-sep, Enter = default)",
                          "21,22,80,443,3306,6379")
                ports = [int(p) for p in raw.split(",")
                         if p.strip().isdigit()] or None

            tcp_port = 80
            if choice == "3":
                tcp_port = ask_int("Port to probe for TCP fingerprint", 80, 1, 65535)

            was_temp = _maybe_start_pcap("OS_Scan")
            try:
                from os_scan import OSScanner
                scanner = OSScanner(target, timeout)

                if choice == "1":
                    scanner.run_full(ports)
                elif choice == "2":
                    scanner.ttl_fingerprint()
                elif choice == "3":
                    scanner.tcp_fingerprint(tcp_port)
                elif choice == "4":
                    scanner.banner_fingerprint(ports)
                elif choice == "5":
                    scanner.icmp_quirks()

            except ImportError as ex:
                err(f"Could not import os_scan: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            finally:
                _stop_pcap(was_temp)
            pause()
        else:
            warn("Enter 1–5 or 0")


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 4 — PING SWEEP
# ═════════════════════════════════════════════════════════════════════════════

def menu_ping_sweep():
    while True:
        banner()
        hdr("Ping Sweep",
            "Fast multi-threaded ICMP + TCP sweep · OS hints · Reverse DNS")
        print(_pcap_status())
        print()
        print(f"  {C.CYN}1.{C.R}  Standard sweep      — ICMP → sys ping → TCP fallback")
        print(f"  {C.CYN}2.{C.R}  Randomized sweep    — shuffled order, evades IDS")
        print(f"  {C.CYN}3.{C.R}  Fast sweep          — high thread count, low timeout")
        print(f"  {C.CYN}4.{C.R}  Custom sweep        — full parameter control")
        print(f"  {C.CYN}0.{C.R}  Back")
        print()
        choice = ask("Select attack", "0")

        if choice == "0":
            break

        elif choice in ("1","2","3","4"):
            target = ask("Target (IP / CIDR / range)", "192.168.1.0/24")

            # Set defaults by mode
            if choice == "1":
                threads, timeout, randomize = 100, 1.0, False
            elif choice == "2":
                threads, timeout, randomize = 100, 1.0, True
            elif choice == "3":
                threads, timeout, randomize = 300, 0.3, False
            else:  # custom
                threads   = ask_int("Threads", 100, 1, 1000)
                timeout   = ask_float("Timeout (s)", 1.0)
                randomize = ask("Randomize order? (y/n)", "n").lower() == "y"

            was_temp = _maybe_start_pcap("Ping_Sweep")
            try:
                from ping_sweep import PingSweep
                sweep = PingSweep(target, threads, timeout, randomize)
                sweep.run()

            except ImportError as ex:
                err(f"Could not import ping_sweep: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            finally:
                _stop_pcap(was_temp)
            pause()
        else:
            warn("Enter 1–4 or 0")


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 5 — PORT SCAN
# ═════════════════════════════════════════════════════════════════════════════

def menu_port_scan():
    while True:
        banner()
        hdr("Port Scan",
            "SYN · Connect · FIN · XMAS · ACK · UDP  +  service/version detection")
        print(_pcap_status())
        print()
        print(f"  {C.BOLD}TCP Scans:{C.R}")
        print(f"  {C.CYN}1.{C.R}  SYN scan     — stealth half-open (root needed)")
        print(f"  {C.CYN}2.{C.R}  Connect scan — full TCP, no root needed")
        print(f"  {C.CYN}3.{C.R}  FIN scan     — stealth, evades some firewalls")
        print(f"  {C.CYN}4.{C.R}  XMAS scan    — FIN+PSH+URG flags")
        print(f"  {C.CYN}5.{C.R}  ACK scan     — firewall rule detection")
        print()
        print(f"  {C.BOLD}UDP & Combined:{C.R}")
        print(f"  {C.CYN}6.{C.R}  UDP scan     — DNS/SNMP/NTP/NetBIOS probes")
        print(f"  {C.CYN}7.{C.R}  Full scan    — SYN + UDP combined (root needed)")
        print()
        print(f"  {C.BOLD}Port Presets:{C.R}  "
              f"{C.DIM}top20 · top100 · all · 1-1024 · custom{C.R}")
        print()
        print(f"  {C.CYN}0.{C.R}  Back")
        print()
        choice = ask("Select scan type", "0")

        if choice == "0":
            break

        elif choice in ("1","2","3","4","5","6","7"):
            target = ask("Target IP / hostname", "192.168.1.100")

            # Port range selection sub-prompt
            print()
            print(f"  {C.DIM}Port presets: top20 · top100 · all · 1-1024 · "
                  f"or enter e.g. 80,443,8080{C.R}")
            port_range = ask("Port range / preset", "top100")
            threads    = ask_int("Threads", 200, 1, 1000)
            timeout    = ask_float("Timeout (s)", 1.0)

            scan_map = {
                "1": "syn",     "2": "connect",
                "3": "fin",     "4": "xmas",
                "5": "ack",     "6": "udp",
                "7": "syn",     # full = syn + udp
            }
            scan_type   = scan_map[choice]
            include_udp = (choice == "7")

            was_temp = _maybe_start_pcap("Port_Scan")
            try:
                from port_scan import PortScanner

                scanner = PortScanner(target, threads, timeout, scan_type)

                if "," in port_range:
                    port_list = [int(p) for p in port_range.split(",")
                                 if p.strip().isdigit()]
                    proto = "udp" if choice == "6" else "tcp"
                    scanner.scan_ports(port_list, proto)
                else:
                    scanner.run_full(port_range, include_udp=include_udp)

            except ImportError as ex:
                err(f"Could not import port_scan: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            finally:
                _stop_pcap(was_temp)
            pause()
        else:
            warn("Enter 1–7 or 0")


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 6 — VULNERABILITY SCAN
# ═════════════════════════════════════════════════════════════════════════════

def menu_vuln_scan():
    while True:
        banner()
        hdr("Vulnerability Scan",
            "CVE detection · SSL/TLS audit · Default credentials · Misconfigurations")
        print(_pcap_status())
        print()
        print(f"  {C.CYN}1.{C.R}  Full vulnerability scan   — auto port scan + all checks")
        print(f"  {C.CYN}2.{C.R}  Specific ports only       — run all checks on chosen ports")
        print(f"  {C.CYN}3.{C.R}  SSL/TLS audit only        — protocol, cipher, certificate")
        print(f"  {C.CYN}4.{C.R}  CVE banner check          — match banner against CVE DB")
        print(f"  {C.CYN}5.{C.R}  Default credential test   — FTP / Redis default logins")
        print(f"  {C.CYN}6.{C.R}  Misconfiguration check    — Telnet, anon FTP, open Redis/Mongo")
        print()
        print(f"  {C.DIM}  CVE DB covers: OpenSSH · Apache · nginx · OpenSSL · MySQL")
        print(f"  {C.DIM}                 vsftpd · Log4j · Struts · ProFTPD · Samba{C.R}")
        print()
        print(f"  {C.CYN}0.{C.R}  Back")
        print()
        choice = ask("Select attack", "0")

        if choice == "0":
            break

        elif choice in ("1","2","3","4","5","6"):
            target  = ask("Target IP / hostname", "192.168.1.100")
            timeout = ask_int("Timeout (s)", 5, 1, 60)

            ssl_port = 443
            ports    = []
            service  = ""
            banner_text = ""

            if choice == "2":
                raw   = ask("Ports (comma-separated)", "22,80,443,21,6379")
                ports = [int(p) for p in raw.split(",") if p.strip().isdigit()]

            elif choice == "3":
                ssl_port = ask_int("SSL/TLS port", 443, 1, 65535)

            elif choice == "4":
                raw   = ask("Ports to banner-check (comma-sep)", "22,80,21,3306")
                ports = [int(p) for p in raw.split(",") if p.strip().isdigit()]

            elif choice == "5":
                print(f"\n  {C.DIM}Services: ftp · redis{C.R}")
                service = ask("Service to test", "ftp").lower()
                port    = ask_int("Port", 21 if service == "ftp" else 6379, 1, 65535)

            elif choice == "6":
                raw   = ask("Ports to check (comma-sep)", "21,23,80,6379,27017")
                ports = [int(p) for p in raw.split(",") if p.strip().isdigit()]

            was_temp = _maybe_start_pcap("Vuln_Scan")
            try:
                from vuln_scan import VulnerabilityScanner
                from recon_utils import grab_banner

                scanner = VulnerabilityScanner(target, timeout=timeout)

                if choice == "1":
                    scanner.run_full()

                elif choice == "2":
                    fake_ports = []
                    for p in ports:
                        b = grab_banner(target, p, timeout) or ""
                        fake_ports.append({"port": p, "service": "", "banner": b})
                    scanner.run_full(fake_ports)

                elif choice == "3":
                    scanner.ssl_audit(ssl_port)

                elif choice == "4":
                    for p in ports:
                        b = grab_banner(target, p, timeout) or ""
                        if b:
                            info(f"Port {p}: {b[:80]}")
                            scanner.check_service_vulns(p, b)
                        else:
                            warn(f"Port {p}: no banner received")

                elif choice == "5":
                    scanner.test_default_credentials(service, port)

                elif choice == "6":
                    for p in ports:
                        b = grab_banner(target, p, timeout) or ""
                        # Infer service name
                        svc_map = {21: "ftp", 23: "telnet", 80: "http",
                                   6379: "redis", 27017: "mongodb"}
                        svc = svc_map.get(p, "")
                        scanner.check_misconfigurations(p, svc, b)

            except ImportError as ex:
                err(f"Could not import vuln_scan: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            finally:
                _stop_pcap(was_temp)
            pause()
        else:
            warn("Enter 1–6 or 0")


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 7 — WIRELESS ADAPTER
# ═════════════════════════════════════════════════════════════════════════════

def menu_wireless():
    banner()
    hdr("Wireless Adapter",
        "Auto-detect · Monitor mode · Channel hopping")

    if os.name != "posix" or os.geteuid() != 0:
        warn("Monitor mode requires root on Linux.")
        warn("Run with: sudo python3 menu.py")
        pause()
        return

    try:
        from recon.modules.wireless import WirelessManager
        wm = WirelessManager()

        print()
        print(f"  {C.CYN}1.{C.R}  Auto-setup (detect + enable monitor mode)")
        print(f"  {C.CYN}2.{C.R}  List wireless interfaces")
        print(f"  {C.CYN}3.{C.R}  Enable monitor mode on specific interface")
        print(f"  {C.CYN}4.{C.R}  Disable monitor mode")
        print(f"  {C.CYN}5.{C.R}  Start channel hopping")
        print(f"  {C.CYN}0.{C.R}  Back")
        print()
        choice = ask("Select", "0")

        if choice == "0":
            return

        elif choice == "1":
            monitor = wm.auto_setup()
            if monitor:
                ok(f"Monitor interface ready: {C.BOLD}{monitor}{C.R}")
                hop = ask("Start channel hopping? (y/n)", "n").lower()
                if hop == "y":
                    try:
                        info("Press Ctrl+C to stop hopping")
                        wm.hop_channels(monitor)
                    except KeyboardInterrupt:
                        pass
                input(f"\n  {C.DIM}Press Enter to disable monitor mode and return…{C.R}")
                wm.disable_monitor_mode(wm.get_monitor_interface() or monitor)
            else:
                err("Monitor mode setup failed")

        elif choice == "2":
            ifaces = wm.discover_interfaces()
            if ifaces:
                print(f"\n  Detected {len(ifaces)} wireless interface(s):")
                for iface_info in ifaces:
                    iface = iface_info["name"]
                    mode = wm.get_interface_mode(iface)
                    mac  = iface_info.get("mac", "unknown")
                    print(f"    {C.CYN}•{C.R} {iface:<12} mode={mode:<10} mac={mac}")
            else:
                warn("No wireless interfaces detected")

        elif choice == "3":
            ifaces = wm.discover_interfaces()
            if not ifaces:
                warn("No wireless interfaces found")
            else:
                iface = ask("Interface name",
                            ifaces[0]["name"] if ifaces else "wlan0")
                monitor = wm.enable_monitor_mode(iface)
                if monitor:
                    ok(f"Monitor mode enabled: {C.BOLD}{monitor}{C.R}")
                else:
                    err("Failed to enable monitor mode")

        elif choice == "4":
            wm.disable_monitor_mode(wm.get_monitor_interface() or "wlan0mon")

        elif choice == "5":
            iface = ask("Monitor interface", wm.get_monitor_interface() or "wlan0mon")
            bands_input = ask("Bands (2.4ghz / 5ghz / both)", "2.4ghz")
            interval = ask_float("Seconds per channel", 0.5)
            if "both" in bands_input.lower():
                bands = ["2.4ghz", "5ghz"]
            elif "5" in bands_input:
                bands = ["5ghz"]
            else:
                bands = ["2.4ghz"]
            try:
                info("Press Ctrl+C to stop hopping")
                wm.hop_channels(iface, bands, interval)
            except KeyboardInterrupt:
                pass

    except ImportError as ex:
        err(f"Could not import wireless: {ex}")
    except SystemExit:
        pass
    pause()


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 8 — HTTP / WEB PROBE
# ═════════════════════════════════════════════════════════════════════════════

def menu_http_probe():
    while True:
        banner()
        hdr("HTTP / Web Probe",
            "WAF · CDN · tech stack · security headers · path discovery · method enum")
        print(_pcap_status())
        print()
        print(f"  {C.CYN}1.{C.R}  Full probe          — all checks combined")
        print(f"  {C.CYN}2.{C.R}  WAF / CDN detection — identify firewall and CDN provider")
        print(f"  {C.CYN}3.{C.R}  Tech stack          — CMS · framework · server · JS libs")
        print(f"  {C.CYN}4.{C.R}  Security headers    — HSTS · CSP · X-Frame · cookie flags")
        print(f"  {C.CYN}5.{C.R}  Path discovery      — admin panels · APIs · config leaks")
        print(f"  {C.CYN}6.{C.R}  HTTP method enum    — OPTIONS/PUT/DELETE/TRACE")
        print(f"  {C.CYN}0.{C.R}  Back")
        print()
        choice = ask("Select", "0")

        if choice == "0":
            break

        elif choice in ("1","2","3","4","5","6"):
            target  = ask("Target hostname / IP", "192.168.1.100")
            port_s  = ask("Port (80/443/8080/…)", "80")
            port    = int(port_s) if port_s.isdigit() else 80
            use_ssl = port == 443 or ask("HTTPS? (y/n)", "n").lower() == "y"

            was_temp = _maybe_start_pcap("HTTP_Probe")
            try:
                from recon.modules.http_probe import HTTPProbe
                probe = HTTPProbe(target, port=port, use_ssl=use_ssl)

                if choice == "1":
                    fp = probe.probe_all(path_discovery=True)
                    probe.print_results(fp)

                elif choice == "2":
                    code, hdrs, body = probe._get("/")
                    waf = probe.detect_waf(code, hdrs, body, hdrs.get("set-cookie",""))
                    cdn = probe.detect_cdn(hdrs)
                    ok(f"WAF: {waf or 'none detected'}")
                    ok(f"CDN: {cdn or 'none detected'}")

                elif choice == "3":
                    code, hdrs, body = probe._get("/")
                    techs = probe.fingerprint_tech(hdrs, body, "")
                    ok(f"Technologies: {', '.join(techs) if techs else 'none detected'}")

                elif choice == "4":
                    code, hdrs, body = probe._get("/")
                    issues = probe.audit_security_headers(hdrs, probe.scheme)
                    if issues:
                        for i in issues:
                            warn(f"[{i['severity']}] {i['header']}: {i['issue']}")
                    else:
                        ok("All security headers present")

                elif choice == "5":
                    info("Scanning sensitive paths (this may take a moment)…")
                    found = probe.discover_paths()
                    for p in found:
                        fn = ok if p["status"] == 200 else warn
                        fn(f"[{p['severity']}] {p['status']} {p['path']} — {p['description']}")
                    if not found:
                        ok("No interesting paths found")

                elif choice == "6":
                    methods = probe.enumerate_methods()
                    ok(f"Allowed methods: {', '.join(methods) or 'unable to determine'}")

            except ImportError as ex:
                err(f"Could not import http_probe: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            finally:
                _stop_pcap(was_temp)
            pause()
        else:
            warn("Enter 1–6 or 0")


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 9 — TLS / SSL DEEP SCAN
# ═════════════════════════════════════════════════════════════════════════════

def menu_tls_probe():
    while True:
        banner()
        hdr("TLS / SSL Deep Scan",
            "Cipher enumeration · cert chain · JA3S fingerprint · CT log discovery")
        print(_pcap_status())
        print()
        print(f"  {C.CYN}1.{C.R}  Full TLS scan       — all checks")
        print(f"  {C.CYN}2.{C.R}  Certificate info    — subject · SANs · expiry · key size")
        print(f"  {C.CYN}3.{C.R}  Protocol versions   — TLS 1.0/1.1/1.2/1.3 support matrix")
        print(f"  {C.CYN}4.{C.R}  Cipher suites       — broken / weak / strong cipher audit")
        print(f"  {C.CYN}5.{C.R}  CT log lookup       — enumerate subdomains via crt.sh")
        print(f"  {C.CYN}0.{C.R}  Back")
        print()
        choice = ask("Select", "0")

        if choice == "0":
            break

        elif choice in ("1","2","3","4","5"):
            target = ask("Target hostname / IP", "192.168.1.100")
            port   = ask_int("Port", 443, 1, 65535)

            try:
                from recon.modules.tls_probe import TLSProbe
                probe = TLSProbe(target, port=port)

                if choice == "1":
                    ct = ask("Query crt.sh CT logs? (y/n)", "n").lower() == "y"
                    r = probe.scan_all(ct=ct)
                    probe.print_results(r)

                elif choice == "2":
                    ci = probe.extract_cert()
                    ok(f"Subject:    {ci.subject}")
                    ok(f"Issuer:     {ci.issuer}")
                    ok(f"Expires:    {ci.not_after} ({ci.days_remaining}d remaining)")
                    ok(f"Key:        {ci.key_type} {ci.key_bits}-bit")
                    ok(f"SHA-256:    {ci.fingerprint_sha256[:32]}…")
                    if ci.san:
                        info(f"SANs: {', '.join(ci.san[:10])}")
                    if ci.expired:
                        err("Certificate is EXPIRED!")
                    if ci.self_signed:
                        warn("Self-signed certificate")

                elif choice == "3":
                    probe.probe_protocol_versions()
                    ok(f"Supported: {', '.join(probe._result.protocols_supported) or 'none'}")
                    warn(f"Rejected:  {', '.join(probe._result.protocols_rejected) or 'none'}")

                elif choice == "4":
                    probe.enumerate_ciphers()
                    if probe._result.broken_ciphers_found:
                        err(f"BROKEN: {', '.join(probe._result.broken_ciphers_found)}")
                    if probe._result.weak_ciphers_found:
                        warn(f"Weak:   {', '.join(probe._result.weak_ciphers_found)}")
                    strong = [c for c in probe._result.supported_ciphers
                              if c not in probe._result.broken_ciphers_found
                              and c not in probe._result.weak_ciphers_found]
                    if strong:
                        ok(f"Strong: {', '.join(strong[:5])}")

                elif choice == "5":
                    parts = target.split(".")
                    apex  = ".".join(parts[-2:]) if len(parts) >= 2 else target
                    info(f"Querying crt.sh for *.{apex} …")
                    from recon.modules.tls_probe import TLSProbe
                    domains = probe.ct_lookup(apex)
                    ok(f"{len(domains)} domain(s) found in CT logs")
                    for d in domains[:30]:
                        info(d)
                    if len(domains) > 30:
                        info(f"… and {len(domains)-30} more")

            except ImportError as ex:
                err(f"Could not import tls_probe: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            pause()
        else:
            warn("Enter 1–5 or 0")


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 10 — SMB ENUMERATION
# ═════════════════════════════════════════════════════════════════════════════

def menu_smb_enum():
    while True:
        banner()
        hdr("SMB / NetBIOS Enumeration",
            "Dialect · signing · shares · EternalBlue pre-check · SMBGhost pre-check")
        print(_pcap_status())
        print()
        print(f"  {C.CYN}1.{C.R}  Full SMB enum       — all checks")
        print(f"  {C.CYN}2.{C.R}  NetBIOS names       — hostname · domain · MAC via UDP 137")
        print(f"  {C.CYN}3.{C.R}  Dialect + signing   — SMBv1/v2/v3 detection")
        print(f"  {C.CYN}4.{C.R}  Share enumeration   — null session share list")
        print(f"  {C.CYN}5.{C.R}  Vuln pre-checks     — EternalBlue · SMBGhost")
        print(f"  {C.CYN}0.{C.R}  Back")
        print()
        choice = ask("Select", "0")

        if choice == "0":
            break

        elif choice in ("1","2","3","4","5"):
            target = ask("Target IP / hostname", "192.168.1.100")

            was_temp = _maybe_start_pcap("SMB_Enum")
            try:
                from recon.modules.smb_enum import SMBEnumerator
                enum = SMBEnumerator(target)

                if choice == "1":
                    r = enum.enumerate_all()
                    enum.print_results(r)

                elif choice == "2":
                    nb = enum.query_netbios()
                    if nb:
                        ok(f"Hostname: {nb.get('hostname','?')}")
                        ok(f"Domain:   {nb.get('domain','?')}")
                        ok(f"MAC:      {nb.get('mac','?')}")
                        for n in nb.get("names", []):
                            info(f"  {n['name']:<20} type={n['type']}  group={n['group']}")
                    else:
                        warn("No NetBIOS response")

                elif choice == "3":
                    r = enum.enumerate_all(check_vulns=False)
                    ok(f"Dialect: {r.smb_dialect or 'unknown'}")
                    ok(f"Signing: {r.smb_signing or 'unknown'}")

                elif choice == "4":
                    shares = enum.enumerate_shares()
                    if shares:
                        for s in shares:
                            ok(f"  {s['name']:<20} [{s['type']}]  {s.get('comment','')}")
                    else:
                        warn("No shares found (or smbclient not installed)")

                elif choice == "5":
                    eb = enum.check_eternalblue()
                    sg = enum.check_smbghost()
                    fn = err if "vulnerable" in eb.lower() else ok
                    fn(f"EternalBlue: {eb}")
                    fn2 = warn if "3.1.1" in sg.lower() else ok
                    fn2(f"SMBGhost:    {sg}")

            except ImportError as ex:
                err(f"Could not import smb_enum: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            finally:
                _stop_pcap(was_temp)
            pause()
        else:
            warn("Enter 1–5 or 0")


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 11 — SNMP ENUMERATION
# ═════════════════════════════════════════════════════════════════════════════

def menu_snmp_enum():
    while True:
        banner()
        hdr("SNMP Enumeration",
            "Community brute-force · sysInfo · interfaces · ARP · routes · processes")
        print(_pcap_status())
        print()
        print(f"  {C.CYN}1.{C.R}  Full enumeration    — brute-force + all MIB walks")
        print(f"  {C.CYN}2.{C.R}  Community brute-force only")
        print(f"  {C.CYN}3.{C.R}  System info         — sysDescr · sysName · location")
        print(f"  {C.CYN}4.{C.R}  Interface + ARP     — interfaces · IP addresses · ARP table")
        print(f"  {C.CYN}5.{C.R}  Process / software  — running processes · installed software")
        print(f"  {C.CYN}0.{C.R}  Back")
        print()
        choice = ask("Select", "0")

        if choice == "0":
            break

        elif choice in ("1","2","3","4","5"):
            target    = ask("Target IP / hostname", "192.168.1.1")
            port      = ask_int("SNMP port", 161, 1, 65535)
            community = ask("Community string (Enter = auto-brute)", "")

            was_temp = _maybe_start_pcap("SNMP_Enum")
            try:
                from recon.modules.snmp_enum import SNMPEnumerator
                enum = SNMPEnumerator(target, port=port)

                comm = community if community else None

                if choice == "1":
                    r = enum.enumerate_all(community=comm, deep=True)
                    enum.print_results(r)

                elif choice == "2":
                    found = enum.brute_community()
                    if found:
                        ok(f"Community: {found}")
                    else:
                        err("No valid community found")

                elif choice == "3":
                    if not comm:
                        comm = enum.brute_community()
                    if comm:
                        enum.get_system_info(comm)
                        r = enum._result
                        ok(f"sysName:    {r.sys_name}")
                        ok(f"sysDescr:   {r.sys_descr[:100]}")
                        ok(f"Location:   {r.sys_location}")
                        ok(f"Contact:    {r.sys_contact}")
                        ok(f"Uptime:     {r.sys_uptime}")
                    else:
                        err("No valid community string")

                elif choice == "4":
                    if not comm:
                        comm = enum.brute_community()
                    if comm:
                        enum.get_interfaces(comm)
                        enum.get_ip_addresses(comm)
                        enum.get_arp_table(comm)
                        enum.print_results(enum._result)
                    else:
                        err("No valid community string")

                elif choice == "5":
                    if not comm:
                        comm = enum.brute_community()
                    if comm:
                        enum.get_processes(comm)
                        enum.get_software(comm)
                        r = enum._result
                        ok(f"Processes ({len(r.processes)}): {', '.join(r.processes[:10])}")
                        ok(f"Software  ({len(r.software)}):  {', '.join(r.software[:10])}")
                    else:
                        err("No valid community string")

            except ImportError as ex:
                err(f"Could not import snmp_enum: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            finally:
                _stop_pcap(was_temp)
            pause()
        else:
            warn("Enter 1–5 or 0")


# ═════════════════════════════════════════════════════════════════════════════
# TOOL 12 — ASYNC FAST SCAN (masscan-speed)
# ═════════════════════════════════════════════════════════════════════════════

def menu_async_scan():
    while True:
        banner()
        hdr("Async Fast Scan  [masscan-speed]",
            "Asyncio connect scan · 10k–50k ports/s · banner grab · network sweep")
        print(_pcap_status())
        print()
        print(f"  {C.CYN}1.{C.R}  Single host scan    — port range / preset + banners")
        print(f"  {C.CYN}2.{C.R}  Network sweep       — CIDR, top-100 ports per host")
        print(f"  {C.CYN}3.{C.R}  Full port blast     — all 65535 ports, no banners (fastest)")
        print()
        print(f"  {C.DIM}  Port presets: top100 · top1000 · top10000 · all · 1-1024 · 80,443,8080{C.R}")
        print()
        print(f"  {C.CYN}0.{C.R}  Back")
        print()
        choice = ask("Select", "0")

        if choice == "0":
            break

        elif choice == "1":
            target  = ask("Target IP / hostname", "192.168.1.100")
            ports   = ask("Port spec", "top1000")
            concurr = ask_int("Concurrency (connections/s)", 5000, 100, 50000)
            timeout = ask_float("Timeout per port (s)", 0.5)
            banners = ask("Grab banners on open ports? (y/n)", "y").lower() == "y"

            was_temp = _maybe_start_pcap("Async_Scan")
            try:
                from recon.modules.async_scan import AsyncScanner
                scanner = AsyncScanner(target, concurrency=concurr,
                                       timeout=timeout, grab_banners=banners)
                r = scanner.scan(ports=ports)
                scanner.print_results(r)
            except ImportError as ex:
                err(f"Could not import async_scan: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            finally:
                _stop_pcap(was_temp)
            pause()

        elif choice == "2":
            cidr    = ask("Target CIDR", "192.168.1.0/24")
            ports   = ask("Port spec", "top100")
            concurr = ask_int("Concurrency per host", 500, 50, 5000)
            timeout = ask_float("Timeout per port (s)", 0.3)

            was_temp = _maybe_start_pcap("Network_Sweep")
            try:
                from recon.modules.async_scan import AsyncScanner
                scanner = AsyncScanner(cidr, concurrency=concurr,
                                       timeout=timeout, grab_banners=False)
                results = scanner.scan_network(
                    cidr, ports=ports, per_host_concurrency=concurr
                )
                live = [(h, r) for h, r in results.items() if r.open_ports]
                ok(f"{len(live)} host(s) with open ports:")
                for host, r in sorted(live):
                    port_strs = [f"{p.port}/{p.service}" for p in r.open_ports[:8]]
                    ok(f"  {host:<18} {', '.join(port_strs)}")
            except ImportError as ex:
                err(f"Could not import async_scan: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            finally:
                _stop_pcap(was_temp)
            pause()

        elif choice == "3":
            target  = ask("Target IP / hostname", "192.168.1.100")
            concurr = ask_int("Concurrency", 10000, 1000, 50000)
            timeout = ask_float("Timeout per port (s)", 0.3)

            was_temp = _maybe_start_pcap("Full_Port_Blast")
            try:
                from recon.modules.async_scan import AsyncScanner
                scanner = AsyncScanner(target, concurrency=concurr,
                                       timeout=timeout, grab_banners=False)
                info("Scanning all 65535 ports — this may take 30–120 seconds…")
                r = scanner.scan(ports="all")
                scanner.print_results(r)
            except ImportError as ex:
                err(f"Could not import async_scan: {ex}")
            except KeyboardInterrupt:
                warn("Interrupted.")
            finally:
                _stop_pcap(was_temp)
            pause()

        else:
            warn("Enter 1–3 or 0")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN MENU
# ═════════════════════════════════════════════════════════════════════════════

def main_menu():
    while True:
        banner()

        # Status bar
        is_root   = (os.name == "posix" and os.geteuid() == 0)
        root_str  = (f"{C.GRN}root ✓{C.R}" if is_root
                     else f"{C.YLW}non-root ⚠{C.R}")
        scapy_str = (f"{C.GRN}Scapy ✓{C.R}" if SCAPY
                     else f"{C.YLW}Scapy ✗{C.R}")
        print(f"  {root_str}   {scapy_str}")
        print(_pcap_status())
        print()

        # Menu items
        print(f"  {C.BOLD}CORE RECONNAISSANCE{C.R}\n")
        print(f"  {C.CYN}1.{C.R}  DNS Enumeration      "
              f"{C.DIM}zone transfer · records · subdomain brute{C.R}")
        print(f"  {C.CYN}2.{C.R}  Host Discovery       "
              f"{C.DIM}ARP · ICMP · TCP · UDP{C.R}")
        print(f"  {C.CYN}3.{C.R}  OS Scan              "
              f"{C.DIM}TTL · TCP stack · banners · ICMP quirks{C.R}")
        print(f"  {C.CYN}4.{C.R}  Ping Sweep           "
              f"{C.DIM}threaded ICMP/TCP with evasion options{C.R}")
        print(f"  {C.CYN}5.{C.R}  Port Scan            "
              f"{C.DIM}SYN/Connect/FIN/XMAS/ACK/UDP + services{C.R}")
        print(f"  {C.CYN}6.{C.R}  Vulnerability Scan   "
              f"{C.DIM}CVE DB · SSL audit · default creds{C.R}")
        print(f"  {C.CYN}7.{C.R}  Wireless Adapter     "
              f"{C.DIM}monitor mode · channel hopping{C.R}")
        print()
        print(f"  {C.BOLD}ADVANCED MODULES{C.R}\n")
        print(f"  {C.CYN}8.{C.R}  HTTP / Web Probe     "
              f"{C.DIM}WAF · CDN · tech stack · headers · path discovery{C.R}")
        print(f"  {C.CYN}9.{C.R}  TLS / SSL Deep Scan  "
              f"{C.DIM}ciphers · cert chain · JA3S · CT logs{C.R}")
        print(f"  {C.CYN}A.{C.R}  SMB Enumeration      "
              f"{C.DIM}NetBIOS · dialect · signing · EternalBlue · SMBGhost{C.R}")
        print(f"  {C.CYN}B.{C.R}  SNMP Enumeration     "
              f"{C.DIM}community brute · sysInfo · interfaces · ARP · routes{C.R}")
        print(f"  {C.CYN}F.{C.R}  {C.BOLD}Async Fast Scan{C.R}      "
              f"{C.DIM}10k–50k ports/s · asyncio · no root required{C.R}")
        print()
        print(f"  {C.CYN}P.{C.R}  PCAP Settings        "
              f"{'  ' + C.GRN + '● capture ON' + C.R if _pcap_enabled else '  ' + C.DIM + '○ capture OFF' + C.R}")
        print()
        print(f"  {C.CYN}0.{C.R}  Exit")
        print()

        choice = ask("Enter selection", "0").strip().lower()

        if   choice == "0":
            print(f"\n  {C.DIM}Exiting.{C.R}\n")
            sys.exit(0)
        elif choice == "1": menu_dns_enum()
        elif choice == "2": menu_host_discovery()
        elif choice == "3": menu_os_scan()
        elif choice == "4": menu_ping_sweep()
        elif choice == "5": menu_port_scan()
        elif choice == "6": menu_vuln_scan()
        elif choice == "7": menu_wireless()
        elif choice == "8": menu_http_probe()
        elif choice == "9": menu_tls_probe()
        elif choice == "a": menu_smb_enum()
        elif choice == "b": menu_snmp_enum()
        elif choice == "f": menu_async_scan()
        elif choice == "p": menu_pcap_settings()
        else:
            warn("Enter 1–9, A, B, F, P, or 0")
            time.sleep(0.8)


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Full wifi_down-style launch banner — shown ONCE at startup
    if _HAS_LOGGER:
        try:
            _full_banner()
        except Exception:
            pass
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {C.DIM}Interrupted.{C.R}\n")
        sys.exit(0)
