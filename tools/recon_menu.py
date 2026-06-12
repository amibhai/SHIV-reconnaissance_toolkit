#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          RECONNAISSANCE TOOLKIT  —  INTERACTIVE MENU                ║
║                                                                      ║
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
    sudo python3 recon_menu.py        (root recommended)
    python3 recon_menu.py             (non-root, reduced feature set)
"""

import sys
import os
import re
import time
import threading
import socket
from datetime import datetime

# ── Resolve sibling module imports ────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR   = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, ROOT_DIR)

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
    print(f"\033[1;38;5;51m  recon-toolkit\033[0m"
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
                wl_default = os.path.join(SCRIPT_DIR, "subdomains.txt")
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
        warn("Run with: sudo python3 recon_menu.py")
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
# ADVANCED TOOL MENUS (shared with menu.py — thin wrappers using recon.modules)
# ═════════════════════════════════════════════════════════════════════════════

def menu_http_probe():
    """HTTP/web probe — delegates to recon.modules.http_probe."""
    import importlib, sys as _sys
    # Ensure recon package is importable from tools/
    _root = os.path.dirname(SCRIPT_DIR)
    if _root not in _sys.path:
        _sys.path.insert(0, _root)
    # Import and run the same function from menu.py logic inline
    banner()
    hdr("HTTP / Web Probe",
        "WAF · CDN · tech stack · security headers · path discovery · method enum")
    target  = ask("Target hostname / IP", "192.168.1.100")
    port_s  = ask("Port (80/443/8080/…)", "80")
    port    = int(port_s) if port_s.isdigit() else 80
    use_ssl = port == 443 or ask("HTTPS? (y/n)", "n").lower() == "y"
    try:
        from recon.modules.http_probe import HTTPProbe
        probe = HTTPProbe(target, port=port, use_ssl=use_ssl)
        fp = probe.probe_all(path_discovery=True)
        probe.print_results(fp)
    except ImportError as ex:
        err(f"Could not import http_probe: {ex}")
    except KeyboardInterrupt:
        warn("Interrupted.")
    pause()


def menu_tls_probe():
    """TLS deep scan — delegates to recon.modules.tls_probe."""
    import sys as _sys
    _root = os.path.dirname(SCRIPT_DIR)
    if _root not in _sys.path:
        _sys.path.insert(0, _root)
    banner()
    hdr("TLS / SSL Deep Scan",
        "Cipher enum · cert chain · JA3S fingerprint · CT log discovery")
    target = ask("Target hostname / IP", "192.168.1.100")
    port   = ask_int("Port", 443, 1, 65535)
    ct     = ask("Query crt.sh CT logs? (y/n)", "n").lower() == "y"
    try:
        from recon.modules.tls_probe import TLSProbe
        probe = TLSProbe(target, port=port)
        r = probe.scan_all(ct=ct)
        probe.print_results(r)
    except ImportError as ex:
        err(f"Could not import tls_probe: {ex}")
    except KeyboardInterrupt:
        warn("Interrupted.")
    pause()


def menu_smb_enum():
    """SMB enumeration — delegates to recon.modules.smb_enum."""
    import sys as _sys
    _root = os.path.dirname(SCRIPT_DIR)
    if _root not in _sys.path:
        _sys.path.insert(0, _root)
    banner()
    hdr("SMB / NetBIOS Enumeration",
        "Dialect · signing · shares · EternalBlue · SMBGhost pre-checks")
    target = ask("Target IP / hostname", "192.168.1.100")
    try:
        from recon.modules.smb_enum import SMBEnumerator
        enum = SMBEnumerator(target)
        r = enum.enumerate_all()
        enum.print_results(r)
    except ImportError as ex:
        err(f"Could not import smb_enum: {ex}")
    except KeyboardInterrupt:
        warn("Interrupted.")
    pause()


def menu_snmp_enum():
    """SNMP enumeration — delegates to recon.modules.snmp_enum."""
    import sys as _sys
    _root = os.path.dirname(SCRIPT_DIR)
    if _root not in _sys.path:
        _sys.path.insert(0, _root)
    banner()
    hdr("SNMP Enumeration",
        "Community brute-force · sysInfo · interfaces · ARP · routes · processes")
    target    = ask("Target IP / hostname", "192.168.1.1")
    port      = ask_int("SNMP port", 161, 1, 65535)
    community = ask("Community string (Enter = auto-brute)", "")
    try:
        from recon.modules.snmp_enum import SNMPEnumerator
        enum = SNMPEnumerator(target, port=port)
        r = enum.enumerate_all(community=community if community else None, deep=True)
        enum.print_results(r)
    except ImportError as ex:
        err(f"Could not import snmp_enum: {ex}")
    except KeyboardInterrupt:
        warn("Interrupted.")
    pause()


def menu_async_scan():
    """Async fast scan — delegates to recon.modules.async_scan."""
    import sys as _sys
    _root = os.path.dirname(SCRIPT_DIR)
    if _root not in _sys.path:
        _sys.path.insert(0, _root)
    banner()
    hdr("Async Fast Scan  [masscan-speed]",
        "Asyncio connect scan · 10k–50k ports/s · banner grab · network sweep")
    target  = ask("Target IP / hostname / CIDR", "192.168.1.100")
    ports   = ask("Port spec (top100/top1000/all/1-1024/custom)", "top1000")
    concurr = ask_int("Concurrency", 5000, 100, 50000)
    timeout = ask_float("Timeout per port (s)", 0.5)
    banners = ask("Grab banners? (y/n)", "y").lower() == "y"
    try:
        from recon.modules.async_scan import AsyncScanner
        scanner = AsyncScanner(target, concurrency=concurr,
                               timeout=timeout, grab_banners=banners)
        if "/" in target:
            results = scanner.scan_network(target, ports=ports, per_host_concurrency=concurr)
            live = [(h, r) for h, r in results.items() if r.open_ports]
            ok(f"{len(live)} host(s) with open ports:")
            for host, r in sorted(live):
                ports_str = ", ".join(f"{p.port}/{p.service}" for p in r.open_ports[:8])
                ok(f"  {host:<18} {ports_str}")
        else:
            r = scanner.scan(ports=ports)
            scanner.print_results(r)
    except ImportError as ex:
        err(f"Could not import async_scan: {ex}")
    except KeyboardInterrupt:
        warn("Interrupted.")
    pause()


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