"""
recon.modules.host_discovery — Multi-method host discovery engine.

Methods:
- ARP (Layer 2, local networks only) with MAC vendor OUI lookup
- ICMP echo + timestamp request fallback
- TCP SYN probe to common ports
- UDP probe with real protocol payloads (DNS, NTP, SNMP)

Results are deduplicated across methods with full attribution.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from recon.core.config import ReconConfig
from recon.core.logger import get_logger, make_progress
from recon.core.privilege import PrivilegeChecker

__all__ = ["HostDiscovery", "HostResult"]

_log = get_logger("host_discovery")

# TCP ports to probe for host alive detection
_TCP_PROBE_PORTS = [22, 80, 443, 445, 3389, 8080, 8443, 21, 25, 110]

# Real protocol payloads
_DNS_QUERY = bytes([
    0x00, 0x01,  # Transaction ID
    0x01, 0x00,  # Flags: standard query, recursion desired
    0x00, 0x01,  # Questions: 1
    0x00, 0x00,  # Answer RRs: 0
    0x00, 0x00,  # Authority RRs: 0
    0x00, 0x00,  # Additional RRs: 0
    0x03, 0x77, 0x77, 0x77,  # www
    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,  # google
    0x03, 0x63, 0x6f, 0x6d,  # com
    0x00,        # End
    0x00, 0x01,  # Type A
    0x00, 0x01,  # Class IN
])

_NTP_REQUEST = bytes([
    0x1b] + [0x00] * 47)  # Mode 3 (client), version 3

_SNMP_GET_REQUEST = bytes([
    0x30, 0x26,  # SEQUENCE
    0x02, 0x01, 0x00,  # INTEGER version=0 (v1)
    0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # OCTET STRING "public"
    0xa0, 0x19,  # GetRequest-PDU
    0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # request-id
    0x02, 0x01, 0x00,  # error-status=0
    0x02, 0x01, 0x00,  # error-index=0
    0x30, 0x0b,  # VarBindList
    0x30, 0x09,  # VarBind
    0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,  # OID 1.3.6.1.2.1
    0x05, 0x00,  # NULL
])


# ------------------------------------------------------------------ #
# OUI / Vendor lookup                                                  #
# ------------------------------------------------------------------ #

_OUI_DB: dict[str, str] = {}
_OUI_LOADED = False
_OUI_LOCK = threading.Lock()


def _load_oui_db() -> None:
    global _OUI_LOADED
    with _OUI_LOCK:
        if _OUI_LOADED:
            return
        oui_path = Path(__file__).parent.parent / "data" / "oui_subset.csv"
        if oui_path.exists():
            try:
                with open(oui_path, encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split(",", 1)
                        if len(parts) == 2:
                            _OUI_DB[parts[0].upper().replace("-", "").replace(":", "")] = parts[1].strip()
            except Exception as exc:
                _log.debug("OUI DB load error: %s", exc)
        _OUI_LOADED = True


def _mac_vendor(mac: str) -> str:
    """Look up vendor from first 3 octets of MAC address."""
    _load_oui_db()
    cleaned = mac.upper().replace(":", "").replace("-", "")[:6]
    return _OUI_DB.get(cleaned, "Unknown")


# ------------------------------------------------------------------ #
# IP range parsing                                                     #
# ------------------------------------------------------------------ #

def parse_targets(target: str) -> list[str]:
    """
    Parse a target string into a list of IP address strings.

    Supports:
    - Single IP: '192.168.1.1'
    - CIDR: '192.168.1.0/24'
    - Range: '192.168.1.1-254'
    - Hostname: 'example.com'

    Args:
        target: Target specification string.

    Returns:
        List of IP address strings.
    """
    target = target.strip()

    # CIDR
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return [str(h) for h in net.hosts()]
        except ValueError:
            pass

    # Range like 192.168.1.1-254
    if "-" in target:
        parts = target.rsplit("-", 1)
        if len(parts) == 2:
            base = parts[0].rsplit(".", 1)
            if len(base) == 2:
                try:
                    start = int(base[1])
                    end = int(parts[1])
                    prefix = base[0]
                    return [f"{prefix}.{i}" for i in range(start, end + 1)]
                except ValueError:
                    pass

    # Hostname or single IP
    try:
        resolved = socket.gethostbyname(target)
        return [resolved]
    except socket.gaierror:
        pass

    return [target]


# ------------------------------------------------------------------ #
# Result dataclass                                                     #
# ------------------------------------------------------------------ #

@dataclass
class HostResult:
    """Aggregated discovery result for a single host."""
    ip: str
    methods: list[str] = field(default_factory=list)
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    ttl: int = 0
    ttl_os_hint: str = ""
    open_ports: list[int] = field(default_factory=list)
    banner: str = ""
    alive: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "methods": self.methods,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "ttl": self.ttl,
            "ttl_os_hint": self.ttl_os_hint,
            "open_ports": self.open_ports,
            "banner": self.banner,
        }


# ------------------------------------------------------------------ #
# TTL OS hint                                                          #
# ------------------------------------------------------------------ #

def _ttl_os_hint(ttl: int) -> str:
    if 60 <= ttl <= 65:
        return "Linux/Unix"
    if 125 <= ttl <= 130:
        return "Windows"
    if 250 <= ttl <= 255:
        return "Cisco/Network gear"
    if ttl == 64:
        return "Linux/macOS"
    if ttl == 128:
        return "Windows"
    if ttl == 255:
        return "Cisco IOS"
    return "Unknown"


# ------------------------------------------------------------------ #
# Banner grab helper                                                   #
# ------------------------------------------------------------------ #

def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Quick TCP banner grab from a known-open port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            probes = {
                80:   b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
                443:  b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
                22:   None,
                21:   None,
                25:   None,
                110:  None,
            }
            probe = probes.get(port)
            if probe:
                s.sendall(probe)
            data = s.recv(256)
            return data.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


# ------------------------------------------------------------------ #
# Main class                                                           #
# ------------------------------------------------------------------ #

class HostDiscovery:
    """
    Multi-method host discovery engine.

    Args:
        target: Target IP, CIDR, range, or hostname.
        config: ReconConfig instance.
    """

    def __init__(self, target: str, config: ReconConfig | None = None) -> None:
        self.target = target
        self.config = config or ReconConfig()
        self._hosts: dict[str, HostResult] = {}
        self._lock = threading.Lock()
        self._priv = PrivilegeChecker()
        self._priv.check()

    def _get_or_create(self, ip: str) -> HostResult:
        with self._lock:
            if ip not in self._hosts:
                self._hosts[ip] = HostResult(ip=ip)
            return self._hosts[ip]

    def _add_method(self, ip: str, method: str) -> None:
        h = self._get_or_create(ip)
        with self._lock:
            if method not in h.methods:
                h.methods.append(method)

    # ------------------------------------------------------------------ #
    # ARP sweep                                                            #
    # ------------------------------------------------------------------ #

    def arp_sweep(self, hosts: list[str]) -> list[HostResult]:
        """
        ARP sweep using Scapy — most reliable for local Layer-2 networks.

        Args:
            hosts: List of IP address strings.

        Returns:
            List of HostResult with MAC and vendor populated.
        """
        if not self._priv.can("arp_sweep"):
            _log.warning("ARP sweep requires root; skipping")
            return []
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import srp
        except ImportError:
            _log.warning("Scapy not available; ARP sweep skipped")
            return []

        found: list[HostResult] = []
        # Build single ARP packet per host with retry
        for ip in hosts:
            for attempt in range(2):
                try:
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                    ans, _ = srp(pkt, timeout=self.config.timeout, verbose=False, retry=0)
                    for _, rcv in ans:
                        mac = rcv[ARP].hwsrc
                        h = self._get_or_create(ip)
                        with self._lock:
                            h.mac = mac
                            h.vendor = _mac_vendor(mac)
                            if "arp" not in h.methods:
                                h.methods.append("arp")
                        found.append(h)
                        _log.debug("ARP: %s → MAC %s (%s)", ip, mac, h.vendor)
                        break
                    if found:
                        break
                except Exception as exc:
                    _log.debug("ARP probe error for %s: %s", ip, exc)
                if attempt == 0:
                    time.sleep(0.1)
        return found

    # ------------------------------------------------------------------ #
    # ICMP sweep                                                           #
    # ------------------------------------------------------------------ #

    def _icmp_probe(self, ip: str) -> bool:
        """Send ICMP echo + timestamp; return True if host responds."""
        if not self._priv.can("icmp_ping"):
            return False
        try:
            from scapy.layers.inet import ICMP, IP
            from scapy.sendrecv import sr1
        except ImportError:
            return self._sys_ping(ip)

        payload = bytes(random.getrandbits(8) for _ in range(16))
        icmp_id = random.randint(1, 65535)
        pkt = IP(dst=ip, ttl=random.randint(54, 128)) / ICMP(
            type=8, id=icmp_id, seq=random.randint(1, 65535)
        ) / payload
        resp = sr1(pkt, timeout=self.config.timeout, verbose=False)
        if resp:
            h = self._get_or_create(ip)
            with self._lock:
                h.ttl = resp[IP].ttl if hasattr(resp, "haslayer") and resp.haslayer("IP") else 0
                h.ttl_os_hint = _ttl_os_hint(h.ttl)
            return True

        # ICMP timestamp fallback (type 13)
        ts_pkt = IP(dst=ip) / ICMP(type=13, id=icmp_id)
        resp = sr1(ts_pkt, timeout=self.config.timeout, verbose=False)
        return resp is not None

    def _sys_ping(self, ip: str) -> bool:
        """System ping fallback for non-root environments."""
        import subprocess
        import platform
        flag = "-n" if platform.system() == "Windows" else "-c"
        try:
            result = subprocess.run(
                ["ping", flag, "1", "-W", "1", ip],
                capture_output=True,
                timeout=self.config.timeout + 1,
            )
            return result.returncode == 0
        except Exception:
            return False

    def icmp_sweep(self, hosts: list[str]) -> list[HostResult]:
        """
        ICMP echo + timestamp sweep.

        Args:
            hosts: List of IP address strings.

        Returns:
            List of responding HostResult entries.
        """
        found: list[HostResult] = []

        def _probe(ip: str) -> HostResult | None:
            alive = self._icmp_probe(ip) or self._sys_ping(ip)
            if alive:
                h = self._get_or_create(ip)
                self._add_method(ip, "icmp")
                return h
            return None

        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {pool.submit(_probe, ip): ip for ip in hosts}
            for fut in as_completed(futures):
                h = fut.result()
                if h:
                    found.append(h)
        return found

    # ------------------------------------------------------------------ #
    # TCP sweep                                                            #
    # ------------------------------------------------------------------ #

    def _tcp_probe(self, ip: str) -> tuple[bool, list[int]]:
        """
        TCP connect probe to common ports. Returns (alive, open_ports).
        Marks host alive on SYN-ACK OR RST.
        """
        open_ports: list[int] = []
        alive = False

        # Raw SYN preferred when root
        if self._priv.can("syn_scan"):
            try:
                from scapy.layers.inet import IP, TCP
                from scapy.sendrecv import sr
                pkts = [
                    IP(dst=ip) / TCP(dport=p, flags="S", seq=random.randint(0, 2**32))
                    for p in _TCP_PROBE_PORTS
                ]
                ans, _ = sr(pkts, timeout=self.config.timeout, verbose=False)
                for _, rcv in ans:
                    if hasattr(rcv, "haslayer") and rcv.haslayer("TCP"):
                        flags = rcv["TCP"].flags
                        port = rcv["TCP"].sport
                        if flags & 0x12:  # SYN-ACK
                            open_ports.append(port)
                            alive = True
                        elif flags & 0x04:  # RST
                            alive = True
                return alive, open_ports
            except Exception as exc:
                _log.debug("Raw SYN probe failed for %s: %s", ip, exc)

        # Connect fallback
        for port in _TCP_PROBE_PORTS:
            try:
                with socket.create_connection((ip, port), timeout=self.config.timeout):
                    open_ports.append(port)
                    alive = True
            except (ConnectionRefusedError, socket.timeout):
                # RST or timeout — host may still be up (RST = up, timeout = filtered/down)
                if False:  # Can't distinguish RST from timeout in connect mode
                    alive = True
            except OSError:
                pass
        return alive, open_ports

    def tcp_sweep(self, hosts: list[str]) -> list[HostResult]:
        """
        TCP-based host discovery probing common service ports.

        Args:
            hosts: List of IP address strings.

        Returns:
            List of alive HostResult entries with open_ports populated.
        """
        found: list[HostResult] = []

        def _probe(ip: str) -> HostResult | None:
            alive, ports = self._tcp_probe(ip)
            if alive or ports:
                h = self._get_or_create(ip)
                with self._lock:
                    h.open_ports = list(set(h.open_ports + ports))
                    if "tcp" not in h.methods:
                        h.methods.append("tcp")
                return h
            return None

        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {pool.submit(_probe, ip): ip for ip in hosts}
            for fut in as_completed(futures):
                h = fut.result()
                if h:
                    found.append(h)
        return found

    # ------------------------------------------------------------------ #
    # UDP sweep                                                            #
    # ------------------------------------------------------------------ #

    def _udp_probe(self, ip: str) -> bool:
        """Send UDP probes to DNS/NTP/SNMP with real payloads."""
        probes = [
            (53,  _DNS_QUERY),
            (123, _NTP_REQUEST),
            (161, _SNMP_GET_REQUEST),
        ]
        for port, payload in probes:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.config.timeout)
                    s.sendto(payload, (ip, port))
                    data, _ = s.recvfrom(1024)
                    if data:
                        return True
            except socket.timeout:
                pass
            except OSError:
                pass
        return False

    def udp_sweep(self, hosts: list[str]) -> list[HostResult]:
        """
        UDP-based host discovery using real protocol payloads.

        Args:
            hosts: List of IP address strings.

        Returns:
            List of alive HostResult entries.
        """
        found: list[HostResult] = []

        def _probe(ip: str) -> HostResult | None:
            if self._udp_probe(ip):
                h = self._get_or_create(ip)
                self._add_method(ip, "udp")
                return h
            return None

        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {pool.submit(_probe, ip): ip for ip in hosts}
            for fut in as_completed(futures):
                h = fut.result()
                if h:
                    found.append(h)
        return found

    # ------------------------------------------------------------------ #
    # Reverse DNS + banner enrichment                                      #
    # ------------------------------------------------------------------ #

    def _enrich_host(self, h: HostResult) -> None:
        """Resolve hostname and grab banner from first open port."""
        try:
            h.hostname = socket.gethostbyaddr(h.ip)[0]
        except (socket.herror, socket.gaierror):
            pass
        if h.open_ports and not h.banner:
            h.banner = _grab_banner(h.ip, h.open_ports[0], timeout=self.config.timeout)

    # ------------------------------------------------------------------ #
    # Full discovery pipeline                                              #
    # ------------------------------------------------------------------ #

    def run_full(
        self,
        use_arp: bool = True,
        use_icmp: bool = True,
        use_tcp: bool = True,
        use_udp: bool = True,
    ) -> list[HostResult]:
        """
        Run all configured discovery methods and return deduplicated results.

        Args:
            use_arp: Include ARP sweep (requires root, local network only).
            use_icmp: Include ICMP sweep.
            use_tcp: Include TCP connect/SYN sweep.
            use_udp: Include UDP probe sweep.

        Returns:
            Sorted list of HostResult objects.
        """
        hosts = parse_targets(self.target)
        if self.config.evasion_level >= 1:
            random.shuffle(hosts)

        _log.info(
            "[bold cyan]Host discovery[/]: %d hosts, methods=[arp=%s icmp=%s tcp=%s udp=%s]",
            len(hosts), use_arp, use_icmp, use_tcp, use_udp,
        )

        with make_progress("Host Discovery") as progress:
            task = progress.add_task("Probing hosts", total=len(hosts))

            if use_arp and self._priv.can("arp_sweep"):
                self.arp_sweep(hosts)
            if use_icmp:
                self.icmp_sweep(hosts)
            if use_tcp:
                self.tcp_sweep(hosts)
            if use_udp:
                self.udp_sweep(hosts)

            progress.update(task, completed=len(hosts))

        # Enrich with reverse DNS + banner
        with self._lock:
            results = list(self._hosts.values())

        enrich_threads = min(len(results), 20)
        if enrich_threads > 0:
            with ThreadPoolExecutor(max_workers=enrich_threads) as pool:
                list(pool.map(self._enrich_host, results))

        results.sort(key=lambda h: tuple(int(o) for o in h.ip.split(".") if o.isdigit()))
        _log.info(
            "[bold green]Discovery complete[/]: %d/%d hosts alive",
            len(results), len(hosts),
        )
        return results

    def results(self) -> list[HostResult]:
        """Return current result list."""
        with self._lock:
            return list(self._hosts.values())
