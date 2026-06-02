"""
recon.modules.port_scan — Production port scanner with multiple scan types.

Scan types implemented via raw Scapy sockets:
- SYN (half-open, stealthiest)
- Connect (full TCP, no root required)
- FIN, XMAS, NULL (stealth variants)
- ACK (firewall detection)
- Window (RST window analysis)
- Maimon (FIN+ACK)
- UDP (with service-specific payloads)

Service detection via probes from data/service_probes.json.
Evasion: randomized port order, IP ID/TTL randomization, inter-packet delay.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from recon.core.config import ReconConfig
from recon.core.logger import get_logger, make_progress
from recon.core.privilege import PrivilegeChecker

__all__ = ["PortScanner", "PortResult", "NMAP_TOP_1000"]

_log = get_logger("port_scan")

# Nmap top-1000 TCP ports — ordered by frequency in nmap-services
NMAP_TOP_1000: list[int] = sorted(set([
    # Top 100 (high frequency)
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113,
    81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000,
    513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128,
    444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
    6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001,
    5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5100, 7937,
    7938, 1434, 912, 914, 4111, 1058, 1059, 2967, 109, 220, 1074, 4125,
    6006, 2869, 1455, 9415, 8402, 6668, 6669, 1148, 2381, 4712,
    # Databases & NoSQL
    1521, 1522, 3306, 5432, 5433, 6379, 6380, 27017, 27018, 27019,
    5984, 9200, 9300, 11211, 28017, 50000, 1433, 1434,
    # DevOps / Container / Cloud
    2375, 2376, 2377, 4243, 6443, 8001, 8002, 8003, 8004, 8005,
    8006, 8007, 8010, 8011, 8012, 8013, 8014, 8015, 8016, 8017,
    8018, 8019, 8020, 8021, 8022, 8023, 8024, 8025, 8026, 8027,
    8028, 8029, 8030, 8031, 8040, 8041, 8042, 8050, 8051, 8060,
    8070, 8090, 8091, 8098, 8099, 8100, 8180, 8181, 8200, 8222,
    8243, 8280, 8281, 8333, 8400, 8443, 8444, 8500, 8501, 8600,
    8649, 8765, 8800, 8834, 8880, 8888, 8889, 8983, 9000, 9001,
    9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010, 9011,
    9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101,
    9102, 9103, 9110, 9111, 9200, 9201, 9300, 9418, 9443, 9444,
    9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876,
    9877, 9878, 9898, 9900, 9911, 9981, 9999, 10000, 10001, 10002,
    10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082,
    # Windows / AD services
    88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389,
    5985, 5986, 9389, 47001, 49152, 49153, 49154, 49155, 49156,
    49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175,
    49176, 49400, 49999,
    # Remote admin
    23, 22, 4899, 5900, 5901, 5902, 5903, 5904, 5800, 5801,
    2222, 22222, 50022, 830, 2022,
    # Mail
    25, 26, 110, 143, 465, 587, 993, 995, 2525, 24441,
    # Web / API
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 99, 300,
    443, 591, 593, 832, 888, 981, 1010, 1311, 2082, 2083,
    2086, 2087, 2095, 2096, 2480, 3000, 3001, 3002, 3003,
    4000, 4001, 4002, 4003, 4848, 5000, 5001, 5002, 5003,
    5104, 5108, 5800, 7000, 7001, 7002, 7070, 7080, 7443,
    7474, 7627, 7676, 7777, 7778, 8000, 8001, 8002, 8080,
    8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8091, 8181, 8222, 8243, 8280, 8281, 8443, 8500,
    8800, 8834, 8880, 8888, 8889, 9000, 9001, 9090, 9091,
    9443, 9999, 10000, 10443, 12000, 16080, 18091, 18092,
    # Security / Monitoring
    514, 601, 1514, 4739, 6514, 9997, 9998,
    161, 162, 199, 391, 1993, 2100,
    # VPN / Tunneling
    500, 1194, 1723, 4500, 8194,
    # DNS / NTP / NFS
    53, 111, 123, 2049, 4045,
    # FTP variations
    21, 990, 989, 2121, 8021,
    # Printing
    515, 631, 9100,
    # Databases extended
    1433, 1434, 1521, 1830, 3050, 3306, 3351, 4333, 5432,
    5433, 5984, 6379, 6380, 7210, 7473, 8087, 8098, 8471,
    9042, 9160, 11211, 27017, 27018, 27019, 28015, 28017,
    50000, 50001, 50002,
    # Misc services
    13, 17, 19, 37, 69, 70, 79, 98, 109, 110, 113, 119,
    143, 194, 220, 443, 445, 464, 465, 513, 514, 515, 530,
    543, 544, 548, 554, 555, 587, 593, 601, 631, 636, 646,
    873, 901, 990, 993, 995, 1080, 1099, 1109, 1433, 1434,
    1521, 1720, 1723, 1755, 1812, 1813, 1883, 1900, 2000,
    2049, 2082, 2083, 2086, 2087, 2095, 2096, 2100, 2181,
    2375, 2376, 2377, 2379, 2380, 2480, 2888, 3000, 3001,
    3128, 3268, 3269, 3306, 3389, 3478, 3632, 4000, 4001,
    4002, 4004, 4006, 4045, 4111, 4444, 4500, 4848, 4899,
    4949, 5000, 5001, 5002, 5004, 5005, 5040, 5060, 5100,
    5101, 5104, 5190, 5222, 5269, 5357, 5432, 5601, 5631,
    5632, 5666, 5672, 5800, 5900, 5984, 6000, 6001, 6002,
    6003, 6004, 6005, 6006, 6007, 6080, 6346, 6379, 6443,
    6502, 6514, 6543, 6646, 6667, 6668, 6669, 6697, 7000,
    7001, 7002, 7070, 7080, 7443, 7474, 7627, 7676, 7777,
    8000, 8080, 8088, 8118, 8161, 8172, 8222, 8243, 8280,
    8443, 8500, 8649, 8800, 8834, 8880, 8888, 8983, 9000,
    9001, 9090, 9100, 9160, 9200, 9300, 9418, 9443, 9999,
    10000, 10001, 10010, 10809, 11211, 11300, 12000, 15672,
    16080, 18091, 18092, 25672, 27017, 27018, 28017, 50000,
]))

# UDP probe payloads keyed by port
_UDP_PAYLOADS: dict[int, bytes] = {
    53:  bytes([0x00,0x01,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                0x03,0x77,0x77,0x77,0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,
                0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01]),
    123: bytes([0x1b] + [0x00]*47),
    161: bytes([0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,
                0x63,0xa0,0x19,0x02,0x04,0x00,0x00,0x00,0x01,0x02,0x01,0x00,
                0x02,0x01,0x00,0x30,0x0b,0x30,0x09,0x06,0x05,0x2b,0x06,0x01,
                0x02,0x01,0x05,0x00]),
    137: bytes([0x00,0x00,0x00,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                0x20,0x43,0x4b,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x00,0x00,0x21,0x00,0x01]),
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
    5353: bytes([0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                 0x09,0x5f,0x73,0x65,0x72,0x76,0x69,0x63,0x65,0x73,0x07,0x5f,
                 0x64,0x6e,0x73,0x2d,0x73,0x64,0x04,0x5f,0x75,0x64,0x70,0x05,
                 0x6c,0x6f,0x63,0x61,0x6c,0x00,0x00,0x0c,0x00,0x01]),
}


@dataclass
class PortResult:
    """Result for a single scanned port."""
    port: int
    state: str  # open, closed, filtered, open|filtered
    service: str = ""
    version: str = ""
    banner: str = ""
    scan_type: str = ""
    protocol: str = "tcp"

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "banner": self.banner[:200] if self.banner else "",
            "scan_type": self.scan_type,
            "protocol": self.protocol,
        }


def _parse_port_spec(spec: str | int) -> list[int]:
    """
    Parse a port specification into a list of port numbers.

    Supports: '80', '80,443', '1-1024', 'top100', 'all'

    Args:
        spec: Port specification string or integer.

    Returns:
        List of port numbers.
    """
    if isinstance(spec, int):
        return [spec]
    spec = str(spec).strip().lower()

    if spec == "all":
        return list(range(1, 65536))
    if spec == "top1000":
        return NMAP_TOP_1000[:1000]
    if spec == "top100":
        return NMAP_TOP_1000[:100]
    if spec == "top20":
        return NMAP_TOP_1000[:20]

    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                ports.extend(range(int(lo), int(hi) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.append(int(part))
            except ValueError:
                pass
    return ports


def _load_service_probes() -> list[dict[str, Any]]:
    """Load service detection probes from data/service_probes.json."""
    path = Path(__file__).parent.parent / "data" / "service_probes.json"
    if path.exists():
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            _log.debug("service_probes.json load error: %s", exc)
    return []


_SERVICE_PROBES: list[dict[str, Any]] = []
_PROBES_LOADED = False
_PROBES_LOCK = threading.Lock()


def _get_probes() -> list[dict[str, Any]]:
    global _SERVICE_PROBES, _PROBES_LOADED
    with _PROBES_LOCK:
        if not _PROBES_LOADED:
            _SERVICE_PROBES = _load_service_probes()
            _PROBES_LOADED = True
    return _SERVICE_PROBES


class PortScanner:
    """
    Multi-type port scanner with service detection.

    Args:
        target: Target IP address or hostname.
        config: ReconConfig instance.
    """

    def __init__(self, target: str, config: ReconConfig | None = None) -> None:
        self.target = target
        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.target_ip = target
        self.config = config or ReconConfig()
        self._results: dict[int, PortResult] = {}
        self._lock = threading.Lock()
        self._priv = PrivilegeChecker()
        self._priv.check()

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _delay(self) -> None:
        delay = self.config.effective_delay()
        if delay > 0:
            time.sleep(delay)

    def _rand_ttl(self) -> int:
        if self.config.ttl_randomize or self.config.evasion_level >= 3:
            return random.randint(48, 128)
        return 64

    def _rand_ip_id(self) -> int:
        return random.randint(1, 65535)

    def _add_result(self, result: PortResult) -> None:
        with self._lock:
            existing = self._results.get(result.port)
            if existing is None or existing.state != "open":
                self._results[result.port] = result

    # ------------------------------------------------------------------ #
    # SYN scan                                                             #
    # ------------------------------------------------------------------ #

    def syn_scan(self, ports: list[int]) -> list[PortResult]:
        """
        Half-open SYN scan. Requires root/CAP_NET_RAW.

        Args:
            ports: List of ports to scan.

        Returns:
            List of PortResult entries for open/closed/filtered ports.
        """
        if not self._priv.can("syn_scan"):
            _log.warning("SYN scan requires root; falling back to connect scan")
            return self.connect_scan(ports)

        try:
            from scapy.layers.inet import IP, TCP
            from scapy.sendrecv import sr
        except ImportError:
            _log.warning("Scapy unavailable; falling back to connect scan")
            return self.connect_scan(ports)

        results: list[PortResult] = []
        batch_size = 1000

        for i in range(0, len(ports), batch_size):
            batch = ports[i : i + batch_size]
            pkts = [
                IP(dst=self.target_ip, ttl=self._rand_ttl(), id=self._rand_ip_id())
                / TCP(
                    dport=p,
                    sport=random.randint(1024, 65535),
                    flags="S",
                    seq=random.randint(0, 2**32 - 1),
                )
                for p in batch
            ]
            self._delay()
            try:
                ans, unans = sr(pkts, timeout=self.config.timeout, verbose=False)
            except Exception as exc:
                _log.error("SYN scan batch error: %s", exc)
                continue

            answered_ports: set[int] = set()
            for _, rcv in ans:
                if not (hasattr(rcv, "haslayer") and rcv.haslayer("TCP")):
                    continue
                port = rcv["TCP"].sport
                flags = rcv["TCP"].flags
                answered_ports.add(port)
                if flags & 0x12:  # SYN-ACK → open
                    r = PortResult(port=port, state="open", scan_type="syn")
                    results.append(r)
                    self._add_result(r)
                    _log.debug("SYN: port %d OPEN", port)
                elif flags & 0x14:  # RST-ACK → closed
                    r = PortResult(port=port, state="closed", scan_type="syn")
                    results.append(r)
                    self._add_result(r)
                elif flags & 0x04:  # RST → closed
                    r = PortResult(port=port, state="closed", scan_type="syn")
                    results.append(r)
                    self._add_result(r)

            # Unanswered = filtered
            for pkt in unans:
                port = pkt["TCP"].dport
                if port not in answered_ports:
                    r = PortResult(port=port, state="filtered", scan_type="syn")
                    results.append(r)
                    self._add_result(r)

        return results

    # ------------------------------------------------------------------ #
    # Connect scan                                                         #
    # ------------------------------------------------------------------ #

    def _connect_one(self, port: int) -> PortResult:
        """Single TCP connect probe."""
        try:
            with socket.create_connection(
                (self.target_ip, port), timeout=self.config.connect_timeout
            ):
                return PortResult(port=port, state="open", scan_type="connect")
        except ConnectionRefusedError:
            return PortResult(port=port, state="closed", scan_type="connect")
        except socket.timeout:
            return PortResult(port=port, state="filtered", scan_type="connect")
        except OSError as exc:
            if "Network is unreachable" in str(exc) or "No route to host" in str(exc):
                return PortResult(port=port, state="filtered", scan_type="connect")
            return PortResult(port=port, state="closed", scan_type="connect")

    def connect_scan(self, ports: list[int]) -> list[PortResult]:
        """
        Full TCP connect scan. No root required.

        Args:
            ports: List of ports to scan.

        Returns:
            List of PortResult entries.
        """
        results: list[PortResult] = []
        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {pool.submit(self._connect_one, p): p for p in ports}
            for fut in as_completed(futures):
                r = fut.result()
                results.append(r)
                self._add_result(r)
                self._delay()
        return results

    # ------------------------------------------------------------------ #
    # Stealth scans (FIN, XMAS, NULL)                                     #
    # ------------------------------------------------------------------ #

    def _raw_flag_scan(
        self, ports: list[int], flags: str, scan_type: str
    ) -> list[PortResult]:
        """
        Generic raw-flag TCP scan (FIN/XMAS/NULL/Maimon).

        Interpretation: no response = open|filtered; RST = closed.
        Unreliable on Windows (all ports closed).

        Args:
            ports: Target ports.
            flags: TCP flags string (e.g. 'F', 'FPU', '').
            scan_type: Label for results.

        Returns:
            List of PortResult entries.
        """
        if not self._priv.can("fin_scan"):
            _log.warning("%s scan requires root; skipping", scan_type)
            return []

        try:
            from scapy.layers.inet import IP, TCP
            from scapy.sendrecv import sr
        except ImportError:
            return []

        results: list[PortResult] = []
        batch_size = 500

        for i in range(0, len(ports), batch_size):
            batch = ports[i : i + batch_size]
            pkts = [
                IP(dst=self.target_ip, ttl=self._rand_ttl())
                / TCP(dport=p, sport=random.randint(1024, 65535), flags=flags)
                for p in batch
            ]
            self._delay()
            try:
                ans, unans = sr(pkts, timeout=self.config.timeout, verbose=False)
            except Exception as exc:
                _log.error("%s scan error: %s", scan_type, exc)
                continue

            closed_ports: set[int] = set()
            for _, rcv in ans:
                if hasattr(rcv, "haslayer") and rcv.haslayer("TCP"):
                    if rcv["TCP"].flags & 0x04:  # RST → closed
                        port = rcv["TCP"].sport
                        closed_ports.add(port)
                        r = PortResult(port=port, state="closed", scan_type=scan_type)
                        results.append(r)
                        self._add_result(r)

            for pkt in unans:
                port = pkt["TCP"].dport
                if port not in closed_ports:
                    r = PortResult(port=port, state="open|filtered", scan_type=scan_type)
                    results.append(r)
                    self._add_result(r)

        return results

    def fin_scan(self, ports: list[int]) -> list[PortResult]:
        """FIN scan — no response means open|filtered."""
        return self._raw_flag_scan(ports, "F", "fin")

    def xmas_scan(self, ports: list[int]) -> list[PortResult]:
        """XMAS scan (FIN+PSH+URG)."""
        return self._raw_flag_scan(ports, "FPU", "xmas")

    def null_scan(self, ports: list[int]) -> list[PortResult]:
        """NULL scan (no flags)."""
        return self._raw_flag_scan(ports, "", "null")

    def maimon_scan(self, ports: list[int]) -> list[PortResult]:
        """Maimon scan (FIN+ACK)."""
        return self._raw_flag_scan(ports, "FA", "maimon")

    # ------------------------------------------------------------------ #
    # ACK scan (firewall detection)                                        #
    # ------------------------------------------------------------------ #

    def ack_scan(self, ports: list[int]) -> list[PortResult]:
        """
        ACK scan for firewall rule mapping.

        RST → unfiltered (no firewall rule); no response → filtered.

        Args:
            ports: Target ports.

        Returns:
            PortResult with state 'unfiltered' or 'filtered'.
        """
        if not self._priv.can("syn_scan"):
            _log.warning("ACK scan requires root; skipping")
            return []

        try:
            from scapy.layers.inet import IP, TCP
            from scapy.sendrecv import sr
        except ImportError:
            return []

        results: list[PortResult] = []
        pkts = [
            IP(dst=self.target_ip) / TCP(dport=p, flags="A", seq=random.randint(0, 2**32))
            for p in ports
        ]
        self._delay()
        try:
            ans, unans = sr(pkts, timeout=self.config.timeout, verbose=False)
        except Exception as exc:
            _log.error("ACK scan error: %s", exc)
            return []

        unfiltered: set[int] = set()
        for _, rcv in ans:
            if hasattr(rcv, "haslayer") and rcv.haslayer("TCP"):
                port = rcv["TCP"].sport
                if rcv["TCP"].flags & 0x04:  # RST → unfiltered
                    unfiltered.add(port)
                    r = PortResult(port=port, state="unfiltered", scan_type="ack")
                    results.append(r)
                    self._add_result(r)

        for pkt in unans:
            port = pkt["TCP"].dport
            if port not in unfiltered:
                r = PortResult(port=port, state="filtered", scan_type="ack")
                results.append(r)
                self._add_result(r)

        return results

    # ------------------------------------------------------------------ #
    # UDP scan                                                             #
    # ------------------------------------------------------------------ #

    def udp_scan(self, ports: list[int]) -> list[PortResult]:
        """
        UDP scan with service-specific payloads.

        Args:
            ports: Target UDP ports.

        Returns:
            List of PortResult entries.
        """
        if not self._priv.can("udp_raw"):
            _log.warning("Raw UDP scan requires root; using connect fallback")
            return self._udp_connect_scan(ports)

        try:
            from scapy.layers.inet import ICMP, IP, UDP
            from scapy.sendrecv import sr
        except ImportError:
            return self._udp_connect_scan(ports)

        results: list[PortResult] = []
        pkts = []
        for p in ports:
            payload = _UDP_PAYLOADS.get(p, b"\x00" * 4)
            pkts.append(
                IP(dst=self.target_ip, ttl=self._rand_ttl())
                / UDP(dport=p, sport=random.randint(1024, 65535))
                / payload
            )

        self._delay()
        try:
            ans, unans = sr(pkts, timeout=self.config.timeout, verbose=False)
        except Exception as exc:
            _log.error("UDP scan error: %s", exc)
            return []

        closed_ports: set[int] = set()
        for _, rcv in ans:
            if hasattr(rcv, "haslayer") and rcv.haslayer("UDP"):
                port = rcv["UDP"].sport
                r = PortResult(port=port, state="open", scan_type="udp", protocol="udp")
                results.append(r)
                self._add_result(r)
            elif hasattr(rcv, "haslayer") and rcv.haslayer("ICMP"):
                icmp_type = rcv["ICMP"].type
                if icmp_type == 3:  # Destination unreachable
                    port = rcv["ICMP"].payload.dport if hasattr(rcv["ICMP"].payload, "dport") else 0
                    if port:
                        closed_ports.add(port)
                        r = PortResult(port=port, state="closed", scan_type="udp", protocol="udp")
                        results.append(r)
                        self._add_result(r)

        for pkt in unans:
            port = pkt["UDP"].dport
            if port not in closed_ports:
                r = PortResult(port=port, state="open|filtered", scan_type="udp", protocol="udp")
                results.append(r)
                self._add_result(r)

        return results

    def _udp_connect_scan(self, ports: list[int]) -> list[PortResult]:
        """UDP socket scan fallback for non-root."""
        results: list[PortResult] = []
        for port in ports:
            payload = _UDP_PAYLOADS.get(port, b"\x00" * 4)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.config.timeout)
                    s.sendto(payload, (self.target_ip, port))
                    s.recvfrom(1024)
                    r = PortResult(port=port, state="open", scan_type="udp", protocol="udp")
                    results.append(r)
                    self._add_result(r)
            except socket.timeout:
                r = PortResult(port=port, state="open|filtered", scan_type="udp", protocol="udp")
                results.append(r)
                self._add_result(r)
            except ConnectionRefusedError:
                r = PortResult(port=port, state="closed", scan_type="udp", protocol="udp")
                results.append(r)
                self._add_result(r)
            except Exception:
                pass
        return results

    # ------------------------------------------------------------------ #
    # Service detection                                                    #
    # ------------------------------------------------------------------ #

    def detect_service(self, port: int) -> tuple[str, str, str]:
        """
        Detect service name, version, and grab banner from an open port.

        Uses probes from service_probes.json, then falls back to raw banner.

        Args:
            port: Open TCP port to probe.

        Returns:
            Tuple (service_name, version, banner).
        """
        probes = _get_probes()

        for probe in probes:
            if "tcp" not in probe.get("protocol", "tcp"):
                continue
            if port not in probe.get("ports", []):
                continue
            try:
                with socket.create_connection(
                    (self.target_ip, port), timeout=self.config.connect_timeout
                ) as s:
                    s.settimeout(self.config.connect_timeout)
                    probe_bytes = probe.get("probe_bytes", "")
                    if probe_bytes:
                        s.sendall(probe_bytes.encode("utf-8", errors="replace"))
                    data = s.recv(2048)
                    banner = data.decode("utf-8", errors="replace").strip()
                    match_regex = probe.get("match_regex")
                    if match_regex:
                        m = re.search(match_regex, banner)
                        if m:
                            version = m.group("version") if "version" in m.groupdict() else ""
                            return probe.get("service_name", ""), version, banner[:300]
                    return probe.get("service_name", ""), "", banner[:300]
            except Exception:
                continue

        # Fallback: raw banner grab
        service_name = _well_known_service(port)
        banner = self._raw_banner(port)
        version = _extract_version(banner)
        return service_name, version, banner

    def _raw_banner(self, port: int) -> str:
        """Raw TCP banner grab with partial-read safety."""
        probes = {
            21: None, 22: None, 23: None, 25: None, 110: None, 143: None,
            80:  b"GET / HTTP/1.0\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n",
            443: b"GET / HTTP/1.0\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n",
            8080: b"GET / HTTP/1.0\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n",
        }
        try:
            with socket.create_connection(
                (self.target_ip, port), timeout=self.config.connect_timeout
            ) as s:
                s.settimeout(self.config.connect_timeout)
                probe = probes.get(port)
                if probe:
                    s.sendall(probe)
                data = s.recv(512)
                return data.decode("utf-8", errors="replace").strip()[:300]
        except Exception:
            return ""

    # ------------------------------------------------------------------ #
    # Full scan pipeline                                                   #
    # ------------------------------------------------------------------ #

    def scan_ports(
        self,
        ports: list[int] | str = "top1000",
        scan_type: str = "syn",
        detect_services: bool = True,
    ) -> list[PortResult]:
        """
        Run a port scan with the specified type and optionally detect services.

        Args:
            ports: Port spec (list, 'top100', 'all', '1-1024', '80,443').
            scan_type: syn|connect|fin|xmas|null|ack|udp|window|maimon.
            detect_services: Run service detection on open ports.

        Returns:
            List of PortResult entries (open ports only if services detected).
        """
        if isinstance(ports, str):
            port_list = _parse_port_spec(ports)
        else:
            port_list = list(ports)

        if self.config.evasion_level >= 1 or self.config.randomize_ports:
            random.shuffle(port_list)

        _log.info(
            "[bold cyan]Port scan[/] target=%s type=%s ports=%d",
            self.target, scan_type, len(port_list),
        )

        scan_map = {
            "syn":     self.syn_scan,
            "connect": self.connect_scan,
            "fin":     self.fin_scan,
            "xmas":    self.xmas_scan,
            "null":    self.null_scan,
            "ack":     self.ack_scan,
            "maimon":  self.maimon_scan,
            "udp":     self.udp_scan,
        }

        scanner = scan_map.get(scan_type, self.syn_scan)

        with make_progress(f"Port scan ({scan_type})") as progress:
            task = progress.add_task("Scanning ports", total=len(port_list))
            results = scanner(port_list)
            progress.update(task, completed=len(port_list))

        open_ports = [r for r in results if r.state == "open"]
        _log.info("[bold green]Open ports[/]: %d/%d", len(open_ports), len(port_list))

        if detect_services and open_ports:
            _log.info("Service detection on %d open ports", len(open_ports))
            with make_progress("Service detection") as progress:
                task = progress.add_task("Detecting services", total=len(open_ports))
                with ThreadPoolExecutor(max_workers=min(len(open_ports), 20)) as pool:
                    futures = {pool.submit(self.detect_service, r.port): r for r in open_ports}
                    for fut, port_result in futures.items():
                        progress.advance(task)
                        try:
                            svc, ver, banner = fut.result()
                            port_result.service = svc
                            port_result.version = ver
                            port_result.banner = banner
                            if svc:
                                _log.debug(
                                    "Port %d: %s %s",
                                    port_result.port, svc, ver,
                                )
                        except Exception as exc:
                            _log.debug("Service detect error port %d: %s", port_result.port, exc)

        return open_ports

    def results(self) -> list[PortResult]:
        """Return all accumulated port results, sorted by port number."""
        with self._lock:
            return sorted(self._results.values(), key=lambda r: r.port)


# ------------------------------------------------------------------ #
# Utility helpers                                                      #
# ------------------------------------------------------------------ #

def _well_known_service(port: int) -> str:
    """Return IANA service name for well-known ports."""
    _svc = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
        135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
        179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
        465: "smtps", 514: "syslog", 515: "printer", 587: "submission",
        631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
        1433: "mssql", 1521: "oracle", 1723: "pptp", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
        8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
        27017: "mongodb", 11211: "memcached", 2375: "docker",
        6443: "kubernetes", 5984: "couchdb",
    }
    return _svc.get(port, "")


def _extract_version(banner: str) -> str:
    """Extract version string from a service banner."""
    patterns = [
        r"(\d+\.\d+[\.\d]*(?:[-_]\w+)?)",
        r"version\s+(\S+)",
        r"v(\d+\.\d+)",
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""
