"""
recon.modules.port_scan — Production port scanner with multiple scan types.

Scan types implemented via raw Scapy sockets:
- SYN (half-open, stealthiest)
- Connect (full TCP, no root required)
- FIN, XMAS, NULL (stealth variants)
- ACK (firewall detection)
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

# Ports that speak TLS immediately (implicit TLS). Service detection wraps the
# socket in a handshake for these instead of sending a cleartext probe that a
# TLS listener never answers (the old behaviour: HTTPS/etc. always timed out).
_TLS_PORTS = {443, 465, 563, 636, 853, 990, 992, 993, 995, 2376, 4443, 5986,
              6443, 8443, 8834, 9443, 9100}


def _wrap_tls(sock, host: str):
    """Wrap a connected socket in TLS (no cert validation — we are scanning)."""
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock, server_hostname=host)

# Nmap top-1000 TCP ports — ordered by frequency in nmap-services.
# dict.fromkeys() dedups while preserving that frequency order; a plain
# sorted(set(...)) would instead reorder everything by ascending port
# number, turning "top100" into "the 100 lowest port numbers" rather
# than "the 100 most common services" (e.g. dropping 3389/RDP).
def _load_top_ports() -> list[int]:
    """Load the frequency-ordered top-ports list from data/nmap_top_ports.txt.

    Replaces a hand-maintained literal that deduped to 437 unique ports, so
    "top1000" silently scanned only 437. The file head is nmap open-frequency
    order; see scripts/build_top_ports.py to regenerate it.
    """
    path = Path(__file__).parent.parent / "data" / "nmap_top_ports.txt"
    try:
        with open(path, encoding="utf-8") as f:
            return [
                int(line) for line in f
                if line.strip() and not line.lstrip().startswith("#")
            ]
    except Exception as exc:  # pragma: no cover - packaging/data error
        _log.error("top-ports list unavailable (%s); using a minimal fallback set", exc)
        return [80, 443, 22, 21, 23, 25, 53, 110, 143, 139, 445, 3389, 3306, 8080, 8443]


NMAP_TOP_1000: list[int] = _load_top_ports()

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
    if spec == "top10000":
        return NMAP_TOP_1000[:10000]
    if spec == "top5000":
        return NMAP_TOP_1000[:5000]
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
    """Load service-detection probes via the shared, validated loader.

    Delegates to recon.core.probes so a malformed probe database raises loudly
    (and fails the data-integrity test / CI) rather than silently returning an
    empty list and disabling service detection, as the old inline loader did.
    """
    from recon.core.probes import ProbeLoadError, load_probes

    try:
        return load_probes()
    except ProbeLoadError as exc:
        _log.error("service probe database unavailable: %s", exc)
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
                # Raw send failed at runtime (Npcap present but unusable, an
                # interface/permission issue the capability check can't see,
                # etc). With no results yet, degrade to a connect scan instead
                # of silently returning an empty list.
                if not results:
                    _log.warning(
                        "SYN scan unavailable at runtime (%s); falling back to connect scan",
                        exc,
                    )
                    return self.connect_scan(ports)
                _log.error("SYN scan batch error after partial results: %s", exc)
                break

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
            _log.warning("Raw UDP scan unavailable at runtime (%s); using connect fallback", exc)
            return self._udp_connect_scan(ports)

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
        from recon.core.probes import probe_payload

        for probe in probes:
            if "tcp" not in probe.get("protocol", "tcp"):
                continue
            if port not in probe.get("ports", []):
                continue
            sock = None
            try:
                sock = socket.create_connection(
                    (self.target_ip, port), timeout=self.config.connect_timeout
                )
                sock.settimeout(self.config.connect_timeout)
                if port in _TLS_PORTS:
                    sock = _wrap_tls(sock, self.target_ip)  # raises if not really TLS
                payload = probe_payload(probe, self.target_ip)
                if payload:
                    sock.sendall(payload)
                data = sock.recv(2048)
                # Match on a byte-faithful latin-1 view (1:1 codepoints) so
                # binary / NUL-byte probe patterns work; UTF-8 only for display.
                match_text = data.decode("latin-1", errors="replace")
                banner = data.decode("utf-8", errors="replace").strip()
                match_regex = probe.get("match_regex")
                if match_regex:
                    m = re.search(match_regex, match_text)
                    if m:
                        version = m.group("version") if "version" in m.groupdict() else ""
                        return probe.get("service_name", ""), version, banner[:300]
                return probe.get("service_name", ""), "", banner[:300]
            except Exception:
                continue
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass

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
            scan_type: syn|connect|fin|xmas|null|ack|udp|maimon.
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

        scanner = scan_map.get(scan_type)
        if scanner is None:
            _log.warning(
                "Unknown scan_type '%s' (expected one of %s) — falling back to SYN scan",
                scan_type, "/".join(scan_map),
            )
            scanner = self.syn_scan

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
