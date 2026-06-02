"""
recon.modules.os_fingerprint — Passive + active OS fingerprinting.

Methods:
- Active TCP SYN-ACK analysis (window size, MSS, WScale, SACK, timestamp)
- TTL analysis with jitter tolerance
- ICMP unreachable IP header copy quirks
- Banner analysis via regex patterns
- Confidence-weighted multi-method consensus
"""

from __future__ import annotations

import re
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from recon.core.config import ReconConfig
from recon.core.logger import get_logger
from recon.core.privilege import PrivilegeChecker

__all__ = ["OSFingerprinter", "OSGuess"]

_log = get_logger("os_fingerprint")

# ------------------------------------------------------------------ #
# OS Signature Database                                                #
# ------------------------------------------------------------------ #

_OS_SIGNATURES: list[dict[str, Any]] = [
    {
        "name": "Linux 5.x (modern)",
        "ttl_range": (63, 65),
        "window_size": 65535,
        "mss": 1460,
        "wscale": (7, 10),
        "sack": True,
        "timestamp": True,
        "df": True,
        "weight": 1.0,
    },
    {
        "name": "Linux 4.x",
        "ttl_range": (63, 65),
        "window_size": 29200,
        "mss": 1460,
        "wscale": (7, 7),
        "sack": True,
        "timestamp": True,
        "df": True,
        "weight": 1.0,
    },
    {
        "name": "Linux 3.x / older",
        "ttl_range": (63, 65),
        "window_size": (5840, 14600),
        "mss": 1460,
        "wscale": None,
        "sack": True,
        "timestamp": True,
        "df": True,
        "weight": 0.8,
    },
    {
        "name": "Windows 10/11/Server 2019+",
        "ttl_range": (126, 130),
        "window_size": 64240,
        "mss": 1460,
        "wscale": (8, 8),
        "sack": True,
        "timestamp": False,
        "df": True,
        "weight": 1.0,
    },
    {
        "name": "Windows 7/8/Server 2012",
        "ttl_range": (126, 130),
        "window_size": (8192, 65535),
        "mss": 1460,
        "wscale": (8, 8),
        "sack": True,
        "timestamp": False,
        "df": True,
        "weight": 0.9,
    },
    {
        "name": "Windows XP/2003",
        "ttl_range": (126, 130),
        "window_size": (16384, 65535),
        "mss": 1460,
        "wscale": None,
        "sack": True,
        "timestamp": False,
        "df": True,
        "weight": 0.8,
    },
    {
        "name": "macOS 12+ (Monterey/Ventura)",
        "ttl_range": (63, 65),
        "window_size": 65535,
        "mss": 1460,
        "wscale": (6, 6),
        "sack": True,
        "timestamp": True,
        "df": True,
        "weight": 0.9,
    },
    {
        "name": "FreeBSD 13+",
        "ttl_range": (63, 65),
        "window_size": 65535,
        "mss": 1460,
        "wscale": (6, 6),
        "sack": True,
        "timestamp": True,
        "df": True,
        "weight": 0.85,
    },
    {
        "name": "OpenBSD 7+",
        "ttl_range": (63, 65),
        "window_size": 16384,
        "mss": 1460,
        "wscale": None,
        "sack": True,
        "timestamp": False,
        "df": True,
        "weight": 0.85,
    },
    {
        "name": "Cisco IOS",
        "ttl_range": (253, 255),
        "window_size": 4128,
        "mss": 536,
        "wscale": None,
        "sack": False,
        "timestamp": False,
        "df": False,
        "weight": 1.0,
    },
    {
        "name": "Cisco IOS XE",
        "ttl_range": (253, 255),
        "window_size": (4096, 8192),
        "mss": 1460,
        "wscale": None,
        "sack": False,
        "timestamp": False,
        "df": True,
        "weight": 0.9,
    },
    {
        "name": "Solaris 11",
        "ttl_range": (253, 255),
        "window_size": 49152,
        "mss": 1460,
        "wscale": (4, 4),
        "sack": True,
        "timestamp": True,
        "df": True,
        "weight": 0.85,
    },
    {
        "name": "Android 10+",
        "ttl_range": (63, 65),
        "window_size": 65535,
        "mss": 1460,
        "wscale": (9, 9),
        "sack": True,
        "timestamp": True,
        "df": True,
        "weight": 0.8,
    },
    {
        "name": "VMware ESXi",
        "ttl_range": (63, 65),
        "window_size": 4096,
        "mss": 1460,
        "wscale": None,
        "sack": False,
        "timestamp": False,
        "df": True,
        "weight": 0.75,
    },
    {
        "name": "Network Embedded (generic)",
        "ttl_range": (60, 70),
        "window_size": (2048, 8192),
        "mss": 536,
        "wscale": None,
        "sack": False,
        "timestamp": False,
        "df": False,
        "weight": 0.6,
    },
]

# Banner regex patterns for OS identification
_BANNER_PATTERNS: list[dict[str, Any]] = [
    {"pattern": r"Ubuntu (\d+\.\d+)", "os": "Linux (Ubuntu {0})", "confidence": 90},
    {"pattern": r"Debian GNU/Linux (\d+)", "os": "Linux (Debian {0})", "confidence": 90},
    {"pattern": r"CentOS(?: Linux)? (\d+)", "os": "Linux (CentOS {0})", "confidence": 90},
    {"pattern": r"Red Hat Enterprise Linux(?: Server)? (\d+)", "os": "Linux (RHEL {0})", "confidence": 90},
    {"pattern": r"Fedora release (\d+)", "os": "Linux (Fedora {0})", "confidence": 85},
    {"pattern": r"OpenSSH[_/](\d+\.\d+)[^ ]* \(FreeBSD\)", "os": "FreeBSD", "confidence": 85},
    {"pattern": r"OpenSSH[_/](\d+\.\d+)[^ ]* \(NetBSD\)", "os": "NetBSD", "confidence": 85},
    {"pattern": r"Microsoft Windows (\d+[^\r\n]*)", "os": "Windows {0}", "confidence": 95},
    {"pattern": r"Windows Server (\d{4}[^\r\n]*)", "os": "Windows Server {0}", "confidence": 95},
    {"pattern": r"IIS/(\d+\.\d+)", "os": "Windows (IIS {0})", "confidence": 70},
    {"pattern": r"Cisco IOS Software.*Version (\S+)", "os": "Cisco IOS {0}", "confidence": 95},
    {"pattern": r"IOS-XE Software.*Version (\S+)", "os": "Cisco IOS XE {0}", "confidence": 95},
    {"pattern": r"Junos (\S+)", "os": "Juniper JunOS {0}", "confidence": 90},
    {"pattern": r"Darwin (\d+\.\d+)", "os": "macOS (Darwin {0})", "confidence": 80},
    {"pattern": r"FortiGate", "os": "Fortinet FortiOS", "confidence": 90},
    {"pattern": r"pfsense", "os": "pfSense (FreeBSD)", "confidence": 85},
    {"pattern": r"OpenBSD (\d+\.\d+)", "os": "OpenBSD {0}", "confidence": 95},
    {"pattern": r"NetBSD (\d+\.\d+)", "os": "NetBSD {0}", "confidence": 95},
]


@dataclass
class OSGuess:
    """OS fingerprinting result."""
    os_guess: str = "Unknown"
    confidence: int = 0
    methods: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "os_guess": self.os_guess,
            "confidence": self.confidence,
            "methods": self.methods,
            "raw": self.raw,
        }


class OSFingerprinter:
    """
    Multi-method OS fingerprinting engine.

    Args:
        target: IP address to fingerprint.
        config: ReconConfig instance.
    """

    def __init__(self, target: str, config: ReconConfig | None = None) -> None:
        self.target = target
        self.config = config or ReconConfig()
        self._priv = PrivilegeChecker()
        self._priv.check()

    # ------------------------------------------------------------------ #
    # TTL fingerprinting                                                   #
    # ------------------------------------------------------------------ #

    def ttl_fingerprint(self) -> tuple[str, int] | None:
        """
        Send ICMP echo and inspect TTL from response.

        Returns:
            Tuple (os_guess, ttl) or None if no response.
        """
        if not self._priv.can("icmp_ping"):
            return self._ttl_via_socket()

        try:
            from scapy.layers.inet import ICMP, IP
            from scapy.sendrecv import sr1

            pkt = IP(dst=self.target) / ICMP(type=8, seq=1)
            resp = sr1(pkt, timeout=self.config.timeout, verbose=False)
            if resp and resp.haslayer("IP"):
                ttl = resp["IP"].ttl
                return _guess_os_from_ttl(ttl), ttl
        except Exception as exc:
            _log.debug("TTL ICMP fingerprint error: %s", exc)
        return None

    def _ttl_via_socket(self) -> tuple[str, int] | None:
        """TCP connect TTL probe (fallback, lower accuracy)."""
        ports = [80, 443, 22, 8080]
        for port in ports:
            try:
                with socket.create_connection((self.target, port), timeout=self.config.timeout):
                    pass
                # Can't get TTL from connect() easily; skip
            except Exception:
                pass
        return None

    # ------------------------------------------------------------------ #
    # TCP stack fingerprinting                                             #
    # ------------------------------------------------------------------ #

    def tcp_stack_fingerprint(self, port: int = 80) -> dict[str, Any] | None:
        """
        Send a SYN and analyze the SYN-ACK TCP options.

        Args:
            port: Target port to probe (tries 80, 443, 22 in order).

        Returns:
            Dict of observed TCP parameters or None if no response.
        """
        if not self._priv.can("syn_scan"):
            _log.debug("TCP stack fingerprint requires root")
            return None

        try:
            from scapy.layers.inet import IP, TCP
            from scapy.sendrecv import sr1
        except ImportError:
            return None

        for target_port in [port, 443, 22, 8080]:
            try:
                import random
                syn = IP(dst=self.target) / TCP(
                    dport=target_port,
                    flags="S",
                    seq=random.randint(1000, 0xFFFFFFFF),
                    options=[
                        ("MSS", 1460),
                        ("SAckOK", b""),
                        ("Timestamp", (int(time.time()) & 0xFFFFFFFF, 0)),
                        ("NOP", None),
                        ("WScale", 7),
                    ],
                )
                resp = sr1(syn, timeout=self.config.timeout, verbose=False)
                if resp and resp.haslayer("TCP") and resp["TCP"].flags & 0x12:
                    return self._parse_tcp_options(resp)
            except Exception as exc:
                _log.debug("TCP fingerprint error on port %d: %s", target_port, exc)
        return None

    @staticmethod
    def _parse_tcp_options(pkt: Any) -> dict[str, Any]:
        """Extract TCP option fields from a SYN-ACK response packet."""
        tcp = pkt["TCP"]
        ip = pkt["IP"]
        result: dict[str, Any] = {
            "window_size": tcp.window,
            "ttl": ip.ttl,
            "df": bool(ip.flags & 0x2),
            "mss": None,
            "wscale": None,
            "sack": False,
            "timestamp": False,
        }
        for opt_name, opt_val in tcp.options:
            if opt_name == "MSS":
                result["mss"] = opt_val
            elif opt_name == "WScale":
                result["wscale"] = opt_val
            elif opt_name in ("SAckOK", "SAck"):
                result["sack"] = True
            elif opt_name == "Timestamp":
                result["timestamp"] = True
        return result

    # ------------------------------------------------------------------ #
    # Signature matching                                                   #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _match_signatures(params: dict[str, Any]) -> list[tuple[str, float]]:
        """
        Score all OS signatures against observed TCP parameters.

        Args:
            params: Dict from _parse_tcp_options.

        Returns:
            Sorted list of (os_name, score) tuples.
        """
        scores: list[tuple[str, float]] = []
        win = params.get("window_size", 0)
        ttl = params.get("ttl", 0)
        mss = params.get("mss")
        wscale = params.get("wscale")
        sack = params.get("sack", False)
        ts = params.get("timestamp", False)
        df = params.get("df", False)

        for sig in _OS_SIGNATURES:
            score = 0.0
            checks = 0

            # TTL range
            tlo, thi = sig["ttl_range"]
            # Adjust for up to 10 hops
            if tlo - 10 <= ttl <= thi:
                score += 30
            checks += 30

            # Window size
            exp_win = sig["window_size"]
            if isinstance(exp_win, tuple):
                if exp_win[0] <= win <= exp_win[1]:
                    score += 25
            elif win == exp_win:
                score += 25
            elif abs(win - exp_win) < 1000:
                score += 10
            checks += 25

            # MSS
            if mss is not None and sig["mss"] is not None:
                if mss == sig["mss"]:
                    score += 15
                checks += 15

            # WScale
            if wscale is not None and sig["wscale"] is not None:
                wlo, whi = sig["wscale"]
                if wlo <= wscale <= whi:
                    score += 10
                checks += 10

            # SACK
            if sack == sig["sack"]:
                score += 10
            checks += 10

            # Timestamp
            if ts == sig["timestamp"]:
                score += 10
            checks += 10

            # DF bit
            if df == sig["df"]:
                score += 10
            checks += 10

            pct = int((score / checks) * 100 * sig["weight"]) if checks else 0
            scores.append((sig["name"], pct))

        return sorted(scores, key=lambda x: x[1], reverse=True)

    # ------------------------------------------------------------------ #
    # Banner fingerprinting                                                #
    # ------------------------------------------------------------------ #

    def banner_fingerprint(self) -> dict[str, Any]:
        """
        Grab banners from common service ports and match OS patterns.

        Returns:
            Dict with per-port os_guess entries.
        """
        results: dict[str, Any] = {}
        probe_ports = [22, 21, 23, 25, 80, 110, 143, 443, 8080, 3389]

        for port in probe_ports:
            banner = self._grab_banner_port(port)
            if not banner:
                continue
            os_guess = self._match_banner(banner)
            if os_guess:
                results[str(port)] = {"banner": banner[:200], "os_guess": os_guess}
                _log.debug("Banner port %d → %s", port, os_guess)
        return results

    def _grab_banner_port(self, port: int) -> str:
        """Attempt to grab a banner from a given port."""
        probes: dict[int, bytes] = {
            80:  b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n",
            443: b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n",
            8080: b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n",
        }
        try:
            with socket.create_connection((self.target, port), timeout=self.config.timeout) as s:
                s.settimeout(self.config.timeout)
                probe = probes.get(port)
                if probe:
                    s.sendall(probe)
                data = s.recv(512)
                return data.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    @staticmethod
    def _match_banner(banner: str) -> str:
        """Match banner string against OS regex patterns."""
        for entry in _BANNER_PATTERNS:
            m = re.search(entry["pattern"], banner, re.IGNORECASE)
            if m:
                os_str = entry["os"]
                if m.groups():
                    os_str = os_str.format(*m.groups())
                return os_str
        return ""

    # ------------------------------------------------------------------ #
    # ICMP quirks                                                          #
    # ------------------------------------------------------------------ #

    def icmp_quirks(self) -> dict[str, Any]:
        """
        Probe ICMP unreachable and fragmentation quirks for OS hints.

        Returns:
            Dict of observed quirk values.
        """
        if not self._priv.can("icmp_ping"):
            return {}

        quirks: dict[str, Any] = {}
        try:
            from scapy.layers.inet import ICMP, IP, UDP
            from scapy.sendrecv import sr1

            # ICMP timestamp request (type 13)
            ts_pkt = IP(dst=self.target) / ICMP(type=13)
            resp = sr1(ts_pkt, timeout=self.config.timeout, verbose=False)
            if resp:
                quirks["icmp_ts_reply"] = True
                if resp.haslayer("IP"):
                    quirks["icmp_ts_ttl"] = resp["IP"].ttl

            # UDP to closed port for ICMP unreachable
            udp_pkt = IP(dst=self.target, ttl=128) / UDP(dport=33434) / b"probe"
            resp = sr1(udp_pkt, timeout=self.config.timeout, verbose=False)
            if resp and resp.haslayer("ICMP") and resp["ICMP"].type == 3:
                quirks["icmp_unreach"] = True
                # Check how much of original IP header is in the response
                orig_len = len(bytes(resp["ICMP"].payload)) if resp["ICMP"].payload else 0
                quirks["icmp_unreach_data_len"] = orig_len
                # Linux includes 8 bytes of UDP data; Windows includes full
                if orig_len > 28:
                    quirks["icmp_unreach_hint"] = "Windows (full original included)"
                else:
                    quirks["icmp_unreach_hint"] = "Linux/BSD (8-byte truncation)"
        except Exception as exc:
            _log.debug("ICMP quirks error: %s", exc)
        return quirks

    # ------------------------------------------------------------------ #
    # Full fingerprinting pipeline                                         #
    # ------------------------------------------------------------------ #

    def run_full(self) -> OSGuess:
        """
        Run all fingerprinting methods and return a confidence-weighted guess.

        Returns:
            OSGuess with best guess, confidence, and per-method details.
        """
        _log.info("[bold cyan]OS fingerprinting[/] target=%s", self.target)
        methods: dict[str, str] = {}
        raw: dict[str, Any] = {}
        candidates: list[tuple[str, int, float]] = []  # (os, confidence, weight)

        # 1. TTL
        ttl_result = self.ttl_fingerprint()
        if ttl_result:
            os_ttl, ttl_val = ttl_result
            methods["ttl"] = f"{os_ttl} (TTL={ttl_val})"
            raw["ttl"] = ttl_val
            candidates.append((os_ttl, 50, 0.6))

        # 2. TCP stack
        tcp_params = self.tcp_stack_fingerprint()
        if tcp_params:
            raw["tcp_stack"] = tcp_params
            matches = self._match_signatures(tcp_params)
            if matches:
                best_os, best_score = matches[0]
                methods["tcp_stack"] = f"{best_os} ({best_score}%)"
                candidates.append((best_os, best_score, 1.0))

        # 3. Banner
        banner_results = self.banner_fingerprint()
        raw["banners"] = banner_results
        for port_str, info in banner_results.items():
            if info.get("os_guess"):
                methods["banner"] = info["os_guess"]
                candidates.append((info["os_guess"], 85, 1.2))
                break

        # 4. ICMP quirks
        quirks = self.icmp_quirks()
        raw["icmp_quirks"] = quirks
        if quirks.get("icmp_unreach_hint"):
            hint = quirks["icmp_unreach_hint"]
            methods["icmp_quirks"] = hint
            os_q = "Windows" if "Windows" in hint else "Linux/BSD"
            candidates.append((os_q, 60, 0.7))

        # Weighted consensus
        os_guess = "Unknown"
        confidence = 0

        if candidates:
            # Group by OS family
            family_scores: dict[str, list[float]] = {}
            for os_str, conf, weight in candidates:
                fam = _normalize_os_family(os_str)
                family_scores.setdefault(fam, []).append(conf * weight)

            best_fam = max(family_scores, key=lambda k: sum(family_scores[k]))
            best_scores = family_scores[best_fam]
            confidence = min(int(sum(best_scores) / len(best_scores)), 99)

            # Find the most specific OS name for that family
            specific = next(
                (os_str for os_str, _, _ in candidates if _normalize_os_family(os_str) == best_fam),
                best_fam,
            )
            os_guess = specific

        guess = OSGuess(
            os_guess=os_guess,
            confidence=confidence,
            methods=methods,
            raw=raw,
        )
        _log.info(
            "[bold green]OS guess[/]: %s (confidence=%d%%, methods=%d)",
            os_guess, confidence, len(methods),
        )
        return guess


def _guess_os_from_ttl(ttl: int) -> str:
    """Map TTL value to OS family string."""
    if 60 <= ttl <= 70:
        return "Linux/Unix"
    if 120 <= ttl <= 135:
        return "Windows"
    if 248 <= ttl <= 255:
        return "Cisco/Network gear"
    if 200 <= ttl <= 255:
        return "Solaris/HP-UX"
    return f"Unknown (TTL={ttl})"


def _normalize_os_family(os_str: str) -> str:
    """Reduce an OS string to a broad family name for grouping."""
    s = os_str.lower()
    if "linux" in s or "ubuntu" in s or "debian" in s or "centos" in s or "fedora" in s or "rhel" in s:
        return "Linux"
    if "windows" in s:
        return "Windows"
    if "cisco" in s or "ios" in s:
        return "Cisco"
    if "freebsd" in s or "openbsd" in s or "netbsd" in s or "bsd" in s:
        return "BSD"
    if "macos" in s or "darwin" in s:
        return "macOS"
    if "solaris" in s:
        return "Solaris"
    if "android" in s:
        return "Android"
    return os_str
