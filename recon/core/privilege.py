"""
recon.core.privilege — Privilege and capability checker.

Checks for root/Administrator privileges, Linux capabilities (CAP_NET_RAW,
CAP_NET_ADMIN), and — critically on Windows — the presence of a raw-packet
backend (Npcap). Raw-socket features gracefully degrade rather than crash:
a scanner asks ``can(feature)`` and falls back (e.g. SYN -> connect) when the
real capability is absent.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field

from recon.core.logger import console, get_logger

__all__ = ["PrivilegeChecker"]

_log = get_logger("privilege")

_FEATURE_REQUIREMENTS: dict[str, dict] = {
    "syn_scan":      {"root": True,  "cap": "CAP_NET_RAW",   "reason": "raw socket SYN packets"},
    "arp_sweep":     {"root": True,  "cap": "CAP_NET_RAW",   "reason": "ARP frame injection"},
    "icmp_ping":     {"root": True,  "cap": "CAP_NET_RAW",   "reason": "raw ICMP packets"},
    "pcap_capture":  {"root": True,  "cap": "CAP_NET_ADMIN", "reason": "promiscuous mode sniffing"},
    "monitor_mode":  {"root": True,  "cap": "CAP_NET_ADMIN", "reason": "wireless monitor mode"},
    "fin_scan":      {"root": True,  "cap": "CAP_NET_RAW",   "reason": "raw TCP FIN/XMAS/NULL packets"},
    "udp_raw":       {"root": True,  "cap": "CAP_NET_RAW",   "reason": "raw UDP probes"},
    "connect_scan":  {"root": False, "cap": None,            "reason": "standard TCP connect"},
    "dns_enum":      {"root": False, "cap": None,            "reason": "DNS queries via socket"},
    "banner_grab":   {"root": False, "cap": None,            "reason": "TCP connect + read"},
    "ssl_audit":     {"root": False, "cap": None,            "reason": "TLS handshake via ssl module"},
    "default_creds": {"root": False, "cap": None,            "reason": "TCP connect attempts"},
}


@dataclass
class CapabilityStatus:
    is_root: bool
    platform: str
    cap_net_raw: bool          # effective raw-socket capability (platform-aware)
    cap_net_admin: bool        # effective CAP_NET_ADMIN-class capability
    has_npcap: bool = False    # Windows: a raw-packet backend (Npcap) is installed
    raw_backend: str = "none"  # how raw access is obtained: root|cap_net_raw|npcap|none
    available_features: set[str] = field(default_factory=set)
    disabled_features: set[str] = field(default_factory=set)


class PrivilegeChecker:
    """
    Checks runtime privileges and builds a map of available features.

    Usage:
        checker = PrivilegeChecker()
        checker.check()
        if not checker.can("syn_scan"):
            ...
    """

    def __init__(self) -> None:
        self._status: CapabilityStatus | None = None

    def check(self) -> CapabilityStatus:
        """Run privilege detection and return a CapabilityStatus."""
        plat = platform.system()
        is_root = self._detect_root(plat)
        has_npcap = self._detect_npcap(plat)

        # Effective raw-socket capability, per platform.
        #   Linux  : root OR the specific capability (CAP_NET_RAW/ADMIN).
        #   Windows: admin AND a raw backend (Npcap) — admin alone is NOT enough;
        #            scapy's send paths fail at runtime without Npcap. Treating
        #            admin as sufficient is why SYN scans silently returned [].
        #   macOS/other: root (BPF access).
        if plat == "Linux":
            cap_raw = is_root or self._detect_cap("cap_net_raw", plat, is_root)
            cap_admin = is_root or self._detect_cap("cap_net_admin", plat, is_root)
            raw_backend = "root" if is_root else ("cap_net_raw" if cap_raw else "none")
        elif plat == "Windows":
            cap_raw = cap_admin = bool(is_root and has_npcap)
            raw_backend = "npcap" if cap_raw else "none"
        else:
            cap_raw = cap_admin = is_root
            raw_backend = "root" if is_root else "none"

        available: set[str] = set()
        disabled: set[str] = set()
        for feature, req in _FEATURE_REQUIREMENTS.items():
            if not req["root"]:
                has_priv = True
            elif req["cap"] == "CAP_NET_ADMIN":
                has_priv = cap_admin
            elif req["cap"] == "CAP_NET_RAW":
                has_priv = cap_raw
            else:
                has_priv = is_root
            (available if has_priv else disabled).add(feature)

        self._status = CapabilityStatus(
            is_root=is_root,
            platform=plat,
            cap_net_raw=cap_raw,
            cap_net_admin=cap_admin,
            has_npcap=has_npcap,
            raw_backend=raw_backend,
            available_features=available,
            disabled_features=disabled,
        )
        return self._status

    def can(self, feature: str) -> bool:
        """Return True if ``feature`` is available under current privileges."""
        if self._status is None:
            self.check()
        return feature in self._status.available_features  # type: ignore[union-attr]

    def warn_if_missing(self, feature: str) -> bool:
        """Check feature availability and emit a warning if missing."""
        if self.can(feature):
            return True
        req = _FEATURE_REQUIREMENTS.get(feature, {})
        reason = req.get("reason", feature)
        _log.warning(
            "Feature %s disabled — requires %s for %s. "
            "Re-run elevated (root/Administrator) or grant CAP_NET_RAW/CAP_NET_ADMIN%s.",
            feature,
            "root/Administrator" if req.get("root") else req.get("cap", "elevated privilege"),
            reason,
            "; on Windows install Npcap" if self._status and self._status.platform == "Windows" else "",
        )
        return False

    def print_status(self) -> None:
        """Print a Rich privilege status table to the console."""
        if self._status is None:
            self.check()
        s = self._status

        from rich.table import Table

        table = Table(title="Privilege Status", border_style="dim")
        table.add_column("Feature", style="cyan")
        table.add_column("Status", width=12)
        table.add_column("Requires")

        for feature, req in sorted(_FEATURE_REQUIREMENTS.items()):
            available = feature in s.available_features
            status = "[bold green]✓ enabled[/bold green]" if available else "[bold red]✗ disabled[/bold red]"
            cap = req.get("cap") or "none"
            root_str = "root" if req.get("root") else "—"
            table.add_row(feature, status, f"root={root_str}, cap={cap}")

        console.print(table)
        console.print(
            f"Running as root/admin: [{'bold green' if s.is_root else 'yellow'}]"
            f"{'yes' if s.is_root else 'no'}[/] · raw backend: "
            f"[{'bold green' if s.raw_backend != 'none' else 'yellow'}]{s.raw_backend}[/]"
        )
        if s.platform == "Windows" and not s.has_npcap:
            console.print(
                "[yellow]Npcap not detected — raw SYN/ARP/ICMP/FIN/UDP scans will "
                "fall back to connect-based scanning. Install Npcap for full capability.[/yellow]"
            )

    @staticmethod
    def _detect_root(plat: str) -> bool:
        if plat == "Windows":
            try:
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        return os.geteuid() == 0

    @staticmethod
    def _detect_cap(cap_name: str, plat: str, is_root: bool) -> bool:
        if plat != "Linux":
            return is_root
        try:
            import ctypes
            import ctypes.util

            lib = ctypes.util.find_library("cap")
            if not lib:
                return is_root

            libcap = ctypes.CDLL(lib)
            cap_map = {"cap_net_raw": 13, "cap_net_admin": 12}
            cap_value = cap_map.get(cap_name, -1)
            if cap_value < 0:
                return is_root

            CAP_EFFECTIVE = 0
            cap = libcap.cap_get_proc()
            if not cap:
                return is_root

            flag_value = ctypes.c_int(0)
            rc = libcap.cap_get_flag(cap, cap_value, CAP_EFFECTIVE, ctypes.byref(flag_value))
            libcap.cap_free(cap)
            if rc == 0:
                return flag_value.value == 1
        except Exception:
            pass
        return is_root

    @staticmethod
    def _detect_npcap(plat: str) -> bool:
        """Detect a raw-packet backend (Npcap/WinPcap) on Windows.

        Administrator rights alone do not grant raw-socket access on Windows;
        scapy needs Npcap (or legacy WinPcap). Checked by locating wpcap.dll,
        then as a fallback by attempting to load it.
        """
        if plat != "Windows":
            return False
        root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or ""
        if root:
            candidates = [
                os.path.join(root, "System32", "Npcap", "wpcap.dll"),
                os.path.join(root, "SysWOW64", "Npcap", "wpcap.dll"),
                os.path.join(root, "System32", "wpcap.dll"),
            ]
            if any(os.path.exists(c) for c in candidates):
                return True
        try:
            import ctypes
            ctypes.WinDLL("wpcap.dll")
            return True
        except Exception:
            return False
