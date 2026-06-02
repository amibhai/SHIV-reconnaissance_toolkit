"""
recon.core.privilege — Privilege and capability checker.

Checks for root/Administrator privileges and Linux capabilities
(CAP_NET_RAW, CAP_NET_ADMIN) required for raw-socket operations.
Gracefully degrades features rather than crashing.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from typing import Callable

from recon.core.logger import console, get_logger

__all__ = ["PrivilegeChecker", "require_privilege"]

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
    cap_net_raw: bool
    cap_net_admin: bool
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
        """
        Run privilege detection and return a CapabilityStatus.

        Returns:
            CapabilityStatus with available/disabled feature sets.
        """
        plat = platform.system()
        is_root = self._detect_root(plat)
        cap_raw = self._detect_cap("cap_net_raw", plat, is_root)
        cap_admin = self._detect_cap("cap_net_admin", plat, is_root)

        available: set[str] = set()
        disabled: set[str] = set()

        for feature, req in _FEATURE_REQUIREMENTS.items():
            needs_root = req["root"]
            needs_cap = req["cap"]

            has_priv = (
                (not needs_root)
                or is_root
                or (needs_cap == "CAP_NET_RAW" and cap_raw)
                or (needs_cap == "CAP_NET_ADMIN" and cap_admin)
            )
            if has_priv:
                available.add(feature)
            else:
                disabled.add(feature)

        self._status = CapabilityStatus(
            is_root=is_root,
            platform=plat,
            cap_net_raw=cap_raw,
            cap_net_admin=cap_admin,
            available_features=available,
            disabled_features=disabled,
        )
        return self._status

    def can(self, feature: str) -> bool:
        """
        Check if a specific feature is available given current privileges.

        Args:
            feature: Feature name from the requirements map.

        Returns:
            True if the feature is available.
        """
        if self._status is None:
            self.check()
        return feature in self._status.available_features  # type: ignore[union-attr]

    def warn_if_missing(self, feature: str) -> bool:
        """
        Check feature availability and emit a warning if missing.

        Args:
            feature: Feature name.

        Returns:
            True if available, False with a warning logged if not.
        """
        if self.can(feature):
            return True
        req = _FEATURE_REQUIREMENTS.get(feature, {})
        reason = req.get("reason", feature)
        _log.warning(
            "Feature [bold]%s[/bold] disabled — requires %s for %s. "
            "Re-run as root or grant CAP_NET_RAW/CAP_NET_ADMIN.",
            feature,
            "root/Administrator" if req.get("root") else req.get("cap", "elevated privilege"),
            reason,
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
            f"Running as root: [{'bold green' if s.is_root else 'yellow'}]"
            f"{'yes' if s.is_root else 'no'}[/{'bold green' if s.is_root else 'yellow'}]"
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


def require_privilege(feature: str) -> Callable:
    """
    Decorator that checks privilege before calling a function.

    Args:
        feature: Feature name to check.

    Returns:
        Decorator function.

    Raises:
        PermissionError: If the feature is not available.
    """
    checker = PrivilegeChecker()

    def decorator(fn: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            if not checker.warn_if_missing(feature):
                raise PermissionError(
                    f"Feature '{feature}' requires elevated privileges. "
                    "Run as root or grant CAP_NET_RAW/CAP_NET_ADMIN."
                )
            return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper
    return decorator
