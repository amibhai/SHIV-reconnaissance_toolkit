"""
recon.core.netutil — small, fail-safe address helpers (IPv4 + IPv6).

Centralises target resolution so modules support IPv6 without each reinventing
``socket.gethostbyname`` (which is IPv4-only and raised on v6 literals).
"""

from __future__ import annotations

import ipaddress
import socket

__all__ = ["resolve_target", "is_ipv6"]


def is_ipv6(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).version == 6
    except ValueError:
        return False


def resolve_target(target: str) -> tuple[str, bool]:
    """Resolve ``target`` to (ip_string, is_ipv6).

    A literal IP is returned as-is. A hostname is resolved via getaddrinfo,
    preferring IPv4 (for compatibility with the raw-socket paths) and falling
    back to IPv6. On failure the original string is returned with is_ipv6=False,
    so callers that pass to ``socket.create_connection`` still work.
    """
    try:
        ip = ipaddress.ip_address(target)
        return target, ip.version == 6
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None)
    except (socket.gaierror, UnicodeError, OSError):
        return target, False
    v4 = [i for i in infos if i[0] == socket.AF_INET]
    if v4:
        return v4[0][4][0], False
    v6 = [i for i in infos if i[0] == socket.AF_INET6]
    if v6:
        return v6[0][4][0], True
    return target, False
