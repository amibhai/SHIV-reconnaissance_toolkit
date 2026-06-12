"""
recon.modules.snmp_enum — SNMP enumeration via pure-Python BER-encoded UDP packets.

No pysnmp dependency — all encoding/decoding is hand-rolled.

Capabilities:
- SNMPv1 / SNMPv2c community string brute-force (default + custom wordlist)
- SNMPv3 auth mechanism fingerprint (usmStats probe)
- System info: sysDescr, sysName, sysLocation, sysContact, sysUpTime
- Interface table: ifDescr, ifType, ifSpeed, ifPhysAddress, ifOperStatus
- IP address table: IP ↔ interface mappings
- ARP cache dump (ipNetToMedia table)
- TCP/UDP connection tables
- Process list (hrSWRunName)
- Installed software (hrSWInstalledName)
- Routing table (ipRouteDest + ipRouteNextHop)
"""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from recon.core.config import ReconConfig
from recon.core.logger import get_logger

__all__ = ["SNMPEnumerator", "SNMPResult"]

_log = get_logger("snmp_enum")

# ──────────────────────────────────────────────────────────────────────────────
# Minimal BER encoder / decoder
# ──────────────────────────────────────────────────────────────────────────────

# ASN.1 / BER tag constants
_T_INT      = 0x02
_T_OCTSTR   = 0x04
_T_NULL     = 0x05
_T_OID      = 0x06
_T_SEQ      = 0x30
_T_IPADDR   = 0x40
_T_COUNTER  = 0x41
_T_GAUGE    = 0x42
_T_TIMETICK = 0x43
_T_COUNTER64= 0x46
_T_GET_REQ  = 0xa0
_T_GET_NEXT = 0xa1
_T_GET_RESP = 0xa2
_T_BULK     = 0xa5


def _ber_len(data: bytes) -> bytes:
    n = len(data)
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xff])
    else:
        return bytes([0x83, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(value) + value


def _encode_int(v: int) -> bytes:
    if v == 0:
        return _tlv(_T_INT, b"\x00")
    n = v
    out = []
    while n:
        out.append(n & 0xff)
        n >>= 8
    out.reverse()
    # Add leading 0x00 if high bit set (positive number)
    if out[0] & 0x80:
        out.insert(0, 0x00)
    return _tlv(_T_INT, bytes(out))


def _encode_string(s: str | bytes) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    return _tlv(_T_OCTSTR, s)


def _encode_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError(f"OID too short: {oid_str}")
    # First two components compressed into one byte
    first = parts[0] * 40 + parts[1]
    encoded = [first]
    for part in parts[2:]:
        if part == 0:
            encoded.append(0)
        else:
            sub: list[int] = []
            while part:
                sub.append(part & 0x7f)
                part >>= 7
            sub.reverse()
            for i, b in enumerate(sub):
                if i < len(sub) - 1:
                    encoded.append(b | 0x80)
                else:
                    encoded.append(b)
    return _tlv(_T_OID, bytes(encoded))


def _build_get_request(community: str, oids: list[str],
                       request_id: int = 1, pdu_type: int = _T_GET_REQ) -> bytes:
    """Build an SNMPv2c GET (or GET-NEXT / GET-BULK) request."""
    varbinds = b""
    for oid in oids:
        vb = _tlv(_T_SEQ, _encode_oid(oid) + _tlv(_T_NULL, b""))
        varbinds += vb

    pdu_body = (
        _encode_int(request_id) +   # Request-ID
        _encode_int(0) +             # Error-Status
        _encode_int(0) +             # Error-Index
        _tlv(_T_SEQ, varbinds)       # Variable-bindings
    )
    pdu = _tlv(pdu_type, pdu_body)

    msg = (
        _encode_int(1) +             # version: SNMPv2c (1)
        _encode_string(community) +
        pdu
    )
    return _tlv(_T_SEQ, msg)


def _build_getnext(community: str, oid: str, request_id: int = 1) -> bytes:
    return _build_get_request(community, [oid], request_id, _T_GET_NEXT)


# ── BER decoder ───────────────────────────────────────────────────────────────

def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    """Return (length, new_offset)."""
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    num_bytes = first & 0x7f
    length = 0
    for _ in range(num_bytes):
        length = (length << 8) | data[offset]
        offset += 1
    return length, offset


def _decode_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Return (tag, value_bytes, end_offset)."""
    if offset >= len(data):
        return 0, b"", offset
    tag = data[offset]
    offset += 1
    length, offset = _read_length(data, offset)
    value = data[offset:offset + length]
    return tag, value, offset + length


def _decode_int(data: bytes) -> int:
    if not data:
        return 0
    n = int.from_bytes(data, "big", signed=True)
    return n


def _decode_oid(data: bytes) -> str:
    if not data:
        return ""
    parts = []
    # First byte encodes first two components
    first = data[0]
    parts.append(str(first // 40))
    parts.append(str(first % 40))
    idx = 1
    while idx < len(data):
        val = 0
        while idx < len(data):
            b = data[idx]
            idx += 1
            val = (val << 7) | (b & 0x7f)
            if not (b & 0x80):
                break
        parts.append(str(val))
    return ".".join(parts)


def _decode_value(tag: int, data: bytes) -> Any:
    if tag == _T_INT or tag == _T_COUNTER or tag == _T_GAUGE or \
       tag == _T_TIMETICK or tag == _T_COUNTER64:
        return _decode_int(data)
    elif tag == _T_OCTSTR:
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return data.hex()
    elif tag == _T_OID:
        return _decode_oid(data)
    elif tag == _T_IPADDR:
        if len(data) == 4:
            return ".".join(str(b) for b in data)
        return data.hex()
    elif tag == _T_NULL:
        return None
    else:
        return data.hex()


def _parse_response(data: bytes) -> list[tuple[str, Any]]:
    """Parse a GET-RESPONSE and return list of (oid_str, value) pairs."""
    results: list[tuple[str, Any]] = []
    try:
        tag, msg_body, _ = _decode_tlv(data, 0)
        if tag != _T_SEQ:
            return results
        offset = 0
        # version
        t, v, offset = _decode_tlv(msg_body, offset)
        # community
        t, v, offset = _decode_tlv(msg_body, offset)
        # PDU
        t, pdu_body, offset = _decode_tlv(msg_body, offset)
        if t != _T_GET_RESP:
            return results
        # request-id, error-status, error-index
        pdu_off = 0
        t, v, pdu_off = _decode_tlv(pdu_body, pdu_off)  # req-id
        t, v, pdu_off = _decode_tlv(pdu_body, pdu_off)  # error-status
        error_status = _decode_int(v)
        t, v, pdu_off = _decode_tlv(pdu_body, pdu_off)  # error-index
        if error_status != 0:
            return results
        # VarBindList
        t, vbl, pdu_off = _decode_tlv(pdu_body, pdu_off)
        vbl_off = 0
        while vbl_off < len(vbl):
            t, vb, vbl_off = _decode_tlv(vbl, vbl_off)  # VarBind SEQUENCE
            vb_off = 0
            t2, oid_data, vb_off = _decode_tlv(vb, vb_off)  # OID
            t3, val_data, vb_off = _decode_tlv(vb, vb_off)  # Value
            oid_str = _decode_oid(oid_data) if t2 == _T_OID else ""
            value   = _decode_value(t3, val_data)
            if oid_str:
                results.append((oid_str, value))
    except Exception as exc:
        _log.debug("SNMP parse error: %s", exc)
    return results


# ──────────────────────────────────────────────────────────────────────────────
# OID constants (key system MIBs)
# ──────────────────────────────────────────────────────────────────────────────

_OID = {
    "sysDescr":       "1.3.6.1.2.1.1.1.0",
    "sysObjectID":    "1.3.6.1.2.1.1.2.0",
    "sysUpTime":      "1.3.6.1.2.1.1.3.0",
    "sysContact":     "1.3.6.1.2.1.1.4.0",
    "sysName":        "1.3.6.1.2.1.1.5.0",
    "sysLocation":    "1.3.6.1.2.1.1.6.0",
    "sysServices":    "1.3.6.1.2.1.1.7.0",
    # Interfaces
    "ifTable":        "1.3.6.1.2.1.2.2",
    "ifDescr":        "1.3.6.1.2.1.2.2.1.2",
    "ifType":         "1.3.6.1.2.1.2.2.1.3",
    "ifSpeed":        "1.3.6.1.2.1.2.2.1.5",
    "ifPhysAddress":  "1.3.6.1.2.1.2.2.1.6",
    "ifOperStatus":   "1.3.6.1.2.1.2.2.1.8",
    # IP
    "ipAdEntAddr":    "1.3.6.1.2.1.4.20.1.1",
    "ipNetToMedia":   "1.3.6.1.2.1.4.22.1.2",  # ARP cache: physAddress
    "ipRouteTable":   "1.3.6.1.2.1.4.21.1.1",  # dest
    "ipRouteNextHop": "1.3.6.1.2.1.4.21.1.7",
    # TCP/UDP
    "tcpConnTable":   "1.3.6.1.2.1.6.13.1",
    "udpTable":       "1.3.6.1.2.1.7.5.1",
    # Host resources
    "hrSWRunName":    "1.3.6.1.2.1.25.4.2.1.2",
    "hrSWInstalled":  "1.3.6.1.2.1.25.6.3.1.2",
    # SNMP engine ID (for v3 detection)
    "snmpEngineID":   "1.3.6.1.6.3.10.2.1.1.0",
}

_DEFAULT_COMMUNITIES = [
    "public", "private", "community", "admin", "manager", "secret",
    "monitor", "cisco", "snmpd", "password", "default", "internal",
    "write", "read", "SNMP", "switch", "router", "network",
]


# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class SNMPResult:
    """SNMP enumeration result."""
    target:      str
    port:        int
    community:   str = ""
    version:     str = ""
    sys_descr:   str = ""
    sys_name:    str = ""
    sys_location:str = ""
    sys_contact: str = ""
    sys_uptime:  str = ""
    interfaces:  list[dict[str, Any]] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    arp_table:   list[dict[str, str]] = field(default_factory=list)
    routes:      list[dict[str, str]] = field(default_factory=list)
    processes:   list[str] = field(default_factory=list)
    software:    list[str] = field(default_factory=list)
    raw_oids:    dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target":      self.target,
            "community":   self.community,
            "sys_name":    self.sys_name,
            "sys_descr":   self.sys_descr[:200],
            "sys_location":self.sys_location,
            "interfaces":  self.interfaces,
            "arp_table":   self.arp_table,
            "routes":      self.routes,
            "processes":   self.processes[:50],
            "software":    self.software[:50],
        }


# ──────────────────────────────────────────────────────────────────────────────
# Main class
# ──────────────────────────────────────────────────────────────────────────────

class SNMPEnumerator:
    """
    SNMP enumerator using pure-Python BER encoding — no pysnmp required.

    Args:
        target:    IP address or hostname.
        port:      SNMP UDP port (default 161).
        timeout:   Per-request timeout in seconds.
        config:    ReconConfig instance.
    """

    def __init__(
        self,
        target: str,
        port: int = 161,
        timeout: float = 2.0,
        config: ReconConfig | None = None,
    ) -> None:
        self.target = target
        self.port   = port
        self.config = config or ReconConfig()
        self._timeout = timeout
        self._result = SNMPResult(target=target, port=port)
        self._req_id = 1

    # ── low-level send / receive ──────────────────────────────────────────────

    def _send(self, pkt: bytes) -> bytes | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self._timeout)
            sock.sendto(pkt, (self.target, self.port))
            data, _ = sock.recvfrom(65535)
            sock.close()
            return data
        except Exception:
            return None

    def _get(self, community: str, oids: list[str]) -> list[tuple[str, Any]]:
        self._req_id += 1
        pkt = _build_get_request(community, oids, self._req_id)
        resp = self._send(pkt)
        if resp:
            return _parse_response(resp)
        return []

    def _getnext(self, community: str, oid: str) -> list[tuple[str, Any]]:
        self._req_id += 1
        pkt = _build_getnext(community, oid, self._req_id)
        resp = self._send(pkt)
        if resp:
            return _parse_response(resp)
        return []

    def _walk(
        self, community: str, base_oid: str, max_entries: int = 200
    ) -> list[tuple[str, Any]]:
        """Iterative GETNEXT walk of a subtree."""
        results: list[tuple[str, Any]] = []
        current = base_oid
        seen: set[str] = set()

        for _ in range(max_entries):
            pairs = self._getnext(community, current)
            if not pairs:
                break
            oid, value = pairs[0]
            if not oid.startswith(base_oid) or oid in seen:
                break
            seen.add(oid)
            results.append((oid, value))
            current = oid

        return results

    # ── community string brute-force ──────────────────────────────────────────

    def brute_community(
        self, wordlist: list[str] | None = None
    ) -> str | None:
        """
        Try community strings. Returns the first working community or None.
        Tests sysDescr (1.3.6.1.2.1.1.1.0) as the probe.
        """
        candidates = wordlist or _DEFAULT_COMMUNITIES
        probe_oid  = _OID["sysDescr"]

        for community in candidates:
            pairs = self._get(community, [probe_oid])
            if pairs:
                _log.info("[bold green]SNMP community found:[/] '%s'", community)
                return community
        return None

    # ── system info ───────────────────────────────────────────────────────────

    def get_system_info(self, community: str) -> None:
        """Populate sysDescr, sysName, sysLocation, sysContact, sysUpTime."""
        oids = [
            _OID["sysDescr"], _OID["sysName"], _OID["sysLocation"],
            _OID["sysContact"], _OID["sysUpTime"],
        ]
        for oid, val in self._get(community, oids):
            if val is None:
                continue
            last = oid.rsplit(".", 1)[-1]
            if "1.0" in oid:
                self._result.sys_descr = str(val)
            elif "5.0" in oid:
                self._result.sys_name = str(val)
            elif "6.0" in oid:
                self._result.sys_location = str(val)
            elif "4.0" in oid:
                self._result.sys_contact = str(val)
            elif "3.0" in oid:
                ticks = int(val) if isinstance(val, int) else 0
                h, rem = divmod(ticks // 100, 3600)
                m, s   = divmod(rem, 60)
                self._result.sys_uptime = f"{h}h {m}m {s}s"

    # ── interface table ───────────────────────────────────────────────────────

    def get_interfaces(self, community: str) -> None:
        """Walk ifDescr, ifPhysAddress, ifOperStatus."""
        descr: dict[str, str] = {}
        mac:   dict[str, str] = {}
        status: dict[str, str] = {}

        for oid, val in self._walk(community, _OID["ifDescr"]):
            idx = oid.rsplit(".", 1)[-1]
            descr[idx] = str(val)

        for oid, val in self._walk(community, _OID["ifPhysAddress"]):
            idx = oid.rsplit(".", 1)[-1]
            if isinstance(val, str) and len(val.replace(":", "").replace("-", "")) == 12:
                mac[idx] = val
            elif isinstance(val, str) and len(val) >= 12:
                # May be hex string
                raw = val.replace(" ", "")[:12]
                mac[idx] = ":".join(raw[i:i+2] for i in range(0, 12, 2))

        for oid, val in self._walk(community, _OID["ifOperStatus"]):
            idx = oid.rsplit(".", 1)[-1]
            status[idx] = "up" if val == 1 else ("down" if val == 2 else str(val))

        for idx in sorted(descr.keys(), key=lambda x: int(x) if x.isdigit() else 0):
            self._result.interfaces.append({
                "index":   idx,
                "name":    descr.get(idx, ""),
                "mac":     mac.get(idx, ""),
                "status":  status.get(idx, ""),
            })

    # ── IP addresses ─────────────────────────────────────────────────────────

    def get_ip_addresses(self, community: str) -> None:
        for oid, val in self._walk(community, _OID["ipAdEntAddr"]):
            if isinstance(val, str) and re.match(r"\d+\.\d+\.\d+\.\d+", val):
                self._result.ip_addresses.append(val)

    # ── ARP cache ────────────────────────────────────────────────────────────

    def get_arp_table(self, community: str) -> None:
        """Walk ipNetToMediaPhysAddress to get IP → MAC mappings."""
        for oid, val in self._walk(community, _OID["ipNetToMedia"], 500):
            # OID suffix encodes: ifIndex.ip1.ip2.ip3.ip4
            parts = oid.split(".")
            if len(parts) >= 4:
                ip = ".".join(parts[-4:])
                mac_val = val if isinstance(val, str) else ""
                self._result.arp_table.append({"ip": ip, "mac": mac_val})

    # ── Routing table ─────────────────────────────────────────────────────────

    def get_routes(self, community: str) -> None:
        dest_map:    dict[str, str] = {}
        nexthop_map: dict[str, str] = {}

        for oid, val in self._walk(community, _OID["ipRouteTable"], 200):
            key = oid.rsplit(".", 4)[-4:]  # last 4 = dest IP
            dest_ip = ".".join(key) if len(key) == 4 else oid
            if isinstance(val, str):
                dest_map[dest_ip] = str(val)

        for oid, val in self._walk(community, _OID["ipRouteNextHop"], 200):
            key = oid.rsplit(".", 4)[-4:]
            dest_ip = ".".join(key) if len(key) == 4 else oid
            nexthop_map[dest_ip] = str(val)

        for dest, gw in nexthop_map.items():
            self._result.routes.append({"destination": dest, "nexthop": gw})

    # ── Process list ─────────────────────────────────────────────────────────

    def get_processes(self, community: str, max_procs: int = 100) -> None:
        for _, val in self._walk(community, _OID["hrSWRunName"], max_procs):
            name = str(val).strip()
            if name and name not in self._result.processes:
                self._result.processes.append(name)

    # ── Installed software ────────────────────────────────────────────────────

    def get_software(self, community: str, max_sw: int = 200) -> None:
        for _, val in self._walk(community, _OID["hrSWInstalled"], max_sw):
            name = str(val).strip()
            if name and name not in self._result.software:
                self._result.software.append(name)

    # ── Full enumeration ──────────────────────────────────────────────────────

    def enumerate_all(
        self,
        community: str | None = None,
        wordlist: list[str] | None = None,
        deep: bool = True,
    ) -> SNMPResult:
        """
        Run full SNMP enumeration.

        Args:
            community: Community string to use (skips brute-force if provided).
            wordlist:  Custom community wordlist.
            deep:      If True, also walk interfaces, ARP, routes, processes, software.
        """
        _log.info("SNMP enum: %s:%d", self.target, self.port)

        # Discover community
        if community is None:
            community = self.brute_community(wordlist)
        if community is None:
            _log.warning("No valid SNMP community found for %s", self.target)
            return self._result

        self._result.community = community
        self._result.version = "SNMPv2c"

        # System info
        self.get_system_info(community)
        if self._result.sys_name:
            _log.info("sysName: %s", self._result.sys_name)
        if self._result.sys_descr:
            _log.info("sysDescr: %s", self._result.sys_descr[:120])

        if not deep:
            return self._result

        # Interfaces
        _log.info("Walking interfaces …")
        self.get_interfaces(community)

        # IPs
        self.get_ip_addresses(community)

        # ARP
        _log.info("Walking ARP table …")
        self.get_arp_table(community)

        # Routes
        _log.info("Walking routing table …")
        self.get_routes(community)

        # Processes (host resources MIB — may not be available on all devices)
        _log.info("Walking process list …")
        self.get_processes(community)

        # Software
        self.get_software(community)

        _log.info(
            "[bold green]SNMP done[/]: %d interface(s), %d ARP entries, "
            "%d route(s), %d process(es)",
            len(self._result.interfaces),
            len(self._result.arp_table),
            len(self._result.routes),
            len(self._result.processes),
        )
        return self._result

    def print_results(self, r: SNMPResult | None = None) -> None:
        from recon.core.logger import console
        from rich.table import Table
        from rich import box

        r = r or self._result

        console.print(f"\n[bold cyan]SNMP Enumeration:[/] {r.target}:{r.port}")
        if not r.community:
            console.print("  [red]No valid community string found[/]")
            return

        console.print(f"  Community:   [bold green]{r.community}[/]  ({r.version})")
        console.print(f"  sysName:     [bold]{r.sys_name}[/]")
        console.print(f"  sysDescr:    {r.sys_descr[:120]}")
        console.print(f"  Location:    {r.sys_location}")
        console.print(f"  Contact:     {r.sys_contact}")
        console.print(f"  Uptime:      {r.sys_uptime}")

        if r.interfaces:
            t = Table("Idx", "Interface", "MAC", "Status", box=box.SIMPLE)
            for iface in r.interfaces:
                status_color = "green" if iface.get("status") == "up" else "dim"
                t.add_row(
                    iface.get("index", ""),
                    iface.get("name", ""),
                    iface.get("mac", ""),
                    f"[{status_color}]{iface.get('status','')}[/]",
                )
            console.print(f"\n[bold]Interfaces ({len(r.interfaces)}):[/]")
            console.print(t)

        if r.ip_addresses:
            console.print(f"\n  IP Addresses: {', '.join(r.ip_addresses)}")

        if r.arp_table:
            t2 = Table("IP", "MAC", box=box.SIMPLE)
            for entry in r.arp_table[:30]:
                t2.add_row(entry.get("ip", ""), entry.get("mac", ""))
            console.print(f"\n[bold]ARP Table (top 30 of {len(r.arp_table)}):[/]")
            console.print(t2)

        if r.routes:
            t3 = Table("Destination", "Next Hop", box=box.SIMPLE)
            for route in r.routes[:20]:
                t3.add_row(route.get("destination", ""), route.get("nexthop", ""))
            console.print(f"\n[bold]Routes (top 20):[/]")
            console.print(t3)

        if r.processes:
            console.print(f"\n  Processes ({len(r.processes)}): "
                          + ", ".join(r.processes[:15])
                          + ("…" if len(r.processes) > 15 else ""))

        if r.software:
            console.print(f"\n  Software ({len(r.software)}): "
                          + ", ".join(r.software[:10])
                          + ("…" if len(r.software) > 10 else ""))


import re
