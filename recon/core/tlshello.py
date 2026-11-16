"""
recon.core.tlshello — minimal, fail-safe raw TLS ClientHello / ServerHello.

Python's stdlib ``ssl`` completes the handshake internally and never exposes the
ServerHello's selected cipher number or extension list, so a real JA3S cannot be
computed from it (the old tls_probe "JA3S" hashed Python's per-process-random
``hash()`` and changed every run). This module sends one standard ClientHello
over a plain socket and parses the ServerHello itself to produce a real,
deterministic JA3S (MD5 of "version,cipher,extensions").

Everything here is best-effort: any socket/parse error yields an empty result,
never an exception.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import struct

__all__ = ["build_client_hello", "parse_server_hello", "ja3s_string", "server_fingerprint"]

# A fixed, realistic TLS 1.2 cipher offering (order matters for JA3S determinism).
_CIPHERS = [
    0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
    0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
]
_GROUPS = [0x001d, 0x0017, 0x0018]  # x25519, secp256r1, secp384r1
_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
_VERSIONS = [0x0303, 0x0302, 0x0301]  # TLS 1.2 / 1.1 / 1.0 (no 1.3: avoids key_share)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _ext(etype: int, data: bytes) -> bytes:
    return struct.pack(">HH", etype, len(data)) + data


def build_client_hello(server_name: str = "") -> bytes:
    """Build a standard TLS 1.2 ClientHello record (bytes)."""
    cipher_bytes = b"".join(struct.pack(">H", c) for c in _CIPHERS)

    exts = b""
    if server_name and not _is_ip(server_name):
        try:
            host = server_name.encode("idna")
        except Exception:
            host = server_name.encode("ascii", "ignore")
        server_list = b"\x00" + struct.pack(">H", len(host)) + host
        exts += _ext(0x0000, struct.pack(">H", len(server_list)) + server_list)

    gb = b"".join(struct.pack(">H", g) for g in _GROUPS)
    exts += _ext(0x000a, struct.pack(">H", len(gb)) + gb)
    exts += _ext(0x000b, b"\x01\x00")  # ec_point_formats: uncompressed
    sb = b"".join(struct.pack(">H", s) for s in _SIGALGS)
    exts += _ext(0x000d, struct.pack(">H", len(sb)) + sb)
    vb = b"".join(struct.pack(">H", v) for v in _VERSIONS)
    exts += _ext(0x002b, struct.pack(">B", len(vb)) + vb)  # supported_versions
    exts += _ext(0xff01, b"\x00")  # renegotiation_info (empty)
    alpn = b"\x08http/1.1\x02h2"
    exts += _ext(0x0010, struct.pack(">H", len(alpn)) + alpn)  # ALPN

    body = b"\x03\x03" + os.urandom(32) + b"\x00"            # version + random + no session id
    body += struct.pack(">H", len(cipher_bytes)) + cipher_bytes
    body += b"\x01\x00"                                       # compression: null
    body += struct.pack(">H", len(exts)) + exts
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body   # type 1 + 3-byte len
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def parse_server_hello(data: bytes) -> dict:
    """Parse a ServerHello from raw TLS record bytes. Returns {} if not found."""
    try:
        hs = b""
        i = 0
        while i + 5 <= len(data):
            ctype = data[i]
            rlen = struct.unpack(">H", data[i + 3:i + 5])[0]
            payload = data[i + 5:i + 5 + rlen]
            if ctype == 0x16:          # handshake
                hs += payload
            elif ctype == 0x15:        # alert -> handshake failed
                return {}
            i += 5 + rlen
            if len(payload) < rlen:
                break

        if len(hs) < 4 or hs[0] != 0x02:   # 0x02 = ServerHello
            return {}
        body_len = int.from_bytes(hs[1:4], "big")
        b = hs[4:4 + body_len]
        if len(b) < 38:
            return {}
        version = struct.unpack(">H", b[0:2])[0]
        p = 2 + 32                         # skip random
        sid_len = b[p]
        p += 1 + sid_len
        cipher = struct.unpack(">H", b[p:p + 2])[0]
        p += 2
        p += 1                             # compression method
        exts: list[int] = []
        negotiated = version
        if p + 2 <= len(b):
            ext_total = struct.unpack(">H", b[p:p + 2])[0]
            p += 2
            end = min(p + ext_total, len(b))
            while p + 4 <= end:
                etype = struct.unpack(">H", b[p:p + 2])[0]
                elen = struct.unpack(">H", b[p + 2:p + 4])[0]
                edata = b[p + 4:p + 4 + elen]
                exts.append(etype)
                if etype == 0x002b and len(edata) >= 2:   # supported_versions => real ver (TLS1.3)
                    negotiated = struct.unpack(">H", edata[0:2])[0]
                p += 4 + elen
        return {"version": version, "negotiated_version": negotiated,
                "cipher": cipher, "extensions": exts}
    except Exception:
        return {}


def ja3s_string(parsed: dict) -> str:
    exts = "-".join(str(e) for e in parsed.get("extensions", []))
    return f"{parsed.get('version', 0)},{parsed.get('cipher', 0)},{exts}"


def server_fingerprint(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Connect, send a ClientHello, parse the ServerHello, and return
    {ja3s, ja3s_string, tls_version, cipher, extensions}. {} on any failure."""
    try:
        hello = build_client_hello(host)
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(hello)
            buf = b""
            while len(buf) < 16384:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
                if parse_server_hello(buf):
                    break
        parsed = parse_server_hello(buf)
        if not parsed:
            return {}
        js = ja3s_string(parsed)
        return {
            "ja3s": hashlib.md5(js.encode()).hexdigest(),
            "ja3s_string": js,
            "tls_version": parsed["negotiated_version"],
            "cipher": parsed["cipher"],
            "extensions": parsed["extensions"],
        }
    except Exception:
        return {}
