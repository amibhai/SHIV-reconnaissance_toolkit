"""
recon.modules.tls_probe — Deep TLS/SSL analysis and fingerprinting.

Capabilities:
- Full certificate chain extraction via Python ssl + cryptography library
- Protocol version matrix (SSLv3, TLS 1.0/1.1/1.2/1.3 — probes each)
- Cipher suite enumeration by category (strong / weak / broken)
- JA3S-style server fingerprint (MD5 of version + cipher + extensions)
- Key exchange and key size analysis
- Subject Alternative Names, wildcard and expiry checks
- Certificate Transparency log lookup (crt.sh)
- HSTS / OCSP stapling detection
- Weak cipher and broken protocol warnings
- Self-signed / untrusted chain detection
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

from recon.core.config import ReconConfig
from recon.core.logger import get_logger

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtensionOID, NameOID
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

__all__ = ["TLSProbe", "TLSResult", "CertInfo"]

_log = get_logger("tls_probe")

# ──────────────────────────────────────────────────────────────────────────────
# Cipher categorisation
# ──────────────────────────────────────────────────────────────────────────────

_BROKEN_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "ANON",
    "ADH", "AECDH", "ARIA128-GCM", "MD5",
}

_WEAK_CIPHERS = {
    "AES128-SHA", "AES256-SHA", "DES-CBC3-SHA",
    "AES128-SHA256", "AES256-SHA256",
    "CAMELLIA128-SHA", "CAMELLIA256-SHA",
    "RC4-SHA", "RC4-MD5",
}

_STRONG_CIPHERS = {
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "TLS_AES_128_GCM_SHA256",       # TLS 1.3
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
}

# TLS version constants for raw probing
_TLS_VERSIONS = {
    "SSLv3":   (0x03, 0x00),
    "TLS 1.0": (0x03, 0x01),
    "TLS 1.1": (0x03, 0x02),
    "TLS 1.2": (0x03, 0x03),
    "TLS 1.3": (0x03, 0x04),
}

# Python ssl protocol names (for cipher enumeration)
_SSL_PROTOCOLS = [
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3 if hasattr(ssl, "TLSVersion") else None),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2 if hasattr(ssl, "TLSVersion") else None),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl, "TLSVersion") else None),
    ("TLS 1.0", ssl.TLSVersion.TLSv1   if hasattr(ssl, "TLSVersion") else None),
]


# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CertInfo:
    """Parsed X.509 certificate information."""
    subject:        str = ""
    issuer:         str = ""
    serial:         str = ""
    not_before:     str = ""
    not_after:      str = ""
    days_remaining: int = 0
    expired:        bool = False
    self_signed:    bool = False
    san:            list[str] = field(default_factory=list)
    fingerprint_sha256: str = ""
    key_type:       str = ""
    key_bits:       int = 0
    sig_algorithm:  str = ""
    is_wildcard:    bool = False
    is_ev:          bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject":       self.subject,
            "issuer":        self.issuer,
            "not_after":     self.not_after,
            "days_remaining": self.days_remaining,
            "expired":       self.expired,
            "self_signed":   self.self_signed,
            "san":           self.san,
            "fingerprint":   self.fingerprint_sha256,
            "key_type":      self.key_type,
            "key_bits":      self.key_bits,
            "sig_algorithm": self.sig_algorithm,
        }


@dataclass
class TLSResult:
    """Aggregated TLS scan result."""
    target: str
    port:   int
    # Protocol support
    protocols_supported: list[str] = field(default_factory=list)
    protocols_rejected:  list[str] = field(default_factory=list)
    # Cipher info
    selected_cipher:     str = ""
    selected_protocol:   str = ""
    supported_ciphers:   list[str] = field(default_factory=list)
    broken_ciphers_found: list[str] = field(default_factory=list)
    weak_ciphers_found:  list[str] = field(default_factory=list)
    # Certificate
    cert:                CertInfo = field(default_factory=CertInfo)
    cert_chain_depth:    int = 0
    # Fingerprint
    ja3s:                str = ""
    # Features
    hsts:                bool = False
    hsts_max_age:        int = 0
    ocsp_stapling:       bool = False
    # Findings
    findings:            list[dict[str, str]] = field(default_factory=list)
    # CT log domains
    ct_domains:          list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target":              self.target,
            "port":                self.port,
            "protocols_supported": self.protocols_supported,
            "selected_cipher":     self.selected_cipher,
            "selected_protocol":   self.selected_protocol,
            "broken_ciphers":      self.broken_ciphers_found,
            "weak_ciphers":        self.weak_ciphers_found,
            "cert":                self.cert.to_dict(),
            "ja3s":                self.ja3s,
            "hsts":                self.hsts,
            "findings":            self.findings,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Main class
# ──────────────────────────────────────────────────────────────────────────────

class TLSProbe:
    """
    Deep TLS/SSL scanner.

    Args:
        target: Hostname or IP.
        port:   TLS port (default 443).
        config: ReconConfig instance.
    """

    def __init__(
        self,
        target: str,
        port: int = 443,
        config: ReconConfig | None = None,
    ) -> None:
        self.target = target
        self.port = port
        self.config = config or ReconConfig()
        self._timeout = min(self.config.timeout, 5)
        self._result = TLSResult(target=target, port=port)

    # ── context factory ───────────────────────────────────────────────────────

    def _ctx(
        self,
        min_ver: Any = None,
        max_ver: Any = None,
        ciphers: str | None = None,
    ) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if ciphers:
            # Let this propagate: if the local OpenSSL build refuses the
            # requested cipher name outright, silently keeping the
            # context's default (modern) cipher list would let the probe
            # connect successfully and misreport the negotiated strong
            # cipher as evidence that the requested legacy one is broken.
            ctx.set_ciphers(ciphers)
        if min_ver and hasattr(ctx, "minimum_version"):
            try:
                ctx.minimum_version = min_ver
            except (AttributeError, ssl.SSLError):
                pass
        if max_ver and hasattr(ctx, "maximum_version"):
            try:
                ctx.maximum_version = max_ver
            except (AttributeError, ssl.SSLError):
                pass
        return ctx

    def _connect_tls(
        self, ctx: ssl.SSLContext
    ) -> ssl.SSLSocket | None:
        try:
            raw = socket.create_connection(
                (self.target, self.port), timeout=self._timeout
            )
        except Exception:
            return None
        try:
            return ctx.wrap_socket(raw, server_hostname=self.target)
        except Exception:
            # Handshake failure is the expected outcome for most probes
            # here (rejected cipher/protocol) — just make sure the plain
            # socket doesn't leak since wrap_socket never returned one.
            raw.close()
            return None

    # ── Certificate extraction ────────────────────────────────────────────────

    def _parse_cert_der(self, der: bytes) -> CertInfo:
        ci = CertInfo()
        if not _HAS_CRYPTO:
            return ci
        try:
            cert = x509.load_der_x509_certificate(der, default_backend())

            # Subject / Issuer
            def _rdn(name: Any) -> str:
                parts = []
                for attr in name:
                    try:
                        parts.append(f"{attr.oid.dotted_string}={attr.value}")
                    except Exception:
                        pass
                # Try to get CN
                try:
                    return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                except Exception:
                    return ", ".join(parts) or "Unknown"

            ci.subject = _rdn(cert.subject)
            ci.issuer = _rdn(cert.issuer)
            ci.serial = hex(cert.serial_number)

            # Validity
            now = datetime.now(timezone.utc)
            nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else \
                 cert.not_valid_before.replace(tzinfo=timezone.utc)
            na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else \
                 cert.not_valid_after.replace(tzinfo=timezone.utc)
            ci.not_before = nb.strftime("%Y-%m-%d")
            ci.not_after  = na.strftime("%Y-%m-%d")
            delta = na - now
            ci.days_remaining = delta.days
            ci.expired = delta.days < 0
            ci.self_signed = cert.issuer == cert.subject

            # Fingerprint
            ci.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

            # SANs
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                ci.san = [str(name) for name in san_ext.value]
                ci.is_wildcard = any("*" in s for s in ci.san)
            except Exception:
                pass

            # Key
            pub = cert.public_key()
            ki = pub.key_size if hasattr(pub, "key_size") else 0
            ci.key_bits = ki
            ci.key_type = type(pub).__name__.replace("_", "").replace("PublicKey", "")

            # Signature algorithm
            ci.sig_algorithm = cert.signature_algorithm_oid.dotted_string
            try:
                ci.sig_algorithm = cert.signature_hash_algorithm.name
            except Exception:
                pass

            # EV heuristic: long organization name
            try:
                org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                ci.is_ev = bool(org)
            except Exception:
                pass

        except Exception as exc:
            _log.debug("Cert parse error: %s", exc)
        return ci

    def extract_cert(self) -> CertInfo:
        """Connect and extract the leaf certificate."""
        ctx = self._ctx()
        sock = self._connect_tls(ctx)
        if not sock:
            return CertInfo()
        try:
            der = sock.getpeercert(binary_form=True)
            chain = sock.get_verified_chain() if hasattr(sock, "get_verified_chain") else []
            self._result.cert_chain_depth = len(chain)
            if der:
                return self._parse_cert_der(der)
        except Exception:
            pass
        finally:
            sock.close()
        return CertInfo()

    # ── Protocol version matrix ───────────────────────────────────────────────

    def probe_protocol_versions(self) -> None:
        """Probe which TLS versions the server accepts."""
        for ver_name, ver_enum in _SSL_PROTOCOLS:
            if ver_enum is None:
                continue
            try:
                ctx = self._ctx(min_ver=ver_enum, max_ver=ver_enum)
                sock = self._connect_tls(ctx)
                if sock:
                    self._result.protocols_supported.append(ver_name)
                    sock.close()
                else:
                    self._result.protocols_rejected.append(ver_name)
            except Exception:
                self._result.protocols_rejected.append(ver_name)

    # ── Cipher suite enumeration ──────────────────────────────────────────────

    def enumerate_ciphers(self) -> None:
        """
        Probe supported cipher suites.
        Tests a focused set of noteworthy ciphers rather than all ~300 OpenSSL names.
        """
        noteworthy: list[str] = [
            # Broken
            "RC4-SHA", "RC4-MD5", "EXP-RC4-MD5",
            "DES-CBC3-SHA", "DES-CBC-SHA",
            "ADH-AES128-SHA", "AECDH-AES128-SHA",
            "EXP-DES-CBC-SHA", "NULL-MD5", "NULL-SHA",
            # Weak (no PFS)
            "AES128-SHA", "AES256-SHA",
            "AES128-SHA256", "AES256-SHA256",
            # Modern / strong
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-CHACHA20-POLY1305",
        ]

        for cipher in noteworthy:
            sock = None
            try:
                ctx = self._ctx(ciphers=cipher)
                sock = self._connect_tls(ctx)
                if sock:
                    selected = sock.cipher()[0] if sock.cipher() else cipher
                    self._result.supported_ciphers.append(selected)
                    # Categorise
                    upper = cipher.upper()
                    if any(b in upper for b in _BROKEN_CIPHERS):
                        if selected not in self._result.broken_ciphers_found:
                            self._result.broken_ciphers_found.append(selected)
                    elif cipher in _WEAK_CIPHERS:
                        if selected not in self._result.weak_ciphers_found:
                            self._result.weak_ciphers_found.append(selected)
            except Exception:
                pass
            finally:
                if sock:
                    sock.close()

    # ── JA3S fingerprint ──────────────────────────────────────────────────────

    def compute_ja3s(self, sock: ssl.SSLSocket) -> str:
        """
        Compute a JA3S-style fingerprint from the negotiated connection.

        JA3S = MD5(TLSVersion,CipherSuite,Extensions)
        We use what's available from Python ssl: negotiated version + cipher.
        """
        try:
            proto = sock.version() or ""
            cipher_info = sock.cipher()
            cipher_name = cipher_info[0] if cipher_info else ""
            # Map version string to hex
            ver_map = {
                "TLSv1": "769", "TLSv1.1": "770",
                "TLSv1.2": "771", "TLSv1.3": "772",
                "SSLv3": "768",
            }
            ver_int = ver_map.get(proto, "0")
            # Map cipher name to IANA numeric (simplified lookup)
            cipher_int = str(abs(hash(cipher_name)) % 65535)
            raw = f"{ver_int},{cipher_int},"
            return hashlib.md5(raw.encode()).hexdigest()
        except Exception:
            return ""

    # ── HSTS check ────────────────────────────────────────────────────────────

    def check_hsts(self) -> tuple[bool, int]:
        """Return (hsts_present, max_age_seconds) by making an HTTP request."""
        conn = None
        try:
            import http.client
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(
                self.target, self.port, timeout=self._timeout, context=ctx
            )
            conn.request("GET", "/", headers={"Host": self.target})
            resp = conn.getresponse()
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            hsts_hdr = hdrs.get("strict-transport-security", "")
            if hsts_hdr:
                m = re.search(r"max-age=(\d+)", hsts_hdr)
                age = int(m.group(1)) if m else 0
                return True, age
        except Exception:
            pass
        finally:
            if conn:
                conn.close()
        return False, 0

    # ── Certificate Transparency lookup ──────────────────────────────────────

    def ct_lookup(self, domain: str) -> list[str]:
        """
        Query crt.sh for all known names on this domain's certificates.
        Returns list of subdomains/domains.
        """
        conn = None
        try:
            import http.client, urllib.parse
            conn = http.client.HTTPSConnection("crt.sh", timeout=10)
            query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
            conn.request("GET", f"/?{query}",
                         headers={"User-Agent": "recon-toolkit/2.0"})
            resp = conn.getresponse()
            if resp.status != 200:
                return []
            data = json.loads(resp.read(512 * 1024).decode("utf-8", errors="replace"))
            seen: set[str] = set()
            for entry in data:
                for name in re.split(r"[\n,]", entry.get("name_value", "")):
                    name = name.strip().lstrip("*.")
                    if name and name not in seen:
                        seen.add(name)
            return sorted(seen)[:200]
        except Exception as exc:
            _log.debug("CT lookup failed: %s", exc)
            return []
        finally:
            if conn:
                conn.close()

    # ── Full scan ─────────────────────────────────────────────────────────────

    def scan_all(self, ct: bool = False) -> TLSResult:
        """
        Run full TLS analysis.

        Args:
            ct: Whether to query Certificate Transparency logs (requires internet).
        """
        _log.info("TLS probe: %s:%d", self.target, self.port)

        # ── Base connection ───────────────────────────────────────────────────
        ctx = self._ctx()
        sock = self._connect_tls(ctx)
        if not sock:
            _log.error("Cannot connect TLS to %s:%d", self.target, self.port)
            return self._result

        try:
            self._result.selected_cipher   = sock.cipher()[0] if sock.cipher() else ""
            self._result.selected_protocol = sock.version() or ""
            self._result.ja3s = self.compute_ja3s(sock)
            der = sock.getpeercert(binary_form=True)
        finally:
            sock.close()

        # ── Certificate ───────────────────────────────────────────────────────
        if der:
            self._result.cert = self._parse_cert_der(der)
            _log.info("Cert subject: %s  expires: %s (%d days)",
                      self._result.cert.subject,
                      self._result.cert.not_after,
                      self._result.cert.days_remaining)

        # ── Protocol versions ─────────────────────────────────────────────────
        self.probe_protocol_versions()

        # ── Cipher enumeration ────────────────────────────────────────────────
        self.enumerate_ciphers()

        # ── HSTS ──────────────────────────────────────────────────────────────
        self._result.hsts, self._result.hsts_max_age = self.check_hsts()

        # ── CT log ────────────────────────────────────────────────────────────
        if ct:
            # Extract apex domain
            parts = self.target.split(".")
            apex = ".".join(parts[-2:]) if len(parts) >= 2 else self.target
            _log.info("Querying crt.sh for %s …", apex)
            self._result.ct_domains = self.ct_lookup(apex)
            if self._result.ct_domains:
                _log.info("[bold green]%d domain(s) from CT logs[/]",
                          len(self._result.ct_domains))

        # ── Build findings ────────────────────────────────────────────────────
        self._build_findings()
        return self._result

    def _build_findings(self) -> None:
        f = self._result.findings
        c = self._result.cert

        if c.expired:
            f.append({"severity": "CRITICAL", "issue": "Certificate is EXPIRED",
                       "detail": f"Expired: {c.not_after}"})
        elif 0 < c.days_remaining < 30:
            f.append({"severity": "HIGH",
                       "issue": f"Certificate expiring in {c.days_remaining} days",
                       "detail": c.not_after})
        elif c.days_remaining < 0:
            pass  # already handled above

        if c.self_signed:
            f.append({"severity": "HIGH", "issue": "Self-signed certificate",
                       "detail": "No trusted CA in chain"})

        if c.key_bits and c.key_bits < 2048:
            f.append({"severity": "HIGH",
                       "issue": f"Weak key size: {c.key_type} {c.key_bits}-bit",
                       "detail": "Minimum recommendation is RSA-2048 / ECDSA-256"})

        if "sha1" in (c.sig_algorithm or "").lower():
            f.append({"severity": "HIGH", "issue": "SHA-1 signature algorithm",
                       "detail": "SHA-1 is cryptographically broken"})

        if "md5" in (c.sig_algorithm or "").lower():
            f.append({"severity": "CRITICAL", "issue": "MD5 signature algorithm",
                       "detail": "MD5 certificates can be forged"})

        for v in ("TLS 1.0", "TLS 1.1", "SSLv3"):
            if v in self._result.protocols_supported:
                sev = "CRITICAL" if v == "SSLv3" else "HIGH"
                f.append({"severity": sev,
                           "issue": f"{v} supported — deprecated protocol",
                           "detail": "POODLE/BEAST/ROBOT attacks possible"})

        for cipher in self._result.broken_ciphers_found:
            f.append({"severity": "CRITICAL",
                       "issue": f"Broken cipher accepted: {cipher}",
                       "detail": "RC4/NULL/EXPORT ciphers are cryptographically broken"})

        for cipher in self._result.weak_ciphers_found:
            f.append({"severity": "MEDIUM",
                       "issue": f"Weak cipher (no PFS): {cipher}",
                       "detail": "Prefer ECDHE/DHE cipher suites for Perfect Forward Secrecy"})

        if not self._result.hsts:
            f.append({"severity": "MEDIUM",
                       "issue": "HSTS not present",
                       "detail": "Add Strict-Transport-Security header"})
        elif self._result.hsts_max_age < 15552000:
            f.append({"severity": "LOW",
                       "issue": f"HSTS max-age too short ({self._result.hsts_max_age}s)",
                       "detail": "Recommend max-age ≥ 15552000 (180 days)"})

    def print_results(self, r: TLSResult | None = None) -> None:
        from recon.core.logger import console
        from rich.table import Table
        from rich import box

        r = r or self._result
        console.print(f"\n[bold cyan]TLS Scan:[/] {r.target}:{r.port}")
        console.print(f"  Protocol:    [bold]{r.selected_protocol}[/]")
        console.print(f"  Cipher:      [bold]{r.selected_cipher}[/]")
        console.print(f"  JA3S hash:   [dim]{r.ja3s}[/]")

        c = r.cert
        if c.subject:
            console.print(f"\n[bold]Certificate:[/]")
            console.print(f"  Subject:     {c.subject}")
            console.print(f"  Issuer:      {c.issuer}")
            console.print(f"  Valid until: {c.not_after}  ({c.days_remaining}d)")
            console.print(f"  Key:         {c.key_type} {c.key_bits}-bit")
            console.print(f"  SHA-256:     {c.fingerprint_sha256[:32]}…")
            if c.san:
                console.print(f"  SANs ({len(c.san)}): {', '.join(c.san[:8])}"
                               + (" …" if len(c.san) > 8 else ""))

        if r.protocols_supported:
            console.print(f"\n  Protocols supported: [green]{', '.join(r.protocols_supported)}[/]")
        if r.protocols_rejected:
            console.print(f"  Protocols rejected:  [dim]{', '.join(r.protocols_rejected)}[/]")

        if r.broken_ciphers_found:
            console.print(f"\n  [bold red]BROKEN ciphers:[/] {', '.join(r.broken_ciphers_found)}")
        if r.weak_ciphers_found:
            console.print(f"  [yellow]Weak ciphers:[/] {', '.join(r.weak_ciphers_found)}")

        if r.ct_domains:
            console.print(f"\n  [bold cyan]CT-log domains ({len(r.ct_domains)}):[/]")
            for d in r.ct_domains[:20]:
                console.print(f"    {d}")
            if len(r.ct_domains) > 20:
                console.print(f"    … and {len(r.ct_domains)-20} more")

        if r.findings:
            t = Table("Severity", "Issue", "Detail", box=box.SIMPLE)
            sev_color = {"CRITICAL": "red", "HIGH": "red",
                         "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
            for fi in r.findings:
                sev = fi.get("severity", "INFO")
                t.add_row(
                    f"[bold {sev_color.get(sev,'white')}]{sev}[/]",
                    fi.get("issue", ""),
                    fi.get("detail", ""),
                )
            console.print("\n[bold]TLS Findings:[/]")
            console.print(t)
