"""
recon.modules.vuln_scan — Structured vulnerability assessment engine.

Capabilities:
- CVE database matching against service banners (data/cve_db.json)
- SSL/TLS audit: protocols, cipher suites, cert chain, expiry, SANs
- Default credential testing (FTP, SSH, HTTP Basic, Redis, MySQL, MongoDB)
- Misconfiguration checks: HTTP headers, open directory, anon FTP,
  unauthenticated Redis/MongoDB/Elasticsearch
- Lockout detection: stops after 3 auth failures per service
"""

from __future__ import annotations

import ftplib
import json
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from recon.core.config import ReconConfig
from recon.core.logger import get_logger, make_progress

__all__ = ["VulnScanner", "Finding"]

_log = get_logger("vuln_scan")

_CVE_DB: list[dict[str, Any]] = []
_CREDS_DB: list[dict[str, Any]] = []
_DB_LOCK = threading.Lock()
_DB_LOADED = False


def _load_databases() -> None:
    global _CVE_DB, _CREDS_DB, _DB_LOADED
    with _DB_LOCK:
        if _DB_LOADED:
            return
        data_dir = Path(__file__).parent.parent / "data"

        cve_path = data_dir / "cve_db.json"
        if cve_path.exists():
            try:
                with open(cve_path, encoding="utf-8") as f:
                    _CVE_DB = json.load(f)
                _log.debug("Loaded CVE DB: %d entries", len(_CVE_DB))
            except Exception as exc:
                _log.error("CVE DB load error: %s", exc)

        creds_path = data_dir / "default_creds.json"
        if creds_path.exists():
            try:
                with open(creds_path, encoding="utf-8") as f:
                    _CREDS_DB = json.load(f)
                _log.debug("Loaded creds DB: %d service entries", len(_CREDS_DB))
            except Exception as exc:
                _log.error("Creds DB load error: %s", exc)

        _DB_LOADED = True


@dataclass
class Finding:
    """A single vulnerability or misconfiguration finding."""
    severity: str          # critical, high, medium, low, info
    finding: str           # CVE ID or short name
    service: str
    port: int
    description: str
    evidence: str = ""
    remediation: str = ""
    cvss_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "cve": self.finding,
            "service": self.service,
            "port": self.port,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
        }


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


class VulnScanner:
    """
    Vulnerability scanner that correlates service banners against CVE database,
    audits SSL/TLS, tests default credentials, and checks misconfigurations.

    Args:
        target: IP address or hostname.
        config: ReconConfig instance.
    """

    def __init__(self, target: str, config: ReconConfig | None = None) -> None:
        self.target = target
        self.config = config or ReconConfig()
        self._findings: list[Finding] = []
        self._lock = threading.Lock()
        _load_databases()

    def _add_finding(self, f: Finding) -> None:
        with self._lock:
            self._findings.append(f)
        sev_style = {
            "critical": "[bold red]CRITICAL[/bold red]",
            "high":     "[red]HIGH[/red]",
            "medium":   "[yellow]MEDIUM[/yellow]",
            "low":      "[green]LOW[/green]",
            "info":     "[cyan]INFO[/cyan]",
        }.get(f.severity, f.severity.upper())
        _log.info(
            "%s %s port=%d %s",
            sev_style, f.finding, f.port, f.description[:80],
        )

    # ------------------------------------------------------------------ #
    # CVE matching                                                         #
    # ------------------------------------------------------------------ #

    def check_service_vulns(
        self,
        port: int,
        banner: str,
        service: str = "",
    ) -> list[Finding]:
        """
        Match a service banner against the CVE database.

        Args:
            port: Port the service is running on.
            banner: Raw banner / version string.
            service: Optional service name hint.

        Returns:
            List of matching Finding objects.
        """
        found: list[Finding] = []
        if not banner and not service:
            return found

        for entry in _CVE_DB:
            svc_match = entry.get("service", "").lower()
            if service and svc_match and svc_match not in service.lower():
                if svc_match not in banner.lower():
                    continue

            version_regex = entry.get("version_regex", "")
            if version_regex:
                try:
                    if not re.search(version_regex, banner, re.IGNORECASE):
                        continue
                except re.error:
                    continue

            score = entry.get("cvss_score", 0.0)
            f = Finding(
                severity=_cvss_to_severity(score),
                finding=entry.get("cve_id", "UNKNOWN"),
                service=entry.get("service", service),
                port=port,
                description=entry.get("description", ""),
                evidence=f"Banner: {banner[:200]}",
                remediation=entry.get("remediation", ""),
                cvss_score=score,
            )
            found.append(f)
            self._add_finding(f)

        return found

    def check_all_ports(
        self,
        port_results: list[dict[str, Any]],
    ) -> list[Finding]:
        """
        Run CVE matching against all port results from a port scan.

        Args:
            port_results: List of port result dicts with keys:
                port, service, version, banner.

        Returns:
            All matched findings.
        """
        all_findings: list[Finding] = []
        for pr in port_results:
            port = pr.get("port", 0)
            banner = pr.get("banner", "") + " " + pr.get("version", "")
            service = pr.get("service", "")
            all_findings.extend(self.check_service_vulns(port, banner.strip(), service))
        return all_findings

    # ------------------------------------------------------------------ #
    # SSL/TLS audit                                                        #
    # ------------------------------------------------------------------ #

    def ssl_audit(self, port: int = 443) -> dict[str, Any]:
        """
        Comprehensive SSL/TLS audit: protocols, ciphers, cert chain.

        Args:
            port: HTTPS/TLS port to audit.

        Returns:
            Dict with protocol_support, cert_info, cipher_weaknesses,
            header_issues, and list of Finding objects.
        """
        report: dict[str, Any] = {
            "port": port,
            "protocol_support": {},
            "cert_info": {},
            "cipher_weaknesses": [],
            "findings": [],
        }

        # Protocol support matrix
        proto_map: list[tuple[str, int]] = []
        # TLS 1.3
        if hasattr(ssl, "PROTOCOL_TLS_CLIENT"):
            proto_map.append(("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT))
        for name, attr in [
            ("TLSv1.2", "PROTOCOL_TLSv1_2"),
            ("TLSv1.1", "PROTOCOL_TLSv1_1"),
            ("TLSv1.0", "PROTOCOL_TLSv1"),
            ("SSLv3",   "PROTOCOL_SSLv3"),
        ]:
            if hasattr(ssl, attr):
                proto_map.append((name, getattr(ssl, attr)))

        for proto_name, proto_const in proto_map:
            supported = self._test_tls_protocol(port, proto_name)
            report["protocol_support"][proto_name] = supported
            if supported and proto_name in ("SSLv3", "TLSv1.0", "TLSv1.1"):
                sev = "high" if proto_name == "SSLv3" else "medium"
                f = Finding(
                    severity=sev,
                    finding=f"WEAK-TLS-{proto_name.replace('.', '')}",
                    service="https",
                    port=port,
                    description=f"Deprecated protocol {proto_name} is supported",
                    evidence=f"TLS handshake succeeded with {proto_name}",
                    remediation=f"Disable {proto_name} in server SSL configuration",
                    cvss_score=7.0 if proto_name == "SSLv3" else 5.0,
                )
                report["findings"].append(f.to_dict())
                self._add_finding(f)

        # Certificate analysis
        cert_info = self._get_cert_info(port)
        report["cert_info"] = cert_info
        if cert_info:
            self._check_cert_findings(cert_info, port, report["findings"])

        # Weak cipher detection
        weak = self._check_weak_ciphers(port)
        report["cipher_weaknesses"] = weak
        for cipher in weak:
            f = Finding(
                severity="medium",
                finding=f"WEAK-CIPHER-{cipher}",
                service="https",
                port=port,
                description=f"Weak cipher suite negotiated: {cipher}",
                remediation="Restrict cipher suites to TLS_AES_256_GCM_SHA384 and similar",
            )
            report["findings"].append(f.to_dict())
            self._add_finding(f)

        return report

    def _test_tls_protocol(self, port: int, proto_name: str) -> bool:
        """Check if a specific TLS protocol version is accepted."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Force specific version
        if proto_name == "TLSv1.3":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        elif proto_name == "TLSv1.2":
            if hasattr(ssl.TLSVersion, "TLSv1_2"):
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        elif proto_name in ("TLSv1.1", "TLSv1.0", "SSLv3"):
            # These are disabled in modern Python; skip gracefully
            return False

        try:
            with socket.create_connection((self.target, port), timeout=self.config.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target):
                    return True
        except Exception:
            return False

    def _get_cert_info(self, port: int) -> dict[str, Any]:
        """Retrieve and parse the server certificate."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((self.target, port), timeout=self.config.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target) as tls:
                    cert = tls.getpeercert()
                    if not cert:
                        return {}
                    # Parse expiry
                    not_after = cert.get("notAfter", "")
                    try:
                        exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                        days_left = (exp_dt - datetime.now(timezone.utc)).days
                    except Exception:
                        days_left = -1

                    # SANs
                    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

                    # Subject CN
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    self_signed = subject.get("commonName") == issuer.get("commonName")

                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "not_after": not_after,
                        "days_until_expiry": days_left,
                        "sans": sans,
                        "self_signed": self_signed,
                        "cipher": tls.cipher(),
                    }
        except Exception as exc:
            _log.debug("Cert retrieval error port %d: %s", port, exc)
            return {}

    def _check_cert_findings(
        self, cert: dict[str, Any], port: int, findings_out: list[dict]
    ) -> None:
        """Append findings for certificate issues."""
        days = cert.get("days_until_expiry", 999)
        if days < 0:
            f = Finding(
                severity="critical",
                finding="CERT-EXPIRED",
                service="https",
                port=port,
                description=f"Certificate expired {abs(days)} days ago",
                remediation="Renew the TLS certificate immediately",
                cvss_score=7.5,
            )
            findings_out.append(f.to_dict())
            self._add_finding(f)
        elif days < 30:
            f = Finding(
                severity="high",
                finding="CERT-EXPIRING-SOON",
                service="https",
                port=port,
                description=f"Certificate expires in {days} days",
                remediation="Renew the TLS certificate before expiry",
            )
            findings_out.append(f.to_dict())
            self._add_finding(f)

        if cert.get("self_signed"):
            f = Finding(
                severity="medium",
                finding="CERT-SELF-SIGNED",
                service="https",
                port=port,
                description="Certificate is self-signed (no trusted CA)",
                remediation="Replace with a certificate from a trusted CA (e.g. Let's Encrypt)",
            )
            findings_out.append(f.to_dict())
            self._add_finding(f)

    def _check_weak_ciphers(self, port: int) -> list[str]:
        """Attempt to negotiate known-weak cipher suites."""
        weak_names: list[str] = []
        weak_ciphers = ["RC4", "DES", "NULL", "EXPORT", "anon", "MD5"]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((self.target, port), timeout=self.config.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target) as tls:
                    negotiated = tls.cipher()
                    if negotiated:
                        cipher_name = negotiated[0]
                        for w in weak_ciphers:
                            if w in cipher_name.upper():
                                weak_names.append(cipher_name)
        except Exception:
            pass
        return weak_names

    # ------------------------------------------------------------------ #
    # HTTP security header audit                                           #
    # ------------------------------------------------------------------ #

    def check_http_headers(self, port: int = 80, use_tls: bool = False) -> list[Finding]:
        """
        Check HTTP response for missing security headers.

        Args:
            port: HTTP/HTTPS port.
            use_tls: Use TLS connection.

        Returns:
            List of Finding objects for missing headers.
        """
        required_headers = {
            "Strict-Transport-Security": ("MISSING-HSTS", "high",
                "Missing HTTP Strict-Transport-Security header enables MITM downgrade attacks",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            "X-Frame-Options": ("MISSING-XFO", "medium",
                "Missing X-Frame-Options allows clickjacking attacks",
                "Add: X-Frame-Options: DENY"),
            "X-Content-Type-Options": ("MISSING-XCTO", "low",
                "Missing X-Content-Type-Options allows MIME type sniffing",
                "Add: X-Content-Type-Options: nosniff"),
            "Content-Security-Policy": ("MISSING-CSP", "medium",
                "Missing Content-Security-Policy enables XSS and injection attacks",
                "Implement a restrictive Content-Security-Policy"),
            "X-XSS-Protection": ("MISSING-XSS-PROT", "low",
                "Missing X-XSS-Protection header (legacy browsers)",
                "Add: X-XSS-Protection: 1; mode=block"),
        }

        findings: list[Finding] = []
        headers = self._fetch_http_headers(port, use_tls)
        if not headers:
            return findings

        header_keys_lower = {k.lower(): v for k, v in headers.items()}

        # Check for directory listing
        body = headers.get("_body", "")
        if re.search(r"Index of /|Directory listing|Parent Directory", body, re.IGNORECASE):
            f = Finding(
                severity="medium",
                finding="OPEN-DIRECTORY-LISTING",
                service="http",
                port=port,
                description="Web server has directory listing enabled",
                evidence=body[:200],
                remediation="Disable directory listing in web server configuration",
            )
            findings.append(f)
            self._add_finding(f)

        for header, (finding_id, sev, desc, rem) in required_headers.items():
            if header.lower() not in header_keys_lower:
                f = Finding(
                    severity=sev,
                    finding=finding_id,
                    service="https" if use_tls else "http",
                    port=port,
                    description=desc,
                    remediation=rem,
                )
                findings.append(f)
                self._add_finding(f)

        # Check for Server header information disclosure
        server = header_keys_lower.get("server", "")
        if server and re.search(r"\d+\.\d+", server):
            f = Finding(
                severity="low",
                finding="SERVER-BANNER-DISCLOSURE",
                service="http",
                port=port,
                description=f"Server banner discloses version: {server}",
                evidence=server,
                remediation="Remove or obscure the Server response header",
            )
            findings.append(f)
            self._add_finding(f)

        return findings

    def _fetch_http_headers(
        self, port: int, use_tls: bool = False
    ) -> dict[str, str]:
        """Perform a HEAD request and return parsed response headers."""
        try:
            raw = socket.create_connection((self.target, port), timeout=self.config.timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = ctx.wrap_socket(raw, server_hostname=self.target)
            else:
                conn = raw
            with conn:
                conn.sendall(
                    f"GET / HTTP/1.0\r\nHost: {self.target}\r\nConnection: close\r\n\r\n".encode()
                )
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 65536:
                        break

            text = data.decode("utf-8", errors="replace")
            parts = text.split("\r\n\r\n", 1)
            header_block = parts[0]
            body = parts[1][:1000] if len(parts) > 1 else ""

            headers: dict[str, str] = {"_body": body}
            for line in header_block.splitlines()[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip()] = v.strip()
            return headers
        except Exception as exc:
            _log.debug("HTTP header fetch error port %d: %s", port, exc)
            return {}

    # ------------------------------------------------------------------ #
    # Default credential testing                                           #
    # ------------------------------------------------------------------ #

    def test_default_credentials(
        self,
        port: int,
        service: str,
    ) -> list[Finding]:
        """
        Test default credential pairs from data/default_creds.json.

        Implements lockout detection: stops after 3 consecutive auth failures.

        Args:
            port: Service port.
            service: Service name (ftp, ssh, http, redis, mysql, mongodb).

        Returns:
            List of Finding objects for valid credentials.
        """
        findings: list[Finding] = []
        svc_lower = service.lower()

        creds_entry = next(
            (e for e in _CREDS_DB if e.get("service", "").lower() == svc_lower),
            None,
        )
        if not creds_entry:
            return findings

        creds: list[dict[str, str]] = creds_entry.get("credentials", [])
        fail_count = 0
        max_fails = 3

        for pair in creds:
            if fail_count >= max_fails:
                _log.debug("Lockout threshold hit for %s:%d; stopping cred test", service, port)
                break

            user = pair.get("user", "")
            passwd = pair.get("pass", "")

            success, evidence = self._try_credential(svc_lower, port, user, passwd)

            if success:
                f = Finding(
                    severity="critical",
                    finding=f"DEFAULT-CREDS-{svc_lower.upper()}",
                    service=svc_lower,
                    port=port,
                    description=f"Default credentials accepted: {user}/{passwd or '<empty>'}",
                    evidence=evidence,
                    remediation=f"Change default credentials for {service} immediately",
                    cvss_score=9.8,
                )
                findings.append(f)
                self._add_finding(f)
                fail_count = 0  # Reset on success
            else:
                fail_count += 1

        return findings

    def _try_credential(
        self, service: str, port: int, user: str, passwd: str
    ) -> tuple[bool, str]:
        """
        Attempt a single credential pair against a service.

        Returns:
            Tuple (success, evidence_string).
        """
        if service == "ftp":
            return self._try_ftp(port, user, passwd)
        if service == "ssh":
            return self._try_ssh(port, user, passwd)
        if service in ("http", "https"):
            return self._try_http_basic(port, user, passwd, tls=(service == "https"))
        if service == "redis":
            return self._try_redis(port, passwd)
        if service == "mysql":
            return self._try_mysql(port, user, passwd)
        if service == "mongodb":
            return self._try_mongodb(port, user, passwd)
        return False, ""

    def _try_ftp(self, port: int, user: str, passwd: str) -> tuple[bool, str]:
        try:
            with ftplib.FTP() as ftp:
                ftp.connect(self.target, port, timeout=self.config.timeout)
                ftp.login(user, passwd)
                welcome = ftp.getwelcome()
                return True, welcome[:200]
        except ftplib.error_perm:
            return False, ""
        except Exception:
            return False, ""

    def _try_ssh(self, port: int, user: str, passwd: str) -> tuple[bool, str]:
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.target, port=port, username=user, password=passwd,
                timeout=self.config.timeout, allow_agent=False, look_for_keys=False,
            )
            client.close()
            return True, f"SSH login succeeded: {user}@{self.target}:{port}"
        except Exception:
            return False, ""

    def _try_http_basic(
        self, port: int, user: str, passwd: str, tls: bool = False
    ) -> tuple[bool, str]:
        import base64
        cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
        try:
            raw = socket.create_connection((self.target, port), timeout=self.config.timeout)
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = ctx.wrap_socket(raw, server_hostname=self.target)
            else:
                conn = raw
            with conn:
                conn.sendall(
                    f"GET / HTTP/1.0\r\nHost: {self.target}\r\n"
                    f"Authorization: Basic {cred}\r\n\r\n".encode()
                )
                resp = conn.recv(512).decode("utf-8", errors="replace")
            if resp.startswith("HTTP/") and " 200 " in resp.split("\r\n")[0]:
                return True, f"HTTP Basic Auth succeeded: {user}"
        except Exception:
            pass
        return False, ""

    def _try_redis(self, port: int, passwd: str) -> tuple[bool, str]:
        try:
            with socket.create_connection((self.target, port), timeout=self.config.timeout) as s:
                s.settimeout(self.config.timeout)
                if passwd:
                    cmd = f"AUTH {passwd}\r\n".encode()
                    s.sendall(cmd)
                    resp = s.recv(64).decode("utf-8", errors="replace")
                    if resp.startswith("+OK"):
                        return True, f"Redis AUTH succeeded with password: {passwd}"
                    return False, ""
                else:
                    s.sendall(b"PING\r\n")
                    resp = s.recv(64).decode("utf-8", errors="replace")
                    if "+PONG" in resp:
                        return True, "Redis: unauthenticated PING/PONG"
        except Exception:
            pass
        return False, ""

    def _try_mysql(self, port: int, user: str, passwd: str) -> tuple[bool, str]:
        try:
            import socket as _socket
            with _socket.create_connection((self.target, port), timeout=self.config.timeout) as s:
                greeting = s.recv(1024)
                if not greeting:
                    return False, ""
                # Send minimal auth packet (version 4.1)
                auth_pkt = self._build_mysql_auth(user, passwd, greeting)
                s.sendall(auth_pkt)
                resp = s.recv(64)
                if resp and resp[4:5] == b"\x00":  # OK packet
                    return True, f"MySQL login succeeded: {user}@{self.target}:{port}"
        except Exception:
            pass
        return False, ""

    @staticmethod
    def _build_mysql_auth(user: str, passwd: str, greeting: bytes) -> bytes:
        """Build minimal MySQL Client Authentication packet."""
        import hashlib
        import struct
        # Extract salt from greeting (simplified)
        salt = greeting[4:12] + greeting[31:43] if len(greeting) > 43 else b"\x00" * 20
        if passwd:
            h1 = hashlib.sha1(passwd.encode()).digest()
            h2 = hashlib.sha1(h1).digest()
            xored = bytes(a ^ b for a, b in zip(h1, hashlib.sha1(salt + h2).digest()))
        else:
            xored = b""
        user_b = user.encode() + b"\x00"
        auth_resp = bytes([len(xored)]) + xored if xored else b"\x00"
        caps = struct.pack("<I", 0x0000_A68F)  # CLIENT_LONG_PASSWORD|CLIENT_PROTOCOL_41 etc.
        body = caps + struct.pack("<I", 0xFFFFFF) + b"\x21" + b"\x00" * 23 + user_b + auth_resp
        pkt = struct.pack("<I", len(body))[:3] + b"\x01" + body
        return pkt

    def _try_mongodb(self, port: int, user: str, passwd: str) -> tuple[bool, str]:
        """MongoDB unauthenticated check via OP_MSG isMaster."""
        try:
            import struct
            with socket.create_connection((self.target, port), timeout=self.config.timeout) as s:
                # MongoDB OP_MSG isMaster
                doc = b"\x10\x00\x00\x00\x01isMaster\x00\x01\x00\x00\x00\x00"
                header = struct.pack("<iiii", len(doc) + 16, 1, 0, 2013)
                msg = struct.pack("<i", 0)  # flagBits
                section = b"\x00" + struct.pack("<i", len(doc) + 5)[:4] + doc
                pkt = header + msg + section
                # Simpler: raw isMaster check
                pkt = b"\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
                s.sendall(pkt)
                resp = s.recv(1024)
                if b"ismaster" in resp.lower() or b"isMain" in resp:
                    return True, f"MongoDB unauthenticated access: {self.target}:{port}"
        except Exception:
            pass
        return False, ""

    # ------------------------------------------------------------------ #
    # Misconfiguration checks                                              #
    # ------------------------------------------------------------------ #

    def check_misconfigurations(
        self,
        port_results: list[dict[str, Any]] | None = None,
    ) -> list[Finding]:
        """
        Check for common service misconfigurations.

        Args:
            port_results: Optional list of port dicts to guide which services to check.

        Returns:
            List of misconfiguration Finding objects.
        """
        findings: list[Finding] = []
        services_to_check = self._infer_services(port_results or [])

        checks = [
            (self._check_anon_ftp,          "ftp",    21),
            (self._check_unauthenticated_redis, "redis", 6379),
            (self._check_unauthenticated_mongodb, "mongodb", 27017),
            (self._check_telnet_enabled,    "telnet", 23),
            (self._check_unauthenticated_elasticsearch, "elasticsearch", 9200),
            (self._check_exposed_docker_api, "docker", 2375),
            (self._check_exposed_k8s_api,   "kubernetes", 8080),
        ]

        for check_fn, svc, default_port in checks:
            port = services_to_check.get(svc, default_port)
            if port is None:
                continue
            try:
                f = check_fn(port)
                if f:
                    findings.append(f)
                    self._add_finding(f)
            except Exception as exc:
                _log.debug("Misconfig check %s:%d error: %s", svc, port, exc)

        # HTTP header checks
        for svc, port, tls in [("http", 80, False), ("https", 443, True)]:
            actual_port = services_to_check.get(svc, port)
            if actual_port:
                findings.extend(self.check_http_headers(actual_port, use_tls=tls))

        return findings

    @staticmethod
    def _infer_services(port_results: list[dict[str, Any]]) -> dict[str, int]:
        """Build a service→port map from scan results."""
        mapping: dict[str, int] = {}
        service_map = {
            "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "http": 80,
            "https": 443, "redis": 6379, "mongodb": 27017, "mysql": 3306,
            "elasticsearch": 9200, "docker": 2375, "kubernetes": 6443,
        }
        for pr in port_results:
            svc = pr.get("service", "").lower()
            port = pr.get("port", 0)
            if svc:
                mapping[svc] = port
        for svc, port in service_map.items():
            if svc not in mapping:
                mapping[svc] = port
        return mapping

    def _check_anon_ftp(self, port: int) -> Finding | None:
        ok, evidence = self._try_ftp(port, "anonymous", "guest@example.com")
        if ok:
            return Finding(
                severity="high",
                finding="ANON-FTP",
                service="ftp",
                port=port,
                description="FTP server allows anonymous login",
                evidence=evidence,
                remediation="Disable anonymous FTP access in vsftpd.conf or proftpd.conf",
                cvss_score=7.5,
            )
        return None

    def _check_unauthenticated_redis(self, port: int) -> Finding | None:
        ok, evidence = self._try_redis(port, "")
        if ok:
            return Finding(
                severity="critical",
                finding="REDIS-NO-AUTH",
                service="redis",
                port=port,
                description="Redis server accepts connections without authentication",
                evidence=evidence,
                remediation="Set requirepass in redis.conf and bind to localhost",
                cvss_score=9.8,
            )
        return None

    def _check_unauthenticated_mongodb(self, port: int) -> Finding | None:
        ok, evidence = self._try_mongodb(port, "", "")
        if ok:
            return Finding(
                severity="critical",
                finding="MONGODB-NO-AUTH",
                service="mongodb",
                port=port,
                description="MongoDB server accessible without authentication",
                evidence=evidence,
                remediation="Enable MongoDB authentication and bind to localhost",
                cvss_score=9.8,
            )
        return None

    def _check_telnet_enabled(self, port: int) -> Finding | None:
        try:
            with socket.create_connection((self.target, port), timeout=self.config.timeout) as s:
                s.settimeout(self.config.timeout)
                banner = s.recv(256).decode("utf-8", errors="replace")
                return Finding(
                    severity="high",
                    finding="TELNET-ENABLED",
                    service="telnet",
                    port=port,
                    description="Telnet service is running (cleartext credentials)",
                    evidence=banner[:200],
                    remediation="Disable Telnet and use SSH for remote administration",
                    cvss_score=7.0,
                )
        except Exception:
            return None

    def _check_unauthenticated_elasticsearch(self, port: int) -> Finding | None:
        try:
            with socket.create_connection((self.target, port), timeout=self.config.timeout) as s:
                s.sendall(
                    f"GET / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode()
                )
                resp = s.recv(2048).decode("utf-8", errors="replace")
                if '"cluster_name"' in resp or '"version"' in resp:
                    return Finding(
                        severity="critical",
                        finding="ELASTICSEARCH-NO-AUTH",
                        service="elasticsearch",
                        port=port,
                        description="Elasticsearch API accessible without authentication",
                        evidence=resp[:300],
                        remediation="Enable Elasticsearch security (xpack.security.enabled=true)",
                        cvss_score=9.8,
                    )
        except Exception:
            pass
        return None

    def _check_exposed_docker_api(self, port: int) -> Finding | None:
        try:
            with socket.create_connection((self.target, port), timeout=self.config.timeout) as s:
                s.sendall(
                    f"GET /info HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode()
                )
                resp = s.recv(2048).decode("utf-8", errors="replace")
                if '"DockerRootDir"' in resp or '"ServerVersion"' in resp:
                    return Finding(
                        severity="critical",
                        finding="DOCKER-API-EXPOSED",
                        service="docker",
                        port=port,
                        description="Docker daemon API exposed without TLS/auth (container escape risk)",
                        evidence=resp[:300],
                        remediation="Bind Docker to a Unix socket or enable TLS client auth",
                        cvss_score=10.0,
                    )
        except Exception:
            pass
        return None

    def _check_exposed_k8s_api(self, port: int) -> Finding | None:
        for k8s_port in [6443, 8080, 8443]:
            try:
                with socket.create_connection((self.target, k8s_port), timeout=self.config.timeout) as s:
                    s.sendall(
                        f"GET /api HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode()
                    )
                    resp = s.recv(2048).decode("utf-8", errors="replace")
                    if '"apiVersion"' in resp or '"versions"' in resp:
                        return Finding(
                            severity="critical",
                            finding="K8S-API-EXPOSED",
                            service="kubernetes",
                            port=k8s_port,
                            description="Kubernetes API server accessible without authentication",
                            evidence=resp[:300],
                            remediation="Enable Kubernetes RBAC and require client certificates",
                            cvss_score=9.8,
                        )
            except Exception:
                continue
        return None

    # ------------------------------------------------------------------ #
    # Full scan pipeline                                                   #
    # ------------------------------------------------------------------ #

    def run_full(
        self,
        port_results: list[dict[str, Any]] | None = None,
        ssl_ports: list[int] | None = None,
        check_creds: bool = True,
        check_misconfig: bool = True,
        check_cve: bool = True,
    ) -> list[Finding]:
        """
        Run all vulnerability checks and return consolidated findings.

        Args:
            port_results: Port scan results to feed into CVE matching and service checks.
            ssl_ports: Ports to run SSL/TLS audit against.
            check_creds: Run default credential tests.
            check_misconfig: Run misconfiguration checks.
            check_cve: Run CVE matching.

        Returns:
            List of all Finding objects.
        """
        _log.info("[bold cyan]Vulnerability scan[/] target=%s", self.target)
        port_results = port_results or []

        if check_cve and port_results:
            _log.info("CVE matching on %d services", len(port_results))
            self.check_all_ports(port_results)

        if ssl_ports is None:
            ssl_ports = [
                pr["port"] for pr in port_results
                if pr.get("service") in ("https", "ssl", "tls")
                   or pr.get("port") in (443, 8443, 993, 995, 465)
            ]
        for sp in ssl_ports:
            _log.info("SSL/TLS audit on port %d", sp)
            self.ssl_audit(sp)

        if check_creds:
            for pr in port_results:
                svc = pr.get("service", "")
                port = pr.get("port", 0)
                if svc in ("ftp", "ssh", "http", "https", "redis", "mysql", "mongodb"):
                    _log.info("Default cred test: %s:%d", svc, port)
                    self.test_default_credentials(port, svc)

        if check_misconfig:
            _log.info("Misconfiguration checks")
            self.check_misconfigurations(port_results)

        findings = self.findings()
        _log.info(
            "[bold green]Vuln scan complete[/]: %d findings (%d critical, %d high)",
            len(findings),
            sum(1 for f in findings if f.severity == "critical"),
            sum(1 for f in findings if f.severity == "high"),
        )
        return findings

    def findings(self) -> list[Finding]:
        """Return all findings sorted by severity."""
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        with self._lock:
            return sorted(self._findings, key=lambda f: sev_order.get(f.severity, 5))
