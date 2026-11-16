"""
recon.engine — the single place that runs a scanner module and normalises its
heterogeneous output into a ScanReport.

Both front-ends (CLI and menu) call these ``run_*`` adapters, so every capability
flows through one reporting pipeline. This is also what finally makes the
advanced modules (async scan, HTTP/TLS/SMB/SNMP probes) reachable with real
reports — previously they were wired into neither front-end.

Each adapter registers a ScannerSpec so the registry can enumerate capabilities
and gate them by privilege.
"""

from __future__ import annotations

import re
from typing import Any

from recon.core.config import ReconConfig
from recon.core.findings import Finding
from recon.core.logger import get_logger
from recon.core.output import HostResult, ScanReport
from recon.core.registry import ScannerSpec, register

__all__ = [
    "run_async", "run_http", "run_tls", "run_smb", "run_snmp",
    "coerce_findings",
]

_log = get_logger("engine")


def _slug(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", text or "").strip("-").upper()
    return s[:48] or "FINDING"


def _coerce_one(raw: dict[str, Any], host: str = "", service: str = "", port: int | None = None) -> Finding:
    """Map a module's loosely-shaped finding dict (commonly {severity, issue,
    detail}) onto the canonical Finding model."""
    title = (raw.get("issue") or raw.get("title") or raw.get("finding")
             or raw.get("description") or "finding")
    detail = raw.get("detail") or raw.get("description") or raw.get("evidence") or ""
    cve = raw.get("cve")
    if isinstance(cve, list):
        ident = cve[0] if cve else _slug(title)
    else:
        ident = raw.get("id") or cve or _slug(title)
    cvss = raw.get("cvss")
    if cvss is None:
        cvss = raw.get("cvss_score", 0.0)
    return Finding.from_legacy(
        severity=raw.get("severity", "info"),
        finding=str(ident),
        description=title,
        service=raw.get("service", service),
        port=raw.get("port", port),
        evidence=detail,
        remediation=raw.get("remediation", ""),
        cvss_score=float(cvss or 0.0),
        host=host,
    )


def coerce_findings(raws: list[dict[str, Any]], host: str = "", service: str = "",
                    port: int | None = None) -> list[Finding]:
    return [_coerce_one(r, host=host, service=service, port=port) for r in (raws or [])]


def _result_findings(result: Any, data: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull a findings list off a result object or its dict form, defensively."""
    for src in (getattr(result, "findings", None), data.get("findings"), data.get("issues")):
        if isinstance(src, list):
            return src
    return []


def _report(target: str, scan_type: str) -> ScanReport:
    return ScanReport(target=target, scan_type=scan_type)


# --------------------------------------------------------------------------- #
# Adapters for the previously-orphaned advanced modules                        #
# --------------------------------------------------------------------------- #

def run_async(target: str, config: ReconConfig | None = None, *, ports: str = "top1000", **_: Any) -> ScanReport:
    from recon.modules.async_scan import AsyncScanner

    cfg = config or ReconConfig()
    report = _report(target, "async")
    result = AsyncScanner(target, cfg).scan(ports=ports)
    data = result.to_dict() if hasattr(result, "to_dict") else {}
    host = HostResult(ip=target)
    for p in getattr(result, "open_ports", []) or []:
        pd = p.to_dict() if hasattr(p, "to_dict") else dict(p)
        host.ports.append({
            "port": pd.get("port"), "state": "open",
            "service": pd.get("service", ""), "version": pd.get("version", ""),
            "banner": pd.get("banner", ""), "protocol": "tcp",
        })
    report.add_host(host)
    report.metadata["async_scan"] = data
    report.finalize()
    return report


def run_http(target: str, config: ReconConfig | None = None, *, port: int | None = None,
             use_ssl: bool | None = None, **_: Any) -> ScanReport:
    from recon.modules.http_probe import HTTPProbe

    cfg = config or ReconConfig()
    report = _report(target, "http")
    probe = HTTPProbe(target, port=port, use_ssl=use_ssl, config=cfg)
    result = probe.probe_all()
    data = result.to_dict() if hasattr(result, "to_dict") else {}
    for raw in _result_findings(result, data):
        report.add_finding(_coerce_one(raw, host=target, service="http", port=port))
    report.metadata["http"] = data
    report.finalize()
    return report


def run_tls(target: str, config: ReconConfig | None = None, *, port: int = 443,
            ct: bool = False, **_: Any) -> ScanReport:
    from recon.modules.tls_probe import TLSProbe

    cfg = config or ReconConfig()
    report = _report(target, "tls")
    result = TLSProbe(target, port=port, config=cfg).scan_all(ct=ct)
    data = result.to_dict() if hasattr(result, "to_dict") else {}
    for raw in _result_findings(result, data):
        report.add_finding(_coerce_one(raw, host=target, service="tls", port=port))
    report.metadata["tls"] = data
    report.finalize()
    return report


def run_smb(target: str, config: ReconConfig | None = None, *, check_vulns: bool = True, **_: Any) -> ScanReport:
    from recon.modules.smb_enum import SMBEnumerator

    cfg = config or ReconConfig()
    report = _report(target, "smb")
    result = SMBEnumerator(target, cfg).enumerate_all(check_vulns=check_vulns)
    data = result.to_dict() if hasattr(result, "to_dict") else {}
    for raw in _result_findings(result, data):
        report.add_finding(_coerce_one(raw, host=target, service="smb", port=445))
    report.metadata["smb"] = data
    report.finalize()
    return report


def run_snmp(target: str, config: ReconConfig | None = None, *, community: str | None = None, **_: Any) -> ScanReport:
    from recon.modules.snmp_enum import SNMPEnumerator

    cfg = config or ReconConfig()
    report = _report(target, "snmp")
    result = SNMPEnumerator(target, config=cfg).enumerate_all(community=community)
    data = result.to_dict() if hasattr(result, "to_dict") else {}
    for raw in _result_findings(result, data):
        report.add_finding(_coerce_one(raw, host=target, service="snmp", port=161))
    report.metadata["snmp"] = data
    report.finalize()
    return report


# --------------------------------------------------------------------------- #
# Registry — every capability is declared here (CLI commands keep their own     #
# explicit bodies; those without a runner are invoked via their Typer command). #
# --------------------------------------------------------------------------- #

def _register_all() -> None:
    specs = [
        ScannerSpec("dns", "DNS enumeration: AXFR, brute-force, records, DNSSEC", None, None, 10),
        ScannerSpec("discover", "Host discovery: ARP/ICMP/TCP/UDP sweep", None, None, 20),
        ScannerSpec("os", "OS fingerprinting: TTL, TCP stack, banners", None, None, 30),
        ScannerSpec("portscan", "Port scan: SYN/connect/FIN/XMAS/NULL/ACK/UDP", None, None, 40),
        ScannerSpec("vulnscan", "Vulnerability scan: CVE, SSL, default creds, misconfig", None, None, 50),
        ScannerSpec("wireless", "Wireless recon: monitor mode, 802.11 capture", "monitor_mode", None, 60),
        ScannerSpec("full", "Full pipeline: discover -> OS -> ports -> vulns -> report", None, None, 70),
        ScannerSpec("asyncscan", "High-concurrency async connect scan (no root)", None, run_async, 80),
        ScannerSpec("httpprobe", "HTTP: WAF/CDN/tech fingerprint, security headers, paths", None, run_http, 90),
        ScannerSpec("tlsprobe", "TLS: protocols, ciphers, cert chain, CT logs", None, run_tls, 100),
        ScannerSpec("smbenum", "SMB: dialects, signing, MS17-010/SMBGhost pre-checks", None, run_smb, 110),
        ScannerSpec("snmpenum", "SNMP: community brute, sysInfo, interfaces, routes", None, run_snmp, 120),
    ]
    for spec in specs:
        register(spec)


_register_all()
