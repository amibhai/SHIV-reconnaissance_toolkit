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
    "run_dns", "run_discover", "run_os", "run_portscan", "run_vulnscan", "run_full",
    "run_async", "run_http", "run_tls", "run_smb", "run_snmp",
    "coerce_findings", "safe_run",
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
# Adapters for the core capabilities                                           #
# --------------------------------------------------------------------------- #

def run_portscan(target: str, config: ReconConfig | None = None, *, ports: str = "top1000",
                 scan_type: str = "connect", detect_services: bool = True, **_: Any) -> ScanReport:
    from recon.modules.port_scan import PortScanner

    cfg = config or ReconConfig()
    report = _report(target, "portscan")
    results = PortScanner(target, cfg).scan_ports(
        ports=ports, scan_type=scan_type, detect_services=detect_services)
    host = HostResult(ip=target)
    host.ports = [r.to_dict() for r in results if r.state != "closed"]
    report.add_host(host)
    report.metadata["ports_spec"] = ports
    report.finalize()
    return report


def run_vulnscan(target: str, config: ReconConfig | None = None, *, ports: str | None = None,
                 **_: Any) -> ScanReport:
    from recon.modules.port_scan import PortScanner
    from recon.modules.vuln_scan import VulnScanner

    cfg = config or ReconConfig()
    report = _report(target, "vulnscan")
    port_results = [r.to_dict() for r in PortScanner(target, cfg).scan_ports(
        ports=ports or "top100", scan_type="connect", detect_services=True)]
    for finding in VulnScanner(target, cfg).run_full(
        port_results=port_results, check_creds=True, check_misconfig=True,
        check_cve=True, check_ssl=True,
    ):
        report.add_finding(finding)  # canonical Finding; add_finding coerces
    report.finalize()
    return report


def run_dns(target: str, config: ReconConfig | None = None, **_: Any) -> ScanReport:
    from recon.modules.dns_enum import DNSEnumerator

    cfg = config or ReconConfig()
    report = _report(target, "dns")
    results = DNSEnumerator(target, cfg).run_full(
        do_zone=True, do_brute=True, do_records=True, do_dnssec=True)

    def _d(obj):
        return obj.to_dict() if hasattr(obj, "to_dict") else obj

    for rec in results.get("records", []):
        report.add_dns(_d(rec))
    for rec in results.get("zone_transfer", []):
        d = _d(rec)
        report.add_dns({**d, "source": "axfr"} if isinstance(d, dict) else d)
    for sub in results.get("subdomains", []):
        report.add_subdomain(_d(sub))
    if results.get("dnssec"):
        report.metadata["dnssec"] = results["dnssec"]
    report.finalize()
    return report


def run_os(target: str, config: ReconConfig | None = None, **_: Any) -> ScanReport:
    from recon.modules.os_fingerprint import OSFingerprinter

    cfg = config or ReconConfig()
    report = _report(target, "os")
    guess = OSFingerprinter(target, cfg).run_full()
    report.add_host(HostResult(
        ip=target, os_guess=getattr(guess, "os_guess", ""),
        os_confidence=getattr(guess, "confidence", 0)))
    report.metadata["os"] = {
        "guess": getattr(guess, "os_guess", ""),
        "confidence": getattr(guess, "confidence", 0),
        "methods": getattr(guess, "methods", {}),
    }
    report.finalize()
    return report


def run_discover(target: str, config: ReconConfig | None = None, **_: Any) -> ScanReport:
    from recon.modules.host_discovery import HostDiscovery
    from recon.core.privilege import PrivilegeChecker

    cfg = config or ReconConfig()
    report = _report(target, "discover")
    priv = PrivilegeChecker()
    priv.check()
    hosts = HostDiscovery(target, cfg).run_full(
        use_arp=priv.can("arp_sweep"), use_icmp=True, use_tcp=True, use_udp=False)
    for h in hosts:
        report.add_host(HostResult(
            ip=h.ip, hostname=getattr(h, "hostname", ""), mac=getattr(h, "mac", ""),
            vendor=getattr(h, "vendor", ""), ttl=getattr(h, "ttl", 0),
            methods=list(getattr(h, "methods", [])),
            os_guess=getattr(h, "ttl_os_hint", "")))
    report.finalize()
    return report


def run_full(target: str, config: ReconConfig | None = None, **_: Any) -> ScanReport:
    """Pipeline: discover -> OS -> ports -> vulns, into one ScanReport."""
    from recon.modules.host_discovery import HostDiscovery
    from recon.modules.os_fingerprint import OSFingerprinter
    from recon.modules.port_scan import PortScanner
    from recon.modules.vuln_scan import VulnScanner
    from recon.core.privilege import PrivilegeChecker

    cfg = config or ReconConfig()
    report = _report(target, "full")
    priv = PrivilegeChecker()
    status = priv.check()
    hosts = HostDiscovery(target, cfg).run_full(
        use_arp=status.is_root, use_icmp=True, use_tcp=True, use_udp=False)
    scan_type = "syn" if priv.can("syn_scan") else "connect"
    for h in hosts[:20]:
        guess = OSFingerprinter(h.ip, cfg).run_full()
        hr = HostResult(
            ip=h.ip, hostname=getattr(h, "hostname", ""), mac=getattr(h, "mac", ""),
            vendor=getattr(h, "vendor", ""), os_guess=getattr(guess, "os_guess", ""),
            os_confidence=getattr(guess, "confidence", 0), ttl=getattr(h, "ttl", 0))
        open_ports = PortScanner(h.ip, cfg).scan_ports(
            ports="top1000", scan_type=scan_type, detect_services=True)
        hr.ports = [r.to_dict() for r in open_ports if r.state != "closed"]
        report.add_host(hr)
        if hr.ports:
            for finding in VulnScanner(h.ip, cfg).run_full(
                port_results=hr.ports, check_creds=True, check_misconfig=True,
                check_cve=True, check_ssl=True,
            ):
                report.add_finding(finding)
    report.finalize()
    return report


def safe_run(spec_or_name, target: str, config: ReconConfig | None = None, **opts: Any) -> ScanReport:
    """Run a capability and NEVER raise.

    Looks up the ScannerSpec (by name or object), runs it, and on any failure
    returns a ScanReport whose `errors` records what went wrong — so a broken
    module, bad target or network error degrades to a clean, reportable result
    instead of a traceback. This is the entry point both front-ends use.
    """
    from recon.core.registry import get

    spec = spec_or_name if hasattr(spec_or_name, "runner") else get(spec_or_name)
    name = getattr(spec, "name", str(spec_or_name))
    if spec is None or spec.runner is None:
        report = _report(target, name)
        report.errors.append(f"capability {name!r} is not runnable")
        report.finalize()
        return report
    try:
        return spec.runner(target, config, **opts)
    except Exception as exc:  # fail-safe: no scan failure crashes the tool
        _log.error("%s failed on %s: %s", name, target, exc)
        report = _report(target, name)
        report.errors.append(f"{name} failed: {exc}")
        report.finalize()
        return report


# --------------------------------------------------------------------------- #
# Registry — every capability is declared here with a runner so both front-ends #
# (CLI `recon list`, the interactive menu) can enumerate and invoke them.        #
# --------------------------------------------------------------------------- #

def _register_all() -> None:
    specs = [
        ScannerSpec("dns", "DNS enumeration: AXFR, brute-force, records, DNSSEC", None, run_dns, 10),
        ScannerSpec("discover", "Host discovery: ARP/ICMP/TCP/UDP sweep", None, run_discover, 20),
        ScannerSpec("os", "OS fingerprinting: TTL, TCP stack, banners", None, run_os, 30),
        ScannerSpec("portscan", "Port scan: SYN/connect/FIN/XMAS/NULL/ACK/UDP", None, run_portscan, 40),
        ScannerSpec("vulnscan", "Vulnerability scan: CVE, SSL, default creds, misconfig", None, run_vulnscan, 50),
        ScannerSpec("wireless", "Wireless recon: monitor mode, 802.11 capture", "monitor_mode", None, 60),
        ScannerSpec("full", "Full pipeline: discover -> OS -> ports -> vulns -> report", None, run_full, 70),
        ScannerSpec("asyncscan", "High-concurrency async connect scan (no root)", None, run_async, 80),
        ScannerSpec("httpprobe", "HTTP: WAF/CDN/tech fingerprint, security headers, paths", None, run_http, 90),
        ScannerSpec("tlsprobe", "TLS: protocols, ciphers, cert chain, CT logs", None, run_tls, 100),
        ScannerSpec("smbenum", "SMB: dialects, signing, MS17-010/SMBGhost pre-checks", None, run_smb, 110),
        ScannerSpec("snmpenum", "SNMP: community brute, sysInfo, interfaces, routes", None, run_snmp, 120),
    ]
    for spec in specs:
        register(spec)


_register_all()
