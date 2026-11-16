"""
recon.core.output — Unified output manager for all scan modules.

Produces JSON, CSV, HTML (Jinja2), and PCAP outputs from a structured
ScanReport dataclass that aggregates results across modules.
"""

from __future__ import annotations

import csv
import html
import json
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from recon.__version__ import __version__

__all__ = ["ScanReport", "OutputManager"]


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os_guess: str = ""
    os_confidence: int = 0
    methods: list[str] = field(default_factory=list)
    ports: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    ttl: int = 0


@dataclass
class ScanReport:
    """Aggregate container for all scan results."""

    target: str
    scan_type: str
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: datetime | None = None
    operator: str = ""
    hosts: list[HostResult] = field(default_factory=list)
    dns_records: list[dict[str, Any]] = field(default_factory=list)
    subdomains: list[dict[str, Any]] = field(default_factory=list)
    wireless_networks: list[dict[str, Any]] = field(default_factory=list)
    raw_findings: list[dict[str, Any]] = field(default_factory=list)
    pcap_files: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def finalize(self) -> None:
        """Mark the scan as complete."""
        self.end_time = datetime.now(timezone.utc)

    def duration_seconds(self) -> float:
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds()

    def add_host(self, host: HostResult) -> None:
        with self._lock:
            self.hosts.append(host)

    def add_finding(self, finding: Any) -> None:
        # Accept a canonical recon.core.findings.Finding or a plain dict and
        # store the dict form, so producers can emit either.
        record = finding.to_dict() if hasattr(finding, "to_dict") else finding
        with self._lock:
            self.raw_findings.append(record)

    def add_dns(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.dns_records.append(record)

    def add_subdomain(self, sub: dict[str, Any]) -> None:
        with self._lock:
            self.subdomains.append(sub)

    def critical_count(self) -> int:
        return sum(
            1 for f in self.raw_findings if f.get("severity", "").lower() == "critical"
        )

    def high_count(self) -> int:
        return sum(
            1 for f in self.raw_findings if f.get("severity", "").lower() == "high"
        )

    def severity_counts(self) -> dict[str, int]:
        """Counts per severity (critical/high/medium/low/info), thread-safe."""
        with self._lock:
            findings = list(self.raw_findings)
        counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        for f in findings:
            sev = str(f.get("severity", "")).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        # Snapshot shared state under the lock so a concurrent add_* (which also
        # takes the lock) cannot mutate a list mid-serialization — the previous
        # version iterated the live lists lock-free and could raise
        # "list changed size during iteration" during recon.py full.
        with self._lock:
            hosts = list(self.hosts)
            dns_records = list(self.dns_records)
            subdomains = list(self.subdomains)
            wireless = list(self.wireless_networks)
            findings = list(self.raw_findings)
            pcap_files = list(self.pcap_files)
            errors = list(self.errors)
            metadata = dict(self.metadata)

        def _count(sev: str) -> int:
            return sum(1 for f in findings if str(f.get("severity", "")).lower() == sev)

        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds(),
            "operator": self.operator,
            "summary": {
                "hosts_found": len(hosts),
                "dns_records": len(dns_records),
                "subdomains": len(subdomains),
                "findings": len(findings),
                "critical": _count("critical"),
                "high": _count("high"),
                "medium": _count("medium"),
                "low": _count("low"),
                "info": _count("info"),
            },
            "hosts": [
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "mac": h.mac,
                    "vendor": h.vendor,
                    "os_guess": h.os_guess,
                    "os_confidence": h.os_confidence,
                    "methods": h.methods,
                    "ports": h.ports,
                    "findings": h.findings,
                    "ttl": h.ttl,
                }
                for h in hosts
            ],
            "dns_records": dns_records,
            "subdomains": subdomains,
            "wireless_networks": wireless,
            "findings": findings,
            "pcap_files": [str(p) for p in pcap_files],
            "errors": errors,
            "metadata": metadata,
        }


class OutputManager:
    """
    Manages writing scan results to disk in multiple formats.

    Args:
        output_dir: Base directory for all output files.
        base_name: Filename prefix (default: target name + timestamp).
    """

    def __init__(self, output_dir: Path, base_name: str = "") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.base_name = base_name or f"recon_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

    def _path(self, extension: str) -> Path:
        return self.output_dir / f"{self.base_name}.{extension}"

    def write_json(self, report: ScanReport) -> Path:
        """
        Serialize the full ScanReport to a JSON file.

        Args:
            report: Completed ScanReport instance.

        Returns:
            Path to the written file.
        """
        path = self._path("json")
        return self._atomic_write_text(path, json.dumps(report.to_dict(), indent=2, default=str))

    def write_csv(self, report: ScanReport) -> Path:
        """
        Write port scan results to CSV.

        Args:
            report: Completed ScanReport instance.

        Returns:
            Path to the written file.
        """
        path = self._path("csv")
        rows: list[dict[str, Any]] = []
        for host in report.hosts:
            for port in host.ports:
                rows.append(
                    {
                        "ip": host.ip,
                        "hostname": host.hostname,
                        "port": port.get("port", ""),
                        "state": port.get("state", ""),
                        "service": port.get("service", ""),
                        "version": port.get("version", ""),
                        "scan_type": port.get("scan_type", ""),
                    }
                )
        if not rows:
            rows = [{"target": report.target, "scan_type": report.scan_type}]

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        return path

    def write_findings_csv(self, report: ScanReport) -> Path:
        """Write findings to CSV — the primary tabular export for triage/CI."""
        path = self.output_dir / f"{self.base_name}_findings.csv"
        fields = ["id", "title", "severity", "confidence", "cve", "cvss",
                  "host", "port", "service", "remediation"]
        findings = report.to_dict().get("findings", [])
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for finding in findings:
                row = dict(finding)
                if isinstance(row.get("cve"), list):
                    row["cve"] = ";".join(row["cve"])
                writer.writerow({k: row.get(k, "") for k in fields})
        return path

    def write_html(self, report: ScanReport) -> Path:
        """
        Render an HTML report via Jinja2 template.

        Args:
            report: Completed ScanReport instance.

        Returns:
            Path to the rendered HTML file.
        """
        try:
            from jinja2 import Environment, FileSystemLoader
        except ImportError:
            return self._write_html_fallback(report)

        template_dir = Path(__file__).parent.parent / "reports"
        template_file = template_dir / "template.html"

        if not template_file.exists():
            return self._write_html_fallback(report)

        env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
        tmpl = env.get_template("template.html")

        rendered = tmpl.render(
            report=report.to_dict(),
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )
        return self._atomic_write_text(self._path("html"), rendered)

    def _write_html_fallback(self, report: ScanReport) -> Path:
        """Minimal HTML fallback when Jinja2 or template is unavailable."""
        data = report.to_dict()
        path = self._path("html")
        esc = html.escape
        target = esc(str(data["target"]))
        lines = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'>",
            f"<title>Recon Report — {target}</title>",
            "<style>body{font-family:monospace;background:#1e1e1e;color:#d4d4d4;}",
            "table{border-collapse:collapse;width:100%;}",
            "th,td{border:1px solid #555;padding:6px 10px;}",
            "th{background:#333;}.critical{color:#f44;}.high{color:#f84;}",
            ".medium{color:#fa0;}.low{color:#8f8;}.info{color:#8cf;}</style></head>",
            f"<body><h1>Recon Report: {target}</h1>",
            f"<p>Scan type: {esc(str(data['scan_type']))} | Duration: {data['duration_seconds']:.1f}s</p>",
            f"<p>Hosts: {data['summary']['hosts_found']} | "
            f"Findings: {data['summary']['findings']} | "
            f"Critical: {data['summary']['critical']}</p>",
        ]

        if data.get("findings"):
            lines.append("<h2>Findings</h2><table><tr>")
            lines.append("<th>Severity</th><th>CVE</th><th>Service</th><th>Port</th><th>Description</th></tr>")
            for f in data["findings"]:
                sev = esc(str(f.get("severity", "info")).lower())
                cve = f.get("cve")
                cve_str = ", ".join(cve) if isinstance(cve, list) else str(cve or f.get("id", ""))
                port = f.get("port")
                lines.append(
                    f"<tr><td class='{sev}'>{sev.upper()}</td>"
                    f"<td>{esc(cve_str or str(f.get('id', 'N/A')))}</td>"
                    f"<td>{esc(str(f.get('service', '')))}</td>"
                    f"<td>{esc('' if port is None else str(port))}</td>"
                    f"<td>{esc(str(f.get('title', f.get('description', ''))))}</td></tr>"
                )
            lines.append("</table>")

        lines.append("</body></html>")
        return self._atomic_write_text(path, "\n".join(lines))

    def _atomic_write_text(self, path: Path, text: str) -> Path:
        """Write text atomically: a temp file in the same dir + os.replace, so a
        crash mid-write never leaves a half-written/corrupt artifact."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.output_dir), prefix=".tmp_", suffix=path.suffix)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
                f.write(text)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return path

    def write_ndjson(self, report: ScanReport) -> Path:
        """Newline-delimited JSON: one self-contained record per line for SIEM /
        log ingestion (a run header, then one line per finding and per host)."""
        data = report.to_dict()
        run_id = f"{data.get('scan_type', 'scan')}-{self.base_name}"
        records: list[dict[str, Any]] = [{
            "type": "run", "run_id": run_id, "target": data.get("target"),
            "scan_type": data.get("scan_type"), "started": data.get("start_time"),
            "version": __version__, "summary": data.get("summary"),
        }]
        for finding in data.get("findings", []):
            rec = {"type": "finding", "run_id": run_id, "target": data.get("target")}
            rec.update(finding)
            records.append(rec)
        for host in data.get("hosts", []):
            rec = {"type": "host", "run_id": run_id, "target": data.get("target")}
            rec.update(host)
            records.append(rec)
        body = "\n".join(json.dumps(r, default=str) for r in records) + "\n"
        return self._atomic_write_text(self._path("ndjson"), body)

    def write_sarif(self, report: ScanReport) -> Path:
        """SARIF 2.1.0 — ingestible by GitHub code scanning and DefectDojo."""
        data = report.to_dict()
        target = data.get("target", "")
        level_map = {"critical": "error", "high": "error", "medium": "warning",
                     "low": "note", "info": "note"}
        rules: dict[str, dict] = {}
        results: list[dict] = []
        for f in data.get("findings", []):
            cves = f.get("cve") or []
            rid = f.get("id") or (cves[0] if cves else "finding")
            if rid not in rules:
                rule = {"id": rid, "name": rid,
                        "shortDescription": {"text": f.get("title") or rid}}
                if cves:
                    rule["helpUri"] = f"https://nvd.nist.gov/vuln/detail/{cves[0]}"
                if f.get("remediation"):
                    rule["help"] = {"text": f["remediation"]}
                rules[rid] = rule
            host = f.get("host") or target
            port = f.get("port")
            svc = f.get("service", "")
            loc_name = f"{host}:{port}/{svc}" if port is not None else str(host)
            uri = f"tcp://{host}:{port}" if port is not None else f"//{host}"
            results.append({
                "ruleId": rid,
                "level": level_map.get(str(f.get("severity", "info")).lower(), "note"),
                "message": {"text": f.get("title") or rid},
                "locations": [{
                    "logicalLocations": [{"name": loc_name, "kind": "resource"}],
                    "physicalLocation": {"artifactLocation": {"uri": uri}},
                }],
                "properties": {k: f.get(k) for k in ("cvss", "confidence", "severity", "service")
                               if f.get(k) is not None},
            })
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "recon-toolkit",
                    "informationUri": "https://github.com/amibhai/SHIV-reconnaissance_toolkit",
                    "version": __version__,
                    "rules": list(rules.values()),
                }},
                "results": results,
                "properties": {"target": target, "scan_type": data.get("scan_type")},
            }],
        }
        return self._atomic_write_text(self._path("sarif"), json.dumps(sarif, indent=2, default=str))

    def write_all(self, report: ScanReport, formats: list[str] | None = None) -> dict[str, Path]:
        """Write every requested format; returns {format: path}. Unknown formats
        are ignored (ReconConfig validates the allowed set upstream)."""
        fmts = formats if formats is not None else ["json", "html"]
        dispatch = {
            "json": self.write_json,
            "html": self.write_html,
            "csv": self.write_csv,
            "sarif": self.write_sarif,
            "ndjson": self.write_ndjson,
        }
        out: dict[str, Path] = {}
        for fmt in fmts:
            fn = dispatch.get(fmt)
            if fn is not None:
                out[fmt] = fn(report)
        return out

    def add_pcap(self, report: ScanReport, pcap_path: Path) -> None:
        """
        Register a PCAP file in the report.

        Args:
            report: ScanReport to update.
            pcap_path: Path to the .pcap file.
        """
        report.pcap_files.append(pcap_path)
