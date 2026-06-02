"""
recon.core.output — Unified output manager for all scan modules.

Produces JSON, CSV, HTML (Jinja2), and PCAP outputs from a structured
ScanReport dataclass that aggregates results across modules.
"""

from __future__ import annotations

import csv
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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

    def add_finding(self, finding: dict[str, Any]) -> None:
        with self._lock:
            self.raw_findings.append(finding)

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds(),
            "operator": self.operator,
            "summary": {
                "hosts_found": len(self.hosts),
                "dns_records": len(self.dns_records),
                "subdomains": len(self.subdomains),
                "findings": len(self.raw_findings),
                "critical": self.critical_count(),
                "high": self.high_count(),
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
                for h in self.hosts
            ],
            "dns_records": self.dns_records,
            "subdomains": self.subdomains,
            "wireless_networks": self.wireless_networks,
            "findings": self.raw_findings,
            "pcap_files": [str(p) for p in self.pcap_files],
            "errors": self.errors,
            "metadata": self.metadata,
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
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        return path

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
        path = self._path("html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(rendered)
        return path

    def _write_html_fallback(self, report: ScanReport) -> Path:
        """Minimal HTML fallback when Jinja2 or template is unavailable."""
        data = report.to_dict()
        path = self._path("html")
        lines = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'>",
            f"<title>Recon Report — {data['target']}</title>",
            "<style>body{font-family:monospace;background:#1e1e1e;color:#d4d4d4;}",
            "table{border-collapse:collapse;width:100%;}",
            "th,td{border:1px solid #555;padding:6px 10px;}",
            "th{background:#333;}.critical{color:#f44;}.high{color:#f84;}",
            ".medium{color:#fa0;}.low{color:#8f8;}.info{color:#8cf;}</style></head>",
            f"<body><h1>Recon Report: {data['target']}</h1>",
            f"<p>Scan type: {data['scan_type']} | Duration: {data['duration_seconds']:.1f}s</p>",
            f"<p>Hosts: {data['summary']['hosts_found']} | "
            f"Findings: {data['summary']['findings']} | "
            f"Critical: {data['summary']['critical']}</p>",
        ]

        if data.get("findings"):
            lines.append("<h2>Findings</h2><table><tr>")
            lines.append("<th>Severity</th><th>CVE</th><th>Service</th><th>Port</th><th>Description</th></tr>")
            for f in data["findings"]:
                sev = f.get("severity", "info").lower()
                lines.append(
                    f"<tr><td class='{sev}'>{sev.upper()}</td>"
                    f"<td>{f.get('cve','N/A')}</td>"
                    f"<td>{f.get('service','')}</td>"
                    f"<td>{f.get('port','')}</td>"
                    f"<td>{f.get('description','')}</td></tr>"
                )
            lines.append("</table>")

        lines.append("</body></html>")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    def add_pcap(self, report: ScanReport, pcap_path: Path) -> None:
        """
        Register a PCAP file in the report.

        Args:
            report: ScanReport to update.
            pcap_path: Path to the .pcap file.
        """
        report.pcap_files.append(pcap_path)
