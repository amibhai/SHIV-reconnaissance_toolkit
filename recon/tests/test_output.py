"""Tests for recon.core.output — file writing and ScanReport."""

import json
import pytest
from datetime import datetime
from pathlib import Path
from recon.core.output import ScanReport, OutputManager, HostResult


@pytest.fixture
def tmp_report(tmp_path):
    report = ScanReport(target="192.168.1.1", scan_type="test")
    report.add_host(HostResult(
        ip="192.168.1.1", hostname="test.local", os_guess="Linux", os_confidence=80,
        ports=[{"port": 80, "state": "open", "service": "http", "version": "nginx/1.24"}],
    ))
    report.add_finding({
        "severity": "critical", "cve": "CVE-2021-41773", "service": "apache",
        "port": 80, "description": "Path traversal RCE", "remediation": "Upgrade",
    })
    report.add_dns({"name": "example.com", "type": "A", "value": "1.2.3.4", "ttl": 300})
    report.add_subdomain({"fqdn": "admin.example.com", "ips": "1.2.3.4", "ttl": 300})
    report.finalize()
    return report


def test_scan_report_summary(tmp_report):
    assert tmp_report.critical_count() == 1
    assert tmp_report.high_count() == 0
    assert len(tmp_report.hosts) == 1
    assert len(tmp_report.dns_records) == 1
    assert len(tmp_report.subdomains) == 1


def test_scan_report_duration(tmp_report):
    assert tmp_report.duration_seconds() >= 0


def test_scan_report_to_dict(tmp_report):
    d = tmp_report.to_dict()
    assert d["target"] == "192.168.1.1"
    assert d["summary"]["hosts_found"] == 1
    assert d["summary"]["critical"] == 1
    assert d["summary"]["dns_records"] == 1
    assert d["summary"]["subdomains"] == 1


def test_write_json(tmp_path, tmp_report):
    mgr = OutputManager(tmp_path, "test_scan")
    path = mgr.write_json(tmp_report)
    assert path.exists()
    with open(path) as f:
        data = json.load(f)
    assert data["target"] == "192.168.1.1"
    assert len(data["findings"]) == 1


def test_write_csv(tmp_path, tmp_report):
    mgr = OutputManager(tmp_path, "test_scan")
    path = mgr.write_csv(tmp_report)
    assert path.exists()
    content = path.read_text()
    assert "192.168.1.1" in content
    assert "http" in content


def test_write_html_fallback(tmp_path, tmp_report):
    mgr = OutputManager(tmp_path, "test_scan")
    path = mgr._write_html_fallback(tmp_report)
    assert path.exists()
    content = path.read_text()
    assert "192.168.1.1" in content
    assert "CVE-2021-41773" in content


def test_add_pcap(tmp_path, tmp_report):
    mgr = OutputManager(tmp_path, "test_scan")
    fake_pcap = tmp_path / "test.pcap"
    fake_pcap.touch()
    mgr.add_pcap(tmp_report, fake_pcap)
    assert fake_pcap in tmp_report.pcap_files


def test_output_manager_path_naming(tmp_path):
    mgr = OutputManager(tmp_path, "myscan")
    assert "myscan" in str(mgr._path("json"))
    assert str(mgr._path("json")).endswith(".json")


def test_thread_safety(tmp_path):
    """Multiple threads can add to a report simultaneously without corruption."""
    import threading
    report = ScanReport(target="10.0.0.1", scan_type="threaded_test")
    errors = []

    def _add():
        try:
            for i in range(50):
                report.add_finding({"severity": "info", "cve": f"FIND-{i}", "service": "test",
                                    "port": 80, "description": "test"})
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=_add) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(report.raw_findings) == 500
