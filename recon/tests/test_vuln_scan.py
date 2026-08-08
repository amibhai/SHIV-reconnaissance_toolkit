"""Tests for recon.modules.vuln_scan — mocked network calls."""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from recon.modules.vuln_scan import VulnScanner, Finding, _cvss_to_severity
from recon.core.config import ReconConfig


@pytest.fixture
def cfg():
    return ReconConfig(threads=5, timeout=1.0)


@pytest.fixture
def scanner(cfg):
    return VulnScanner("127.0.0.1", cfg)


# ── Severity mapping ──────────────────────────────────────────────────────────

def test_cvss_critical():
    assert _cvss_to_severity(9.5) == "critical"
    assert _cvss_to_severity(10.0) == "critical"


def test_cvss_high():
    assert _cvss_to_severity(7.0) == "high"
    assert _cvss_to_severity(8.9) == "high"


def test_cvss_medium():
    assert _cvss_to_severity(4.0) == "medium"
    assert _cvss_to_severity(6.9) == "medium"


def test_cvss_low():
    assert _cvss_to_severity(0.1) == "low"
    assert _cvss_to_severity(3.9) == "low"


def test_cvss_info():
    assert _cvss_to_severity(0.0) == "info"


# ── Finding dataclass ─────────────────────────────────────────────────────────

def test_finding_to_dict():
    f = Finding(
        severity="critical",
        finding="CVE-2021-44228",
        service="log4j",
        port=8080,
        description="Log4Shell RCE",
        evidence="log4j-2.14.1.jar",
        remediation="Upgrade to 2.17.1",
        cvss_score=10.0,
    )
    d = f.to_dict()
    assert d["severity"] == "critical"
    assert d["cve"] == "CVE-2021-44228"
    assert d["port"] == 8080
    assert len(d["evidence"]) <= 500


# ── CVE matching ──────────────────────────────────────────────────────────────

def test_cve_match_apache(scanner):
    """Apache 2.4.49 banner should match CVE-2021-41773."""
    from recon.modules.vuln_scan import _load_databases, _CVE_DB
    _load_databases()
    banner = "Apache/2.4.49 (Unix)"
    findings = scanner.check_service_vulns(80, banner, "apache")
    cve_ids = [f.finding for f in findings]
    assert "CVE-2021-41773" in cve_ids


def test_cve_match_vsftpd(scanner):
    """vsftpd 2.3.4 banner should match CVE-2011-2523."""
    from recon.modules.vuln_scan import _load_databases
    _load_databases()
    banner = "220 (vsFTPd 2.3.4)"
    findings = scanner.check_service_vulns(21, banner, "vsftpd")
    cve_ids = [f.finding for f in findings]
    assert "CVE-2011-2523" in cve_ids


def test_no_false_positive_new_apache(scanner):
    """Apache 2.4.51 should NOT match CVE-2021-41773."""
    from recon.modules.vuln_scan import _load_databases
    _load_databases()
    banner = "Apache/2.4.51 (Unix)"
    findings = scanner.check_service_vulns(80, banner, "apache")
    cve_ids = [f.finding for f in findings]
    assert "CVE-2021-41773" not in cve_ids


# ── SSL audit (mocked) ────────────────────────────────────────────────────────

def test_ssl_audit_structure(scanner):
    """ssl_audit returns expected keys even when connection fails."""
    with patch.object(scanner, "_test_tls_protocol", return_value=False):
        with patch.object(scanner, "_get_cert_info", return_value={}):
            with patch.object(scanner, "_check_weak_ciphers", return_value=[]):
                result = scanner.ssl_audit(443)
    assert "protocol_support" in result
    assert "cert_info" in result
    assert "findings" in result


def test_expired_cert_finding(scanner):
    """Expired certificate should generate a critical finding."""
    mock_cert = {
        "subject": {"commonName": "example.com"},
        "issuer": {"commonName": "example.com"},
        "not_after": "Jan 01 00:00:00 2020 GMT",
        "days_until_expiry": -500,
        "sans": [],
        "self_signed": True,
        "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
    }
    findings_out: list = []
    scanner._check_cert_findings(mock_cert, 443, findings_out)
    sevs = [f["severity"] for f in findings_out]
    assert "critical" in sevs


# ── Misconfiguration checks (mocked) ─────────────────────────────────────────

def test_unauthenticated_redis(scanner):
    """Unauthenticated Redis PING should generate critical finding."""
    with patch.object(scanner, "_try_redis", return_value=(True, "Redis PONG")):
        f = scanner._check_unauthenticated_redis(6379)
    assert f is not None
    assert f.severity == "critical"
    assert f.finding == "REDIS-NO-AUTH"


def test_authenticated_redis(scanner):
    """Authenticated Redis should NOT generate a finding."""
    with patch.object(scanner, "_try_redis", return_value=(False, "")):
        f = scanner._check_unauthenticated_redis(6379)
    assert f is None


def test_anon_ftp(scanner):
    """Anonymous FTP should generate high-severity finding."""
    with patch.object(scanner, "_try_ftp", return_value=(True, "220 FTP server ready")):
        f = scanner._check_anon_ftp(21)
    assert f is not None
    assert f.severity == "high"


def test_run_full_skips_ssl_when_disabled(scanner):
    """check_ssl=False must not trigger any TLS handshake, even on 443."""
    ports = [{"port": 443, "service": "https", "banner": "", "version": ""}]
    with patch.object(scanner, "ssl_audit") as mock_ssl:
        scanner.run_full(
            port_results=ports,
            check_creds=False,
            check_misconfig=False,
            check_cve=False,
            check_ssl=False,
        )
    mock_ssl.assert_not_called()


def test_run_full_runs_ssl_when_enabled(scanner):
    """check_ssl=True audits TLS-looking ports exactly once each."""
    ports = [
        {"port": 443, "service": "https", "banner": "", "version": ""},
        {"port": 8080, "service": "http", "banner": "", "version": ""},
    ]
    with patch.object(scanner, "ssl_audit") as mock_ssl:
        scanner.run_full(
            port_results=ports,
            check_creds=False,
            check_misconfig=False,
            check_cve=False,
            check_ssl=True,
        )
    audited = {c.args[0] for c in mock_ssl.call_args_list}
    assert audited == {443}
    assert mock_ssl.call_count == 1


def test_findings_sorted(scanner):
    """findings() returns results sorted by severity."""
    scanner._findings = [
        Finding("low", "L1", "http", 80, "Low finding"),
        Finding("critical", "C1", "ftp", 21, "Critical finding"),
        Finding("medium", "M1", "ssh", 22, "Medium finding"),
        Finding("high", "H1", "redis", 6379, "High finding"),
    ]
    sorted_f = scanner.findings()
    sevs = [f.severity for f in sorted_f]
    assert sevs.index("critical") < sevs.index("high")
    assert sevs.index("high") < sevs.index("medium")
    assert sevs.index("medium") < sevs.index("low")
