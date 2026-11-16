"""Tests for the canonical Finding model (recon.core.findings)."""

from __future__ import annotations

import pytest

from recon.core.findings import Confidence, Finding, Severity


def test_severity_rank_ordering():
    order = sorted(Severity, key=lambda s: s.rank, reverse=True)
    assert order == [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]


def test_severity_coerce_unknown_is_info():
    assert Severity.coerce("CRITICAL") is Severity.critical
    assert Severity.coerce("nonsense") is Severity.info
    assert Severity.coerce(None) is Severity.info


def test_finding_to_dict_shape():
    f = Finding(id="CVE-2021-41773", title="Apache path traversal",
                severity=Severity.critical, confidence=Confidence.confirmed,
                cve=["CVE-2021-41773"], cvss=9.8, host="10.0.0.1", port=80,
                service="http", evidence="x" * 999, references=["https://x"],
                remediation="upgrade")
    d = f.to_dict()
    assert d["severity"] == "critical" and d["confidence"] == "confirmed"
    assert d["cve"] == ["CVE-2021-41773"] and d["cvss"] == 9.8
    assert d["port"] == 80 and d["host"] == "10.0.0.1"
    assert len(d["evidence"]) <= 500  # evidence is truncated


def test_from_legacy_maps_old_shape():
    f = Finding.from_legacy(severity="high", finding="CVE-2019-0708",
                            service="rdp", port=3389,
                            description="BlueKeep RCE", cvss_score=9.8)
    d = f.to_dict()
    assert d["id"] == "CVE-2019-0708"
    assert d["title"] == "BlueKeep RCE"
    assert d["severity"] == "high"
    assert d["cve"] == ["CVE-2019-0708"]  # parsed from the id
    assert d["cvss"] == 9.8


def test_from_legacy_non_cve_id_has_empty_cve_list():
    f = Finding.from_legacy(severity="critical", finding="REDIS-NO-AUTH",
                            service="redis", port=6379, description="Unauthenticated Redis")
    d = f.to_dict()
    assert d["id"] == "REDIS-NO-AUTH" and d["cve"] == [] and d["cvss"] is None


def test_scanreport_severity_counts_and_summary():
    from recon.core.output import ScanReport

    r = ScanReport(target="t", scan_type="x")
    r.add_finding(Finding(id="A", title="a", severity=Severity.critical))
    r.add_finding(Finding(id="B", title="b", severity=Severity.medium))
    r.add_finding({"severity": "medium", "id": "C", "title": "c"})  # dict path
    counts = r.severity_counts()
    assert counts["critical"] == 1 and counts["medium"] == 2
    summary = r.to_dict()["summary"]
    assert summary["critical"] == 1 and summary["medium"] == 2 and summary["info"] == 0


def test_kev_auto_tagging():
    log4shell = Finding(id="CVE-2021-44228", title="Log4Shell", severity=Severity.critical,
                        cve=["CVE-2021-44228"])
    benign = Finding(id="CVE-2011-2523", title="vsftpd backdoor", severity=Severity.critical,
                     cve=["CVE-2011-2523"])
    assert log4shell.kev is True and log4shell.to_dict()["kev"] is True
    assert benign.kev is False
    # also via the legacy factory path
    assert Finding.from_legacy(severity="high", finding="CVE-2019-0708", description="BlueKeep").kev is True
