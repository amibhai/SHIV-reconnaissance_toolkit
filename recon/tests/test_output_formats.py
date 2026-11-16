"""SARIF / NDJSON / atomic-write output tests."""

from __future__ import annotations

import json

import pytest

from recon.core.findings import Finding, Severity
from recon.core.output import OutputManager, ScanReport


@pytest.fixture
def report():
    r = ScanReport(target="10.0.0.1", scan_type="full")
    r.add_finding(Finding(id="CVE-2021-41773", title="Apache path traversal",
                          severity=Severity.critical, cve=["CVE-2021-41773"], cvss=9.8,
                          host="10.0.0.1", port=80, service="http", remediation="Upgrade"))
    r.add_finding(Finding(id="SSL-WEAK", title="TLS 1.0 enabled", severity=Severity.medium,
                          host="10.0.0.1", port=443, service="https"))
    r.finalize()
    return r


def test_sarif_shape(tmp_path, report):
    path = OutputManager(tmp_path, "s").write_sarif(report)
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "recon-toolkit" and driver["version"]
    assert len(driver["rules"]) == 2
    results = doc["runs"][0]["results"]
    r0 = next(r for r in results if r["ruleId"] == "CVE-2021-41773")
    assert r0["level"] == "error"
    assert r0["locations"][0]["logicalLocations"][0]["name"] == "10.0.0.1:80/http"


def test_ndjson_lines_parse_and_are_typed(tmp_path, report):
    path = OutputManager(tmp_path, "n").write_ndjson(report)
    recs = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert recs[0]["type"] == "run" and recs[0]["version"] and recs[0]["target"] == "10.0.0.1"
    findings = [r for r in recs if r["type"] == "finding"]
    assert {f["id"] for f in findings} == {"CVE-2021-41773", "SSL-WEAK"}
    assert all("target" in r for r in recs)  # each line self-contained


def test_write_all_honors_formats_and_is_atomic(tmp_path, report):
    mgr = OutputManager(tmp_path, "a")
    out = mgr.write_all(report, ["json", "sarif", "ndjson"])
    assert set(out) == {"json", "sarif", "ndjson"}
    assert not (tmp_path / "a.html").exists()  # html not requested
    for p in out.values():
        assert p.exists()
    assert not list(tmp_path.glob(".tmp_*")), "atomic write left a temp file behind"


def test_sarif_and_ndjson_carry_kev(tmp_path):
    from recon.core.findings import Finding, Severity
    from recon.core.output import OutputManager, ScanReport
    import json as _json

    r = ScanReport(target="10.0.0.1", scan_type="vulnscan")
    r.add_finding(Finding(id="CVE-2021-44228", title="Log4Shell", severity=Severity.critical,
                          cve=["CVE-2021-44228"], host="10.0.0.1", port=8080, service="http"))
    r.finalize()
    mgr = OutputManager(tmp_path, "kev")
    sarif = _json.loads(mgr.write_sarif(r).read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"][0]["properties"]["kev"] is True
    ndjson = mgr.write_ndjson(r).read_text(encoding="utf-8")
    finding_line = [l for l in ndjson.splitlines() if '"type": "finding"' in l][0]
    assert _json.loads(finding_line)["kev"] is True
