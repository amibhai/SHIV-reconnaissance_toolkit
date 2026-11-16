"""Registry + engine: capability discovery, privilege gating, finding coercion."""

from __future__ import annotations

import pytest

from recon import engine
from recon.core.registry import REGISTRY, all_specs, available
from recon.core.privilege import PrivilegeChecker


def test_registry_has_all_capabilities():
    names = {s.name for s in all_specs()}
    assert {"dns", "discover", "os", "portscan", "vulnscan", "full",
            "asyncscan", "httpprobe", "tlsprobe", "smbenum", "snmpenum"} <= names
    assert len(REGISTRY) >= 12


def test_available_gates_on_privilege(monkeypatch):
    priv = PrivilegeChecker()
    # Force a no-raw environment: only unprivileged features available.
    monkeypatch.setattr(priv, "can", lambda feature: feature not in {"monitor_mode", "syn_scan"})
    names = {s.name for s in available(priv)}
    assert "wireless" not in names        # needs monitor_mode
    assert "asyncscan" in names and "tlsprobe" in names


def test_coerce_findings_maps_module_shape():
    raws = [
        {"severity": "CRITICAL", "issue": "SMBv1 enabled", "detail": "disable it"},
        {"severity": "HIGH", "issue": "Self-signed cert", "detail": "no CA"},
    ]
    findings = engine.coerce_findings(raws, host="10.0.0.1", service="smb", port=445)
    d0 = findings[0].to_dict()
    assert d0["severity"] == "critical"
    assert d0["title"] == "SMBv1 enabled"
    assert d0["port"] == 445 and d0["host"] == "10.0.0.1"
    assert findings[1].to_dict()["severity"] == "high"


def test_run_async_builds_report_localhost():
    report = engine.run_async("127.0.0.1", ports="80,443")
    assert report.scan_type == "async"
    assert "async_scan" in report.metadata
    assert len(report.hosts) == 1 and report.hosts[0].ip == "127.0.0.1"


def test_safe_run_never_raises_on_module_failure():
    from recon.core.registry import ScannerSpec, register, REGISTRY

    def boom(target, config=None, **opts):
        raise RuntimeError("module exploded")

    register(ScannerSpec("boomtest", "always fails", None, boom, 999))
    try:
        report = engine.safe_run("boomtest", "10.0.0.1")
        assert report.scan_type == "boomtest"
        assert any("boomtest failed" in e for e in report.errors)
        assert report.end_time is not None  # finalized
    finally:
        REGISTRY.pop("boomtest", None)


def test_safe_run_unknown_capability_is_reported():
    report = engine.safe_run("does-not-exist", "10.0.0.1")
    assert any("not runnable" in e for e in report.errors)


def test_safe_run_wireless_has_no_runner_is_reported():
    # wireless is registered without a runner -> reported, not crashed.
    report = engine.safe_run("wireless", "10.0.0.1")
    assert any("not runnable" in e for e in report.errors)
