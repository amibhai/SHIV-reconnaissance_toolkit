"""Privilege/capability detection tests, incl. Windows Npcap gating."""

from __future__ import annotations

import platform

import pytest

from recon.core.privilege import PrivilegeChecker


def _patched(monkeypatch, system, is_root, has_npcap):
    monkeypatch.setattr(platform, "system", lambda: system)
    monkeypatch.setattr(PrivilegeChecker, "_detect_root", staticmethod(lambda p: is_root))
    monkeypatch.setattr(PrivilegeChecker, "_detect_npcap", staticmethod(lambda p: has_npcap))
    # Linux cap probe: treat root as holding the capability (no libcap in CI).
    monkeypatch.setattr(PrivilegeChecker, "_detect_cap", staticmethod(lambda c, p, r: r))
    return PrivilegeChecker().check()


def test_windows_admin_without_npcap_cannot_syn_scan(monkeypatch):
    s = _patched(monkeypatch, "Windows", is_root=True, has_npcap=False)
    assert not s.cap_net_raw
    assert "syn_scan" not in s.available_features
    assert "connect_scan" in s.available_features  # always available
    assert s.raw_backend == "none"


def test_windows_admin_with_npcap_can_syn_scan(monkeypatch):
    s = _patched(monkeypatch, "Windows", is_root=True, has_npcap=True)
    assert s.cap_net_raw and "syn_scan" in s.available_features
    assert s.raw_backend == "npcap"


def test_linux_root_can_syn_scan(monkeypatch):
    s = _patched(monkeypatch, "Linux", is_root=True, has_npcap=False)
    assert "syn_scan" in s.available_features and s.raw_backend == "root"


def test_linux_non_root_cannot_syn_scan(monkeypatch):
    s = _patched(monkeypatch, "Linux", is_root=False, has_npcap=False)
    assert "syn_scan" not in s.available_features
    assert "dns_enum" in s.available_features  # unprivileged feature


def test_non_raw_features_always_available(monkeypatch):
    s = _patched(monkeypatch, "Windows", is_root=False, has_npcap=False)
    for f in ("connect_scan", "dns_enum", "banner_grab", "ssl_audit", "default_creds"):
        assert f in s.available_features
