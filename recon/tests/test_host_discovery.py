"""Host-discovery tests: per-OS ping, MAC vendor lookup, target parsing."""

from __future__ import annotations

import platform
import subprocess

import pytest

from recon.modules import host_discovery as hd


class _PingResult:
    def __init__(self, rc, out=b""):
        self.returncode = rc
        self.stdout = out
        self.stderr = b""


def _run_sys_ping(monkeypatch, config, system, result):
    disc = hd.HostDiscovery("127.0.0.1", config)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(platform, "system", lambda: system)
    monkeypatch.setattr(subprocess, "run", fake_run)
    ok = disc._sys_ping("203.0.113.5")
    return ok, captured["cmd"]


def test_sys_ping_windows_flags_and_reply_guard(monkeypatch, config):
    ok, cmd = _run_sys_ping(
        monkeypatch, config, "Windows",
        _PingResult(0, b"Reply from 203.0.113.5: bytes=32 time<1ms TTL=118"),
    )
    assert ok is True
    assert cmd[:4] == ["ping", "-n", "1", "-w"]  # NOT the Linux -W


def test_sys_ping_windows_unreachable_is_false(monkeypatch, config):
    # Windows `ping` exits 0 on "unreachable"; no TTL in output -> treat as down.
    ok, cmd = _run_sys_ping(
        monkeypatch, config, "Windows",
        _PingResult(0, b"Reply from 203.0.113.1: Destination host unreachable."),
    )
    assert ok is False


def test_sys_ping_linux_flags(monkeypatch, config):
    ok, cmd = _run_sys_ping(
        monkeypatch, config, "Linux",
        _PingResult(0, b"64 bytes from 203.0.113.5: icmp_seq=1 ttl=56 time=1 ms"),
    )
    assert ok is True
    assert cmd[:4] == ["ping", "-c", "1", "-W"]


def test_sys_ping_macos_flags(monkeypatch, config):
    ok, cmd = _run_sys_ping(
        monkeypatch, config, "Darwin",
        _PingResult(0, b"64 bytes from 203.0.113.5: icmp_seq=0 ttl=56 time=1 ms"),
    )
    assert ok is True
    assert cmd[:4] == ["ping", "-c", "1", "-t"]


def test_mac_vendor_resolves_known_oui():
    assert "VMware" in hd._mac_vendor("00:0c:29:ab:cd:ef")
    assert hd._mac_vendor("de:ad:be:ef:00:01") == "Unknown"


def test_parse_targets_cidr_and_range():
    assert hd.parse_targets("192.168.1.5") == ["192.168.1.5"]
    assert hd.parse_targets("10.0.0.1-3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert "192.168.1.1" in hd.parse_targets("192.168.1.0/30")
