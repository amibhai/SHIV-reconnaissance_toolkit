"""SYN/UDP raw scans must degrade to connect scans when raw send fails."""

from __future__ import annotations

import pytest

from recon.modules import port_scan as ps


def test_syn_scan_falls_back_to_connect_when_raw_send_raises(monkeypatch, config):
    scanner = ps.PortScanner("127.0.0.1", config)
    # Pretend the capability check says SYN is available...
    monkeypatch.setattr(scanner._priv, "can", lambda feature: True)
    # ...but the actual raw send raises at runtime (e.g. Npcap missing).
    import scapy.sendrecv as snd

    def boom(*a, **k):
        raise OSError("no raw backend")

    monkeypatch.setattr(snd, "sr", boom)

    sentinel = [ps.PortResult(port=80, state="open", scan_type="connect")]
    monkeypatch.setattr(scanner, "connect_scan", lambda ports: sentinel)

    out = scanner.syn_scan([80, 443])
    assert out is sentinel, "syn_scan should return the connect-scan fallback, not []"


def test_udp_scan_falls_back_to_connect_when_raw_send_raises(monkeypatch, config):
    scanner = ps.PortScanner("127.0.0.1", config)
    monkeypatch.setattr(scanner._priv, "can", lambda feature: True)
    import scapy.sendrecv as snd

    def boom(*a, **k):
        raise OSError("no raw backend")

    monkeypatch.setattr(snd, "sr", boom)
    sentinel = [ps.PortResult(port=53, state="open", scan_type="udp", protocol="udp")]
    monkeypatch.setattr(scanner, "_udp_connect_scan", lambda ports: sentinel)

    out = scanner.udp_scan([53])
    assert out is sentinel
