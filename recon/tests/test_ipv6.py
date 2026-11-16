"""IPv6 parity for connect-based scanning; raw paths degrade safely."""

from __future__ import annotations

import socket
import threading

import pytest

from recon.core import netutil
from recon.core.config import ReconConfig
from recon.modules.port_scan import PortScanner


def test_resolve_target():
    assert netutil.resolve_target("127.0.0.1") == ("127.0.0.1", False)
    assert netutil.resolve_target("::1") == ("::1", True)
    assert netutil.is_ipv6("::1") and not netutil.is_ipv6("10.0.0.1")
    # unresolvable name is returned as-is, never raises
    host, v6 = netutil.resolve_target("nonexistent.invalid.")
    assert host == "nonexistent.invalid." and v6 is False


def _ipv6_loopback_available() -> bool:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _ipv6_loopback_available(), reason="no IPv6 loopback on this host")
def test_connect_scan_over_ipv6():
    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    srv.bind(("::1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        try:
            c, _ = srv.accept()
            c.close()
        except Exception:
            pass
        finally:
            srv.close()

    threading.Thread(target=serve, daemon=True).start()

    sc = PortScanner("::1", ReconConfig(connect_timeout=2.0, timeout=2.0, output_dir="./output", verbosity=0))
    assert sc._is_ipv6 is True
    results = sc.connect_scan([port])
    assert any(r.port == port and r.state == "open" for r in results)


def test_raw_scans_degrade_on_ipv6(monkeypatch):
    sc = PortScanner("::1", ReconConfig(output_dir="./output", verbosity=0))
    # Pretend raw is "available" so only the IPv6 guard can trigger the fallback.
    monkeypatch.setattr(sc._priv, "can", lambda feature: True)
    # syn_scan must fall back to connect (returns the connect result, no crash).
    monkeypatch.setattr(sc, "connect_scan", lambda ports: ["SENTINEL"])
    assert sc.syn_scan([80]) == ["SENTINEL"]
    # FIN/ACK are raw-only -> empty, never a crafted v6 packet.
    assert sc.fin_scan([80]) == []
    assert sc.ack_scan([80]) == []
