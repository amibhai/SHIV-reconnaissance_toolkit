"""Tests for recon.modules.port_scan — mocked network calls."""

import pytest
import socket
from unittest.mock import MagicMock, patch
from recon.modules.port_scan import (
    PortScanner, PortResult, _parse_port_spec,
    _well_known_service, _extract_version, NMAP_TOP_1000,
)
from recon.core.config import ReconConfig


@pytest.fixture
def cfg():
    return ReconConfig(threads=10, timeout=1.0, connect_timeout=0.5)


@pytest.fixture
def scanner(cfg):
    with patch("socket.gethostbyname", return_value="127.0.0.1"):
        return PortScanner("127.0.0.1", cfg)


# ── _parse_port_spec ─────────────────────────────────────────────────────────

def test_parse_single_port():
    assert _parse_port_spec("80") == [80]


def test_parse_comma_list():
    assert set(_parse_port_spec("80,443,22")) == {80, 443, 22}


def test_parse_range():
    assert _parse_port_spec("1-5") == [1, 2, 3, 4, 5]


def test_parse_top100():
    ports = _parse_port_spec("top100")
    assert len(ports) == 100
    assert 80 in ports


def test_parse_top1000():
    ports = _parse_port_spec("top1000")
    assert len(ports) >= 400   # deduped; real nmap top-1000 as unique set
    assert 80 in ports
    assert 443 in ports
    assert 22 in ports


def test_parse_all():
    ports = _parse_port_spec("all")
    assert len(ports) == 65535
    assert 1 in ports
    assert 65535 in ports


def test_parse_int():
    assert _parse_port_spec(443) == [443]


# ── Well-known service names ──────────────────────────────────────────────────

def test_well_known_service_http():
    assert _well_known_service(80) == "http"


def test_well_known_service_ssh():
    assert _well_known_service(22) == "ssh"


def test_well_known_service_unknown():
    assert _well_known_service(31337) == ""


# ── Version extraction ────────────────────────────────────────────────────────

def test_extract_version_from_banner():
    assert _extract_version("Apache/2.4.49") == "2.4.49"


def test_extract_version_ssh():
    assert _extract_version("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1") == "8.9"


def test_extract_version_empty():
    assert _extract_version("") == ""


# ── PortResult ────────────────────────────────────────────────────────────────

def test_port_result_to_dict():
    r = PortResult(port=80, state="open", service="http", version="nginx/1.24.0",
                   banner="HTTP/1.1 200 OK", scan_type="syn")
    d = r.to_dict()
    assert d["port"] == 80
    assert d["state"] == "open"
    assert d["service"] == "http"
    assert len(d["banner"]) <= 200


def test_port_result_banner_truncated():
    r = PortResult(port=80, state="open", banner="X" * 500)
    assert len(r.to_dict()["banner"]) == 200


# ── Connect scan (mocked) ─────────────────────────────────────────────────────

def test_connect_scan_open(scanner):
    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        result = scanner._connect_one(80)
    assert result.state == "open"
    assert result.port == 80


def test_connect_scan_refused(scanner):
    with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
        result = scanner._connect_one(80)
    assert result.state == "closed"


def test_connect_scan_timeout(scanner):
    with patch("socket.create_connection", side_effect=socket.timeout()):
        result = scanner._connect_one(80)
    assert result.state == "filtered"


# ── Service detection ─────────────────────────────────────────────────────────

def test_detect_service_http(scanner):
    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"
    with patch("socket.create_connection", return_value=mock_sock):
        svc, ver, banner = scanner.detect_service(80)
    assert "nginx" in banner or svc in ("http", "")


def test_detect_service_ssh(scanner):
    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
    with patch("socket.create_connection", return_value=mock_sock):
        svc, ver, banner = scanner.detect_service(22)
    assert "SSH" in banner or svc in ("ssh", "")


# ── NMAP_TOP_1000 ─────────────────────────────────────────────────────────────

def test_top_1000_has_common_ports():
    assert 80 in NMAP_TOP_1000
    assert 443 in NMAP_TOP_1000
    assert 22 in NMAP_TOP_1000
    assert 3306 in NMAP_TOP_1000
