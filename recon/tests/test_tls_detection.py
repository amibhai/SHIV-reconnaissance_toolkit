"""TLS-aware service detection: implicit-TLS ports get a real handshake."""

from __future__ import annotations

import socket
import ssl
import threading
import datetime

import pytest

from recon.core.config import ReconConfig
from recon.core import probes as probes_mod
import recon.modules.port_scan as ps


def _self_signed(cert_path, key_path):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))


def _start_tls_server(certfile, keyfile):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(certfile), str(keyfile))

    def serve():
        try:
            conn, _ = srv.accept()
            sconn = ctx.wrap_socket(conn, server_side=True)
            sconn.recv(1024)
            sconn.sendall(b"HTTP/1.1 200 OK\r\nServer: nginx/9.9.9\r\n\r\nhello")
            sconn.close()
        except Exception:
            pass
        finally:
            srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


def test_detect_service_over_tls(tmp_path, monkeypatch):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    _self_signed(cert, key)
    port = _start_tls_server(cert, key)

    # Treat the ephemeral port as implicit-TLS and let the HTTPS probe target it.
    monkeypatch.setattr(ps, "_TLS_PORTS", ps._TLS_PORTS | {port})
    probes = [dict(p) for p in probes_mod.load_probes()]
    for pr in probes:
        if pr["name"] == "HTTPS":
            pr["ports"] = list(pr["ports"]) + [port]
    monkeypatch.setattr(ps, "_SERVICE_PROBES", probes)
    monkeypatch.setattr(ps, "_PROBES_LOADED", True)

    cfg = ReconConfig(connect_timeout=3.0, timeout=3.0, output_dir=tmp_path, verbosity=0)
    svc, ver, banner = ps.PortScanner("127.0.0.1", cfg).detect_service(port)
    assert svc == "https", (svc, ver, banner)
    assert ver == "nginx/9.9.9", (svc, ver, banner)
