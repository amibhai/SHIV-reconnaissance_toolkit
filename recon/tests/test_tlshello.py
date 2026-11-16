"""Real JA3S from a raw ServerHello: deterministic, spec-shaped, fail-safe."""

from __future__ import annotations

import datetime
import socket
import ssl
import threading

import pytest

from recon.core import tlshello


def _cert(tmp_path):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n)
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=5))
         .not_valid_after(now + datetime.timedelta(days=1))
         .sign(k, hashes.SHA256()))
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(k.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
    return cert, key


def _tls_server(cert, key):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            try:
                ctx.wrap_socket(conn, server_side=True)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1]


def test_ja3s_is_real_and_deterministic(tmp_path):
    port = _tls_server(*_cert(tmp_path))
    a = tlshello.server_fingerprint("127.0.0.1", port, 3.0)
    b = tlshello.server_fingerprint("127.0.0.1", port, 3.0)
    assert a and len(a["ja3s"]) == 32            # real MD5 hex
    assert all(ch in "0123456789abcdef" for ch in a["ja3s"])
    assert a["ja3s"] == b["ja3s"]                # deterministic, unlike hash()
    assert a["cipher"] != 0                      # a genuinely negotiated cipher
    assert a["ja3s_string"].startswith(f"{a['tls_version']},{a['cipher']},")


def test_server_fingerprint_failsafe_on_dead_port():
    # Nothing listening -> empty dict, never an exception.
    assert tlshello.server_fingerprint("127.0.0.1", 1, 0.5) == {}


def test_parse_server_hello_rejects_garbage():
    assert tlshello.parse_server_hello(b"") == {}
    assert tlshello.parse_server_hello(b"\x15\x03\x03\x00\x02\x02\x28") == {}  # alert record
