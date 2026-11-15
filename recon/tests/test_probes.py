"""Unit tests for the service-detection probe engine (recon.core.probes)."""

from __future__ import annotations

import base64
import json

import pytest

from recon.core import probes as P


def test_text_probe_payload_substitutes_target_and_is_latin1():
    probe = {"probe_encoding": "text", "probe": "GET / HTTP/1.0\r\nHost: {target}\r\n\r\n"}
    out = P.probe_payload(probe, "10.0.0.5")
    assert out == b"GET / HTTP/1.0\r\nHost: 10.0.0.5\r\n\r\n"


def test_base64_probe_payload_roundtrips_exact_bytes():
    raw = bytes([0x30, 0x0c, 0x00, 0x80, 0xfe])
    probe = {"probe_encoding": "base64", "probe": base64.b64encode(raw).decode()}
    assert P.probe_payload(probe, "x") == raw


def test_validate_probes_flags_bad_base64_and_bad_regex():
    bad = [
        {"name": "A", "protocol": "tcp", "ports": [1], "probe_encoding": "base64",
         "probe": "not!base64!", "service_name": "a", "match_regex": "ok"},
        {"name": "B", "protocol": "tcp", "ports": [2], "probe_encoding": "text",
         "probe": "x", "service_name": "b", "match_regex": "(unclosed"},
    ]
    errs = P.validate_probes(bad)
    assert any("base64" in e for e in errs)
    assert any("match_regex" in e for e in errs)


def test_validate_probes_flags_target_in_binary_probe():
    bad = [{"name": "C", "protocol": "tcp", "ports": [3], "probe_encoding": "base64",
            "probe": base64.b64encode(b"{target}").decode(), "service_name": "c"}]
    assert any("{target}" in e for e in P.validate_probes(bad))


def test_load_probes_raises_on_malformed_file(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("[ this is not json ]", encoding="utf-8")
    with pytest.raises(P.ProbeLoadError):
        P.load_probes(path=bad)

    missing = tmp_path / "nope.json"
    with pytest.raises(P.ProbeLoadError):
        P.load_probes(path=missing)
