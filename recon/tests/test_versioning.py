"""Tolerant version parsing / range checks (must never raise)."""

from __future__ import annotations

import pytest

from recon.core import versioning as V


@pytest.mark.parametrize("text,expected", [
    ("Apache/2.4.49 (Unix)", "2.4.49"),
    ("SSH-2.0-OpenSSH_7.4", "2.0"),   # generic extract takes the FIRST token
    ("OpenSSH_7.4", "7.4"),           # which is why per-entry version_capture exists
    ("nginx", None),
    ("", None),
    (None, None),
])
def test_extract(text, expected):
    assert V.extract(text) == expected


def test_compare():
    assert V.compare("2.4.49", "2.4.50") < 0
    assert V.compare("2.4.50", "2.4.49") > 0
    assert V.compare("2.4", "2.4.0") == 0      # zero-padded
    assert V.compare("10.0", "9.9") > 0        # numeric, not lexical


@pytest.mark.parametrize("ver,con,ok", [
    ("2.4.49", "==2.4.49", True),
    ("2.4.51", "==2.4.49", False),
    ("7.4", "<7.7", True),
    ("8.0", "<7.7", False),
    ("2.4.49", ">=2.4.0,<2.4.50", True),
    ("2.4.50", ">=2.4.0,<2.4.50", False),
    ("1.2.3", "<=1.2.3", True),
])
def test_satisfies(ver, con, ok):
    assert V.satisfies(ver, con) is ok


@pytest.mark.parametrize("ver,con", [
    ("garbage", "<7.7"), ("1.0", "nonsense"), ("", "==1.0"), ("1.0", ""),
    (None, "<1.0"), ("1.0", None),
])
def test_satisfies_is_failsafe(ver, con):
    # Must return a bool, never raise, on malformed input.
    assert isinstance(V.satisfies(ver, con), bool)
