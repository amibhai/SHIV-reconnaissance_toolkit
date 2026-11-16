"""CLI smoke tests: commands must run non-interactively (never block on input)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _run(args: list[str]) -> subprocess.CompletedProcess:
    env = dict(os.environ, RECON_NO_BANNER="1")
    # stdin=DEVNULL + timeout: if a command ever blocks on input() this raises.
    return subprocess.run(
        [sys.executable, "recon.py", *args],
        cwd=ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=90,
        stdin=subprocess.DEVNULL,
        env=env,
    )


def test_privcheck_runs_non_interactively():
    r = _run(["privcheck"])
    assert r.returncode == 0, r.stderr
    assert "Privilege Status" in r.stdout


def test_help_exits_zero():
    r = _run(["--help"])
    assert r.returncode == 0
    assert "Usage" in r.stdout


def test_no_banner_flag_accepted():
    r = _run(["--no-banner", "privcheck"])
    assert r.returncode == 0
