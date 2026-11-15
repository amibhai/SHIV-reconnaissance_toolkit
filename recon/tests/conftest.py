"""Shared pytest fixtures for the recon-toolkit test suite.

Keep fixtures dependency-light so the whole unit suite runs without root, raw
sockets, Npcap, or a live target (those tests are marked `integration`).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure the project root is importable (so `import recon` works when pytest is
# launched from anywhere), without the ad-hoc sys.path hacks the old menus used.
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


@pytest.fixture
def tmp_output_dir(tmp_path: Path) -> Path:
    """An isolated output directory for a single test."""
    d = tmp_path / "output"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def config(tmp_output_dir: Path):
    """A fast, isolated ReconConfig suitable for unit tests."""
    from recon.core.config import ReconConfig

    return ReconConfig(
        threads=4,
        timeout=0.5,
        connect_timeout=0.5,
        output_dir=tmp_output_dir,
        verbosity=0,
    )


@pytest.fixture(autouse=True)
def _never_block_on_banner(monkeypatch):
    """Safety net: no unit test should ever block on the banner's ENTER prompt.

    The banner is fully decoupled from the CLI commands, but this guards against
    a stray `input()` hanging CI if a test imports a path that still prompts.
    """
    monkeypatch.setenv("RECON_NO_BANNER", "1")
    monkeypatch.setattr("builtins.input", lambda *a, **k: "", raising=False)
