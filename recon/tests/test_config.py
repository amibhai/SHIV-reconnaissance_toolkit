"""Tests for recon.core.config."""

import os
import pytest
from pathlib import Path
from recon.core.config import ReconConfig


def test_defaults():
    cfg = ReconConfig()
    assert cfg.threads == 50
    assert cfg.timeout == 3.0
    assert cfg.evasion_level == 0
    assert cfg.verbosity == 1
    assert cfg.pcap_enabled is False


def test_env_override(monkeypatch):
    monkeypatch.setenv("RECON_THREADS", "200")
    monkeypatch.setenv("RECON_TIMEOUT", "5.0")
    monkeypatch.setenv("RECON_EVASION_LEVEL", "2")
    cfg = ReconConfig()
    assert cfg.threads == 200
    assert cfg.timeout == 5.0
    assert cfg.evasion_level == 2


def test_threads_bounds():
    with pytest.raises(Exception):
        ReconConfig(threads=0)
    with pytest.raises(Exception):
        ReconConfig(threads=10001)


def test_evasion_bounds():
    with pytest.raises(Exception):
        ReconConfig(evasion_level=4)
    with pytest.raises(Exception):
        ReconConfig(evasion_level=-1)


def test_effective_delay_evasion0():
    cfg = ReconConfig(evasion_level=0, rate_limit=0.0)
    assert cfg.effective_delay() == 0.0


def test_effective_delay_evasion1():
    cfg = ReconConfig(evasion_level=1)
    assert cfg.effective_delay() == 0.01


def test_effective_delay_evasion2():
    cfg = ReconConfig(evasion_level=2)
    delay = cfg.effective_delay()
    assert 0.05 <= delay <= 0.3


def test_effective_delay_evasion3():
    cfg = ReconConfig(evasion_level=3)
    delay = cfg.effective_delay()
    assert 0.5 <= delay <= 2.0


def test_ensure_output_dir(tmp_path):
    cfg = ReconConfig(output_dir=tmp_path / "recon_out")
    result = cfg.ensure_output_dir()
    assert result.exists()
    assert result.is_dir()


def test_output_dir_expansion():
    cfg = ReconConfig(output_dir="~/recon_test_output")
    assert "~" not in str(cfg.output_dir)
