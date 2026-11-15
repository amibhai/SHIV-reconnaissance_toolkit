"""Data-file integrity gate.

The toolkit is data-driven (CVE rules, service probes, credentials, OUI, port
lists). A malformed data file used to fail *silently* at runtime (e.g. an
invalid service_probes.json disabled all service detection with no error).
These cheap tests turn every such defect into a hard CI failure.

Sections are added as each data file is repaired across the Foundation Phase.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def _load_json(name: str):
    path = DATA_DIR / name
    assert path.exists(), f"missing data file: {path}"
    with open(path, encoding="utf-8") as f:
        return json.load(f)  # raises -> test fails, instead of a silent runtime []


# --- cve_db.json -----------------------------------------------------------

def test_cve_db_is_valid_json_list():
    db = _load_json("cve_db.json")
    assert isinstance(db, list) and db, "cve_db.json must be a non-empty list"


def test_cve_db_entries_have_required_fields():
    db = _load_json("cve_db.json")
    required = {"cve_id", "service", "version_regex", "cvss_score", "severity"}
    for e in db:
        missing = required - e.keys()
        assert not missing, f"{e.get('cve_id', '?')} missing fields: {missing}"


def test_every_cve_regex_compiles():
    """Regressions guard: 2 regexes used to be uncompilable and silently skipped."""
    db = _load_json("cve_db.json")
    bad = []
    for e in db:
        try:
            re.compile(e["version_regex"])
        except re.error as ex:
            bad.append(f"{e['cve_id']}: {ex}")
    assert not bad, "non-compiling CVE regex(es): " + "; ".join(bad)


def test_cve_ids_are_unique():
    db = _load_json("cve_db.json")
    ids = [e["cve_id"] for e in db]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate cve_id(s): {dupes}"


# --- default_creds.json ----------------------------------------------------

def test_default_creds_is_valid_json():
    creds = _load_json("default_creds.json")
    assert isinstance(creds, list) and creds
    for svc in creds:
        assert "service" in svc and "credentials" in svc
        assert isinstance(svc["credentials"], list)


# --- service_probes.json ---------------------------------------------------

def test_service_probes_load_and_validate():
    """Regression guard: the file used to be invalid JSON (raw hex-byte escapes),
    which silently disabled ALL service detection. It must now parse, validate,
    and expose the full probe set."""
    from recon.core.probes import load_probes, validate_probes

    probes = load_probes(force=True)
    assert len(probes) == 34, f"expected 34 probes, got {len(probes)}"
    assert validate_probes(probes) == []


def test_service_probes_payloads_build():
    """Every probe must produce bytes; {target} must be substituted in text."""
    from recon.core.probes import load_probes, probe_payload

    for probe in load_probes(force=True):
        payload = probe_payload(probe, "scanme.example")
        assert isinstance(payload, bytes)
        assert b"{target}" not in payload
